using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Immutable;
using LocalDocumentOrganizer.Application.Contracts;
using LocalDocumentOrganizer.Application.Processing;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Application.Review;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Cases.Receivable;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public sealed class SqliteProductCommitStore :
    IProductCommitStore,
    IProductQueryStore,
    IInvoiceReviewQueryStore,
    IExtractionOutboxStore
{
    private const int DuplicateAppendRetryLimit = 16;
    private const int ImportBusyRetryLimit = 8;

    private readonly string _connectionString;
    private readonly VaultKeyRingStore _keyRing;
    private readonly SqliteProjectionRegistration _registration;
    private readonly SqliteProjectionRegistry _registry;
    private readonly SqliteEventStore _events;

    public SqliteProductCommitStore(
        string connectionString,
        TimeProvider? timeProvider = null)
        : this(
            connectionString,
            timeProvider,
            faultInjector: null)
    {
    }

    internal SqliteProductCommitStore(
        string connectionString,
        TimeProvider? timeProvider,
        IProductCommitFaultInjector? faultInjector)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString =
            SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        var source = new SqliteConnectionStringBuilder(_connectionString).DataSource;
        if (string.IsNullOrWhiteSpace(source)
            || string.Equals(source, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Product storage requires a file-backed Vault.",
                nameof(connectionString));
        }

        _keyRing = new VaultKeyRingStore(source + ".keyring");
        var projection = new SqliteProductProjection(faultInjector);
        _registration = SqliteProductProjection.CreateRegistration(projection);
        _registry = new SqliteProjectionRegistry([_registration]);
        _events = new SqliteEventStore(
            _connectionString,
            ProductEventContracts.CreateSchemaRegistry(),
            _registry,
            _keyRing,
            timeProvider,
            deletionFaultInjector: null,
            operationCommitFaultInjector:
                new ProductEventStoreFaultAdapter(
                    faultInjector ?? NoOpProductCommitFaultInjector.Instance));
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        _events.InitializeAsync(cancellationToken);

    public Task<ProjectionRebuildResult> RebuildProjectionsAsync(
        CancellationToken cancellationToken = default) =>
        _events.RebuildProjectionsAsync(cancellationToken);

    public async Task<ExtractionOutboxClaim?> ClaimNextAsync(
        Guid ownerId,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        CancellationToken cancellationToken)
    {
        if (ownerId == Guid.Empty || nowUtc.Offset != TimeSpan.Zero || leaseDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(ownerId));
        }

        SqliteEventStoreSchema.ValidateVaultPath(_connectionString, _keyRing.MaintenanceGate);
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireMutationAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString, _keyRing.MaintenanceGate, cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: false);
        await ValidateReadBoundaryAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        var now = ProductEventPayloads.Utc(nowUtc);
        await using (var recover = connection.CreateCommand())
        {
            recover.Transaction = transaction;
            recover.CommandText = """
                UPDATE product_outbox
                SET dispatch_status=2,lease_owner_id=NULL,lease_expires_at_utc=NULL
                WHERE commit_kind IN ('import-committed','explicit-reprocess') AND dispatch_status=1
                  AND lease_expires_at_utc IS NOT NULL AND lease_expires_at_utc<=$now;
                """;
            recover.Parameters.AddWithValue("$now", now);
            await recover.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await using var select = connection.CreateCommand();
        select.Transaction = transaction;
        select.CommandText = """
            SELECT o.operation_id,o.aggregate_id,o.inbox_id,d.content_sha256,
                   o.extraction_attempt_id,o.target_extraction_revision,
                   o.extraction_commit_operation_id,o.source_binding_json,o.automatic_failure_count
            FROM product_outbox o
            JOIN product_documents d ON d.document_id=o.aggregate_id
            WHERE o.commit_kind IN ('import-committed','explicit-reprocess')
              AND o.extraction_attempt_id IS NOT NULL
              AND o.dispatch_status IN (0,2)
            ORDER BY o.occurred_at_utc COLLATE BINARY,o.operation_id COLLATE BINARY
            LIMIT 1;
            """;
        await using var reader = await select.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return null;
        }

        var work = new ExtractionOutboxWorkItem(
            ProductEventPayloads.GuidValue(reader.GetString(0)),
            new DocumentId(ProductEventPayloads.GuidValue(reader.GetString(1))),
            new InboxId(ProductEventPayloads.GuidValue(reader.GetString(2))),
            new ContentSha256((byte[])reader.GetValue(3)),
            reader.IsDBNull(7) ? null : ReadSourceBinding(reader.GetString(7)),
            new ExtractionAttemptId(ProductEventPayloads.GuidValue(reader.GetString(4))),
            reader.GetInt32(5),
            new OperationId(ProductEventPayloads.GuidValue(reader.GetString(6))),
            ImmutableArray.Create("en-US", "ko-KR"),
            ExtractionCapability.EmbeddedText | ExtractionCapability.Ocr,
            reader.GetInt32(8),
            ExtractionOutboxState.Running,
            nowUtc.Add(leaseDuration));
        await reader.DisposeAsync().ConfigureAwait(false);
        await using (var claim = connection.CreateCommand())
        {
            claim.Transaction = transaction;
            claim.CommandText = """
                UPDATE product_outbox
                SET dispatch_status=1,lease_owner_id=$owner,lease_expires_at_utc=$expires
                WHERE operation_id=$operation AND dispatch_status IN (0,2);
                """;
            claim.Parameters.AddWithValue("$owner", ProductEventPayloads.Canonical(ownerId));
            claim.Parameters.AddWithValue("$expires", ProductEventPayloads.Utc(work.LeaseExpiresAtUtc!.Value));
            claim.Parameters.AddWithValue("$operation", ProductEventPayloads.Canonical(work.OutboxId));
            if (await claim.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                throw new VaultRecoveryRequiredException();
            }
        }
        await using (var inbox = connection.CreateCommand())
        {
            inbox.Transaction = transaction;
            inbox.CommandText = "UPDATE product_inbox SET status=$status WHERE document_id=$document AND status=0;";
            inbox.Parameters.AddWithValue("$status", (int)ProductInboxStatus.Processing);
            inbox.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(work.DocumentId.Value));
            await inbox.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new ExtractionOutboxClaim(work, ownerId);
    }

    public async Task<ExtractionOutboxCompletion> CompleteAsync(
        ExtractionOutboxCompletionCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.ExtractionCommit is not null)
        {
            var committed = await CommitExtractionAsync(command.ExtractionCommit, cancellationToken)
                .ConfigureAwait(false);
            if (committed is ProductCommitted)
            {
                // The extraction projection accepted the event and completed the
                // live outbox claim in its own event-store transaction.
                return new ExtractionOutboxCompletion(command.Claim.Work.TargetRevision, false);
            }
            if (committed is ProductAlreadyCommitted)
            {
                return new ExtractionOutboxCompletion(command.Claim.Work.TargetRevision, true);
            }
            throw new InvalidOperationException("Extraction commit requires recovery.");
        }

        SqliteEventStoreSchema.ValidateVaultPath(_connectionString, _keyRing.MaintenanceGate);
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireMutationAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString, _keyRing.MaintenanceGate, cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: false);
        await ValidateReadBoundaryAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE product_outbox
            SET dispatch_status=$status,automatic_failure_count=$failures,
                lease_owner_id=NULL,lease_expires_at_utc=NULL
            WHERE operation_id=$operation AND dispatch_status=1 AND lease_owner_id=$owner;
            """;
        update.Parameters.AddWithValue("$status", ToStorageStatus(command.NextState));
        update.Parameters.AddWithValue("$failures", command.AutomaticFailureCount);
        update.Parameters.AddWithValue("$operation", ProductEventPayloads.Canonical(command.Claim.Work.OutboxId));
        update.Parameters.AddWithValue("$owner", ProductEventPayloads.Canonical(command.Claim.OwnerId));
        var affected = await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        if (affected == 0)
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new ExtractionOutboxCompletion(command.Claim.Work.TargetRevision, true);
        }
        if (command.NextState == ExtractionOutboxState.TerminalFailure)
        {
            await using var inbox = connection.CreateCommand();
            inbox.Transaction = transaction;
            inbox.CommandText = """
                UPDATE product_inbox SET status=$status
                WHERE document_id=$document;
                """;
            inbox.Parameters.AddWithValue(
                "$status",
                command.FailureCode == DocumentProcessingFailureCode.UnsupportedDocument
                    ? (int)ProductInboxStatus.Unsupported
                    : (int)ProductInboxStatus.Failed);
            inbox.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(command.Claim.Work.DocumentId.Value));
            if (await inbox.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                throw new VaultRecoveryRequiredException();
            }
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new ExtractionOutboxCompletion(command.Claim.Work.TargetRevision, false);
    }

    public async Task<ExplicitReprocessResult> ScheduleReprocessAsync(
        ExplicitReprocessCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.ExpectedCurrentRevision < 0 || command.CommandOperationId.Value == Guid.Empty)
        {
            throw new ArgumentOutOfRangeException(nameof(command));
        }

        var currentRevision = await ReadCurrentExtractionRevisionAsync(
            command.DocumentId,
            cancellationToken).ConfigureAwait(false);
        if (currentRevision != command.ExpectedCurrentRevision)
        {
            return new ExplicitReprocessResult(
                ExplicitReprocessOutcome.RevisionConflict,
                checked(command.ExpectedCurrentRevision + 1));
        }

        SqliteEventStoreSchema.ValidateVaultPath(_connectionString, _keyRing.MaintenanceGate);
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireMutationAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString, _keyRing.MaintenanceGate, cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: false);
        await ValidateReadBoundaryAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        await using (var existing = connection.CreateCommand())
        {
            existing.Transaction = transaction;
            existing.CommandText = """
                SELECT target_extraction_revision FROM product_outbox
                WHERE operation_id=$operation AND commit_kind='explicit-reprocess';
                """;
            existing.Parameters.AddWithValue("$operation", ProductEventPayloads.Canonical(command.CommandOperationId.Value));
            var value = await existing.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (value is long revision)
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return new ExplicitReprocessResult(
                    ExplicitReprocessOutcome.AlreadyScheduled,
                    checked((int)revision));
            }
            if (value is not null)
            {
                throw new VaultRecoveryRequiredException();
            }
        }

        string inboxId;
        await using (var inbox = connection.CreateCommand())
        {
            inbox.Transaction = transaction;
            inbox.CommandText = "SELECT inbox_id FROM product_inbox WHERE document_id=$document;";
            inbox.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(command.DocumentId.Value));
            inboxId = await inbox.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string
                ?? throw new VaultRecoveryRequiredException();
        }
        ProductDocumentSourceBinding? sourceBinding;
        await using (var source = connection.CreateCommand())
        {
            source.Transaction = transaction;
            source.CommandText = """
                SELECT source_binding_json FROM product_outbox
                WHERE aggregate_id=$document AND commit_kind='import-committed'
                ORDER BY occurred_at_utc COLLATE BINARY,operation_id COLLATE BINARY
                LIMIT 1;
                """;
            source.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(command.DocumentId.Value));
            var sourceBindingJson = await source.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            sourceBinding = sourceBindingJson is DBNull or null
                ? null
                : ReadSourceBinding(sourceBindingJson as string
                    ?? throw new VaultRecoveryRequiredException());
        }
        var targetRevision = checked((int)(currentRevision + 1));
        var occurred = ProductEventPayloads.Utc(DateTimeOffset.UtcNow);
        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO product_outbox(
                    operation_id,event_id,commit_kind,aggregate_id,inbox_id,occurred_at_utc,
                    dispatch_status,extraction_attempt_id,target_extraction_revision,
                    extraction_commit_operation_id,source_binding_json)
                VALUES($operation,$event,'explicit-reprocess',$document,$inbox,$occurred,
                    0,$attempt,$revision,$commit_operation,$source_binding);
                """;
            insert.Parameters.AddWithValue("$operation", ProductEventPayloads.Canonical(command.CommandOperationId.Value));
            insert.Parameters.AddWithValue("$event", ProductEventPayloads.Canonical(command.CommandOperationId.Value));
            insert.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(command.DocumentId.Value));
            insert.Parameters.AddWithValue("$inbox", inboxId);
            insert.Parameters.AddWithValue("$occurred", occurred);
            insert.Parameters.AddWithValue("$attempt", ProductEventPayloads.Canonical(Guid.NewGuid()));
            insert.Parameters.AddWithValue("$revision", targetRevision);
            insert.Parameters.AddWithValue("$commit_operation", ProductEventPayloads.Canonical(Guid.NewGuid()));
            insert.Parameters.Add("$source_binding", SqliteType.Text).Value =
                sourceBinding is null ? DBNull.Value : JsonSerializer.Serialize(sourceBinding);
            try
            {
                if (await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 19)
            {
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return new ExplicitReprocessResult(
                    ExplicitReprocessOutcome.RevisionConflict,
                    targetRevision);
            }
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new ExplicitReprocessResult(ExplicitReprocessOutcome.Scheduled, targetRevision);
    }

    public async Task<ImportCommitResult> CommitImportAsync(
        CommitImportCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var fingerprint = ProductEventPayloads.ImportFingerprint(command);
        try
        {
            for (var attempt = 0; attempt < ImportBusyRetryLimit; attempt++)
            {
                var result = await CommitImportOnceAsync(
                    command,
                    fingerprint,
                    cancellationToken).ConfigureAwait(false);
                if (result is not ProductRecoveryRequired
                    {
                        Kind: ProductRecoveryKind.StorageBusy,
                    })
                {
                    return result;
                }

                ExistingDocument? winner = null;
                try
                {
                    winner = await FindDocumentByShaAsync(
                        command.ContentSha256,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (SqliteException exception) when (
                    exception.SqliteErrorCode is 5 or 6)
                {
                }

                if (winner is not null)
                {
                    var duplicate = await CommitDuplicateImportAsync(
                        command,
                        winner,
                        fingerprint,
                        cancellationToken).ConfigureAwait(false);
                    if (duplicate is not ProductRecoveryRequired
                        {
                            Kind: ProductRecoveryKind.StorageBusy,
                        })
                    {
                        return duplicate;
                    }
                }

                if (attempt + 1 < ImportBusyRetryLimit)
                {
                    await DelayBeforeBusyRetryAsync(
                        attempt,
                        cancellationToken).ConfigureAwait(false);
                }
            }

            return new ProductRecoveryRequired(ProductRecoveryKind.StorageBusy);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ProjectionRebuildRequiredException)
        {
            return new ProductRecoveryRequired(
                ProductRecoveryKind.ProjectionRebuildRequired);
        }
        catch (Exception exception) when (IsProtectedStateFailure(exception))
        {
            return new ProductRecoveryRequired(
                ProductRecoveryKind.ProtectedStateInvalid);
        }
        catch (Exception exception) when (
            exception is SqliteException
                or InjectedProductCommitFaultException
                or IOException
                or UnauthorizedAccessException)
        {
            return new ProductRecoveryRequired(ProductRecoveryKind.StorageFailure);
        }
    }

    private async Task<ImportCommitResult> CommitImportOnceAsync(
        CommitImportCommand command,
        byte[] fingerprint,
        CancellationToken cancellationToken)
    {
        try
        {
            var append = await _events.AppendAsync(
                new AppendEventsCommand(
                    new StreamId(command.DocumentId.Value),
                    StreamVersion.NoStream,
                    command.OperationId,
                    [
                        new EventToAppend(
                            command.EventId,
                            ProductEventContracts.DocumentImported,
                            ProductEventContracts.SchemaVersion,
                            ProductEventPayloads.SerializeImport(
                                command,
                                fingerprint),
                            DocumentProtection(command.DocumentId)),
                    ]),
                cancellationToken).ConfigureAwait(false);
            if (append is Appended)
            {
                return new ImportCommitted(command.InboxId);
            }

            if (append is AlreadyApplied)
            {
                return new ImportAlreadyCommitted(command.InboxId);
            }

            if (append is StorageBusy)
            {
                return new ProductRecoveryRequired(
                    ProductRecoveryKind.StorageBusy);
            }

            if (append is OperationConflict
                or OperationComparisonUnavailable
                or ConcurrencyConflict)
            {
                var existing = await FindDocumentByShaAsync(
                    command.ContentSha256,
                    cancellationToken).ConfigureAwait(false);
                if (existing is not null)
                {
                    return await CommitDuplicateImportAsync(
                        command,
                        existing,
                        fingerprint,
                        cancellationToken).ConfigureAwait(false);
                }

                return append is ConcurrencyConflict
                    ? new ImportConflict(
                        ProductConflictKind.StreamVersionMismatch)
                    : new ImportConflict(
                        ProductConflictKind.OperationIdentityMismatch);
            }

            return new ProductRecoveryRequired(
                ProductRecoveryKind.StorageFailure);
        }
        catch (SqliteException exception) when (
            exception.SqliteErrorCode == 19)
        {
            var existing = await FindDocumentByShaAsync(
                command.ContentSha256,
                cancellationToken).ConfigureAwait(false);
            return existing is not null
                ? await CommitDuplicateImportAsync(
                    command,
                    existing,
                    fingerprint,
                    cancellationToken).ConfigureAwait(false)
                : new ProductRecoveryRequired(
                    ProductRecoveryKind.StorageFailure);
        }
        catch (SqliteException exception) when (
            exception.SqliteErrorCode is 5 or 6)
        {
            return new ProductRecoveryRequired(ProductRecoveryKind.StorageBusy);
        }
    }

    public Task<ProductCommitResult> CommitExtractionAsync(
        CommitExtractionCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var fingerprint = ProductEventPayloads.ExtractionFingerprint(command);
        return CommitDocumentProgressAsync(
            command.OperationId,
            command.EventId,
            command.DocumentId,
            command.ExpectedVersion,
            ProductEventContracts.ExtractionCommitted,
            ProductEventPayloads.SerializeExtraction(command, fingerprint),
            cancellationToken);
    }

    public Task<ProductCommitResult> CommitReviewAsync(
        CommitReviewCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var fingerprint = ProductEventPayloads.ReviewFingerprint(command);
        return CommitDocumentProgressAsync(
            command.OperationId,
            command.EventId,
            command.DocumentId,
            command.ExpectedVersion,
            ProductEventContracts.ReviewCommitted,
            ProductEventPayloads.SerializeReview(command, fingerprint),
            cancellationToken);
    }

    public async Task<ProductCommitResult> CommitReceivableCaseAsync(
        CommitReceivableCaseCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var fingerprint =
            ProductEventPayloads.ReceivableCaseFingerprint(command);
        try
        {
            try
            {
                return MapGeneralAppend(
                    await _events.AppendAsync(
                        new AppendEventsCommand(
                            new StreamId(command.CaseId.Value),
                            StreamVersion.NoStream,
                            command.OperationId,
                            [
                                new EventToAppend(
                                    command.EventId,
                                    ProductEventContracts.ReceivableCaseCommitted,
                                    ProductEventContracts.SchemaVersion,
                                    ProductEventPayloads.SerializeReceivableCase(
                                        command,
                                        fingerprint),
                                    CaseProtection(command.CaseId)),
                            ]),
                        cancellationToken).ConfigureAwait(false));
            }
            catch (SqliteException exception) when (
                exception.SqliteErrorCode == 19)
            {
                var existing = await FindCaseBySourceDocumentAsync(
                    command.SourceDocumentId,
                    cancellationToken).ConfigureAwait(false);
                return existing is not null
                    ? new ProductConflict(
                        ProductConflictKind.SourceDocumentAlreadyHasCase,
                        existing.Value)
                    : new ProductConflict(ProductConflictKind.StorageConstraint);
            }
        }
        catch (ProductProjectionConflictException conflict)
        {
            return new ProductConflict(conflict.Kind);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            return MapRecovery(exception);
        }
    }

    public async Task<InboxPage> QueryInboxAsync(
        InboxPageRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            SqliteEventStoreSchema.ValidateVaultPath(
                _connectionString,
                _keyRing.MaintenanceGate);
            await using var lease = await _keyRing.MaintenanceGate
                .AcquireReadAsync(cancellationToken).ConfigureAwait(false);
            await using var connection =
                await SqliteEventStoreSchema.OpenConnectionAsync(
                    _connectionString,
                    _keyRing.MaintenanceGate,
                    cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: true);
            await ValidateReadBoundaryAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            var administrative = SqliteProjectionContexts.CreateAdministrative(
                connection,
                transaction,
                _keyRing,
                lease,
                _registration);

            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = BuildInboxQuery(request);
            if (request.Status is { } status)
            {
                command.Parameters.AddWithValue("$status", (int)status);
            }

            if (request.After is { } after)
            {
                command.Parameters.AddWithValue(
                    "$after_received",
                    ProductEventPayloads.Utc(after.ReceivedAtUtc));
                command.Parameters.AddWithValue(
                    "$after_document",
                    ProductEventPayloads.Canonical(after.DocumentId.Value));
            }

            command.Parameters.AddWithValue("$limit", request.PageSize);
            var items = new List<InboxListItem>(request.PageSize);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var inboxId = new InboxId(
                    ProductEventPayloads.GuidValue(reader.GetString(0)));
                var documentId = new DocumentId(
                    ProductEventPayloads.GuidValue(reader.GetString(1)));
                var receivedAt = ProductEventPayloads.UtcValue(reader.GetString(2));
                var rawStatus = reader.GetInt32(3);
                if (!Enum.IsDefined(typeof(ProductInboxStatus), rawStatus))
                {
                    throw new VaultRecoveryRequiredException();
                }

                var owner = ReadOwner(reader, 4, 5);
                var keyId = new DataKeyId(
                    ProductEventPayloads.GuidValue(reader.GetString(6)));
                var encrypted = new EncryptedProjectionValue(
                    reader.GetInt32(7),
                    keyId,
                    (byte[])reader.GetValue(8),
                    (byte[])reader.GetValue(9),
                    (byte[])reader.GetValue(10));
                var fileName = await administrative.Values.UnprotectAsync(
                    "product_inbox",
                    "file_name",
                    ProductEventPayloads.Canonical(inboxId.Value),
                    owner,
                    keyId,
                    encrypted,
                    (plaintext, _) => ValueTask.FromResult(
                        new UTF8Encoding(false, true).GetString(plaintext.Span)),
                    cancellationToken).ConfigureAwait(false);
                items.Add(
                    new InboxListItem(
                        inboxId,
                        documentId,
                        receivedAt,
                        (ProductInboxStatus)rawStatus,
                        fileName));
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            var next = items.Count == request.PageSize && items.Count != 0
                ? new InboxCursor(
                    items[^1].ReceivedAtUtc,
                    items[^1].DocumentId)
                : null;
            return new InboxPage(items.AsReadOnly(), next);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SqliteException
                or ProjectionValueRecoveryRequiredException
                or DecoderFallbackException
                or InvalidCastException
                or FormatException
                or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    public async Task<TodayPage> QueryTodayAsync(
        TodayPageRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            await using var lease = await _keyRing.MaintenanceGate
                .AcquireReadAsync(cancellationToken).ConfigureAwait(false);
            await using var connection =
                await SqliteEventStoreSchema.OpenConnectionAsync(
                    _connectionString,
                    _keyRing.MaintenanceGate,
                    cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: true);
            await ValidateReadBoundaryAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            var administrative = SqliteProjectionContexts.CreateAdministrative(
                connection,
                transaction,
                _keyRing,
                lease,
                _registration);
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = BuildTodayQuery(request);
            if (request.Status is { } status)
            {
                command.Parameters.AddWithValue("$status", (int)status);
            }

            if (request.After is { } after)
            {
                command.Parameters.AddWithValue(
                    "$after_due",
                    after.DueDate.ToString(
                        "yyyy-MM-dd",
                        CultureInfo.InvariantCulture));
                command.Parameters.AddWithValue(
                    "$after_case",
                    ProductEventPayloads.Canonical(after.CaseId.Value));
            }

            command.Parameters.AddWithValue("$limit", request.PageSize);
            var items = new List<TodayListItem>(request.PageSize);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var rawStatus = reader.GetInt32(3);
                if (!Enum.IsDefined(typeof(ProductTodayStatus), rawStatus))
                {
                    throw new VaultRecoveryRequiredException();
                }

                var caseId = new CaseId(
                    ProductEventPayloads.GuidValue(reader.GetString(0)));
                ReceivableActionId? actionId = null;
                ReceivableActionType? actionType = null;
                decimal? amount = null;
                string? currency = null;
                string? safeReason = null;
                if (!reader.IsDBNull(4))
                {
                    var actionGuid =
                        ProductEventPayloads.GuidValue(reader.GetString(4));
                    var rawActionType = reader.GetInt32(5);
                    if (!Enum.IsDefined(
                            typeof(ReceivableActionType),
                            rawActionType))
                    {
                        throw new VaultRecoveryRequiredException();
                    }
                    var owner = ReadOwner(reader, 6, 7);
                    if (owner.Kind != SensitiveObjectKind.Case
                        || owner.Id.Value != caseId.Value)
                    {
                        throw new VaultRecoveryRequiredException();
                    }
                    var keyId = new DataKeyId(
                        ProductEventPayloads.GuidValue(reader.GetString(8)));
                    var encrypted = new EncryptedProjectionValue(
                        reader.GetInt32(9),
                        keyId,
                        (byte[])reader.GetValue(10),
                        (byte[])reader.GetValue(11),
                        (byte[])reader.GetValue(12));
                    var display = await administrative.Values.UnprotectAsync(
                        "product_today",
                        "display",
                        ProductEventPayloads.Canonical(caseId.Value),
                        owner,
                        keyId,
                        encrypted,
                        (plaintext, _) => ValueTask.FromResult(
                            JsonSerializer.Deserialize<TodayProtectedPayload>(
                                plaintext.Span)
                            ?? throw new VaultRecoveryRequiredException()),
                        cancellationToken).ConfigureAwait(false);
                    if (display.Version != 1
                        || !decimal.TryParse(
                            display.TotalAmount,
                            NumberStyles.Number,
                            CultureInfo.InvariantCulture,
                            out var parsedAmount)
                        || parsedAmount <= 0
                        || !string.Equals(
                            parsedAmount.ToString(
                                "0.#############################",
                                CultureInfo.InvariantCulture),
                            display.TotalAmount,
                            StringComparison.Ordinal)
                        || !Iso4217CurrencyCatalog.IsValid(display.Currency)
                        || string.IsNullOrWhiteSpace(display.SafeReason))
                    {
                        throw new VaultRecoveryRequiredException();
                    }
                    actionId = new ReceivableActionId(actionGuid);
                    actionType = (ReceivableActionType)rawActionType;
                    amount = parsedAmount;
                    currency = display.Currency;
                    safeReason = display.SafeReason;
                }
                else if (Enumerable.Range(5, 8)
                    .Any(ordinal => !reader.IsDBNull(ordinal)))
                {
                    throw new VaultRecoveryRequiredException();
                }

                items.Add(new TodayListItem(
                    caseId,
                    new DocumentId(
                        ProductEventPayloads.GuidValue(reader.GetString(1))),
                    ProductEventPayloads.DateValue(reader.GetString(2)),
                    (ProductTodayStatus)rawStatus,
                    actionId,
                    actionType,
                    amount,
                    currency,
                    safeReason));
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            var next = items.Count == request.PageSize && items.Count != 0
                ? new TodayCursor(items[^1].DueDate, items[^1].CaseId)
                : null;
            return new TodayPage(items.AsReadOnly(), next);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SqliteException
                or ProjectionValueRecoveryRequiredException
                or JsonException
                or InvalidCastException
                or FormatException
                or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    public async Task<ConfirmedInvoiceReview?> LoadConfirmedAsync(DocumentId documentId, CancellationToken cancellationToken)
    {
        try
        {
            var row = await LoadReviewPayloadAsync(documentId, cancellationToken)
                .ConfigureAwait(false);
            return row is null ? null : ParseReview(row);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ProjectionValueRecoveryRequiredException
                or JsonException
                or DecoderFallbackException
                or FormatException
                or InvalidCastException
                or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    public async Task<InvoiceReviewSnapshot?> LoadCurrentAsync(DocumentId documentId, CancellationToken cancellationToken)
    {
        try
        {
            var state = await ReadProjectedReviewStateAsync(
                    documentId,
                    cancellationToken)
                .ConfigureAwait(false);
            var draftProjection = await LoadCurrentDraftAsync(
                    documentId,
                    cancellationToken)
                .ConfigureAwait(false);
            var review = await LoadConfirmedAsync(documentId, cancellationToken)
                .ConfigureAwait(false);
            if (draftProjection is null)
            {
                return null;
            }
            if (draftProjection.ExtractionRevision != state.ExtractionRevision
                || draftProjection.StreamVersion != state.StreamVersion)
            {
                throw new VaultRecoveryRequiredException();
            }

            if (review is not null
                && !state.SourceIdentity.Equals(review.SourceIdentity))
            {
                throw new VaultRecoveryRequiredException();
            }

            var fields = review is null
                ? ImmutableDictionary.Create<string, ReviewExtractionField>(
                    StringComparer.Ordinal)
                : review.Fields.ToImmutableDictionary(
                    field => field.FieldId,
                    field => new ReviewExtractionField(
                        field.FieldId,
                        field.OriginalNormalizedValue),
                    StringComparer.Ordinal);
            var sourcePages = draftProjection.Draft.Extraction.SourcePages;
            return new InvoiceReviewSnapshot(
                documentId,
                state.SourceIdentity,
                state.ExtractionRevision,
                review?.ReviewRevision ?? 0,
                state.StreamVersion,
                state.Status,
                fields,
                sourcePages.Length,
                draftProjection.Draft,
                sourcePages);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ProjectionValueRecoveryRequiredException
                or ExtractionDraftSerializationException
                or JsonException
                or DecoderFallbackException
                or FormatException
                or InvalidCastException
                or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private async Task<ProjectedCurrentDraft?> LoadCurrentDraftAsync(
        DocumentId documentId,
        CancellationToken cancellationToken)
    {
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireReadAsync(cancellationToken).ConfigureAwait(false);
        await using var connection =
            await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString,
                _keyRing.MaintenanceGate,
                cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await ValidateReadBoundaryAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
        var administrative = SqliteProjectionContexts.CreateAdministrative(
            connection,
            transaction,
            _keyRing,
            lease,
            _registration);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT extraction_revision,current_stream_version,
                   owner_kind,owner_id,key_id,encryption_version,
                   payload_nonce,payload_ciphertext,payload_tag
            FROM product_review_drafts
            WHERE document_id=$document;
            """;
        var logicalKey = ProductEventPayloads.Canonical(documentId.Value);
        command.Parameters.AddWithValue("$document", logicalKey);
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            await transaction.CommitAsync(cancellationToken)
                .ConfigureAwait(false);
            return null;
        }

        var extractionRevision = reader.GetInt32(0);
        var streamVersion = reader.GetInt64(1);
        var owner = ReadOwner(reader, 2, 3);
        var keyId = new DataKeyId(
            ProductEventPayloads.GuidValue(reader.GetString(4)));
        var encrypted = new EncryptedProjectionValue(
            reader.GetInt32(5),
            keyId,
            (byte[])reader.GetValue(6),
            (byte[])reader.GetValue(7),
            (byte[])reader.GetValue(8));
        if (extractionRevision <= 0
            || streamVersion < 0
            || await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new VaultRecoveryRequiredException();
        }
        await reader.DisposeAsync().ConfigureAwait(false);
        var payload = await administrative.Values.UnprotectAsync(
            "product_review_drafts",
            "payload",
            logicalKey,
            owner,
            keyId,
            encrypted,
            (plaintext, _) => ValueTask.FromResult(
                new UTF8Encoding(false, true).GetString(plaintext.Span)),
            cancellationToken).ConfigureAwait(false);
        var draft = AuthenticatedExtractionDraftSerializer.Deserialize(payload);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new ProjectedCurrentDraft(
            extractionRevision,
            new StreamVersion(streamVersion),
            draft);
    }

    private Task<int> ReadCurrentExtractionRevisionAsync(
        DocumentId documentId,
        CancellationToken cancellationToken) =>
        ReadStructuralAsync(
            async (connection, transaction, token) =>
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT current_extraction_revision
                    FROM product_inbox
                    WHERE document_id=$document;
                    """;
                command.Parameters.AddWithValue(
                    "$document",
                    ProductEventPayloads.Canonical(documentId.Value));
                var value = await command.ExecuteScalarAsync(token)
                    .ConfigureAwait(false);
                return value is long revision
                    && revision >= 0
                    && revision <= int.MaxValue
                    ? checked((int)revision)
                    : -1;
            },
            cancellationToken);

    private async Task<ProjectedReviewState> ReadProjectedReviewStateAsync(
        DocumentId documentId,
        CancellationToken cancellationToken)
    {
        await using var lease = await _keyRing.MaintenanceGate.AcquireReadAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(_connectionString, _keyRing.MaintenanceGate, cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await ValidateReadBoundaryAsync(connection, transaction, cancellationToken)
            .ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT d.content_sha256,i.current_extraction_revision,
                   i.current_stream_version,i.status
            FROM product_documents d
            JOIN product_inbox i ON i.document_id=d.document_id
            WHERE d.document_id=$document;
            """;
        command.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(documentId.Value));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            throw new VaultRecoveryRequiredException();
        var sourceIdentity = new ContentSha256((byte[])reader.GetValue(0));
        var extractionRevision = reader.GetInt32(1);
        var streamVersion = reader.GetInt64(2);
        var rawStatus = reader.GetInt32(3);
        if (extractionRevision <= 0
            || streamVersion < 0
            || !Enum.IsDefined(typeof(ProductInboxStatus), rawStatus)
            || await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new VaultRecoveryRequiredException();
        }
        await reader.DisposeAsync().ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new ProjectedReviewState(
            sourceIdentity,
            extractionRevision,
            new StreamVersion(streamVersion),
            (ProductInboxStatus)rawStatus);
    }

    private async Task<string?> LoadReviewPayloadAsync(DocumentId documentId, CancellationToken cancellationToken)
    {
        await using var lease = await _keyRing.MaintenanceGate.AcquireReadAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(_connectionString, _keyRing.MaintenanceGate, cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await ValidateReadBoundaryAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        var administrative = SqliteProjectionContexts.CreateAdministrative(connection, transaction, _keyRing, lease, _registration);
        await using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT owner_kind,owner_id,key_id,encryption_version,payload_nonce,payload_ciphertext,payload_tag FROM product_reviews WHERE document_id=$document;";
        command.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(documentId.Value));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        var owner = ReadOwner(reader, 0, 1); var key = new DataKeyId(ProductEventPayloads.GuidValue(reader.GetString(2)));
        var encrypted = new EncryptedProjectionValue(reader.GetInt32(3), key, (byte[])reader.GetValue(4), (byte[])reader.GetValue(5), (byte[])reader.GetValue(6));
        var payload = await administrative.Values.UnprotectAsync("product_reviews", "payload", ProductEventPayloads.Canonical(documentId.Value), owner, key, encrypted,
            (plain, _) => ValueTask.FromResult(new UTF8Encoding(false, true).GetString(plain.Span)), cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return payload;
    }

    private static ConfirmedInvoiceReview ParseReview(string payload)
    {
        var stored = JsonSerializer.Deserialize<PersistedConfirmedInvoiceReview>(payload) ?? throw new VaultRecoveryRequiredException();
        if (!Guid.TryParseExact(stored.DocumentId, "D", out var document)
            || document == Guid.Empty
            || stored.ExtractionRevision <= 0
            || stored.ReviewRevision <= 0
            || stored.ApprovedAtUtc.Offset != TimeSpan.Zero
            || stored.ApprovedAtUtc == default
            || stored.ConfirmedMarket is not ("ko-KR" or "en-US")
            || !IsCanonicalSha256(stored.SourceIdentitySha256)
            || !IsValidPersistedReviewFields(
                stored.Fields,
                stored.ExtractionRevision))
            throw new VaultRecoveryRequiredException();
        OperationId? operationId = null;
        EventId? eventId = null;
        StreamVersion? committedVersion = null;
        var hasAnyCommitIdentity = stored.CommitOperationId is not null
            || stored.CommitEventId is not null
            || stored.CommittedStreamVersion is not null;
        if (hasAnyCommitIdentity)
        {
            if (!Guid.TryParseExact(
                    stored.CommitOperationId,
                    "D",
                    out var operation)
                || operation == Guid.Empty
                || !Guid.TryParseExact(
                    stored.CommitEventId,
                    "D",
                    out var eventValue)
                || eventValue == Guid.Empty
                || stored.CommittedStreamVersion is not >= 0)
            {
                throw new VaultRecoveryRequiredException();
            }
            operationId = new OperationId(operation);
            eventId = new EventId(eventValue);
            committedVersion = new StreamVersion(
                stored.CommittedStreamVersion.Value);
        }
        return new ConfirmedInvoiceReview(
            new DocumentId(document),
            new ContentSha256(Convert.FromHexString(stored.SourceIdentitySha256)),
            stored.ExtractionRevision,
            stored.ReviewRevision,
            stored.ConfirmedMarket,
            stored.IsOutboundInvoice,
            stored.ApprovedAtUtc,
            stored.Fields,
            operationId,
            eventId,
            committedVersion);
    }

    private static bool IsCanonicalSha256(string? value) =>
        value is { Length: 64 }
        && value.All(static character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static bool IsValidPersistedReviewFields(
        ImmutableArray<ConfirmedInvoiceReviewField> fields,
        int extractionRevision)
    {
        if (fields.IsDefaultOrEmpty
            || fields.Length != PilotCatalog.RequiredFieldIds.Length
            || fields.Any(static field => field is null)
            || fields.Select(static field => field.FieldId)
                    .Distinct(StringComparer.Ordinal)
                    .Count()
                != fields.Length
            || !fields.Select(static field => field.FieldId)
                .ToImmutableHashSet(StringComparer.Ordinal)
                .SetEquals(PilotCatalog.RequiredFieldIds))
        {
            return false;
        }

        var totalEvidence = 0;
        foreach (var field in fields)
        {
            if (string.IsNullOrWhiteSpace(field.FieldId)
                || field.ConfirmedDisplayValue is null
                || field.ConfirmedNormalizedValue is null
                || Encoding.UTF8.GetByteCount(field.ConfirmedDisplayValue)
                    > InvoiceReviewLimits.MaxConfirmedValueUtf8Bytes
                || Encoding.UTF8.GetByteCount(field.ConfirmedNormalizedValue)
                    > InvoiceReviewLimits.MaxConfirmedValueUtf8Bytes
                || field.Evidence.IsDefaultOrEmpty
                || field.Evidence.Length
                    > InvoiceReviewLimits.MaxEvidencePerField
                || field.Evidence.Any(static evidence => evidence is null)
                || totalEvidence
                    > InvoiceReviewLimits.MaxTotalEvidence
                        - field.Evidence.Length)
            {
                return false;
            }
            totalEvidence += field.Evidence.Length;
            foreach (var evidence in field.Evidence)
            {
                var box = evidence.Box;
                if (evidence.ExtractionRevision != extractionRevision
                    || box is null
                    || box.SourceIndex < 0
                    || !double.IsFinite(box.X)
                    || !double.IsFinite(box.Y)
                    || !double.IsFinite(box.Width)
                    || !double.IsFinite(box.Height)
                    || box.X < 0
                    || box.Y < 0
                    || box.Width <= 0
                    || box.Height <= 0
                    || !Enum.IsDefined(evidence.CoordinateSystem))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private async Task<ProductCommitResult> CommitDocumentProgressAsync(
        OperationId operationId,
        EventId eventId,
        DocumentId documentId,
        StreamVersion expectedVersion,
        string eventType,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        try
        {
            var append = await _events.AppendAsync(
                new AppendEventsCommand(
                    new StreamId(documentId.Value),
                    expectedVersion,
                    operationId,
                    [
                        new EventToAppend(
                            eventId,
                            eventType,
                            ProductEventContracts.SchemaVersion,
                            payload,
                            DocumentProtection(documentId)),
                    ]),
                cancellationToken).ConfigureAwait(false);
            return MapGeneralAppend(append);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ProductProjectionConflictException conflict)
        {
            return new ProductConflict(conflict.Kind);
        }
        catch (Exception exception)
        {
            return MapRecovery(exception);
        }
    }

    private async Task<ImportCommitResult> CommitDuplicateImportAsync(
        CommitImportCommand command,
        ExistingDocument existing,
        byte[] fingerprint,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < DuplicateAppendRetryLimit; attempt++)
        {
            try
            {
                var streamId = new StreamId(existing.DocumentId.Value);
                var events = await _events.ReadStreamAsync(
                    streamId,
                    cancellationToken).ConfigureAwait(false);
                if (events.Count == 0)
                {
                    return new ProductRecoveryRequired(
                        ProductRecoveryKind.StorageFailure);
                }

                EventForReplay? committedOperation = null;
                foreach (var replayEvent in events)
                {
                    if (replayEvent.Metadata.OperationId != command.OperationId)
                    {
                        continue;
                    }

                    if (committedOperation is not null)
                    {
                        return new ProductRecoveryRequired(
                            ProductRecoveryKind.StorageFailure);
                    }

                    committedOperation = replayEvent;
                }

                StreamVersion expectedVersion;
                if (committedOperation is not null)
                {
                    if (!string.Equals(
                            committedOperation.Metadata.EventType,
                            ProductEventContracts.DocumentImportDuplicate,
                            StringComparison.Ordinal))
                    {
                        return new ImportConflict(
                            ProductConflictKind.OperationIdentityMismatch);
                    }

                    expectedVersion = new StreamVersion(
                        checked(
                            committedOperation.Metadata.StreamVersion.Value
                            - 1));
                }
                else
                {
                    expectedVersion = events[^1].Metadata.StreamVersion;
                }

                var result = await _events.AppendAsync(
                    new AppendEventsCommand(
                        streamId,
                        expectedVersion,
                        command.OperationId,
                        [
                            new EventToAppend(
                                command.EventId,
                                ProductEventContracts.DocumentImportDuplicate,
                                ProductEventContracts.SchemaVersion,
                                ProductEventPayloads.SerializeDuplicate(
                                    existing.DocumentId,
                                    existing.InboxId,
                                    command.ContentSha256,
                                    fingerprint),
                                new PayloadProtection.DurableStructural()),
                        ]),
                    cancellationToken).ConfigureAwait(false);
                switch (result)
                {
                    case Appended:
                    case AlreadyApplied:
                        return new AlreadyImported(existing.InboxId);
                    case ConcurrencyConflict:
                        continue;
                    case OperationConflict:
                    case OperationComparisonUnavailable:
                        return new ImportConflict(
                            ProductConflictKind.OperationIdentityMismatch);
                    case StorageBusy:
                        return new ProductRecoveryRequired(
                            ProductRecoveryKind.StorageBusy);
                }
            }
            catch (SqliteException exception) when (
                exception.SqliteErrorCode is 5 or 6)
            {
                return new ProductRecoveryRequired(
                    ProductRecoveryKind.StorageBusy);
            }
            catch (OverflowException)
            {
                return new ProductRecoveryRequired(
                    ProductRecoveryKind.StorageFailure);
            }
        }

        return new ProductRecoveryRequired(ProductRecoveryKind.StorageBusy);
    }

    private async Task<ExistingDocument?> FindDocumentByShaAsync(
        ContentSha256 sha,
        CancellationToken cancellationToken)
    {
        return await ReadStructuralAsync<ExistingDocument?>(
            async (connection, transaction, token) =>
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT d.document_id,i.inbox_id
                    FROM product_documents d
                    JOIN product_inbox i ON i.document_id=d.document_id
                    WHERE d.content_sha256=$sha;
                    """;
                command.Parameters.Add("$sha", SqliteType.Blob).Value =
                    sha.Bytes.ToArray();
                await using var reader = await command.ExecuteReaderAsync(token)
                    .ConfigureAwait(false);
                if (!await reader.ReadAsync(token).ConfigureAwait(false))
                {
                    return null;
                }

                var result = new ExistingDocument(
                    new DocumentId(
                        ProductEventPayloads.GuidValue(reader.GetString(0))),
                    new InboxId(
                        ProductEventPayloads.GuidValue(reader.GetString(1))));
                if (await reader.ReadAsync(token).ConfigureAwait(false))
                {
                    throw new VaultRecoveryRequiredException();
                }

                return result;
            },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<Guid?> FindCaseBySourceDocumentAsync(
        DocumentId sourceDocumentId,
        CancellationToken cancellationToken)
    {
        return await ReadStructuralAsync<Guid?>(
            async (connection, transaction, token) =>
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT case_id FROM product_cases
                    WHERE source_document_id=$document;
                    """;
                command.Parameters.AddWithValue(
                    "$document",
                    ProductEventPayloads.Canonical(sourceDocumentId.Value));
                var value = await command.ExecuteScalarAsync(token).ConfigureAwait(false);
                return value is string text
                    ? ProductEventPayloads.GuidValue(text)
                    : null;
            },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> ReadStructuralAsync<T>(
        Func<SqliteConnection, SqliteTransaction, CancellationToken, Task<T>> read,
        CancellationToken cancellationToken)
    {
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireReadAsync(cancellationToken).ConfigureAwait(false);
        await using var connection =
            await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString,
                _keyRing.MaintenanceGate,
                cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await ValidateReadBoundaryAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
        var result = await read(connection, transaction, cancellationToken)
            .ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    private async Task ValidateReadBoundaryAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
            connection,
            transaction,
            _registry,
            cancellationToken).ConfigureAwait(false);
        var identity =
            await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateCurrentKeyRingIdentityAsync(
            _keyRing,
            identity,
            cancellationToken).ConfigureAwait(false);
    }

    private static string BuildInboxQuery(InboxPageRequest request)
    {
        var status = request.Status is null ? string.Empty : "status=$status AND ";
        var cursor = request.After is null
            ? string.Empty
            : """
              (received_at_utc>$after_received OR
               (received_at_utc=$after_received AND document_id>$after_document)) AND
              """;
        return $"""
            SELECT inbox_id,document_id,received_at_utc,status,owner_kind,owner_id,key_id,
                   encryption_version,file_name_nonce,file_name_ciphertext,file_name_tag
            FROM product_inbox
            WHERE {status}{cursor} 1=1
            ORDER BY received_at_utc COLLATE BINARY,document_id COLLATE BINARY
            LIMIT $limit;
            """;
    }

    private static int ToStorageStatus(ExtractionOutboxState state) => state switch
    {
        ExtractionOutboxState.Pending => 0,
        ExtractionOutboxState.Running => 1,
        ExtractionOutboxState.RetryPending => 2,
        ExtractionOutboxState.Succeeded => 3,
        ExtractionOutboxState.TerminalFailure => 4,
        _ => throw new ArgumentOutOfRangeException(nameof(state)),
    };

    private static string BuildTodayQuery(TodayPageRequest request)
    {
        var status = request.Status is null ? string.Empty : "status=$status AND ";
        var cursor = request.After is null
            ? string.Empty
            : """
              (due_date>$after_due OR
               (due_date=$after_due AND case_id>$after_case)) AND
              """;
        return $"""
            SELECT case_id,source_document_id,due_date,status,
                   action_id,action_type,owner_kind,owner_id,key_id,
                   encryption_version,display_nonce,display_ciphertext,
                   display_tag
            FROM product_today
            WHERE {status}{cursor} 1=1
            ORDER BY due_date COLLATE BINARY,case_id COLLATE BINARY
            LIMIT $limit;
            """;
    }

    private static SensitiveObjectRef ReadOwner(
        SqliteDataReader reader,
        int kindOrdinal,
        int idOrdinal)
    {
        var rawKind = reader.GetInt32(kindOrdinal);
        if (!Enum.IsDefined(typeof(SensitiveObjectKind), rawKind))
        {
            throw new VaultRecoveryRequiredException();
        }

        return new SensitiveObjectRef(
            (SensitiveObjectKind)rawKind,
            new SensitiveObjectId(
                ProductEventPayloads.GuidValue(reader.GetString(idOrdinal))));
    }

    private static PayloadProtection DocumentProtection(DocumentId documentId) =>
        new PayloadProtection.Shreddable(
            new SensitiveObjectRef(
                SensitiveObjectKind.DocumentEvidence,
                new SensitiveObjectId(documentId.Value)));

    private static PayloadProtection CaseProtection(CaseId caseId) =>
        new PayloadProtection.Shreddable(
            new SensitiveObjectRef(
                SensitiveObjectKind.Case,
                new SensitiveObjectId(caseId.Value)));

    private static ProductCommitResult MapGeneralAppend(
        AppendEventsResult result) =>
        result switch
        {
            Appended appended => new ProductCommitted(appended.NewVersion),
            AlreadyApplied already => new ProductAlreadyCommitted(
                already.ExistingVersion),
            ConcurrencyConflict => new ProductConflict(
                ProductConflictKind.StreamVersionMismatch),
            OperationConflict or OperationComparisonUnavailable =>
                new ProductConflict(ProductConflictKind.OperationIdentityMismatch),
            StorageBusy => new ProductRecoveryRequired(
                ProductRecoveryKind.StorageBusy),
            _ => new ProductRecoveryRequired(ProductRecoveryKind.StorageFailure),
        };

    private static ProductCommitResult MapRecovery(Exception exception) =>
        exception switch
        {
            ProjectionRebuildRequiredException =>
                new ProductRecoveryRequired(
                    ProductRecoveryKind.ProjectionRebuildRequired),
            SqliteException sqlite when sqlite.SqliteErrorCode is 5 or 6 =>
                new ProductRecoveryRequired(ProductRecoveryKind.StorageBusy),
            _ when IsProtectedStateFailure(exception) =>
                new ProductRecoveryRequired(
                    ProductRecoveryKind.ProtectedStateInvalid),
            _ => new ProductRecoveryRequired(ProductRecoveryKind.StorageFailure),
        };

    private static bool IsProtectedStateFailure(Exception exception) =>
        exception is VaultRecoveryRequiredException
            or ProjectionValueRecoveryRequiredException
            or CryptographicException;

    private static ProductDocumentSourceBinding ReadSourceBinding(string value)
    {
        try
        {
            var sourceBinding = JsonSerializer.Deserialize<ProductDocumentSourceBinding>(value)
                ?? throw new VaultRecoveryRequiredException();
            return sourceBinding.IsValid
                ? sourceBinding
                : throw new VaultRecoveryRequiredException();
        }
        catch (JsonException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static Task DelayBeforeBusyRetryAsync(
        int attempt,
        CancellationToken cancellationToken) =>
        Task.Delay(
            TimeSpan.FromMilliseconds(
                Math.Min(100, checked((attempt + 1) * 25))),
            cancellationToken);

    private sealed record ExistingDocument(
        DocumentId DocumentId,
        InboxId InboxId);

    private sealed record ProjectedCurrentDraft(
        int ExtractionRevision,
        StreamVersion StreamVersion,
        AuthenticatedExtractionDraft Draft);

    private sealed record TodayProtectedPayload(
        int Version,
        string TotalAmount,
        string Currency,
        string SafeReason);

    private sealed record ProjectedReviewState(
        ContentSha256 SourceIdentity,
        int ExtractionRevision,
        StreamVersion StreamVersion,
        ProductInboxStatus Status);
}
