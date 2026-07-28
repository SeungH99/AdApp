using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public sealed class SqliteProductCommitStore :
    IProductCommitStore,
    IProductQueryStore
{
    private const int DuplicateAppendRetryLimit = 16;

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

    public async Task<ImportCommitResult> CommitImportAsync(
        CommitImportCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var fingerprint = ProductEventPayloads.ImportFingerprint(command);
        try
        {
            var receipt = await ReadReceiptAsync(
                command.OperationId,
                cancellationToken).ConfigureAwait(false);
            if (receipt is not null)
            {
                return ReceiptMatches(receipt, fingerprint)
                    ? receipt.Kind switch
                    {
                        "import-committed" when receipt.InboxId is { } inbox =>
                            new ImportAlreadyCommitted(inbox),
                        "already-imported" when receipt.InboxId is { } inbox =>
                            new AlreadyImported(inbox),
                        _ => new ImportConflict(
                            ProductConflictKind.OperationIdentityMismatch),
                    }
                    : new ImportConflict(
                        ProductConflictKind.OperationIdentityMismatch);
            }

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
                return append switch
                {
                    Appended => new ImportCommitted(command.InboxId),
                    AlreadyApplied => new ImportAlreadyCommitted(command.InboxId),
                    ConcurrencyConflict => new ImportConflict(
                        ProductConflictKind.StreamVersionMismatch),
                    OperationConflict or OperationComparisonUnavailable =>
                        new ImportConflict(
                            ProductConflictKind.OperationIdentityMismatch),
                    StorageBusy => new ProductRecoveryRequired(
                        ProductRecoveryKind.StorageBusy),
                    _ => new ProductRecoveryRequired(
                        ProductRecoveryKind.StorageFailure),
                };
            }
            catch (SqliteException exception) when (
                exception.SqliteErrorCode == 19)
            {
                existing = await FindDocumentByShaAsync(
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
            fingerprint,
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
            fingerprint,
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
            var receipt = await ReadReceiptAsync(
                command.OperationId,
                cancellationToken).ConfigureAwait(false);
            if (receipt is not null)
            {
                return ReceiptMatches(receipt, fingerprint)
                    && string.Equals(
                        receipt.Kind,
                        "receivable-case-committed",
                        StringComparison.Ordinal)
                    ? new ProductAlreadyCommitted(
                        new StreamVersion(receipt.StreamVersion))
                    : new ProductConflict(
                        ProductConflictKind.OperationIdentityMismatch);
            }

            var existing = await FindCaseBySourceDocumentAsync(
                command.SourceDocumentId,
                cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                return new ProductConflict(
                    ProductConflictKind.SourceDocumentAlreadyHasCase,
                    existing.Value);
            }

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
                        cancellationToken).ConfigureAwait(false),
                    command.OperationId);
            }
            catch (SqliteException exception) when (
                exception.SqliteErrorCode == 19)
            {
                existing = await FindCaseBySourceDocumentAsync(
                    command.SourceDocumentId,
                    cancellationToken).ConfigureAwait(false);
                return existing is not null
                    ? new ProductConflict(
                        ProductConflictKind.SourceDocumentAlreadyHasCase,
                        existing.Value)
                    : new ProductConflict(ProductConflictKind.StorageConstraint);
            }
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

                items.Add(
                    new TodayListItem(
                        new CaseId(
                            ProductEventPayloads.GuidValue(reader.GetString(0))),
                        new DocumentId(
                            ProductEventPayloads.GuidValue(reader.GetString(1))),
                        ProductEventPayloads.DateValue(reader.GetString(2)),
                        (ProductTodayStatus)rawStatus));
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
                or InvalidCastException
                or FormatException
                or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private async Task<ProductCommitResult> CommitDocumentProgressAsync(
        OperationId operationId,
        EventId eventId,
        DocumentId documentId,
        StreamVersion expectedVersion,
        string eventType,
        byte[] payload,
        byte[] fingerprint,
        CancellationToken cancellationToken)
    {
        try
        {
            var receipt = await ReadReceiptAsync(
                operationId,
                cancellationToken).ConfigureAwait(false);
            if (receipt is not null)
            {
                return ReceiptMatches(receipt, fingerprint)
                    ? new ProductAlreadyCommitted(
                        new StreamVersion(receipt.StreamVersion))
                    : new ProductConflict(
                        ProductConflictKind.OperationIdentityMismatch);
            }

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
            return MapGeneralAppend(append, operationId);
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

    private async Task<ImportCommitResult> CommitDuplicateImportAsync(
        CommitImportCommand command,
        ExistingDocument existing,
        byte[] fingerprint,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < DuplicateAppendRetryLimit; attempt++)
        {
            var receipt = await ReadReceiptAsync(
                command.OperationId,
                cancellationToken).ConfigureAwait(false);
            if (receipt is not null)
            {
                return ReceiptMatches(receipt, fingerprint)
                    && receipt.InboxId is { } inbox
                    ? new AlreadyImported(inbox)
                    : new ImportConflict(
                        ProductConflictKind.OperationIdentityMismatch);
            }

            var events = await _events.ReadStreamAsync(
                new StreamId(existing.DocumentId.Value),
                cancellationToken).ConfigureAwait(false);
            if (events.Count == 0)
            {
                return new ProductRecoveryRequired(
                    ProductRecoveryKind.StorageFailure);
            }

            var result = await _events.AppendAsync(
                new AppendEventsCommand(
                    new StreamId(existing.DocumentId.Value),
                    new StreamVersion(events.Count - 1L),
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

        return new ProductRecoveryRequired(ProductRecoveryKind.StorageBusy);
    }

    private async Task<OutboxReceipt?> ReadReceiptAsync(
        OperationId operationId,
        CancellationToken cancellationToken)
    {
        return await ReadStructuralAsync<OutboxReceipt?>(
            async (connection, transaction, token) =>
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT commit_kind,inbox_id,commit_fingerprint,stream_version
                    FROM product_outbox WHERE operation_id=$operation;
                    """;
                command.Parameters.AddWithValue(
                    "$operation",
                    ProductEventPayloads.Canonical(operationId.Value));
                await using var reader = await command.ExecuteReaderAsync(token)
                    .ConfigureAwait(false);
                if (!await reader.ReadAsync(token).ConfigureAwait(false))
                {
                    return null;
                }

                if (reader.GetValue(0) is not string kind
                    || reader.GetValue(2) is not byte[] fingerprint
                    || fingerprint.Length != 32
                    || reader.GetValue(3) is not long streamVersion
                    || streamVersion < 0)
                {
                    throw new VaultRecoveryRequiredException();
                }

                InboxId? inbox = reader.IsDBNull(1)
                    ? null
                    : new InboxId(
                        ProductEventPayloads.GuidValue(reader.GetString(1)));
                if (await reader.ReadAsync(token).ConfigureAwait(false))
                {
                    throw new VaultRecoveryRequiredException();
                }

                return new OutboxReceipt(
                    kind,
                    inbox,
                    fingerprint,
                    streamVersion);
            },
            cancellationToken).ConfigureAwait(false);
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
            SELECT case_id,source_document_id,due_date,status
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
        AppendEventsResult result,
        OperationId operationId) =>
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

    private static bool ReceiptMatches(
        OutboxReceipt receipt,
        ReadOnlySpan<byte> fingerprint) =>
        CryptographicOperations.FixedTimeEquals(
            receipt.Fingerprint,
            fingerprint);

    private sealed record ExistingDocument(
        DocumentId DocumentId,
        InboxId InboxId);

    private sealed record OutboxReceipt(
        string Kind,
        InboxId? InboxId,
        byte[] Fingerprint,
        long StreamVersion);
}
