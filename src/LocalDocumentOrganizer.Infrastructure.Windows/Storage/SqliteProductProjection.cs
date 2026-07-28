using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal enum ProductCommitFaultPoint
{
    BeforeEvent,
    BeforeDocument,
    BeforeInbox,
    BeforeCase,
    BeforeToday,
    BeforeCaseInbox,
    BeforeOutbox,
    BeforeCheckpoint,
}

internal interface IProductCommitFaultInjector
{
    void ThrowIfRequested(ProductCommitFaultPoint point);
}

internal sealed class InjectedProductCommitFaultException(ProductCommitFaultPoint point)
    : InvalidOperationException($"Injected product commit fault at {point}.");

internal sealed class NoOpProductCommitFaultInjector : IProductCommitFaultInjector
{
    internal static NoOpProductCommitFaultInjector Instance { get; } = new();

    private NoOpProductCommitFaultInjector()
    {
    }

    public void ThrowIfRequested(ProductCommitFaultPoint point)
    {
    }
}

internal sealed class ProductEventStoreFaultAdapter(
    IProductCommitFaultInjector faults) : ISqliteOperationCommitFaultInjector
{
    public void ThrowIfRequested(SqliteOperationCommitFaultPoint point)
    {
        if (point == SqliteOperationCommitFaultPoint.BeforeEventInsert)
        {
            faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeEvent);
        }
        else if (point == SqliteOperationCommitFaultPoint.BeforeCheckpoint)
        {
            faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeCheckpoint);
        }
    }
}

internal sealed class SqliteProductProjection(
    IProductCommitFaultInjector? faultInjector = null) : ISqliteProjection
{
    internal const string ProjectionName = "product";
    internal const int ProjectionSchemaVersion = 3;

    private const string SchemaSql = """
        CREATE TABLE IF NOT EXISTS product_documents(
            document_id TEXT PRIMARY KEY CHECK(length(document_id)=36),
            content_sha256 BLOB NOT NULL CHECK(length(content_sha256)=32),
            received_at_utc TEXT NOT NULL
        ) STRICT;
        CREATE UNIQUE INDEX IF NOT EXISTS product_documents_content_sha256
            ON product_documents(content_sha256);
        CREATE TABLE IF NOT EXISTS product_inbox(
            inbox_id TEXT PRIMARY KEY CHECK(length(inbox_id)=36),
            document_id TEXT NOT NULL UNIQUE CHECK(length(document_id)=36)
                REFERENCES product_documents(document_id) ON DELETE CASCADE,
            received_at_utc TEXT NOT NULL,
            status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 8),
            owner_kind INTEGER NOT NULL,
            owner_id TEXT NOT NULL CHECK(length(owner_id)=36),
            key_id TEXT NOT NULL CHECK(length(key_id)=36),
            encryption_version INTEGER NOT NULL CHECK(encryption_version=1),
            file_name_nonce BLOB NOT NULL CHECK(length(file_name_nonce)=12),
            file_name_ciphertext BLOB NOT NULL,
            file_name_tag BLOB NOT NULL CHECK(length(file_name_tag)=16),
            metadata_nonce BLOB NOT NULL CHECK(length(metadata_nonce)=12),
            metadata_ciphertext BLOB NOT NULL,
            metadata_tag BLOB NOT NULL CHECK(length(metadata_tag)=16)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS product_inbox_status_received_document
            ON product_inbox(status,received_at_utc COLLATE BINARY,document_id COLLATE BINARY);
        CREATE TABLE IF NOT EXISTS product_cases(
            case_id TEXT PRIMARY KEY CHECK(length(case_id)=36),
            source_document_id TEXT NOT NULL CHECK(length(source_document_id)=36)
                REFERENCES product_documents(document_id) ON DELETE CASCADE,
            status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 1),
            due_date TEXT NOT NULL CHECK(length(due_date)=10),
            created_at_utc TEXT NOT NULL,
            owner_kind INTEGER NOT NULL,
            owner_id TEXT NOT NULL CHECK(length(owner_id)=36),
            key_id TEXT NOT NULL CHECK(length(key_id)=36),
            encryption_version INTEGER NOT NULL CHECK(encryption_version=1),
            metadata_nonce BLOB NOT NULL CHECK(length(metadata_nonce)=12),
            metadata_ciphertext BLOB NOT NULL,
            metadata_tag BLOB NOT NULL CHECK(length(metadata_tag)=16)
        ) STRICT;
        CREATE UNIQUE INDEX IF NOT EXISTS product_cases_source_document
            ON product_cases(source_document_id);
        CREATE TABLE IF NOT EXISTS product_today(
            case_id TEXT PRIMARY KEY CHECK(length(case_id)=36)
                REFERENCES product_cases(case_id) ON DELETE CASCADE,
            source_document_id TEXT NOT NULL CHECK(length(source_document_id)=36),
            due_date TEXT NOT NULL CHECK(length(due_date)=10),
            status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 1)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS product_today_status_due_case
            ON product_today(status,due_date COLLATE BINARY,case_id COLLATE BINARY);
        CREATE TABLE IF NOT EXISTS product_outbox(
            operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=36),
            event_id TEXT NOT NULL UNIQUE CHECK(length(event_id)=36),
            commit_kind TEXT NOT NULL,
            aggregate_id TEXT NOT NULL CHECK(length(aggregate_id)=36),
            inbox_id TEXT NULL CHECK(inbox_id IS NULL OR length(inbox_id)=36),
            occurred_at_utc TEXT NOT NULL,
            dispatch_status INTEGER NOT NULL DEFAULT 0 CHECK(dispatch_status BETWEEN 0 AND 4),
            extraction_attempt_id TEXT NULL CHECK(extraction_attempt_id IS NULL OR length(extraction_attempt_id)=36),
            target_extraction_revision INTEGER NULL CHECK(target_extraction_revision IS NULL OR target_extraction_revision > 0),
            extraction_commit_operation_id TEXT NULL CHECK(extraction_commit_operation_id IS NULL OR length(extraction_commit_operation_id)=36),
            automatic_failure_count INTEGER NOT NULL DEFAULT 0 CHECK(automatic_failure_count BETWEEN 0 AND 1),
            lease_owner_id TEXT NULL CHECK(lease_owner_id IS NULL OR length(lease_owner_id)=36),
            lease_expires_at_utc TEXT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS product_outbox_dispatch_order
            ON product_outbox(dispatch_status,occurred_at_utc COLLATE BINARY,operation_id COLLATE BINARY);
        CREATE UNIQUE INDEX IF NOT EXISTS product_outbox_explicit_reprocess_revision
            ON product_outbox(aggregate_id,target_extraction_revision)
            WHERE commit_kind='explicit-reprocess';
        """;

    private static readonly ProjectionOwnedTable[] Tables =
    [
        new("product_documents"),
        new("product_inbox"),
        new("product_cases"),
        new("product_today"),
        new("product_outbox"),
    ];

    private static readonly EncryptedProjectionLocation[] ProtectedLocations =
    [
        new("product_inbox", "file_name"),
        new("product_inbox", "metadata"),
        new("product_cases", "metadata"),
    ];

    private readonly IProductCommitFaultInjector _faults =
        faultInjector ?? NoOpProductCommitFaultInjector.Instance;

    public string Name => ProjectionName;

    public int SchemaVersion => ProjectionSchemaVersion;

    public int EncryptionVersion => EncryptedProjectionValue.CurrentVersion;

    internal static SqliteProjectionRegistration CreateRegistration(
        SqliteProductProjection projection) =>
        new(projection, Tables, ProtectedLocations);

    public async Task<ProjectionCompatibilityResult> InitializeAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken)
    {
        var existing = await ExistingTableCountAsync(context, cancellationToken)
            .ConfigureAwait(false);
        var legacyOutbox =
            !await OutboxHasExtractionFieldsAsync(context, cancellationToken)
            .ConfigureAwait(false);
        if (legacyOutbox)
        {
            await ExecuteAsync(
                context.Connection,
                context.Transaction,
                "DROP TABLE product_outbox;",
                cancellationToken).ConfigureAwait(false);
        }
        await ExecuteAsync(context.Connection, context.Transaction, SchemaSql, cancellationToken)
            .ConfigureAwait(false);
        return new ProjectionCompatibilityResult(
            existing == Tables.Length && !legacyOutbox
                ? ProjectionCompatibility.Compatible
                : ProjectionCompatibility.CreatedEmpty);
    }

    public async Task ApplyAsync(
        EventForReplay replayEvent,
        long globalPosition,
        SqliteProjectionApplyContext context,
        CancellationToken cancellationToken)
    {
        if (replayEvent is not DecryptedEvent decrypted)
        {
            return;
        }

        switch (decrypted.Metadata.EventType)
        {
            case ProductEventContracts.DocumentImported:
                await ApplyImportAsync(decrypted, context, cancellationToken)
                    .ConfigureAwait(false);
                break;
            case ProductEventContracts.DocumentImportDuplicate:
                await ApplyDuplicateAsync(decrypted, context, cancellationToken)
                    .ConfigureAwait(false);
                break;
            case ProductEventContracts.ExtractionCommitted:
                var extractionPayload = ProductEventPayloads.Read<ProductDocumentProgressPayload>(
                    decrypted.Payload);
                var extractionStatus = extractionPayload.InboxStatus is { } rawStatus
                    && Enum.IsDefined(typeof(ProductInboxStatus), rawStatus)
                    ? (ProductInboxStatus)rawStatus
                    : ProductInboxStatus.Extracted;
                await ApplyProgressAsync(
                    decrypted,
                    context,
                    extractionStatus,
                    "extraction-committed",
                    cancellationToken).ConfigureAwait(false);
                break;
            case ProductEventContracts.ReviewCommitted:
                await ApplyProgressAsync(
                    decrypted,
                    context,
                    ProductInboxStatus.Reviewed,
                    "review-committed",
                    cancellationToken).ConfigureAwait(false);
                break;
            case ProductEventContracts.ReceivableCaseCommitted:
                await ApplyReceivableCaseAsync(decrypted, context, cancellationToken)
                    .ConfigureAwait(false);
                break;
        }
    }

    private async Task ApplyImportAsync(
        DecryptedEvent replayEvent,
        SqliteProjectionApplyContext context,
        CancellationToken cancellationToken)
    {
        var payload = ProductEventPayloads.Read<ProductImportPayload>(replayEvent.Payload);
        var documentId = ProductEventPayloads.GuidValue(payload.DocumentId);
        var inboxId = ProductEventPayloads.GuidValue(payload.InboxId);
        var receivedAt = ProductEventPayloads.UtcValue(payload.ReceivedAtUtc);
        var sha = ParseSha(payload.ContentSha256);
        var attemptId = ProductEventPayloads.GuidValue(payload.ExtractionAttemptId);
        var commitOperationId = ProductEventPayloads.GuidValue(payload.ExtractionCommitOperationId);
        if (payload.TargetExtractionRevision != 1)
        {
            throw new VaultRecoveryRequiredException();
        }
        _ = ProductEventPayloads.FingerprintValue(payload.CommitFingerprint);
        RequireOwner(
            context,
            SensitiveObjectKind.DocumentEvidence,
            documentId);
        var logicalKey = ProductEventPayloads.Canonical(inboxId);
        var fileName = await context.Values.ProtectAsync(
            "product_inbox",
            "file_name",
            logicalKey,
            context.Values.BoundOwner,
            context.Values.BoundDataKeyId,
            Encoding.UTF8.GetBytes(payload.FileName),
            cancellationToken).ConfigureAwait(false);
        var metadata = await context.Values.ProtectAsync(
            "product_inbox",
            "metadata",
            logicalKey,
            context.Values.BoundOwner,
            context.Values.BoundDataKeyId,
            Encoding.UTF8.GetBytes(payload.AuthenticatedMetadata),
            cancellationToken).ConfigureAwait(false);

        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeDocument);
        await using (var document = context.Connection.CreateCommand())
        {
            document.Transaction = context.Transaction;
            document.CommandText = """
                INSERT INTO product_documents(document_id,content_sha256,received_at_utc)
                VALUES($document,$sha,$received);
                """;
            document.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(documentId));
            document.Parameters.Add("$sha", SqliteType.Blob).Value = sha;
            document.Parameters.AddWithValue("$received", ProductEventPayloads.Utc(receivedAt));
            RequireSingle(await document.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }

        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeInbox);
        await using (var inbox = context.Connection.CreateCommand())
        {
            inbox.Transaction = context.Transaction;
            inbox.CommandText = """
                INSERT INTO product_inbox(
                    inbox_id,document_id,received_at_utc,status,owner_kind,owner_id,key_id,
                    encryption_version,file_name_nonce,file_name_ciphertext,file_name_tag,
                    metadata_nonce,metadata_ciphertext,metadata_tag)
                VALUES(
                    $inbox,$document,$received,$status,$owner_kind,$owner_id,$key_id,
                    $version,$file_nonce,$file_ciphertext,$file_tag,
                    $metadata_nonce,$metadata_ciphertext,$metadata_tag);
                """;
            inbox.Parameters.AddWithValue("$inbox", ProductEventPayloads.Canonical(inboxId));
            inbox.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(documentId));
            inbox.Parameters.AddWithValue("$received", ProductEventPayloads.Utc(receivedAt));
            inbox.Parameters.AddWithValue("$status", (int)ProductInboxStatus.Imported);
            AddOwnerAndKey(inbox, context.Values.BoundOwner, fileName);
            inbox.Parameters.Add("$file_nonce", SqliteType.Blob).Value = fileName.Nonce.ToArray();
            inbox.Parameters.Add("$file_ciphertext", SqliteType.Blob).Value =
                fileName.Ciphertext.ToArray();
            inbox.Parameters.Add("$file_tag", SqliteType.Blob).Value = fileName.Tag.ToArray();
            inbox.Parameters.Add("$metadata_nonce", SqliteType.Blob).Value =
                metadata.Nonce.ToArray();
            inbox.Parameters.Add("$metadata_ciphertext", SqliteType.Blob).Value =
                metadata.Ciphertext.ToArray();
            inbox.Parameters.Add("$metadata_tag", SqliteType.Blob).Value = metadata.Tag.ToArray();
            RequireSingle(await inbox.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }

        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeOutbox);
        await InsertOutboxAsync(
            replayEvent,
            context,
            "import-committed",
            documentId,
            new InboxId(inboxId),
            attemptId,
            payload.TargetExtractionRevision,
            commitOperationId,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task ApplyDuplicateAsync(
        DecryptedEvent replayEvent,
        SqliteProjectionApplyContext context,
        CancellationToken cancellationToken)
    {
        var payload = ProductEventPayloads.Read<ProductDuplicateImportPayload>(
            replayEvent.Payload);
        var documentId = ProductEventPayloads.GuidValue(payload.ExistingDocumentId);
        var inboxId = ProductEventPayloads.GuidValue(payload.ExistingInboxId);
        _ = ParseSha(payload.ContentSha256);
        _ = ProductEventPayloads.FingerprintValue(payload.CommitFingerprint);
        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeOutbox);
        await InsertOutboxAsync(
            replayEvent,
            context,
            "already-imported",
            documentId,
            new InboxId(inboxId),
            null,
            null,
            null,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task ApplyProgressAsync(
        DecryptedEvent replayEvent,
        SqliteProjectionApplyContext context,
        ProductInboxStatus status,
        string kind,
        CancellationToken cancellationToken)
    {
        var payload = ProductEventPayloads.Read<ProductDocumentProgressPayload>(
            replayEvent.Payload);
        var documentId = ProductEventPayloads.GuidValue(payload.DocumentId);
        _ = ProductEventPayloads.UtcValue(payload.OccurredAtUtc);
        _ = ProductEventPayloads.FingerprintValue(payload.CommitFingerprint);
        RequireOwner(context, SensitiveObjectKind.DocumentEvidence, documentId);
        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeInbox);
        await using (var update = context.Connection.CreateCommand())
        {
            update.Transaction = context.Transaction;
            update.CommandText = """
                UPDATE product_inbox SET status=$status WHERE document_id=$document;
                """;
            update.Parameters.AddWithValue("$status", (int)status);
            update.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            RequireSingle(await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }

        var inboxId = await ReadInboxIdAsync(
            context.Connection,
            context.Transaction,
            documentId,
            cancellationToken).ConfigureAwait(false);
        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeOutbox);
        await InsertOutboxAsync(
            replayEvent,
            context,
            kind,
            documentId,
            inboxId,
            null,
            null,
            null,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task ApplyReceivableCaseAsync(
        DecryptedEvent replayEvent,
        SqliteProjectionApplyContext context,
        CancellationToken cancellationToken)
    {
        var payload = ProductEventPayloads.Read<ProductReceivableCasePayload>(
            replayEvent.Payload);
        var caseId = ProductEventPayloads.GuidValue(payload.CaseId);
        var documentId = ProductEventPayloads.GuidValue(payload.SourceDocumentId);
        var dueDate = ProductEventPayloads.DateValue(payload.DueDate);
        var createdAt = ProductEventPayloads.UtcValue(payload.CreatedAtUtc);
        _ = ProductEventPayloads.FingerprintValue(payload.CommitFingerprint);
        RequireOwner(context, SensitiveObjectKind.Case, caseId);
        var logicalKey = ProductEventPayloads.Canonical(caseId);
        var metadata = await context.Values.ProtectAsync(
            "product_cases",
            "metadata",
            logicalKey,
            context.Values.BoundOwner,
            context.Values.BoundDataKeyId,
            Encoding.UTF8.GetBytes(payload.AuthenticatedMetadata),
            cancellationToken).ConfigureAwait(false);

        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeCase);
        await using (var receivableCase = context.Connection.CreateCommand())
        {
            receivableCase.Transaction = context.Transaction;
            receivableCase.CommandText = """
                INSERT INTO product_cases(
                    case_id,source_document_id,status,due_date,created_at_utc,
                    owner_kind,owner_id,key_id,encryption_version,
                    metadata_nonce,metadata_ciphertext,metadata_tag)
                VALUES(
                    $case,$document,$status,$due,$created,
                    $owner_kind,$owner_id,$key_id,$version,
                    $nonce,$ciphertext,$tag);
                """;
            receivableCase.Parameters.AddWithValue(
                "$case",
                ProductEventPayloads.Canonical(caseId));
            receivableCase.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            receivableCase.Parameters.AddWithValue("$status", (int)ProductCaseStatus.Open);
            receivableCase.Parameters.AddWithValue(
                "$due",
                dueDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            receivableCase.Parameters.AddWithValue(
                "$created",
                ProductEventPayloads.Utc(createdAt));
            AddOwnerAndKey(receivableCase, context.Values.BoundOwner, metadata);
            receivableCase.Parameters.Add("$nonce", SqliteType.Blob).Value =
                metadata.Nonce.ToArray();
            receivableCase.Parameters.Add("$ciphertext", SqliteType.Blob).Value =
                metadata.Ciphertext.ToArray();
            receivableCase.Parameters.Add("$tag", SqliteType.Blob).Value =
                metadata.Tag.ToArray();
            RequireSingle(
                await receivableCase.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false));
        }

        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeToday);
        await using (var today = context.Connection.CreateCommand())
        {
            today.Transaction = context.Transaction;
            today.CommandText = """
                INSERT INTO product_today(case_id,source_document_id,due_date,status)
                VALUES($case,$document,$due,$status);
                """;
            today.Parameters.AddWithValue("$case", ProductEventPayloads.Canonical(caseId));
            today.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            today.Parameters.AddWithValue(
                "$due",
                dueDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            today.Parameters.AddWithValue("$status", (int)ProductTodayStatus.Pending);
            RequireSingle(await today.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }

        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeCaseInbox);
        await using (var inbox = context.Connection.CreateCommand())
        {
            inbox.Transaction = context.Transaction;
            inbox.CommandText = """
                UPDATE product_inbox SET status=$status WHERE document_id=$document;
                """;
            inbox.Parameters.AddWithValue("$status", (int)ProductInboxStatus.CaseCreated);
            inbox.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            RequireSingle(await inbox.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }

        var inboxId = await ReadInboxIdAsync(
            context.Connection,
            context.Transaction,
            documentId,
            cancellationToken).ConfigureAwait(false);
        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeOutbox);
        await InsertOutboxAsync(
            replayEvent,
            context,
            "receivable-case-committed",
            caseId,
            inboxId,
            null,
            null,
            null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task PurgeOwnerAsync(
        SensitiveObjectRef owner,
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken)
    {
        var table = owner.Kind switch
        {
            SensitiveObjectKind.DocumentEvidence => "product_documents",
            SensitiveObjectKind.Case => "product_cases",
            _ => null,
        };
        var column = owner.Kind switch
        {
            SensitiveObjectKind.DocumentEvidence => "document_id",
            SensitiveObjectKind.Case => "case_id",
            _ => null,
        };
        if (table is null || column is null)
        {
            return;
        }

        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = $"DELETE FROM {table} WHERE {column}=$id;";
        command.Parameters.AddWithValue(
            "$id",
            ProductEventPayloads.Canonical(owner.Id.Value));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task ResetAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken) =>
        ExecuteAsync(
            context.Connection,
            context.Transaction,
            """
            DELETE FROM product_outbox;
            DELETE FROM product_today;
            DELETE FROM product_cases;
            DELETE FROM product_inbox;
            DELETE FROM product_documents;
            """,
            cancellationToken);

    public async Task<string> CalculateChecksumAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await AppendRowsAsync(
            context.Connection,
            context.Transaction,
            "SELECT document_id,hex(content_sha256),received_at_utc FROM product_documents ORDER BY document_id COLLATE BINARY;",
            hash,
            cancellationToken).ConfigureAwait(false);
        await AppendInboxRowsAsync(context, hash, cancellationToken).ConfigureAwait(false);
        await AppendCaseRowsAsync(context, hash, cancellationToken).ConfigureAwait(false);
        await AppendRowsAsync(
            context.Connection,
            context.Transaction,
            "SELECT case_id,source_document_id,due_date,status FROM product_today ORDER BY case_id COLLATE BINARY;",
            hash,
            cancellationToken).ConfigureAwait(false);
        await AppendRowsAsync(
            context.Connection,
            context.Transaction,
            """
            SELECT operation_id,event_id,commit_kind,aggregate_id,COALESCE(inbox_id,''),
                   occurred_at_utc,dispatch_status,COALESCE(extraction_attempt_id,''),
                   COALESCE(target_extraction_revision,0),
                   COALESCE(extraction_commit_operation_id,''),automatic_failure_count,
                   COALESCE(lease_owner_id,''),COALESCE(lease_expires_at_utc,'')
            FROM product_outbox ORDER BY operation_id COLLATE BINARY;
            """,
            hash,
            cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static async Task AppendInboxRowsAsync(
        SqliteProjectionAdministrativeContext context,
        IncrementalHash hash,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT inbox_id,document_id,received_at_utc,status,owner_kind,owner_id,key_id,
                   encryption_version,file_name_nonce,file_name_ciphertext,file_name_tag,
                   metadata_nonce,metadata_ciphertext,metadata_tag
            FROM product_inbox ORDER BY inbox_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < 4; ordinal++)
            {
                AppendValue(hash, reader.GetValue(ordinal));
            }

            var owner = Owner(reader, 4, 5);
            var keyId = new DataKeyId(ProductEventPayloads.GuidValue(reader.GetString(6)));
            var version = reader.GetInt32(7);
            await AppendProtectedAsync(
                context,
                hash,
                "product_inbox",
                "file_name",
                reader.GetString(0),
                owner,
                keyId,
                version,
                reader,
                8,
                cancellationToken).ConfigureAwait(false);
            await AppendProtectedAsync(
                context,
                hash,
                "product_inbox",
                "metadata",
                reader.GetString(0),
                owner,
                keyId,
                version,
                reader,
                11,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task AppendCaseRowsAsync(
        SqliteProjectionAdministrativeContext context,
        IncrementalHash hash,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT case_id,source_document_id,status,due_date,created_at_utc,
                   owner_kind,owner_id,key_id,encryption_version,
                   metadata_nonce,metadata_ciphertext,metadata_tag
            FROM product_cases ORDER BY case_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < 5; ordinal++)
            {
                AppendValue(hash, reader.GetValue(ordinal));
            }

            var owner = Owner(reader, 5, 6);
            var keyId = new DataKeyId(ProductEventPayloads.GuidValue(reader.GetString(7)));
            await AppendProtectedAsync(
                context,
                hash,
                "product_cases",
                "metadata",
                reader.GetString(0),
                owner,
                keyId,
                reader.GetInt32(8),
                reader,
                9,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task AppendProtectedAsync(
        SqliteProjectionAdministrativeContext context,
        IncrementalHash hash,
        string table,
        string field,
        string logicalKey,
        SensitiveObjectRef owner,
        DataKeyId keyId,
        int version,
        SqliteDataReader reader,
        int envelopeStart,
        CancellationToken cancellationToken)
    {
        var encrypted = new EncryptedProjectionValue(
            version,
            keyId,
            (byte[])reader.GetValue(envelopeStart),
            (byte[])reader.GetValue(envelopeStart + 1),
            (byte[])reader.GetValue(envelopeStart + 2));
        await context.Values.UnprotectAsync(
            table,
            field,
            logicalKey,
            owner,
            keyId,
            encrypted,
            (plaintext, _) =>
            {
                AppendValue(hash, plaintext.Span);
                return ValueTask.FromResult(0);
            },
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task AppendRowsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        IncrementalHash hash,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
            {
                AppendValue(hash, reader.GetValue(ordinal));
            }
        }
    }

    private static void AppendValue(IncrementalHash hash, object value)
    {
        var bytes = value switch
        {
            string text => Encoding.UTF8.GetBytes(text),
            byte[] blob => blob,
            long integer => Encoding.UTF8.GetBytes(
                integer.ToString(CultureInfo.InvariantCulture)),
            int integer => Encoding.UTF8.GetBytes(
                integer.ToString(CultureInfo.InvariantCulture)),
            _ => throw new VaultRecoveryRequiredException(),
        };
        AppendValue(hash, bytes);
    }

    private static void AppendValue(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static SensitiveObjectRef Owner(
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

    private static async Task<int> ExistingTableCountAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table'
              AND name IN (
                'product_documents','product_inbox','product_cases',
                'product_today','product_outbox');
            """;
        return Convert.ToInt32(
            await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            CultureInfo.InvariantCulture);
    }

    private static async Task<bool> OutboxHasExtractionFieldsAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT sql
            FROM sqlite_master
            WHERE type='table' AND name='product_outbox';
            """;
        var schema = await command.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false);
        return schema is not string sql
            || (sql.Contains("extraction_attempt_id", StringComparison.OrdinalIgnoreCase)
                && sql.Contains("extraction_commit_operation_id", StringComparison.OrdinalIgnoreCase));
    }

    private static async Task InsertOutboxAsync(
        DecryptedEvent replayEvent,
        SqliteProjectionApplyContext context,
        string kind,
        Guid aggregateId,
        InboxId? inboxId,
        Guid? extractionAttemptId,
        int? targetExtractionRevision,
        Guid? extractionCommitOperationId,
        CancellationToken cancellationToken)
    {
        await using var outbox = context.Connection.CreateCommand();
        outbox.Transaction = context.Transaction;
        outbox.CommandText = """
            INSERT INTO product_outbox(
                operation_id,event_id,commit_kind,aggregate_id,inbox_id,
                occurred_at_utc,dispatch_status,extraction_attempt_id,
                target_extraction_revision,extraction_commit_operation_id)
            VALUES(
                $operation,$event,$kind,$aggregate,$inbox,
                $occurred,0,$attempt,$revision,$commit_operation);
            """;
        outbox.Parameters.AddWithValue(
            "$operation",
            ProductEventPayloads.Canonical(replayEvent.Metadata.OperationId.Value));
        outbox.Parameters.AddWithValue(
            "$event",
            ProductEventPayloads.Canonical(replayEvent.Metadata.EventId.Value));
        outbox.Parameters.AddWithValue("$kind", kind);
        outbox.Parameters.AddWithValue(
            "$aggregate",
            ProductEventPayloads.Canonical(aggregateId));
        outbox.Parameters.Add("$inbox", SqliteType.Text).Value =
            inboxId is { } present
                ? ProductEventPayloads.Canonical(present.Value)
                : DBNull.Value;
        outbox.Parameters.AddWithValue(
            "$occurred",
            ProductEventPayloads.Utc(replayEvent.Metadata.RecordedAtUtc));
        outbox.Parameters.Add("$attempt", SqliteType.Text).Value =
            extractionAttemptId is { } attempt ? ProductEventPayloads.Canonical(attempt) : DBNull.Value;
        outbox.Parameters.Add("$revision", SqliteType.Integer).Value =
            targetExtractionRevision is { } revision ? revision : DBNull.Value;
        outbox.Parameters.Add("$commit_operation", SqliteType.Text).Value =
            extractionCommitOperationId is { } commit ? ProductEventPayloads.Canonical(commit) : DBNull.Value;
        RequireSingle(await outbox.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
    }

    private static async Task<InboxId> ReadInboxIdAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid documentId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT inbox_id FROM product_inbox WHERE document_id=$document;";
        command.Parameters.AddWithValue(
            "$document",
            ProductEventPayloads.Canonical(documentId));
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return value is string text
            ? new InboxId(ProductEventPayloads.GuidValue(text))
            : throw new VaultRecoveryRequiredException();
    }

    private static byte[] ParseSha(string value)
    {
        if (value.Length != 64
            || !value.All(character => character is >= '0' and <= '9'
                or >= 'a' and <= 'f'))
        {
            throw new VaultRecoveryRequiredException();
        }

        try
        {
            var bytes = Convert.FromHexString(value);
            return bytes.Length == ContentSha256.Size
                ? bytes
                : throw new VaultRecoveryRequiredException();
        }
        catch (FormatException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static void RequireOwner(
        SqliteProjectionApplyContext context,
        SensitiveObjectKind expectedKind,
        Guid expectedId)
    {
        if (context.Values.BoundOwner.Kind != expectedKind
            || context.Values.BoundOwner.Id.Value != expectedId)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static void AddOwnerAndKey(
        SqliteCommand command,
        SensitiveObjectRef owner,
        EncryptedProjectionValue encrypted)
    {
        command.Parameters.AddWithValue("$owner_kind", (int)owner.Kind);
        command.Parameters.AddWithValue(
            "$owner_id",
            ProductEventPayloads.Canonical(owner.Id.Value));
        command.Parameters.AddWithValue(
            "$key_id",
            ProductEventPayloads.Canonical(encrypted.DataKeyId.Value));
        command.Parameters.AddWithValue("$version", encrypted.EncryptionVersion);
    }

    private static void RequireSingle(int affected)
    {
        if (affected != 1)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
