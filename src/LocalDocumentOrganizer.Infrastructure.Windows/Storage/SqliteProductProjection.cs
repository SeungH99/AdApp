using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Processing;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases.Receivable;
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

internal sealed class ProductProjectionConflictException(ProductConflictKind kind)
    : InvalidOperationException("The product projection precondition was not satisfied.")
{
    internal ProductConflictKind Kind { get; } = kind;
}

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
    internal const int ProjectionSchemaVersion = 9;

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
            current_stream_version INTEGER NOT NULL DEFAULT 0 CHECK(current_stream_version>=0),
            current_extraction_revision INTEGER NOT NULL DEFAULT 0 CHECK(current_extraction_revision>=0),
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
        CREATE TABLE IF NOT EXISTS product_reviews(
            document_id TEXT PRIMARY KEY CHECK(length(document_id)=36)
                REFERENCES product_documents(document_id) ON DELETE CASCADE,
            extraction_revision INTEGER NOT NULL CHECK(extraction_revision>0),
            review_revision INTEGER NOT NULL CHECK(review_revision>0),
            approved_at_utc TEXT NOT NULL,
            owner_kind INTEGER NOT NULL, owner_id TEXT NOT NULL CHECK(length(owner_id)=36),
            key_id TEXT NOT NULL CHECK(length(key_id)=36), encryption_version INTEGER NOT NULL CHECK(encryption_version=1),
            payload_nonce BLOB NOT NULL CHECK(length(payload_nonce)=12), payload_ciphertext BLOB NOT NULL,
            payload_tag BLOB NOT NULL CHECK(length(payload_tag)=16)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS product_review_drafts(
            document_id TEXT PRIMARY KEY CHECK(length(document_id)=36)
                REFERENCES product_documents(document_id) ON DELETE CASCADE,
            extraction_revision INTEGER NOT NULL CHECK(extraction_revision>0),
            current_stream_version INTEGER NOT NULL CHECK(current_stream_version>=0),
            owner_kind INTEGER NOT NULL,
            owner_id TEXT NOT NULL CHECK(length(owner_id)=36),
            key_id TEXT NOT NULL CHECK(length(key_id)=36),
            encryption_version INTEGER NOT NULL CHECK(encryption_version=1),
            payload_nonce BLOB NOT NULL CHECK(length(payload_nonce)=12),
            payload_ciphertext BLOB NOT NULL,
            payload_tag BLOB NOT NULL CHECK(length(payload_tag)=16)
        ) STRICT;
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
            action_id TEXT NULL CHECK(action_id IS NULL OR length(action_id)=36),
            action_type INTEGER NULL CHECK(action_type IS NULL OR action_type=1),
            source_document_id TEXT NOT NULL CHECK(length(source_document_id)=36),
            due_date TEXT NOT NULL CHECK(length(due_date)=10),
            status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 1),
            owner_kind INTEGER NULL,
            owner_id TEXT NULL CHECK(owner_id IS NULL OR length(owner_id)=36),
            key_id TEXT NULL CHECK(key_id IS NULL OR length(key_id)=36),
            encryption_version INTEGER NULL
                CHECK(encryption_version IS NULL OR encryption_version=1),
            display_nonce BLOB NULL
                CHECK(display_nonce IS NULL OR length(display_nonce)=12),
            display_ciphertext BLOB NULL,
            display_tag BLOB NULL
                CHECK(display_tag IS NULL OR length(display_tag)=16),
            CHECK(
                (action_id IS NULL AND action_type IS NULL
                 AND owner_kind IS NULL AND owner_id IS NULL AND key_id IS NULL
                 AND encryption_version IS NULL AND display_nonce IS NULL
                 AND display_ciphertext IS NULL AND display_tag IS NULL)
                OR
                (action_id IS NOT NULL AND action_type IS NOT NULL
                 AND owner_kind IS NOT NULL AND owner_id IS NOT NULL
                 AND key_id IS NOT NULL AND encryption_version IS NOT NULL
                 AND display_nonce IS NOT NULL
                 AND display_ciphertext IS NOT NULL
                 AND display_tag IS NOT NULL))
        ) STRICT;
        CREATE UNIQUE INDEX IF NOT EXISTS product_today_action
            ON product_today(action_id) WHERE action_id IS NOT NULL;
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
            source_binding_json TEXT NULL,
            automatic_failure_count INTEGER NOT NULL DEFAULT 0 CHECK(automatic_failure_count BETWEEN 0 AND 1),
            lease_owner_id TEXT NULL CHECK(lease_owner_id IS NULL OR length(lease_owner_id)=36),
            lease_expires_at_utc TEXT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS product_outbox_dispatch_order
            ON product_outbox(dispatch_status,occurred_at_utc COLLATE BINARY,operation_id COLLATE BINARY);
        CREATE UNIQUE INDEX IF NOT EXISTS product_outbox_extraction_revision
            ON product_outbox(aggregate_id,target_extraction_revision)
            WHERE extraction_attempt_id IS NOT NULL
              AND target_extraction_revision IS NOT NULL;
        """;

    private static readonly ProjectionOwnedTable[] Tables =
    [
        new("product_documents"),
        new("product_inbox"),
        new("product_reviews"),
        new("product_review_drafts"),
        new("product_cases"),
        new("product_today"),
        new("product_outbox"),
    ];

    private static readonly EncryptedProjectionLocation[] ProtectedLocations =
    [
        new("product_inbox", "file_name"),
        new("product_inbox", "metadata"),
        new("product_reviews", "payload"),
        new("product_review_drafts", "payload"),
        new("product_cases", "metadata"),
        new("product_today", "display"),
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
        var legacyInbox =
            !await InboxHasExtractionRevisionAsync(context, cancellationToken)
                .ConfigureAwait(false);
        var legacyToday =
            !await TodayHasActionFieldsAsync(context, cancellationToken)
                .ConfigureAwait(false);
        if (legacyInbox)
        {
            await ExecuteAsync(
                context.Connection,
                context.Transaction,
                """
                ALTER TABLE product_inbox
                ADD COLUMN current_extraction_revision INTEGER NOT NULL DEFAULT 0
                    CHECK(current_extraction_revision>=0);
                """,
                cancellationToken).ConfigureAwait(false);
        }
        if (legacyOutbox)
        {
            await ExecuteAsync(
                context.Connection,
                context.Transaction,
                "DROP TABLE product_outbox;",
                cancellationToken).ConfigureAwait(false);
        }
        if (legacyToday)
        {
            await ExecuteAsync(
                context.Connection,
                context.Transaction,
                "DROP TABLE product_today;",
                cancellationToken).ConfigureAwait(false);
        }
        await ExecuteAsync(context.Connection, context.Transaction, SchemaSql, cancellationToken)
            .ConfigureAwait(false);
        return new ProjectionCompatibilityResult(
            existing == Tables.Length
                && !legacyOutbox
                && !legacyInbox
                && !legacyToday
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
        if (payload.SourceBinding is { IsValid: false })
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
            payload.SourceBinding,
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
        if (kind == "review-committed" && payload.ExpectedExtractionRevision is { } extractionRevision
            && payload.ReviewRevision is { } reviewRevision)
        {
            if (extractionRevision <= 0 || reviewRevision <= 0)
                throw new VaultRecoveryRequiredException();
            await RequireReviewCommitPreconditionAsync(
                context,
                documentId,
                extractionRevision,
                reviewRevision,
                cancellationToken).ConfigureAwait(false);
            var encrypted = await context.Values.ProtectAsync("product_reviews", "payload",
                ProductEventPayloads.Canonical(documentId), context.Values.BoundOwner,
                context.Values.BoundDataKeyId, Encoding.UTF8.GetBytes(payload.AuthenticatedPayload), cancellationToken).ConfigureAwait(false);
            await using var review = context.Connection.CreateCommand();
            review.Transaction = context.Transaction;
            review.CommandText = """
                INSERT INTO product_reviews(document_id,extraction_revision,review_revision,approved_at_utc,owner_kind,owner_id,key_id,encryption_version,payload_nonce,payload_ciphertext,payload_tag)
                VALUES($document,$extraction,$review,$approved,$owner_kind,$owner_id,$key_id,$version,$nonce,$cipher,$tag)
                ON CONFLICT(document_id) DO UPDATE SET extraction_revision=excluded.extraction_revision,review_revision=excluded.review_revision,approved_at_utc=excluded.approved_at_utc,owner_kind=excluded.owner_kind,owner_id=excluded.owner_id,key_id=excluded.key_id,encryption_version=excluded.encryption_version,payload_nonce=excluded.payload_nonce,payload_ciphertext=excluded.payload_ciphertext,payload_tag=excluded.payload_tag;
                """;
            review.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(documentId));
            review.Parameters.AddWithValue("$extraction", extractionRevision); review.Parameters.AddWithValue("$review", reviewRevision);
            review.Parameters.AddWithValue("$approved", ProductEventPayloads.Utc(replayEvent.Metadata.RecordedAtUtc));
            AddOwnerAndKey(review, context.Values.BoundOwner, encrypted);
            review.Parameters.Add("$nonce", SqliteType.Blob).Value=encrypted.Nonce.ToArray(); review.Parameters.Add("$cipher", SqliteType.Blob).Value=encrypted.Ciphertext.ToArray(); review.Parameters.Add("$tag", SqliteType.Blob).Value=encrypted.Tag.ToArray();
            RequireSingle(await review.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }
        if (kind == "extraction-committed"
            && context.Mode == ProjectionApplyMode.LiveAppend
            && payload.ClaimOwnerId is not null)
        {
            if (payload.ClaimAttemptId is null
                || payload.ClaimTargetRevision is null
                || string.IsNullOrWhiteSpace(payload.ClaimLeaseExpiresAtUtc))
            {
                throw new VaultRecoveryRequiredException();
            }
            await using var complete = context.Connection.CreateCommand();
            complete.Transaction = context.Transaction;
            complete.CommandText = """
                UPDATE product_outbox
                SET dispatch_status=3,lease_owner_id=NULL,lease_expires_at_utc=NULL
                WHERE aggregate_id=$document AND extraction_attempt_id=$attempt
                  AND target_extraction_revision=$revision
                  AND lease_owner_id=$owner AND dispatch_status=1
                  AND lease_expires_at_utc>=$occurred;
                """;
            complete.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(documentId));
            complete.Parameters.AddWithValue("$attempt", ProductEventPayloads.Canonical(payload.ClaimAttemptId.Value));
            complete.Parameters.AddWithValue("$revision", payload.ClaimTargetRevision.Value);
            complete.Parameters.AddWithValue("$owner", ProductEventPayloads.Canonical(payload.ClaimOwnerId.Value));
            complete.Parameters.AddWithValue("$occurred", ProductEventPayloads.Utc(replayEvent.Metadata.RecordedAtUtc));
            RequireSingle(await complete.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }
        else if (kind == "extraction-committed"
            && context.Mode == ProjectionApplyMode.RebuildReplay
            && payload.ClaimAttemptId is { } replayAttempt
            && payload.ClaimTargetRevision is { } replayRevision)
        {
            await using var complete = context.Connection.CreateCommand();
            complete.Transaction = context.Transaction;
            complete.CommandText = """
                UPDATE product_outbox
                SET dispatch_status=3,lease_owner_id=NULL,lease_expires_at_utc=NULL
                WHERE aggregate_id=$document AND extraction_attempt_id=$attempt
                  AND target_extraction_revision=$revision;
                """;
            complete.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(documentId));
            complete.Parameters.AddWithValue("$attempt", ProductEventPayloads.Canonical(replayAttempt));
            complete.Parameters.AddWithValue("$revision", replayRevision);
            RequireSingle(await complete.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }
        int? currentExtractionRevision = null;
        if (kind == "extraction-committed")
        {
            currentExtractionRevision = payload.ClaimTargetRevision
                ?? await ReadNextExtractionRevisionAsync(
                    context,
                    documentId,
                    cancellationToken).ConfigureAwait(false);
            if (currentExtractionRevision <= 0)
                throw new VaultRecoveryRequiredException();
            await ReplaceCurrentReviewDraftAsync(
                context,
                documentId,
                currentExtractionRevision.Value,
                replayEvent.Metadata.StreamVersion,
                payload.AuthenticatedPayload,
                cancellationToken).ConfigureAwait(false);
        }
        _faults.ThrowIfRequested(ProductCommitFaultPoint.BeforeInbox);
        await using (var update = context.Connection.CreateCommand())
        {
            update.Transaction = context.Transaction;
            update.CommandText = currentExtractionRevision is null
                ? """
                  UPDATE product_inbox
                  SET status=$status,current_stream_version=$version
                  WHERE document_id=$document;
                  """
                : """
                  UPDATE product_inbox
                  SET status=$status,current_stream_version=$version,
                      current_extraction_revision=$extraction_revision
                  WHERE document_id=$document;
                  """;
            update.Parameters.AddWithValue("$status", (int)status);
            update.Parameters.AddWithValue("$version", replayEvent.Metadata.StreamVersion.Value);
            if (currentExtractionRevision is { } revision)
                update.Parameters.AddWithValue("$extraction_revision", revision);
            update.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            RequireSingle(await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
        }
        if (kind == "review-committed")
        {
            await using var draftHead = context.Connection.CreateCommand();
            draftHead.Transaction = context.Transaction;
            draftHead.CommandText = """
                UPDATE product_review_drafts
                SET current_stream_version=$version
                WHERE document_id=$document;
                """;
            draftHead.Parameters.AddWithValue(
                "$version",
                replayEvent.Metadata.StreamVersion.Value);
            draftHead.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            await draftHead.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
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
            null,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task ReplaceCurrentReviewDraftAsync(
        SqliteProjectionApplyContext context,
        Guid documentId,
        int extractionRevision,
        StreamVersion currentStreamVersion,
        string authenticatedPayload,
        CancellationToken cancellationToken)
    {
        await using (var delete = context.Connection.CreateCommand())
        {
            delete.Transaction = context.Transaction;
            delete.CommandText =
                "DELETE FROM product_review_drafts WHERE document_id=$document;";
            delete.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            await delete.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false);
        }

        if (!AuthenticatedExtractionDraftSerializer.TryDeserialize(
                authenticatedPayload,
                out _))
        {
            // Historical extraction events predate the authenticated draft
            // contract. They remain replayable, but do not synthesize review
            // data that was never persisted.
            return;
        }

        var logicalKey = ProductEventPayloads.Canonical(documentId);
        var encrypted = await context.Values.ProtectAsync(
            "product_review_drafts",
            "payload",
            logicalKey,
            context.Values.BoundOwner,
            context.Values.BoundDataKeyId,
            Encoding.UTF8.GetBytes(authenticatedPayload),
            cancellationToken).ConfigureAwait(false);
        await using var insert = context.Connection.CreateCommand();
        insert.Transaction = context.Transaction;
        insert.CommandText = """
            INSERT INTO product_review_drafts(
                document_id,extraction_revision,current_stream_version,
                owner_kind,owner_id,key_id,encryption_version,
                payload_nonce,payload_ciphertext,payload_tag)
            VALUES(
                $document,$extraction,$stream,
                $owner_kind,$owner_id,$key_id,$version,
                $nonce,$ciphertext,$tag);
            """;
        insert.Parameters.AddWithValue("$document", logicalKey);
        insert.Parameters.AddWithValue("$extraction", extractionRevision);
        insert.Parameters.AddWithValue(
            "$stream",
            currentStreamVersion.Value);
        AddOwnerAndKey(insert, context.Values.BoundOwner, encrypted);
        insert.Parameters.Add("$nonce", SqliteType.Blob).Value =
            encrypted.Nonce.ToArray();
        insert.Parameters.Add("$ciphertext", SqliteType.Blob).Value =
            encrypted.Ciphertext.ToArray();
        insert.Parameters.Add("$tag", SqliteType.Blob).Value =
            encrypted.Tag.ToArray();
        RequireSingle(
            await insert.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false));
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
        var hasAnyAction = payload.ActionId is not null
            || payload.ActionType is not null
            || payload.TotalAmount is not null
            || payload.Currency is not null
            || payload.SafeReason is not null;
        Guid? actionId = null;
        ReceivableActionType? actionType = null;
        TodayProtectedPayload? todayDisplay = null;
        if (hasAnyAction)
        {
            if (payload.ActionId is null
                || payload.ActionType is null
                || payload.TotalAmount is null
                || payload.Currency is null
                || string.IsNullOrWhiteSpace(payload.SafeReason))
            {
                throw new VaultRecoveryRequiredException();
            }
            actionId = ProductEventPayloads.GuidValue(payload.ActionId);
            if (!Enum.IsDefined(
                    typeof(ReceivableActionType),
                    payload.ActionType.Value)
                || !decimal.TryParse(
                    payload.TotalAmount,
                    NumberStyles.Number,
                    CultureInfo.InvariantCulture,
                    out var amount)
                || amount <= 0
                || !string.Equals(
                    amount.ToString(
                        "0.#############################",
                        CultureInfo.InvariantCulture),
                    payload.TotalAmount,
                    StringComparison.Ordinal)
                || !Iso4217CurrencyCatalog.IsValid(payload.Currency))
            {
                throw new VaultRecoveryRequiredException();
            }
            actionType = (ReceivableActionType)payload.ActionType.Value;
            todayDisplay = new TodayProtectedPayload(
                1,
                payload.TotalAmount,
                payload.Currency,
                payload.SafeReason);
        }
        if (payload.ConfirmedReviewRevision is { } confirmedReviewRevision)
        {
            await using var confirmed = context.Connection.CreateCommand();
            confirmed.Transaction = context.Transaction;
            confirmed.CommandText = """
                SELECT 1
                FROM product_reviews r
                JOIN product_inbox i ON i.document_id=r.document_id
                WHERE r.document_id=$document
                  AND r.review_revision=$review
                  AND r.extraction_revision=i.current_extraction_revision
                  AND i.status=$reviewed;
                """;
            confirmed.Parameters.AddWithValue("$document", ProductEventPayloads.Canonical(documentId));
            confirmed.Parameters.AddWithValue("$review", confirmedReviewRevision);
            confirmed.Parameters.AddWithValue("$reviewed", (int)ProductInboxStatus.Reviewed);
            if (await confirmed.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is null)
                throw new ProductProjectionConflictException(
                    ProductConflictKind.StreamVersionMismatch);
        }
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
        if (todayDisplay is null)
        {
            await using var legacyToday = context.Connection.CreateCommand();
            legacyToday.Transaction = context.Transaction;
            legacyToday.CommandText = """
                INSERT INTO product_today(
                    case_id,source_document_id,due_date,status)
                VALUES($case,$document,$due,$status);
                """;
            legacyToday.Parameters.AddWithValue(
                "$case",
                ProductEventPayloads.Canonical(caseId));
            legacyToday.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            legacyToday.Parameters.AddWithValue(
                "$due",
                dueDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            legacyToday.Parameters.AddWithValue(
                "$status",
                (int)ProductTodayStatus.Pending);
            RequireSingle(
                await legacyToday.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false));
        }
        else
        {
            var protectedDisplay = await context.Values.ProtectAsync(
                "product_today",
                "display",
                logicalKey,
                context.Values.BoundOwner,
                context.Values.BoundDataKeyId,
                JsonSerializer.SerializeToUtf8Bytes(todayDisplay),
                cancellationToken).ConfigureAwait(false);
            await using var today = context.Connection.CreateCommand();
            today.Transaction = context.Transaction;
            today.CommandText = """
                INSERT INTO product_today(
                    case_id,action_id,action_type,source_document_id,
                    due_date,status,owner_kind,owner_id,key_id,
                    encryption_version,display_nonce,display_ciphertext,
                    display_tag)
                VALUES(
                    $case,$action,$action_type,$document,
                    $due,$status,$owner_kind,$owner_id,$key_id,
                    $version,$nonce,$ciphertext,$tag);
                """;
            today.Parameters.AddWithValue("$case", logicalKey);
            today.Parameters.AddWithValue(
                "$action",
                ProductEventPayloads.Canonical(actionId!.Value));
            today.Parameters.AddWithValue(
                "$action_type",
                (int)actionType!.Value);
            today.Parameters.AddWithValue(
                "$document",
                ProductEventPayloads.Canonical(documentId));
            today.Parameters.AddWithValue(
                "$due",
                dueDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            today.Parameters.AddWithValue(
                "$status",
                (int)ProductTodayStatus.Pending);
            AddOwnerAndKey(
                today,
                context.Values.BoundOwner,
                protectedDisplay);
            today.Parameters.Add("$nonce", SqliteType.Blob).Value =
                protectedDisplay.Nonce.ToArray();
            today.Parameters.Add("$ciphertext", SqliteType.Blob).Value =
                protectedDisplay.Ciphertext.ToArray();
            today.Parameters.Add("$tag", SqliteType.Blob).Value =
                protectedDisplay.Tag.ToArray();
            RequireSingle(
                await today.ExecuteNonQueryAsync(cancellationToken)
                    .ConfigureAwait(false));
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
            null,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task RequireReviewCommitPreconditionAsync(
        SqliteProjectionApplyContext context,
        Guid documentId,
        int extractionRevision,
        int reviewRevision,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT i.current_extraction_revision,i.status,
                   COALESCE(r.review_revision,0)
            FROM product_inbox i
            LEFT JOIN product_reviews r ON r.document_id=i.document_id
            WHERE i.document_id=$document;
            """;
        command.Parameters.AddWithValue(
            "$document",
            ProductEventPayloads.Canonical(documentId));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            throw new ProductProjectionConflictException(
                ProductConflictKind.StreamVersionMismatch);
        var currentExtractionRevision = reader.GetInt32(0);
        var rawStatus = reader.GetInt32(1);
        var currentReviewRevision = reader.GetInt32(2);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            || currentExtractionRevision != extractionRevision
            || rawStatus is not ((int)ProductInboxStatus.ReadyForReview)
                and not ((int)ProductInboxStatus.NeedsReview)
                and not ((int)ProductInboxStatus.Reviewed)
            || reviewRevision != checked(currentReviewRevision + 1))
        {
            throw new ProductProjectionConflictException(
                ProductConflictKind.StreamVersionMismatch);
        }
    }

    private static async Task<int> ReadNextExtractionRevisionAsync(
        SqliteProjectionApplyContext context,
        Guid documentId,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT current_extraction_revision
            FROM product_inbox
            WHERE document_id=$document;
            """;
        command.Parameters.AddWithValue(
            "$document",
            ProductEventPayloads.Canonical(documentId));
        var value = await command.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false);
        return value is long revision && revision >= 0 && revision < int.MaxValue
            ? checked((int)revision + 1)
            : throw new VaultRecoveryRequiredException();
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
        await AppendReviewDraftRowsAsync(
            context,
            hash,
            cancellationToken).ConfigureAwait(false);
        await AppendReviewRowsAsync(
            context,
            hash,
            cancellationToken).ConfigureAwait(false);
        await AppendCaseRowsAsync(context, hash, cancellationToken).ConfigureAwait(false);
        await AppendTodayRowsAsync(
            context,
            hash,
            cancellationToken).ConfigureAwait(false);
        await AppendRowsAsync(
            context.Connection,
            context.Transaction,
            """
            SELECT operation_id,event_id,commit_kind,aggregate_id,COALESCE(inbox_id,''),
                   occurred_at_utc,dispatch_status,COALESCE(extraction_attempt_id,''),
                   COALESCE(target_extraction_revision,0),
                   COALESCE(extraction_commit_operation_id,''),
                   COALESCE(source_binding_json,''),automatic_failure_count,
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
            SELECT inbox_id,document_id,received_at_utc,status,
                   current_stream_version,current_extraction_revision,
                   owner_kind,owner_id,key_id,
                   encryption_version,file_name_nonce,file_name_ciphertext,file_name_tag,
                   metadata_nonce,metadata_ciphertext,metadata_tag
            FROM product_inbox ORDER BY inbox_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < 6; ordinal++)
            {
                AppendValue(hash, reader.GetValue(ordinal));
            }

            var owner = Owner(reader, 6, 7);
            var keyId = new DataKeyId(ProductEventPayloads.GuidValue(reader.GetString(8)));
            var version = reader.GetInt32(9);
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
                10,
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
                13,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task AppendReviewDraftRowsAsync(
        SqliteProjectionAdministrativeContext context,
        IncrementalHash hash,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT document_id,extraction_revision,current_stream_version,
                   owner_kind,owner_id,key_id,encryption_version,
                   payload_nonce,payload_ciphertext,payload_tag
            FROM product_review_drafts
            ORDER BY document_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < 3; ordinal++)
                AppendValue(hash, reader.GetValue(ordinal));
            var owner = Owner(reader, 3, 4);
            var keyId = new DataKeyId(
                ProductEventPayloads.GuidValue(reader.GetString(5)));
            await AppendProtectedAsync(
                context,
                hash,
                "product_review_drafts",
                "payload",
                reader.GetString(0),
                owner,
                keyId,
                reader.GetInt32(6),
                reader,
                7,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task AppendReviewRowsAsync(
        SqliteProjectionAdministrativeContext context,
        IncrementalHash hash,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT document_id,extraction_revision,review_revision,
                   approved_at_utc,owner_kind,owner_id,key_id,
                   encryption_version,payload_nonce,payload_ciphertext,
                   payload_tag
            FROM product_reviews
            ORDER BY document_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < 4; ordinal++)
                AppendValue(hash, reader.GetValue(ordinal));
            var owner = Owner(reader, 4, 5);
            var keyId = new DataKeyId(
                ProductEventPayloads.GuidValue(reader.GetString(6)));
            await AppendProtectedAsync(
                context,
                hash,
                "product_reviews",
                "payload",
                reader.GetString(0),
                owner,
                keyId,
                reader.GetInt32(7),
                reader,
                8,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task AppendTodayRowsAsync(
        SqliteProjectionAdministrativeContext context,
        IncrementalHash hash,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT case_id,source_document_id,due_date,status,
                   COALESCE(action_id,''),COALESCE(action_type,0),
                   owner_kind,owner_id,key_id,encryption_version,
                   display_nonce,display_ciphertext,display_tag
            FROM product_today
            ORDER BY case_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < 6; ordinal++)
                AppendValue(hash, reader.GetValue(ordinal));
            if (reader.IsDBNull(6))
            {
                if (Enumerable.Range(7, 6)
                    .Any(ordinal => !reader.IsDBNull(ordinal)))
                {
                    throw new VaultRecoveryRequiredException();
                }
                continue;
            }
            var owner = Owner(reader, 6, 7);
            var keyId = new DataKeyId(
                ProductEventPayloads.GuidValue(reader.GetString(8)));
            await AppendProtectedAsync(
                context,
                hash,
                "product_today",
                "display",
                reader.GetString(0),
                owner,
                keyId,
                reader.GetInt32(9),
                reader,
                10,
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
                'product_documents','product_inbox','product_reviews',
                'product_review_drafts','product_cases','product_today',
                'product_outbox');
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
        if (schema is not string sql)
            return true;
        if (!(sql.Contains("extraction_attempt_id", StringComparison.OrdinalIgnoreCase)
                && sql.Contains("extraction_commit_operation_id", StringComparison.OrdinalIgnoreCase)
                && sql.Contains("source_binding_json", StringComparison.OrdinalIgnoreCase)))
            return false;
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type='index' AND name='product_outbox_extraction_revision';";
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not null;
    }

    private static async Task<bool> InboxHasExtractionRevisionAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT sql
            FROM sqlite_master
            WHERE type='table' AND name='product_inbox';
            """;
        var schema = await command.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false);
        return schema is not string sql
            || sql.Contains(
                "current_extraction_revision",
                StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<bool> TodayHasActionFieldsAsync(
        SqliteProjectionAdministrativeContext context,
        CancellationToken cancellationToken)
    {
        await using var command = context.Connection.CreateCommand();
        command.Transaction = context.Transaction;
        command.CommandText = """
            SELECT sql
            FROM sqlite_master
            WHERE type='table' AND name='product_today';
            """;
        var schema = await command.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false);
        return schema is not string sql
            || sql.Contains("action_id", StringComparison.OrdinalIgnoreCase)
            && sql.Contains(
                "display_ciphertext",
                StringComparison.OrdinalIgnoreCase);
    }

    private sealed record TodayProtectedPayload(
        int Version,
        string TotalAmount,
        string Currency,
        string SafeReason);

    private static async Task InsertOutboxAsync(
        DecryptedEvent replayEvent,
        SqliteProjectionApplyContext context,
        string kind,
        Guid aggregateId,
        InboxId? inboxId,
        Guid? extractionAttemptId,
        int? targetExtractionRevision,
        Guid? extractionCommitOperationId,
        ProductDocumentSourceBinding? sourceBinding,
        CancellationToken cancellationToken)
    {
        await using var outbox = context.Connection.CreateCommand();
        outbox.Transaction = context.Transaction;
        outbox.CommandText = """
            INSERT INTO product_outbox(
                operation_id,event_id,commit_kind,aggregate_id,inbox_id,
                occurred_at_utc,dispatch_status,extraction_attempt_id,
                target_extraction_revision,extraction_commit_operation_id,source_binding_json)
            VALUES(
                $operation,$event,$kind,$aggregate,$inbox,
                $occurred,0,$attempt,$revision,$commit_operation,$source_binding);
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
        outbox.Parameters.Add("$source_binding", SqliteType.Text).Value =
            sourceBinding is null ? DBNull.Value : System.Text.Json.JsonSerializer.Serialize(sourceBinding);
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
