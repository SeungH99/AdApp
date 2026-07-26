using System.Globalization;
using System.Security.Cryptography;
using LocalDocumentOrganizer.CorpusEval;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Ingestion;
using LocalDocumentOrganizer.CorpusWorkbench.Labels;
using LocalDocumentOrganizer.CorpusWorkbench.Rules;
using LocalDocumentOrganizer.CorpusWorkbench.Review;
using LocalDocumentOrganizer.CorpusWorkbench.Serialization;
using LocalDocumentOrganizer.CorpusWorkbench.Sampling;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using Microsoft.Data.Sqlite;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.CorpusWorkbench.Persistence;

public sealed class CorpusWorkbenchStore : IDisposable, IAsyncDisposable
{
    private const int BusyTimeoutMilliseconds = 30_000;

    private const string SchemaSql = """
        CREATE TABLE IF NOT EXISTS source_receipts (
          receipt_id TEXT PRIMARY KEY,
          receipt_sha256 TEXT NOT NULL UNIQUE,
          canonical_json BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
          document_id TEXT PRIMARY KEY,
          content_sha256 TEXT NOT NULL UNIQUE,
          source_family_id TEXT NOT NULL,
          market_id TEXT NOT NULL,
          contract_id TEXT NOT NULL,
          input_kind TEXT NOT NULL,
          codec_id TEXT NULL,
          receipt_id TEXT NOT NULL REFERENCES source_receipts(receipt_id),
          lifecycle_state TEXT NOT NULL,
          created_at_utc TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS label_revisions (
          revision_id TEXT PRIMARY KEY,
          document_id TEXT NOT NULL REFERENCES documents(document_id),
          previous_revision_id TEXT NULL,
          revision_sha256 TEXT NOT NULL UNIQUE,
          canonical_json BLOB NOT NULL,
          created_at_utc TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS approval_entries (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          entry_id TEXT NOT NULL UNIQUE,
          previous_entry_sha256 TEXT NOT NULL,
          entry_sha256 TEXT NOT NULL UNIQUE,
          canonical_json BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS checkpoints (
          checkpoint_id TEXT PRIMARY KEY,
          scope_sha256 TEXT NOT NULL,
          canonical_json BLOB NOT NULL
        );
        """;

    private static readonly IReadOnlyDictionary<string, string[]> Columns =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["source_receipts"] =
            [
                "receipt_id",
                "receipt_sha256",
                "canonical_json",
            ],
            ["documents"] =
            [
                "document_id",
                "content_sha256",
                "source_family_id",
                "market_id",
                "contract_id",
                "input_kind",
                "codec_id",
                "receipt_id",
                "lifecycle_state",
                "created_at_utc",
            ],
            ["label_revisions"] =
            [
                "revision_id",
                "document_id",
                "previous_revision_id",
                "revision_sha256",
                "canonical_json",
                "created_at_utc",
            ],
            ["approval_entries"] =
            [
                "sequence",
                "entry_id",
                "previous_entry_sha256",
                "entry_sha256",
                "canonical_json",
            ],
            ["checkpoints"] =
            [
                "checkpoint_id",
                "scope_sha256",
                "canonical_json",
            ],
        };

    private static readonly IReadOnlyDictionary<string, string[]> Types =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["source_receipts"] =
                ["TEXT", "TEXT", "BLOB"],
            ["documents"] =
            [
                "TEXT",
                "TEXT",
                "TEXT",
                "TEXT",
                "TEXT",
                "TEXT",
                "TEXT",
                "TEXT",
                "TEXT",
                "TEXT",
            ],
            ["label_revisions"] =
                ["TEXT", "TEXT", "TEXT", "TEXT", "BLOB", "TEXT"],
            ["approval_entries"] =
                ["INTEGER", "TEXT", "TEXT", "TEXT", "BLOB"],
            ["checkpoints"] =
                ["TEXT", "TEXT", "BLOB"],
        };

    private static readonly IReadOnlyDictionary<string, string>
        PrimaryKeys =
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["source_receipts"] = "receipt_id",
                ["documents"] = "document_id",
                ["label_revisions"] = "revision_id",
                ["approval_entries"] = "sequence",
                ["checkpoints"] = "checkpoint_id",
            };

    private static readonly HashSet<string> NullableColumns =
    [
        "documents.codec_id",
        "label_revisions.previous_revision_id",
    ];

    private readonly ApprovedRootFileStore _fileStore;
    private readonly string _databasePath;
    private readonly Action<CorpusImportFaultPoint>? _injectFault;
    private SafeFileHandle? _databaseLease;
    private int _disposed;

    internal CorpusWorkbenchStore(
        ApprovedRootFileStore fileStore,
        string databasePath,
        Action<CorpusImportFaultPoint>? injectFault)
    {
        ArgumentNullException.ThrowIfNull(fileStore);
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        _fileStore = fileStore;
        _databasePath = Path.GetFullPath(databasePath);
        _injectFault = injectFault;
        _databaseLease = fileStore.OpenExistingMutableVerified(
            "workbench.db");
        try
        {
            Initialize();
        }
        catch
        {
            _databaseLease.Dispose();
            _databaseLease = null;
            throw;
        }
    }

    internal async Task<WorkbenchDocument?> FindImportAsync(
        SourceReceipt receipt,
        byte[] canonicalReceipt,
        string receiptSha256,
        string inputKind,
        string? codecId,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        ValidateSchema(connection, transaction: null);
        var persisted = await ReadPersistedImportAsync(
                connection,
                transaction: null,
                receipt.ExpectedContentSha256,
                cancellationToken)
            .ConfigureAwait(false);
        if (persisted is not null)
        {
            RequireExactRetry(
                persisted,
                receipt,
                canonicalReceipt,
                receiptSha256,
                inputKind,
                codecId);
        }

        RevalidateDatabaseSet();
        return persisted?.Document;
    }

    internal async Task<LabelDraftState> LoadLabelStateAsync(
        string documentId,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(documentId);
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        ValidateSchema(connection, transaction: null);
        var state = await ReadLabelStateAsync(
                connection,
                transaction: null,
                documentId,
                cancellationToken)
            .ConfigureAwait(false);
        RevalidateDatabaseSet();
        return state;
    }

    internal async Task<IReadOnlyList<LabelDraftState>>
        LoadAllLabelStatesAsync(
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        ValidateSchema(connection, transaction: null);
        var states = await ReadAllApprovalLabelStatesAsync(
                connection,
                transaction: null)
            .ConfigureAwait(false);
        RevalidateDatabaseSet();
        return states;
    }

    internal Task<ReviewDecisionCheckpoint?>
        LoadReviewDecisionCheckpointAsync(
        string expectedRevisionSha256,
        CancellationToken cancellationToken)
        => LoadReviewCheckpointAsync(
            expectedRevisionSha256,
            isSchedule: false,
            cancellationToken);

    internal Task<ReviewDecisionCheckpoint?>
        LoadReviewScheduleCheckpointAsync(
        string expectedRevisionSha256,
        CancellationToken cancellationToken)
        => LoadReviewCheckpointAsync(
            expectedRevisionSha256,
            isSchedule: true,
            cancellationToken);

    private Task<ReviewDecisionCheckpoint?> LoadReviewCheckpointAsync(
        string expectedRevisionSha256,
        bool isSchedule,
        CancellationToken cancellationToken)
    {
        ValidateLowerSha256(expectedRevisionSha256);
        return ExecuteApprovalReadAsync(
            async (connection, transaction) =>
            {
                await using var command =
                    connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT
                      checkpoint_id,
                      scope_sha256,
                      canonical_json
                    FROM checkpoints
                    WHERE checkpoint_id=$checkpoint_id;
                    """;
                command.Parameters.AddWithValue(
                    "$checkpoint_id",
                    ReviewCheckpointId(
                        expectedRevisionSha256,
                        isSchedule));
                await using var reader =
                    await command.ExecuteReaderAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false);
                if (!await reader.ReadAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false))
                {
                    return null;
                }

                var checkpoint =
                    ReadReviewDecisionCheckpoint(reader);
                if (await reader.ReadAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false))
                {
                    throw InvalidState();
                }

                return checkpoint;
            },
            cancellationToken);
    }

    internal Task<ReviewSampleProof?> LoadReviewSampleProofAsync(
        string marketId,
        CancellationToken cancellationToken)
    {
        ValidateMarketId(marketId);
        return ExecuteApprovalReadAsync(
            async (connection, transaction) =>
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT
                      checkpoint_id,
                      scope_sha256,
                      canonical_json
                    FROM checkpoints
                    WHERE checkpoint_id=$checkpoint_id;
                    """;
                command.Parameters.AddWithValue(
                    "$checkpoint_id",
                    ReviewSampleCheckpointId(marketId));
                await using var reader = await command
                    .ExecuteReaderAsync(CancellationToken.None)
                    .ConfigureAwait(false);
                if (!await reader.ReadAsync(CancellationToken.None)
                        .ConfigureAwait(false))
                {
                    return null;
                }

                var proof = ReadReviewSampleProof(reader);
                if (await reader.ReadAsync(CancellationToken.None)
                        .ConfigureAwait(false))
                {
                    throw InvalidState();
                }

                return proof;
            },
            cancellationToken);
    }

    internal Task<ReviewSampleProof> SaveReviewSampleProofAsync(
        ReviewSampleProof proof,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proof);
        proof.ValidateCanonical();
        var canonical = WorkbenchJson.Serialize(
            proof,
            WorkbenchJsonContext.Default.ReviewSampleProof);
        var scopeSha256 = Convert.ToHexStringLower(
            SHA256.HashData(canonical));
        var checkpointId = ReviewSampleCheckpointId(
            proof.MarketId);
        return ExecuteApprovalWriteAsync(
            async (connection, transaction) =>
            {
                await using (var read = connection.CreateCommand())
                {
                    read.Transaction = transaction;
                    read.CommandText = """
                        SELECT
                          checkpoint_id,
                          scope_sha256,
                          canonical_json
                        FROM checkpoints
                        WHERE checkpoint_id=$checkpoint_id;
                        """;
                    read.Parameters.AddWithValue(
                        "$checkpoint_id",
                        checkpointId);
                    await using var reader = await read
                        .ExecuteReaderAsync(CancellationToken.None)
                        .ConfigureAwait(false);
                    if (await reader.ReadAsync(
                                CancellationToken.None)
                            .ConfigureAwait(false))
                    {
                        var existing = ReadReviewSampleProof(
                            reader);
                        if (!FixedHashEquals(
                                existing.SampleSha256,
                                proof.SampleSha256))
                        {
                            throw InvalidState();
                        }

                        return existing;
                    }
                }

                await using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO checkpoints(
                      checkpoint_id,
                      scope_sha256,
                      canonical_json)
                    VALUES(
                      $checkpoint_id,
                      $scope_sha256,
                      $canonical_json);
                    """;
                insert.Parameters.AddWithValue(
                    "$checkpoint_id",
                    checkpointId);
                insert.Parameters.AddWithValue(
                    "$scope_sha256",
                    scopeSha256);
                insert.Parameters.Add(
                    "$canonical_json",
                    SqliteType.Blob).Value = canonical;
                if (await insert.ExecuteNonQueryAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false) != 1)
                {
                    throw InvalidState();
                }

                return proof;
            },
            cancellationToken);
    }

    internal Task<IReadOnlyList<ReviewDecisionCheckpoint>>
        LoadReviewDecisionCheckpointsAsync(
        CancellationToken cancellationToken) =>
        LoadReviewCheckpointsAsync(
            isSchedule: false,
            cancellationToken);

    internal Task<IReadOnlyList<ReviewDecisionCheckpoint>>
        LoadReviewScheduleCheckpointsAsync(
        CancellationToken cancellationToken) =>
        LoadReviewCheckpointsAsync(
            isSchedule: true,
            cancellationToken);

    private Task<IReadOnlyList<ReviewDecisionCheckpoint>>
        LoadReviewCheckpointsAsync(
        bool isSchedule,
        CancellationToken cancellationToken) =>
        ExecuteApprovalReadAsync(
            async (connection, transaction) =>
            {
                var result =
                    new List<ReviewDecisionCheckpoint>();
                await using var command =
                    connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = isSchedule
                    ? """
                    SELECT
                      checkpoint_id,
                      scope_sha256,
                      canonical_json
                    FROM checkpoints
                    WHERE checkpoint_id LIKE 'review-schedule-%'
                    ORDER BY checkpoint_id;
                    """
                    : """
                    SELECT
                      checkpoint_id,
                      scope_sha256,
                      canonical_json
                    FROM checkpoints
                    WHERE checkpoint_id LIKE 'review-decision-%'
                    ORDER BY checkpoint_id;
                    """;
                await using var reader =
                    await command.ExecuteReaderAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false);
                while (await reader.ReadAsync(
                           CancellationToken.None)
                       .ConfigureAwait(false))
                {
                    result.Add(
                        ReadReviewDecisionCheckpoint(reader));
                }

                return (IReadOnlyList<
                    ReviewDecisionCheckpoint>)result;
            },
            cancellationToken);

    internal Task<ReviewDecisionCheckpoint>
        SaveReviewDecisionCheckpointAsync(
        ReviewDecisionCheckpoint checkpoint,
        CancellationToken cancellationToken)
    {
        ValidateReviewDecisionCheckpoint(checkpoint);
        var canonical = WorkbenchJson.Serialize(
            checkpoint,
            WorkbenchJsonContext.Default
                .ReviewDecisionCheckpoint);
        var scopeSha256 = Convert.ToHexStringLower(
            SHA256.HashData(canonical));
        var checkpointId = ReviewCheckpointId(
            checkpoint.ExpectedRevisionSha256,
            checkpoint.Decision == ReviewDecisionKind.Defer);
        return ExecuteApprovalWriteAsync(
            async (connection, transaction) =>
            {
                if (checkpoint.Decision == ReviewDecisionKind.Defer)
                {
                    await using var readTerminal =
                        connection.CreateCommand();
                    readTerminal.Transaction = transaction;
                    readTerminal.CommandText = """
                        SELECT
                          checkpoint_id,
                          scope_sha256,
                          canonical_json
                        FROM checkpoints
                        WHERE checkpoint_id=$checkpoint_id;
                        """;
                    readTerminal.Parameters.AddWithValue(
                        "$checkpoint_id",
                        ReviewCheckpointId(
                            checkpoint.ExpectedRevisionSha256,
                            isSchedule: false));
                    await using var terminalReader =
                        await readTerminal.ExecuteReaderAsync(
                                CancellationToken.None)
                            .ConfigureAwait(false);
                    if (await terminalReader.ReadAsync(
                                CancellationToken.None)
                            .ConfigureAwait(false))
                    {
                        var terminal =
                            ReadReviewDecisionCheckpoint(
                                terminalReader);
                        if (await terminalReader.ReadAsync(
                                    CancellationToken.None)
                                .ConfigureAwait(false))
                        {
                            throw InvalidState();
                        }

                        return terminal;
                    }
                }
                else
                {
                    await using var clearSchedule =
                        connection.CreateCommand();
                    clearSchedule.Transaction = transaction;
                    clearSchedule.CommandText = """
                        DELETE FROM checkpoints
                        WHERE checkpoint_id=$checkpoint_id;
                        """;
                    clearSchedule.Parameters.AddWithValue(
                        "$checkpoint_id",
                        ReviewCheckpointId(
                            checkpoint.ExpectedRevisionSha256,
                            isSchedule: true));
                    await clearSchedule.ExecuteNonQueryAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false);
                }

                await using (var read =
                             connection.CreateCommand())
                {
                    read.Transaction = transaction;
                    read.CommandText = """
                        SELECT
                          checkpoint_id,
                          scope_sha256,
                          canonical_json
                        FROM checkpoints
                        WHERE checkpoint_id=$checkpoint_id;
                        """;
                    read.Parameters.AddWithValue(
                        "$checkpoint_id",
                        checkpointId);
                    await using var reader =
                        await read.ExecuteReaderAsync(
                                CancellationToken.None)
                            .ConfigureAwait(false);
                    if (await reader.ReadAsync(
                                CancellationToken.None)
                            .ConfigureAwait(false))
                    {
                        var existing =
                            ReadReviewDecisionCheckpoint(
                                reader);
                        if (!SameReviewDecisionRequest(
                                existing,
                                checkpoint))
                        {
                            throw InvalidState();
                        }

                        if (existing.Completed
                            || !checkpoint.Completed)
                        {
                            return existing;
                        }

                        await reader.DisposeAsync()
                            .ConfigureAwait(false);
                        await using var update =
                            connection.CreateCommand();
                        update.Transaction = transaction;
                        update.CommandText = """
                            UPDATE checkpoints
                            SET
                              scope_sha256=$scope_sha256,
                              canonical_json=$canonical_json
                            WHERE checkpoint_id=$checkpoint_id;
                            """;
                        update.Parameters.AddWithValue(
                            "$scope_sha256",
                            scopeSha256);
                        update.Parameters.Add(
                            "$canonical_json",
                            SqliteType.Blob).Value = canonical;
                        update.Parameters.AddWithValue(
                            "$checkpoint_id",
                            checkpointId);
                        if (await update.ExecuteNonQueryAsync(
                                    CancellationToken.None)
                                .ConfigureAwait(false) != 1)
                        {
                            throw InvalidState();
                        }

                        return checkpoint;
                    }
                }

                await using var insert =
                    connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO checkpoints(
                      checkpoint_id,
                      scope_sha256,
                      canonical_json)
                    VALUES(
                      $checkpoint_id,
                      $scope_sha256,
                      $canonical_json);
                    """;
                insert.Parameters.AddWithValue(
                    "$checkpoint_id",
                    checkpointId);
                insert.Parameters.AddWithValue(
                    "$scope_sha256",
                    scopeSha256);
                var canonicalParameter =
                    insert.Parameters.Add(
                        "$canonical_json",
                        SqliteType.Blob);
                canonicalParameter.Value = canonical;
                if (await insert.ExecuteNonQueryAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false)
                    != 1)
                {
                    throw InvalidState();
                }

                return checkpoint;
            },
            cancellationToken);
    }

    /*
     * Terminal checkpoints may move exactly once from pending to complete.
     * The request identity and its first accepted timestamp never change.
     */
    private static bool SameReviewDecisionRequest(
        ReviewDecisionCheckpoint left,
        ReviewDecisionCheckpoint right) =>
        string.Equals(
            left.SchemaVersion,
            right.SchemaVersion,
            StringComparison.Ordinal)
        && string.Equals(
            left.DocumentId,
            right.DocumentId,
            StringComparison.Ordinal)
        && string.Equals(
            left.ExpectedRevisionSha256,
            right.ExpectedRevisionSha256,
            StringComparison.Ordinal)
        && string.Equals(
            left.RequestSha256,
            right.RequestSha256,
            StringComparison.Ordinal)
        && left.Decision == right.Decision
        && (!(left.Completed && right.Completed)
            || string.Equals(
                left.OutcomeRevisionSha256,
                right.OutcomeRevisionSha256,
                StringComparison.Ordinal));

    internal Task<LabelDraftState> ReadApprovalLabelStateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string documentId) =>
        ReadLabelStateAsync(
            connection,
            transaction,
            documentId,
            CancellationToken.None);

    internal async Task<IReadOnlyList<LabelDraftState>>
        ReadAllApprovalLabelStatesAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        var documentIds = new List<string>();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT document_id
                FROM documents
                ORDER BY document_id;
                """;
            await using var reader =
                await command.ExecuteReaderAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            while (await reader.ReadAsync(CancellationToken.None)
                       .ConfigureAwait(false))
            {
                documentIds.Add(reader.GetString(0));
            }
        }

        var states = new List<LabelDraftState>(documentIds.Count);
        foreach (var documentId in documentIds)
        {
            states.Add(
                await ReadLabelStateAsync(
                        connection,
                        transaction,
                        documentId,
                        CancellationToken.None)
                    .ConfigureAwait(false));
        }

        return states;
    }

    internal async Task<T> ExecuteApprovalWriteAsync<T>(
        Func<SqliteConnection, SqliteTransaction, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(operation);
        cancellationToken.ThrowIfCancellationRequested();
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        await using var transaction =
            connection.BeginTransaction(deferred: false);
        try
        {
            RevalidateDatabaseSet();
            ValidateSchema(connection, transaction);
            var result = await operation(connection, transaction)
                .ConfigureAwait(false);
            ValidateSchema(connection, transaction);
            RevalidateDatabaseSet();
            await transaction.CommitAsync(CancellationToken.None)
                .ConfigureAwait(false);
            return result;
        }
        catch
        {
            try
            {
                await transaction.RollbackAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch
            {
                // The primary transaction failure remains canonical.
            }

            throw;
        }
    }

    internal async Task<T> ExecuteApprovalReadAsync<T>(
        Func<SqliteConnection, SqliteTransaction, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(operation);
        cancellationToken.ThrowIfCancellationRequested();
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        await using var transaction =
            connection.BeginTransaction(deferred: false);
        try
        {
            RevalidateDatabaseSet();
            ValidateSchema(connection, transaction);
            var result = await operation(connection, transaction)
                .ConfigureAwait(false);
            ValidateSchema(connection, transaction);
            RevalidateDatabaseSet();
            await transaction.CommitAsync(CancellationToken.None)
                .ConfigureAwait(false);
            return result;
        }
        catch
        {
            try
            {
                await transaction.RollbackAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch
            {
                // The primary transaction failure remains canonical.
            }

            throw;
        }
    }

    internal async Task<LabelRevision> PersistLabelRevisionAsync(
        LabelDraftState expectedState,
        LabelDraft draft,
        OfficialRuleCatalogSnapshot rules,
        CorpusWorkerPackageIdentity workerIdentity,
        DateTimeOffset createdAtUtc,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(expectedState);
        ArgumentNullException.ThrowIfNull(draft);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(workerIdentity);
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        await using var transaction =
            connection.BeginTransaction(deferred: false);
        try
        {
            RevalidateDatabaseSet();
            ValidateSchema(connection, transaction);
            var current = await ReadLabelStateAsync(
                    connection,
                    transaction,
                    expectedState.Document.DocumentId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (current.Document != expectedState.Document)
            {
                throw InvalidState();
            }

            if (current.PreviousRevision is { } currentHead
                && DraftLabelService.HasSameBinding(
                    currentHead,
                    current.Document,
                    draft,
                    rules,
                    workerIdentity))
            {
                await transaction.CommitAsync(CancellationToken.None)
                    .ConfigureAwait(false);
                RevalidateDatabaseSet();
                return currentHead;
            }

            if (!SameRevision(
                    current.PreviousRevision,
                    expectedState.PreviousRevision))
            {
                throw InvalidState();
            }

            var revision =
                DraftLabelService.CreateCanonicalRevision(
                    current.Document,
                    draft,
                    rules,
                    workerIdentity,
                    current.PreviousRevision,
                    createdAtUtc);
            var canonical = WorkbenchJson.Serialize(
                revision,
                WorkbenchJsonContext.Default.LabelRevision);
            await using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    INSERT INTO label_revisions(
                      revision_id,
                      document_id,
                      previous_revision_id,
                      revision_sha256,
                      canonical_json,
                      created_at_utc)
                    VALUES(
                      $revision_id,
                      $document_id,
                      $previous_revision_id,
                      $revision_sha256,
                      $canonical_json,
                      $created_at_utc);
                    """;
                command.Parameters.AddWithValue(
                    "$revision_id",
                    revision.RevisionId);
                command.Parameters.AddWithValue(
                    "$document_id",
                    revision.DocumentId);
                command.Parameters.AddWithValue(
                    "$previous_revision_id",
                    (object?)revision.PreviousRevisionId
                        ?? DBNull.Value);
                command.Parameters.AddWithValue(
                    "$revision_sha256",
                    revision.RevisionSha256);
                var canonicalParameter = command.Parameters.Add(
                    "$canonical_json",
                    SqliteType.Blob);
                canonicalParameter.Value = canonical;
                command.Parameters.AddWithValue(
                    "$created_at_utc",
                    revision.CreatedAtUtc.UtcDateTime.ToString(
                        "O",
                        CultureInfo.InvariantCulture));
                if (await command.ExecuteNonQueryAsync(cancellationToken)
                        .ConfigureAwait(false)
                    != 1)
                {
                    throw InvalidState();
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            ValidateSchema(connection, transaction);
            RevalidateDatabaseSet();
            await transaction.CommitAsync(CancellationToken.None)
                .ConfigureAwait(false);
            RevalidateDatabaseSet();
            return revision;
        }
        catch
        {
            try
            {
                await transaction.RollbackAsync(CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch
            {
                // The primary transaction failure remains canonical.
            }

            throw;
        }
    }

    internal async Task<PersistedImport> PersistImportAsync(
        SourceReceipt receipt,
        byte[] canonicalReceipt,
        string receiptSha256,
        string inputKind,
        string? codecId,
        Action acceptanceRevalidation,
        ImportCommitOwnership ownership,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(canonicalReceipt);
        ArgumentNullException.ThrowIfNull(acceptanceRevalidation);
        ArgumentNullException.ThrowIfNull(ownership);
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        await using var transaction =
            connection.BeginTransaction(deferred: false);
        try
        {
            RevalidateDatabaseSet();
            ValidateSchema(connection, transaction);
            var existing = await ReadPersistedImportAsync(
                    connection,
                    transaction,
                    receipt.ExpectedContentSha256,
                    cancellationToken)
                .ConfigureAwait(false);
            if (existing is not null)
            {
                RequireExactRetry(
                    existing,
                    receipt,
                    canonicalReceipt,
                    receiptSha256,
                    inputKind,
                    codecId);
                await CommitAcceptedAsync(
                        connection,
                        transaction,
                        acceptanceRevalidation,
                        ownership,
                        cancellationToken)
                    .ConfigureAwait(false);
                return new PersistedImport(
                    existing.Document,
                    WasExisting: true);
            }

            await RequireReceiptAvailableAsync(
                    connection,
                    transaction,
                    receipt,
                    receiptSha256,
                    cancellationToken)
                .ConfigureAwait(false);

            await using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    INSERT INTO source_receipts(
                      receipt_id,
                      receipt_sha256,
                      canonical_json)
                    VALUES($receipt_id, $receipt_sha256, $canonical_json);
                    """;
                command.Parameters.AddWithValue(
                    "$receipt_id",
                    receipt.ReceiptId);
                command.Parameters.AddWithValue(
                    "$receipt_sha256",
                    receiptSha256);
                var canonicalParameter =
                    command.Parameters.Add(
                        "$canonical_json",
                        SqliteType.Blob);
                canonicalParameter.Value = canonicalReceipt;
                if (await command.ExecuteNonQueryAsync(cancellationToken)
                        .ConfigureAwait(false)
                    != 1)
                {
                    throw InvalidState();
                }
            }

            var createdAt = DateTimeOffset.UtcNow;
            var document = new WorkbenchDocument(
                CreateDocumentId(receipt.ExpectedContentSha256),
                receipt.ExpectedContentSha256,
                receipt.SourceFamilyId,
                receipt.MarketId,
                receipt.ContractId,
                inputKind,
                codecId,
                receipt.ReceiptId,
                "imported",
                createdAt);
            await using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    INSERT INTO documents(
                      document_id,
                      content_sha256,
                      source_family_id,
                      market_id,
                      contract_id,
                      input_kind,
                      codec_id,
                      receipt_id,
                      lifecycle_state,
                      created_at_utc)
                    VALUES(
                      $document_id,
                      $content_sha256,
                      $source_family_id,
                      $market_id,
                      $contract_id,
                      $input_kind,
                      $codec_id,
                      $receipt_id,
                      $lifecycle_state,
                      $created_at_utc);
                    """;
                command.Parameters.AddWithValue(
                    "$document_id",
                    document.DocumentId);
                command.Parameters.AddWithValue(
                    "$content_sha256",
                    document.ContentSha256);
                command.Parameters.AddWithValue(
                    "$source_family_id",
                    document.SourceFamilyId);
                command.Parameters.AddWithValue(
                    "$market_id",
                    document.MarketId);
                command.Parameters.AddWithValue(
                    "$contract_id",
                    document.ContractId);
                command.Parameters.AddWithValue(
                    "$input_kind",
                    document.InputKind);
                command.Parameters.AddWithValue(
                    "$codec_id",
                    (object?)document.CodecId ?? DBNull.Value);
                command.Parameters.AddWithValue(
                    "$receipt_id",
                    document.ReceiptId);
                command.Parameters.AddWithValue(
                    "$lifecycle_state",
                    document.LifecycleState);
                command.Parameters.AddWithValue(
                    "$created_at_utc",
                    document.CreatedAtUtc.ToString(
                        "O",
                        CultureInfo.InvariantCulture));
                if (await command.ExecuteNonQueryAsync(cancellationToken)
                        .ConfigureAwait(false)
                    != 1)
                {
                    throw InvalidState();
                }
            }

            await CommitAcceptedAsync(
                    connection,
                    transaction,
                    acceptanceRevalidation,
                    ownership,
                    cancellationToken)
                .ConfigureAwait(false);
            return new PersistedImport(
                document,
                WasExisting: false);
        }
        catch
        {
            if (!ownership.IsTransferred)
            {
                try
                {
                    await transaction.RollbackAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                    // The primary transaction failure remains canonical.
                }
            }

            throw;
        }
    }

    internal async Task<bool> DeleteIfDocumentMissingAsync(
        string contentSha256,
        Action deleteOwnedObject)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(deleteOwnedObject);
        await using var connection =
            await OpenConnectionAsync(CancellationToken.None)
                .ConfigureAwait(false);
        await using var transaction =
            connection.BeginTransaction(deferred: false);
        RevalidateDatabaseSet();
        ValidateSchema(connection, transaction);
        if (await ReadPersistedImportAsync(
                connection,
                transaction,
                contentSha256,
                CancellationToken.None)
            .ConfigureAwait(false) is not null)
        {
            return false;
        }

        deleteOwnedObject();
        RevalidateDatabaseSet();
        await transaction.CommitAsync(CancellationToken.None)
            .ConfigureAwait(false);
        RevalidateDatabaseSet();
        return true;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Interlocked.Exchange(
                    ref _databaseLease,
                    null)
                ?.Dispose();
        }
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private void Initialize()
    {
        ThrowIfDisposed();
        RevalidateDatabaseSet();
        using var connection = CreateConnection();
        connection.Open();
        RevalidateDatabaseSet();
        ConfigureConnection(connection);
        RevalidateDatabaseSet();
        RequirePragma(connection, "journal_mode", "wal");

        using var transaction =
            connection.BeginTransaction(deferred: false);
        try
        {
            RevalidateDatabaseSet();
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = SchemaSql;
                command.ExecuteNonQuery();
            }

            ValidateSchema(connection, transaction);
            RevalidateDatabaseSet();
            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }

        ValidateSchema(connection, transaction: null);
        RevalidateDatabaseSet();
    }

    private async Task<SqliteConnection> OpenConnectionAsync(
        CancellationToken cancellationToken)
    {
        RevalidateDatabaseSet();
        var connection = CreateConnection();
        try
        {
            await connection.OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            RevalidateDatabaseSet();
            await ConfigureConnectionAsync(
                    connection,
                    cancellationToken)
                .ConfigureAwait(false);
            RevalidateDatabaseSet();
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private SqliteConnection CreateConnection() =>
        new(
            new SqliteConnectionStringBuilder
            {
                DataSource = _databasePath,
                Mode = SqliteOpenMode.ReadWrite,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
                DefaultTimeout =
                    BusyTimeoutMilliseconds / 1000,
            }.ToString());

    private static void ConfigureConnection(SqliteConnection connection)
    {
        Execute(
            connection,
            $"""
             PRAGMA foreign_keys=ON;
             PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA trusted_schema=OFF;
             PRAGMA busy_timeout={BusyTimeoutMilliseconds};
             """);
        RequirePragma(connection, "foreign_keys", "1");
        RequirePragma(connection, "journal_mode", "wal");
        RequirePragma(connection, "synchronous", "2");
        RequirePragma(connection, "trusted_schema", "0");
        RequirePragma(
            connection,
            "busy_timeout",
            BusyTimeoutMilliseconds.ToString(
                CultureInfo.InvariantCulture));
    }

    private static async Task ConfigureConnectionAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await ExecuteAsync(
                connection,
                $"""
                 PRAGMA foreign_keys=ON;
                 PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA trusted_schema=OFF;
                 PRAGMA busy_timeout={BusyTimeoutMilliseconds};
                 """,
                cancellationToken)
            .ConfigureAwait(false);
        await RequirePragmaAsync(
                connection,
                "foreign_keys",
                "1",
                cancellationToken)
            .ConfigureAwait(false);
        await RequirePragmaAsync(
                connection,
                "journal_mode",
                "wal",
                cancellationToken)
            .ConfigureAwait(false);
        await RequirePragmaAsync(
                connection,
                "synchronous",
                "2",
                cancellationToken)
            .ConfigureAwait(false);
        await RequirePragmaAsync(
                connection,
                "trusted_schema",
                "0",
                cancellationToken)
            .ConfigureAwait(false);
        await RequirePragmaAsync(
                connection,
                "busy_timeout",
                BusyTimeoutMilliseconds.ToString(
                    CultureInfo.InvariantCulture),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<PersistedImportIdentity?>
        ReadPersistedImportAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string contentSha256,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT
              document_id,
              content_sha256,
              source_family_id,
              market_id,
              contract_id,
              input_kind,
              codec_id,
              documents.receipt_id,
              lifecycle_state,
              created_at_utc,
              source_receipts.receipt_sha256,
              source_receipts.canonical_json
            FROM documents
            INNER JOIN source_receipts
              ON source_receipts.receipt_id=documents.receipt_id
            WHERE documents.content_sha256=$content_sha256;
            """;
        command.Parameters.AddWithValue(
            "$content_sha256",
            contentSha256);
        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken)
                .ConfigureAwait(false))
        {
            return null;
        }

        var createdAtText = reader.GetString(9);
        if (!DateTimeOffset.TryParseExact(
                createdAtText,
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var createdAt))
        {
            throw InvalidState();
        }

        var document = new WorkbenchDocument(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetString(5),
            reader.IsDBNull(6) ? null : reader.GetString(6),
            reader.GetString(7),
            reader.GetString(8),
            createdAt);
        var persistedReceiptSha256 = reader.GetString(10);
        if (reader.GetValue(11) is not byte[] persistedCanonicalReceipt)
        {
            throw InvalidState();
        }

        if (await reader.ReadAsync(cancellationToken)
                .ConfigureAwait(false))
        {
            throw InvalidState();
        }

        return new PersistedImportIdentity(
            document,
            persistedReceiptSha256,
            persistedCanonicalReceipt);
    }

    private static async Task<LabelDraftState> ReadLabelStateAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string documentId,
        CancellationToken cancellationToken)
    {
        string contentSha256;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT content_sha256
                FROM documents
                WHERE document_id=$document_id;
                """;
            command.Parameters.AddWithValue(
                "$document_id",
                documentId);
            var value = await command.ExecuteScalarAsync(
                    cancellationToken)
                .ConfigureAwait(false);
            contentSha256 = value as string
                ?? throw InvalidState();
        }

        var persisted = await ReadPersistedImportAsync(
                connection,
                transaction,
                contentSha256,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw InvalidState();
        if (!string.Equals(
                persisted.Document.DocumentId,
                documentId,
                StringComparison.Ordinal))
        {
            throw InvalidState();
        }

        RequireReceiptIdentity(persisted);
        var revisions = new List<LabelRevision>();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT
                  revision_id,
                  previous_revision_id,
                  revision_sha256,
                  canonical_json,
                  created_at_utc
                FROM label_revisions
                WHERE document_id=$document_id;
                """;
            command.Parameters.AddWithValue(
                "$document_id",
                documentId);
            await using var reader =
                await command.ExecuteReaderAsync(cancellationToken)
                    .ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken)
                       .ConfigureAwait(false))
            {
                if (reader.GetValue(3) is not byte[] canonical)
                {
                    throw InvalidState();
                }

                LabelRevision revision;
                try
                {
                    revision = WorkbenchJson.Parse(
                        canonical,
                        WorkbenchJsonContext.Default.LabelRevision);
                }
                catch (Exception exception) when (
                    exception is System.Text.Json.JsonException
                        or NotSupportedException)
                {
                    throw InvalidState();
                }

                var createdAtText = reader.GetString(4);
                if (!DateTimeOffset.TryParseExact(
                        createdAtText,
                        "O",
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind,
                        out var createdAt)
                    || createdAt.Offset != TimeSpan.Zero
                    || revision.CreatedAtUtc.Offset != TimeSpan.Zero
                    || revision.CreatedAtUtc != createdAt
                    || !string.Equals(
                        revision.RevisionId,
                        reader.GetString(0),
                        StringComparison.Ordinal)
                    || !string.Equals(
                        revision.DocumentId,
                        documentId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        revision.DocumentSha256,
                        persisted.Document.ContentSha256,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        revision.MarketId,
                        persisted.Document.MarketId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        revision.ContractId,
                        persisted.Document.ContractId,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        revision.PreviousRevisionId,
                        reader.IsDBNull(1)
                            ? null
                            : reader.GetString(1),
                        StringComparison.Ordinal)
                    || !string.Equals(
                        revision.RevisionSha256,
                        reader.GetString(2),
                        StringComparison.Ordinal)
                    || !string.Equals(
                        revision.RevisionId,
                        "revision-" + revision.RevisionSha256,
                        StringComparison.Ordinal)
                    || !DraftLabelService.HasValidCanonicalHash(
                        revision)
                    || !CryptographicOperations.FixedTimeEquals(
                        canonical,
                        WorkbenchJson.Serialize(
                            revision,
                            WorkbenchJsonContext.Default
                                .LabelRevision)))
                {
                    throw InvalidState();
                }

                revisions.Add(revision);
            }
        }

        return new LabelDraftState(
            persisted.Document,
            RequireLinearHead(revisions));
    }

    private static void RequireReceiptIdentity(
        PersistedImportIdentity persisted)
    {
        SourceReceipt receipt;
        try
        {
            receipt = WorkbenchJson.Parse(
                persisted.CanonicalReceipt,
                WorkbenchJsonContext.Default.SourceReceipt);
        }
        catch (Exception exception) when (
            exception is System.Text.Json.JsonException
                or NotSupportedException)
        {
            throw InvalidState();
        }

        var canonical = CanonicalSourceReceipt.Serialize(receipt);
        var sha256 =
            Convert.ToHexStringLower(SHA256.HashData(canonical));
        var document = persisted.Document;
        if (!CryptographicOperations.FixedTimeEquals(
                canonical,
                persisted.CanonicalReceipt)
            || !string.Equals(
                sha256,
                persisted.ReceiptSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ReceiptId,
                document.ReceiptId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ExpectedContentSha256,
                document.ContentSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.SourceFamilyId,
                document.SourceFamilyId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.MarketId,
                document.MarketId,
                StringComparison.Ordinal)
            || !string.Equals(
                receipt.ContractId,
                document.ContractId,
                StringComparison.Ordinal))
        {
            throw InvalidState();
        }
    }

    private static LabelRevision? RequireLinearHead(
        IReadOnlyList<LabelRevision> revisions)
    {
        if (revisions.Count == 0)
        {
            return null;
        }

        var byId = revisions.ToDictionary(
            static revision => revision.RevisionId,
            StringComparer.Ordinal);
        var referenced = new HashSet<string>(StringComparer.Ordinal);
        foreach (var revision in revisions)
        {
            if (revision.PreviousRevisionId is null)
            {
                if (revision.PreviousRevisionSha256 is not null)
                {
                    throw InvalidState();
                }

                continue;
            }

            if (!byId.TryGetValue(
                    revision.PreviousRevisionId,
                    out var previous)
                || !string.Equals(
                    revision.PreviousRevisionSha256,
                    previous.RevisionSha256,
                    StringComparison.Ordinal)
                || !referenced.Add(previous.RevisionId))
            {
                throw InvalidState();
            }
        }

        var heads = revisions
            .Where(revision => !referenced.Contains(revision.RevisionId))
            .ToArray();
        if (heads.Length != 1)
        {
            throw InvalidState();
        }

        var visited = new HashSet<string>(StringComparer.Ordinal);
        var current = heads[0];
        while (true)
        {
            if (!visited.Add(current.RevisionId))
            {
                throw InvalidState();
            }

            if (current.PreviousRevisionId is null)
            {
                break;
            }

            current = byId[current.PreviousRevisionId];
        }

        return visited.Count == revisions.Count
            ? heads[0]
            : throw InvalidState();
    }

    private static bool SameRevision(
        LabelRevision? left,
        LabelRevision? right) =>
        left is null && right is null
        || left is not null
        && right is not null
        && string.Equals(
            left.RevisionId,
            right.RevisionId,
            StringComparison.Ordinal)
        && string.Equals(
            left.RevisionSha256,
            right.RevisionSha256,
            StringComparison.Ordinal);

    private static void RequireExactRetry(
        PersistedImportIdentity persisted,
        SourceReceipt receipt,
        byte[] canonicalReceipt,
        string receiptSha256,
        string inputKind,
        string? codecId)
    {
        var document = persisted.Document;
        if (!string.Equals(
                document.DocumentId,
                CreateDocumentId(receipt.ExpectedContentSha256),
                StringComparison.Ordinal)
            || !string.Equals(
                document.ContentSha256,
                receipt.ExpectedContentSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                document.SourceFamilyId,
                receipt.SourceFamilyId,
                StringComparison.Ordinal)
            || !string.Equals(
                document.MarketId,
                receipt.MarketId,
                StringComparison.Ordinal)
            || !string.Equals(
                document.ContractId,
                receipt.ContractId,
                StringComparison.Ordinal)
            || !string.Equals(
                document.InputKind,
                inputKind,
                StringComparison.Ordinal)
            || !string.Equals(
                document.CodecId,
                codecId,
                StringComparison.Ordinal)
            || !string.Equals(
                document.ReceiptId,
                receipt.ReceiptId,
                StringComparison.Ordinal)
            || !string.Equals(
                document.LifecycleState,
                "imported",
                StringComparison.Ordinal)
            || !string.Equals(
                persisted.ReceiptSha256,
                receiptSha256,
                StringComparison.Ordinal)
            || !CryptographicOperations.FixedTimeEquals(
                persisted.CanonicalReceipt,
                canonicalReceipt))
        {
            throw InvalidState();
        }
    }

    private static async Task RequireReceiptAvailableAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SourceReceipt receipt,
        string receiptSha256,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT receipt_id, receipt_sha256
            FROM source_receipts
            WHERE receipt_id=$receipt_id
               OR receipt_sha256=$receipt_sha256;
            """;
        command.Parameters.AddWithValue(
            "$receipt_id",
            receipt.ReceiptId);
        command.Parameters.AddWithValue(
            "$receipt_sha256",
            receiptSha256);
        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken)
                .ConfigureAwait(false))
        {
            throw InvalidState();
        }
    }

    private async Task CommitAcceptedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Action acceptanceRevalidation,
        ImportCommitOwnership ownership,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateSchema(connection, transaction);
        RevalidateDatabaseSet();

        // This is the last acceptance check. The live source/object handles
        // deny data writes and delete/rename while the IMMEDIATE SQLite
        // transaction serializes database ownership. NTFS hard-link creation
        // is not fully fenced by sharing flags, so the approved roots must also
        // enforce an exclusive-writer ACL. The check below detects any link
        // introduced before this boundary; no stronger race-free claim is made.
        acceptanceRevalidation();
        await transaction.CommitAsync(CancellationToken.None)
            .ConfigureAwait(false);

        // This transfer cannot throw. It is intentionally the first operation
        // after a successful durable commit so later health failures can never
        // authorize deletion of the committed object.
        ownership.Transfer();
        RevalidateDatabaseSet();
        _injectFault?.Invoke(
            CorpusImportFaultPoint.AfterDatabaseCommit);
    }

    private static string CreateDocumentId(string contentSha256) =>
        "document-" + contentSha256;

    private static void ValidateSchema(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        var tableNames = new List<string>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT name
                FROM sqlite_schema
                WHERE type='table'
                ORDER BY name;
                """;
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                tableNames.Add(reader.GetString(0));
            }
        }

        if (!tableNames.SequenceEqual(
                Columns.Keys
                    .Append("sqlite_sequence")
                    .Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw InvalidState();
        }

        RequireExactSqliteSequenceSql(
            connection,
            transaction);

        foreach (var (table, expectedColumns) in Columns)
        {
            RequireExactTableSql(
                connection,
                transaction,
                table);
            var actualColumns = new List<TableColumn>();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                $"PRAGMA table_xinfo(\"{table}\");";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                actualColumns.Add(
                    new TableColumn(
                        checked((int)reader.GetInt64(0)),
                        reader.GetString(1),
                        reader.GetString(2),
                        reader.GetInt64(3) != 0,
                        reader.IsDBNull(4)
                            ? null
                            : reader.GetValue(4),
                        checked((int)reader.GetInt64(5)),
                        checked((int)reader.GetInt64(6))));
            }

            if (actualColumns.Count != expectedColumns.Length)
            {
                throw InvalidState();
            }

            for (var index = 0;
                 index < expectedColumns.Length;
                 index++)
            {
                var column = expectedColumns[index];
                var isPrimaryKey = string.Equals(
                    PrimaryKeys[table],
                    column,
                    StringComparison.Ordinal);
                var expectedNotNull = !isPrimaryKey
                    && !NullableColumns.Contains(
                        table + "." + column);
                var actual = actualColumns[index];
                if (actual.Ordinal != index
                    || !string.Equals(
                        actual.Name,
                        column,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        actual.Type,
                        Types[table][index],
                        StringComparison.Ordinal)
                    || actual.NotNull != expectedNotNull
                    || actual.DefaultValue is not null
                    || actual.PrimaryKeyOrder
                        != (isPrimaryKey ? 1 : 0)
                    || actual.Hidden != 0)
                {
                    throw InvalidState();
                }
            }

            RequireExactIndexes(
                connection,
                transaction,
                table);
            RequireExactForeignKeys(
                connection,
                transaction,
                table);
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "PRAGMA foreign_key_check;";
            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                throw InvalidState();
            }
        }

        using var unexpected = connection.CreateCommand();
        unexpected.Transaction = transaction;
        unexpected.CommandText = """
            SELECT COUNT(*)
            FROM sqlite_schema
            WHERE type IN ('trigger', 'view')
               OR (type='index' AND sql IS NOT NULL);
            """;
        if (Convert.ToInt64(
                unexpected.ExecuteScalar(),
                CultureInfo.InvariantCulture)
            != 0)
        {
            throw InvalidState();
        }
    }

    private static void RequireExactTableSql(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT sql
            FROM sqlite_schema
            WHERE type='table' AND name=$name AND tbl_name=$name;
            """;
        command.Parameters.AddWithValue("$name", table);
        if (command.ExecuteScalar() is not string actual
            || !string.Equals(
                NormalizeSql(actual),
                NormalizeSql(ExtractSchemaStatement(table)),
                StringComparison.Ordinal))
        {
            throw InvalidState();
        }
    }

    private static void RequireExactSqliteSequenceSql(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT sql
            FROM sqlite_schema
            WHERE type='table'
              AND name='sqlite_sequence'
              AND tbl_name='sqlite_sequence';
            """;
        if (command.ExecuteScalar() is not string actual
            || !string.Equals(
                NormalizeSql(actual),
                NormalizeSql(
                    "CREATE TABLE sqlite_sequence(name,seq)"),
                StringComparison.Ordinal))
        {
            throw InvalidState();
        }
    }

    private static void RequireExactIndexes(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table)
    {
        var actual = new List<IndexSignature>();
        var indexNames = new List<(string Name, string Origin)>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                $"PRAGMA index_list(\"{table}\");";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                if (reader.GetInt64(2) != 1
                    || reader.GetInt64(4) != 0)
                {
                    throw InvalidState();
                }

                indexNames.Add((
                    reader.GetString(1),
                    reader.GetString(3)));
            }
        }

        foreach (var (name, origin) in indexNames)
        {
            var keyColumns = new List<string>();
            var auxiliaryRows = 0;
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                $"PRAGMA index_xinfo(\"{name}\");";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var columnId = reader.GetInt64(1);
                var descending = reader.GetInt64(3);
                var collation = reader.IsDBNull(4)
                    ? null
                    : reader.GetString(4);
                var isKey = reader.GetInt64(5) != 0;
                if (descending != 0
                    || !string.Equals(
                        collation,
                        "BINARY",
                        StringComparison.Ordinal))
                {
                    throw InvalidState();
                }

                if (isKey)
                {
                    if (columnId < 0 || reader.IsDBNull(2))
                    {
                        throw InvalidState();
                    }

                    keyColumns.Add(reader.GetString(2));
                }
                else
                {
                    if (columnId != -1 || !reader.IsDBNull(2))
                    {
                        throw InvalidState();
                    }

                    auxiliaryRows++;
                }
            }

            if (auxiliaryRows != 1)
            {
                throw InvalidState();
            }

            actual.Add(
                new IndexSignature(
                    origin,
                    [.. keyColumns]));
        }

        if (!actual.OrderBy(
                    static item => item.SortKey,
                    StringComparer.Ordinal)
                .Select(static item => item.SortKey)
                .SequenceEqual(
                    ExpectedIndexes(table).OrderBy(
                        static item => item.SortKey,
                        StringComparer.Ordinal)
                    .Select(static item => item.SortKey),
                    StringComparer.Ordinal))
        {
            throw InvalidState();
        }
    }

    private static void RequireExactForeignKeys(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table)
    {
        var actual = new List<ForeignKeySignature>();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"PRAGMA foreign_key_list(\"{table}\");";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (reader.GetInt64(1) != 0)
            {
                throw InvalidState();
            }

            actual.Add(
                new ForeignKeySignature(
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.GetString(6),
                    reader.GetString(7)));
        }

        if (!actual.SequenceEqual(ExpectedForeignKeys(table)))
        {
            throw InvalidState();
        }
    }

    private static IReadOnlyList<IndexSignature> ExpectedIndexes(
        string table) =>
        table switch
        {
            "source_receipts" =>
            [
                new("pk", ["receipt_id"]),
                new("u", ["receipt_sha256"]),
            ],
            "documents" =>
            [
                new("pk", ["document_id"]),
                new("u", ["content_sha256"]),
            ],
            "label_revisions" =>
            [
                new("pk", ["revision_id"]),
                new("u", ["revision_sha256"]),
            ],
            "approval_entries" =>
            [
                new("u", ["entry_id"]),
                new("u", ["entry_sha256"]),
            ],
            "checkpoints" =>
            [
                new("pk", ["checkpoint_id"]),
            ],
            _ => throw InvalidState(),
        };

    private static IReadOnlyList<ForeignKeySignature>
        ExpectedForeignKeys(string table) =>
        table switch
        {
            "documents" =>
            [
                new(
                    "source_receipts",
                    "receipt_id",
                    "receipt_id",
                    "NO ACTION",
                    "NO ACTION",
                    "NONE"),
            ],
            "label_revisions" =>
            [
                new(
                    "documents",
                    "document_id",
                    "document_id",
                    "NO ACTION",
                    "NO ACTION",
                    "NONE"),
            ],
            _ => [],
        };

    private static string ExtractSchemaStatement(string table)
    {
        var prefix = "CREATE TABLE IF NOT EXISTS " + table + " ";
        var start = SchemaSql.IndexOf(
            prefix,
            StringComparison.Ordinal);
        if (start < 0)
        {
            throw InvalidState();
        }

        var end = SchemaSql.IndexOf(';', start);
        if (end < 0)
        {
            throw InvalidState();
        }

        return SchemaSql[start..end].Replace(
            "CREATE TABLE IF NOT EXISTS",
            "CREATE TABLE",
            StringComparison.Ordinal);
    }

    private static string NormalizeSql(string sql)
    {
        var normalized = new System.Text.StringBuilder(sql.Length);
        var inSingleQuote = false;
        var inDoubleQuote = false;
        for (var index = 0; index < sql.Length; index++)
        {
            var character = sql[index];
            if (character == '\'' && !inDoubleQuote)
            {
                normalized.Append(character);
                if (inSingleQuote
                    && index + 1 < sql.Length
                    && sql[index + 1] == '\'')
                {
                    normalized.Append(sql[++index]);
                }
                else
                {
                    inSingleQuote = !inSingleQuote;
                }

                continue;
            }

            if (character == '"' && !inSingleQuote)
            {
                normalized.Append(character);
                if (inDoubleQuote
                    && index + 1 < sql.Length
                    && sql[index + 1] == '"')
                {
                    normalized.Append(sql[++index]);
                }
                else
                {
                    inDoubleQuote = !inDoubleQuote;
                }

                continue;
            }

            if (!inSingleQuote && !inDoubleQuote)
            {
                if (char.IsWhiteSpace(character)
                    || character == ';')
                {
                    continue;
                }

                normalized.Append(
                    char.ToLowerInvariant(character));
            }
            else
            {
                normalized.Append(character);
            }
        }

        return normalized.ToString();
    }

    private static void Execute(
        SqliteConnection connection,
        string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static void RequirePragma(
        SqliteConnection connection,
        string name,
        string expected)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA {name};";
        var actual = Convert.ToString(
            command.ExecuteScalar(),
            CultureInfo.InvariantCulture);
        if (!string.Equals(
                actual,
                expected,
                StringComparison.OrdinalIgnoreCase))
        {
            throw InvalidState();
        }
    }

    private static async Task RequirePragmaAsync(
        SqliteConnection connection,
        string name,
        string expected,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA {name};";
        var actual = Convert.ToString(
            await command.ExecuteScalarAsync(cancellationToken)
                .ConfigureAwait(false),
            CultureInfo.InvariantCulture);
        if (!string.Equals(
                actual,
                expected,
                StringComparison.OrdinalIgnoreCase))
        {
            throw InvalidState();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(
                nameof(CorpusWorkbenchStore));
        }
    }

    private void RevalidateDatabaseSet()
    {
        var lease = _databaseLease
            ?? throw new ObjectDisposedException(
                nameof(CorpusWorkbenchStore));
        _fileStore.RevalidateExisting(
            lease,
            "workbench.db");
        _fileStore.RevalidateDatabaseFileSet(
            "workbench.db");
    }

    private static ReviewDecisionCheckpoint
        ReadReviewDecisionCheckpoint(
        SqliteDataReader reader)
    {
        var checkpointId = reader.GetString(0);
        var persistedScope = reader.GetString(1);
        if (reader.GetValue(2) is not byte[] canonical)
        {
            throw InvalidState();
        }

        ReviewDecisionCheckpoint checkpoint;
        try
        {
            checkpoint = WorkbenchJson.Parse(
                canonical,
                WorkbenchJsonContext.Default
                    .ReviewDecisionCheckpoint);
        }
        catch (Exception exception) when (
            exception is System.Text.Json.JsonException
                or NotSupportedException)
        {
            throw InvalidState();
        }

        ValidateReviewDecisionCheckpoint(checkpoint);
        var expectedId = ReviewCheckpointId(
            checkpoint.ExpectedRevisionSha256,
            checkpoint.Decision == ReviewDecisionKind.Defer);
        var expectedScope = Convert.ToHexStringLower(
            SHA256.HashData(canonical));
        if (!string.Equals(
                checkpointId,
                expectedId,
                StringComparison.Ordinal)
            || !IsLowerSha256(persistedScope)
            || !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(persistedScope),
                Convert.FromHexString(expectedScope))
            || !CryptographicOperations.FixedTimeEquals(
                canonical,
                WorkbenchJson.Serialize(
                    checkpoint,
                    WorkbenchJsonContext.Default
                        .ReviewDecisionCheckpoint)))
        {
            throw InvalidState();
        }

        return checkpoint;
    }

    private static ReviewSampleProof ReadReviewSampleProof(
        SqliteDataReader reader)
    {
        var checkpointId = reader.GetString(0);
        var persistedScope = reader.GetString(1);
        if (reader.GetValue(2) is not byte[] canonical)
        {
            throw InvalidState();
        }

        ReviewSampleProof proof;
        try
        {
            proof = WorkbenchJson.Parse(
                canonical,
                WorkbenchJsonContext.Default.ReviewSampleProof);
            proof.ValidateCanonical();
        }
        catch (Exception exception) when (
            exception is System.Text.Json.JsonException
                or NotSupportedException
                or WorkbenchException)
        {
            throw InvalidState();
        }

        var expectedScope = Convert.ToHexStringLower(
            SHA256.HashData(canonical));
        if (!string.Equals(
                checkpointId,
                ReviewSampleCheckpointId(proof.MarketId),
                StringComparison.Ordinal)
            || !IsLowerSha256(persistedScope)
            || !FixedHashEquals(persistedScope, expectedScope)
            || !CryptographicOperations.FixedTimeEquals(
                canonical,
                WorkbenchJson.Serialize(
                    proof,
                    WorkbenchJsonContext.Default
                        .ReviewSampleProof)))
        {
            throw InvalidState();
        }

        return proof;
    }

    private static void ValidateReviewDecisionCheckpoint(
        ReviewDecisionCheckpoint? checkpoint)
    {
        if (checkpoint is null
            || checkpoint.SchemaVersion
                != PilotCatalog.SchemaVersion
            || checkpoint.DocumentId.Length != 73
            || !checkpoint.DocumentId.StartsWith(
                "document-",
                StringComparison.Ordinal)
            || checkpoint.DocumentId.AsSpan(9)
                .IndexOfAnyExcept(
                    "0123456789abcdef") >= 0
            || !IsLowerSha256(
                checkpoint.ExpectedRevisionSha256)
            || !IsLowerSha256(checkpoint.RequestSha256)
            || !IsLowerSha256(
                checkpoint.OutcomeRevisionSha256)
            || !Enum.IsDefined(checkpoint.Decision)
            || checkpoint.RecordedAtUtc.Offset
                != TimeSpan.Zero
            || checkpoint.RecordedAtUtc
                < new DateTimeOffset(
                    2020,
                    1,
                    1,
                    0,
                    0,
                    0,
                    TimeSpan.Zero)
            || checkpoint.RecordedAtUtc
                > DateTimeOffset.UtcNow.AddMinutes(5)
            || checkpoint.Decision == ReviewDecisionKind.Defer
                && !checkpoint.Completed)
        {
            throw InvalidState();
        }
    }

    private static string ReviewCheckpointId(
        string expectedRevisionSha256,
        bool isSchedule) =>
        (isSchedule
            ? "review-schedule-"
            : "review-decision-")
        + expectedRevisionSha256;

    private static string ReviewSampleCheckpointId(
        string marketId) =>
        "review-sample-" + marketId;

    private static void ValidateMarketId(string marketId)
    {
        if (!PilotCatalog.MarketIds.Contains(
                marketId,
                StringComparer.Ordinal))
        {
            throw InvalidState();
        }
    }

    private static bool FixedHashEquals(
        string left,
        string right) =>
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));

    private static void ValidateLowerSha256(string value)
    {
        if (!IsLowerSha256(value))
        {
            throw InvalidState();
        }
    }

    private static bool IsLowerSha256(string? value) =>
        value is not null
        && value.Length == 64
        && value.All(static character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static WorkbenchException InvalidState() =>
        new(WorkbenchFailureCode.InvalidState);
}

internal sealed record PersistedImport(
    WorkbenchDocument Document,
    bool WasExisting);

internal sealed record PersistedImportIdentity(
    WorkbenchDocument Document,
    string ReceiptSha256,
    byte[] CanonicalReceipt);

internal sealed record LabelDraftState(
    WorkbenchDocument Document,
    LabelRevision? PreviousRevision);

internal sealed class ImportCommitOwnership
{
    private int _transferred;

    internal bool IsTransferred =>
        Volatile.Read(ref _transferred) != 0;

    internal void Transfer() =>
        Volatile.Write(ref _transferred, 1);
}

internal sealed record TableColumn(
    int Ordinal,
    string Name,
    string Type,
    bool NotNull,
    object? DefaultValue,
    int PrimaryKeyOrder,
    int Hidden);

internal sealed record IndexSignature(
    string Origin,
    string[] Columns)
{
    internal string SortKey =>
        Origin + ":" + string.Join("\u001f", Columns);
}

internal sealed record ForeignKeySignature(
    string TargetTable,
    string FromColumn,
    string TargetColumn,
    string OnUpdate,
    string OnDelete,
    string Match);
