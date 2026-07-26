using System.Globalization;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
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
    private SafeFileHandle? _databaseLease;
    private int _disposed;

    internal CorpusWorkbenchStore(
        ApprovedRootFileStore fileStore,
        string databasePath)
    {
        ArgumentNullException.ThrowIfNull(fileStore);
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        _fileStore = fileStore;
        _databasePath = Path.GetFullPath(databasePath);
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

    internal async Task<WorkbenchDocument?> FindDocumentAsync(
        string contentSha256,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        var result = await ReadDocumentAsync(
                connection,
                transaction: null,
                contentSha256,
                cancellationToken)
            .ConfigureAwait(false);
        RevalidateDatabase();
        return result;
    }

    internal async Task<PersistedImport> PersistImportAsync(
        SourceReceipt receipt,
        byte[] canonicalReceipt,
        string receiptSha256,
        string inputKind,
        string? codecId,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(canonicalReceipt);
        await using var connection =
            await OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);
        await using var transaction =
            connection.BeginTransaction(deferred: false);
        var committed = false;
        try
        {
            var existing = await ReadDocumentAsync(
                    connection,
                    transaction,
                    receipt.ExpectedContentSha256,
                    cancellationToken)
                .ConfigureAwait(false);
            if (existing is not null)
            {
                await transaction.CommitAsync(cancellationToken)
                    .ConfigureAwait(false);
                committed = true;
                RevalidateDatabase();
                return new PersistedImport(existing, WasExisting: true);
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

            await transaction.CommitAsync(cancellationToken)
                .ConfigureAwait(false);
            committed = true;
            RevalidateDatabase();
            return new PersistedImport(document, WasExisting: false);
        }
        catch
        {
            if (!committed)
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
        RevalidateDatabase();
        using var connection = CreateConnection();
        connection.Open();
        ConfigureConnection(connection);
        RequirePragma(connection, "journal_mode", "wal");

        using var transaction =
            connection.BeginTransaction(deferred: false);
        try
        {
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = SchemaSql;
                command.ExecuteNonQuery();
            }

            ValidateSchema(connection, transaction);
            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }

        ValidateSchema(connection, transaction: null);
        RevalidateDatabase();
    }

    private async Task<SqliteConnection> OpenConnectionAsync(
        CancellationToken cancellationToken)
    {
        RevalidateDatabase();
        var connection = CreateConnection();
        try
        {
            await connection.OpenAsync(cancellationToken)
                .ConfigureAwait(false);
            await ConfigureConnectionAsync(
                    connection,
                    cancellationToken)
                .ConfigureAwait(false);
            RevalidateDatabase();
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

    private static async Task<WorkbenchDocument?> ReadDocumentAsync(
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
              receipt_id,
              lifecycle_state,
              created_at_utc
            FROM documents
            WHERE content_sha256=$content_sha256;
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
        if (await reader.ReadAsync(cancellationToken)
                .ConfigureAwait(false))
        {
            throw InvalidState();
        }

        return document;
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
                  AND name NOT LIKE 'sqlite_%'
                ORDER BY name;
                """;
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                tableNames.Add(reader.GetString(0));
            }
        }

        if (!tableNames.SequenceEqual(
                Columns.Keys.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw InvalidState();
        }

        foreach (var (table, expectedColumns) in Columns)
        {
            var actualColumns = new List<string>();
            var actualTypes = new List<string>();
            var actualNotNull = new List<bool>();
            var actualPrimaryKeys = new List<int>();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                $"PRAGMA table_info(\"{table}\");";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                actualColumns.Add(reader.GetString(1));
                actualTypes.Add(reader.GetString(2));
                actualNotNull.Add(reader.GetInt64(3) != 0);
                actualPrimaryKeys.Add(
                    checked((int)reader.GetInt64(5)));
            }

            if (!actualColumns.SequenceEqual(
                    expectedColumns,
                    StringComparer.Ordinal)
                || !actualTypes.SequenceEqual(
                    Types[table],
                    StringComparer.OrdinalIgnoreCase))
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
                if (actualNotNull[index] != expectedNotNull
                    || actualPrimaryKeys[index]
                        != (isPrimaryKey ? 1 : 0))
                {
                    throw InvalidState();
                }
            }
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

        RequireUniqueColumn(
            connection,
            transaction,
            "source_receipts",
            "receipt_sha256");
        RequireUniqueColumn(
            connection,
            transaction,
            "documents",
            "content_sha256");
        RequireUniqueColumn(
            connection,
            transaction,
            "label_revisions",
            "revision_sha256");
        RequireUniqueColumn(
            connection,
            transaction,
            "approval_entries",
            "entry_id");
        RequireUniqueColumn(
            connection,
            transaction,
            "approval_entries",
            "entry_sha256");
        RequireForeignKey(
            connection,
            transaction,
            "documents",
            "receipt_id",
            "source_receipts",
            "receipt_id");
        RequireForeignKey(
            connection,
            transaction,
            "label_revisions",
            "document_id",
            "documents",
            "document_id");

        using var unexpected = connection.CreateCommand();
        unexpected.Transaction = transaction;
        unexpected.CommandText = """
            SELECT COUNT(*)
            FROM sqlite_schema
            WHERE type IN ('trigger', 'view');
            """;
        if (Convert.ToInt64(
                unexpected.ExecuteScalar(),
                CultureInfo.InvariantCulture)
            != 0)
        {
            throw InvalidState();
        }
    }

    private static void RequireUniqueColumn(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table,
        string column)
    {
        var found = false;
        var indexes = new List<string>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                $"PRAGMA index_list(\"{table}\");";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                if (reader.GetInt64(2) == 1)
                {
                    indexes.Add(reader.GetString(1));
                }
            }
        }

        foreach (var index in indexes)
        {
            var columns = new List<string>();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                $"PRAGMA index_info(\"{index}\");";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                columns.Add(reader.GetString(2));
            }

            found |= columns.Count == 1
                && string.Equals(
                    columns[0],
                    column,
                    StringComparison.Ordinal);
        }

        if (!found)
        {
            throw InvalidState();
        }
    }

    private static void RequireForeignKey(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table,
        string fromColumn,
        string targetTable,
        string targetColumn)
    {
        var found = false;
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            $"PRAGMA foreign_key_list(\"{table}\");";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            found |= string.Equals(
                    reader.GetString(2),
                    targetTable,
                    StringComparison.Ordinal)
                && string.Equals(
                    reader.GetString(3),
                    fromColumn,
                    StringComparison.Ordinal)
                && string.Equals(
                    reader.GetString(4),
                    targetColumn,
                    StringComparison.Ordinal);
        }

        if (!found)
        {
            throw InvalidState();
        }
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

    private void RevalidateDatabase()
    {
        var lease = _databaseLease
            ?? throw new ObjectDisposedException(
                nameof(CorpusWorkbenchStore));
        _fileStore.RevalidateExisting(
            lease,
            "workbench.db");
    }

    private static WorkbenchException InvalidState() =>
        new(WorkbenchFailureCode.InvalidState);
}

internal sealed record PersistedImport(
    WorkbenchDocument Document,
    bool WasExisting);
