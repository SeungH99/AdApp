using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class SqliteEventStoreSchema
{
    private const int CurrentVersion = 2;
    private static readonly string[] RequiredEventColumns =
    [
        "global_position", "event_id", "stream_id", "stream_version", "event_type",
        "schema_version", "recorded_at_utc", "operation_id", "protection_kind",
        "owner_kind", "owner_id", "key_id", "envelope_version", "payload_nonce",
        "payload_ciphertext", "payload_tag",
    ];

    private const string VersionTwoSql = """
        CREATE TABLE event_streams(
            stream_id TEXT PRIMARY KEY CHECK(stream_id <> '00000000-0000-0000-0000-000000000000' AND length(stream_id) = 36 AND stream_id = lower(stream_id) AND substr(stream_id,9,1)='-' AND substr(stream_id,14,1)='-' AND substr(stream_id,19,1)='-' AND substr(stream_id,24,1)='-' AND length(replace(stream_id,'-','')) = 32 AND replace(stream_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            head_version INTEGER NOT NULL CHECK(head_version >= 0)
        ) STRICT;
        CREATE TABLE timeline_events(
            global_position INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL CHECK(event_id <> '00000000-0000-0000-0000-000000000000' AND length(event_id) = 36 AND event_id = lower(event_id) AND substr(event_id,9,1)='-' AND substr(event_id,14,1)='-' AND substr(event_id,19,1)='-' AND substr(event_id,24,1)='-' AND length(replace(event_id,'-','')) = 32 AND replace(event_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_id TEXT NOT NULL CHECK(stream_id <> '00000000-0000-0000-0000-000000000000' AND length(stream_id) = 36 AND stream_id = lower(stream_id) AND substr(stream_id,9,1)='-' AND substr(stream_id,14,1)='-' AND substr(stream_id,19,1)='-' AND substr(stream_id,24,1)='-' AND length(replace(stream_id,'-','')) = 32 AND replace(stream_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_version INTEGER NOT NULL CHECK(stream_version >= 0),
            event_type TEXT NOT NULL CHECK(length(event_type) > 0),
            schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
            recorded_at_utc TEXT NOT NULL CHECK(length(recorded_at_utc) > 0),
            operation_id TEXT NOT NULL CHECK(operation_id <> '00000000-0000-0000-0000-000000000000' AND length(operation_id) = 36 AND operation_id = lower(operation_id) AND substr(operation_id,9,1)='-' AND substr(operation_id,14,1)='-' AND substr(operation_id,19,1)='-' AND substr(operation_id,24,1)='-' AND length(replace(operation_id,'-','')) = 32 AND replace(operation_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            protection_kind INTEGER NOT NULL CHECK(protection_kind IN (0, 1)),
            owner_kind INTEGER,
            owner_id TEXT,
            key_id TEXT,
            envelope_version INTEGER NOT NULL,
            payload_nonce BLOB,
            payload_ciphertext BLOB NOT NULL CHECK(typeof(payload_ciphertext) = 'blob'),
            payload_tag BLOB,
            UNIQUE(stream_id, stream_version),
            FOREIGN KEY(stream_id) REFERENCES event_streams(stream_id),
            CHECK(
                (protection_kind = 0
                    AND owner_kind IS NULL AND owner_id IS NULL AND key_id IS NULL
                    AND envelope_version = 0 AND payload_nonce IS NULL AND payload_tag IS NULL)
                OR
                (protection_kind = 1
                    AND owner_kind IN (0, 1, 2, 3) AND owner_id IS NOT NULL AND key_id IS NOT NULL
                    AND owner_id <> '00000000-0000-0000-0000-000000000000' AND length(owner_id) = 36 AND owner_id = lower(owner_id) AND substr(owner_id,9,1)='-' AND substr(owner_id,14,1)='-' AND substr(owner_id,19,1)='-' AND substr(owner_id,24,1)='-' AND length(replace(owner_id,'-','')) = 32 AND replace(owner_id,'-','') NOT GLOB '*[^0-9a-f]*'
                    AND key_id <> '00000000-0000-0000-0000-000000000000' AND length(key_id) = 36 AND key_id = lower(key_id) AND substr(key_id,9,1)='-' AND substr(key_id,14,1)='-' AND substr(key_id,19,1)='-' AND substr(key_id,24,1)='-' AND length(replace(key_id,'-','')) = 32 AND replace(key_id,'-','') NOT GLOB '*[^0-9a-f]*'
                    AND envelope_version = 1
                    AND payload_nonce IS NOT NULL AND typeof(payload_nonce) = 'blob' AND length(payload_nonce) = 12
                    AND payload_tag IS NOT NULL AND typeof(payload_tag) = 'blob' AND length(payload_tag) = 16)
            )
        ) STRICT;
        CREATE INDEX timeline_events_operation_position
            ON timeline_events(operation_id, global_position);
        CREATE TABLE projection_checkpoints(
            projection_name TEXT PRIMARY KEY,
            last_global_position INTEGER NOT NULL CHECK(last_global_position >= 0)
        ) STRICT;
        CREATE TRIGGER timeline_events_immutable_update
        BEFORE UPDATE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TRIGGER timeline_events_immutable_delete
        BEFORE DELETE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        PRAGMA user_version = 2;
        """;

    public static async Task InitializeAsync(
        string connectionString,
        IReadOnlyList<ISqliteProjection> projections,
        VaultKeyRingStore keyRing,
        CancellationToken cancellationToken)
    {
        ValidateConnectionString(connectionString);
        await using var firstLease = await keyRing.MaintenanceGate.AcquireAsync(cancellationToken);
        var inspection = await InspectBeforeMutationAsync(connectionString, cancellationToken);
        if (inspection.Kind == VaultSchemaKind.LegacyNonEmpty)
        {
            throw new LegacyPlaintextVaultRecoveryRequiredException();
        }

        if (inspection.Kind is VaultSchemaKind.Unknown or VaultSchemaKind.Malformed)
        {
            throw new VaultRecoveryRequiredException();
        }

        await firstLease.DisposeAsync();
        VaultKeyRing ring;
        if (inspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1)
        {
            try
            {
                try { ring = await keyRing.CreateAsync(cancellationToken); }
                catch (VaultKeyRingPersistenceException) { ring = await keyRing.OpenAsync(cancellationToken); }
            }
            catch (VaultKeyRingException exception)
            {
                throw new VaultRecoveryRequiredException(exception);
            }
            if (ring.ActiveKeys.Count != 0 || ring.DestroyedReceipts.Count != 0) throw new VaultRecoveryRequiredException();
        }
        else
        {
            try { ring = await keyRing.OpenAsync(cancellationToken); }
            catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
        }

        await using var lease = await keyRing.MaintenanceGate.AcquireAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(connectionString, cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        try
        {
            var finalInspection = await InspectInsideTransactionAsync(connection, transaction, cancellationToken);
            if (finalInspection.Kind is VaultSchemaKind.Unknown or VaultSchemaKind.Malformed or VaultSchemaKind.LegacyNonEmpty)
                throw new VaultRecoveryRequiredException();
            if (finalInspection.Kind == VaultSchemaKind.EmptyV1)
            {
                await DropApplicationTablesAsync(connection, transaction, cancellationToken);
            }

            if (finalInspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1)
            {
                await ExecuteNonQueryAsync(connection, transaction, VersionTwoSql, cancellationToken);
            }
            else
            {
                await ValidateExistingVersionTwoAsync(connection, transaction, cancellationToken);
            }

            foreach (var projection in projections)
            {
                await projection.InitializeAsync(connection, transaction, cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await RollbackWithoutMaskingAsync(transaction);
            throw;
        }
    }

    public static async Task<SqliteConnection> OpenConnectionAsync(
        string connectionString,
        CancellationToken cancellationToken)
    {
        ValidateConnectionString(connectionString);
        var connection = new SqliteConnection(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            await RequirePragmaAsync(connection, "foreign_keys = ON", "foreign_keys", "1", cancellationToken);
            await RequirePragmaAsync(connection, "secure_delete = ON", "secure_delete", "1", cancellationToken);
            var builder = new SqliteConnectionStringBuilder(connectionString);
            if (builder.Mode != SqliteOpenMode.Memory && !string.Equals(builder.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase))
            {
                await RequirePragmaAsync(connection, "journal_mode = WAL", "journal_mode", "wal", cancellationToken);
            }

            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private static async Task<VaultSchemaInspection> InspectBeforeMutationAsync(string connectionString, CancellationToken cancellationToken)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        if (builder.Mode == SqliteOpenMode.Memory || string.Equals(builder.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            return new VaultSchemaInspection(VaultSchemaKind.New);
        }

        if (!File.Exists(builder.DataSource)) return new VaultSchemaInspection(VaultSchemaKind.New);
        builder.Mode = SqliteOpenMode.ReadOnly;
        await using var connection = new SqliteConnection(builder.ToString());
        await connection.OpenAsync(cancellationToken);
        var version = Convert.ToInt32(await ExecuteScalarAsync(connection, null, "PRAGMA user_version;", cancellationToken));
        var tables = await ReadApplicationTablesAsync(connection, null, cancellationToken);
        if (version == 0 && tables.Count == 0) return new VaultSchemaInspection(VaultSchemaKind.New);
        if (version == 1) return new VaultSchemaInspection(await AreAllTablesEmptyAsync(connection, tables, cancellationToken)
            ? VaultSchemaKind.EmptyV1 : VaultSchemaKind.LegacyNonEmpty);
        if (version == 2) return new VaultSchemaInspection(VaultSchemaKind.V2);
        return new VaultSchemaInspection(version > 2 || version < 0 ? VaultSchemaKind.Unknown : VaultSchemaKind.Malformed);
    }

    private static async Task<VaultSchemaInspection> InspectInsideTransactionAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        var version = Convert.ToInt32(await ExecuteScalarAsync(connection, transaction, "PRAGMA user_version;", cancellationToken));
        var tables = await ReadApplicationTablesAsync(connection, transaction, cancellationToken);
        if (version == 0 && tables.Count == 0) return new VaultSchemaInspection(VaultSchemaKind.New);
        if (version == 1)
        {
            foreach (var table in tables)
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = $"SELECT EXISTS(SELECT 1 FROM \"{table.Replace("\"", "\"\"")}\" LIMIT 1);";
                if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) != 0) return new VaultSchemaInspection(VaultSchemaKind.LegacyNonEmpty);
            }
            return new VaultSchemaInspection(VaultSchemaKind.EmptyV1);
        }
        return version == 2 ? new VaultSchemaInspection(VaultSchemaKind.V2) : new VaultSchemaInspection(VaultSchemaKind.Unknown);
    }

    internal static async Task ValidateExistingVersionTwoAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        var version = Convert.ToInt32(await ExecuteScalarAsync(connection, transaction, "PRAGMA user_version;", cancellationToken));
        if (version != CurrentVersion) throw new VaultRecoveryRequiredException();
        var columns = new HashSet<string>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "PRAGMA table_info(timeline_events);";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) columns.Add(reader.GetString(1));
        }
        if (columns.Contains("payload_json") || !RequiredEventColumns.All(columns.Contains)) throw new VaultRecoveryRequiredException();
        var master = await ReadMasterSqlAsync(connection, transaction, cancellationToken);
        if (!master.Contains("timeline_events_operation_position", StringComparison.Ordinal)
            || !master.Contains("timeline_events_immutable_update", StringComparison.Ordinal)
            || !master.Contains("timeline_events_immutable_delete", StringComparison.Ordinal)
            || !master.Contains("STRICT", StringComparison.OrdinalIgnoreCase)) throw new VaultRecoveryRequiredException();
    }

    private static async Task DropApplicationTablesAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        var tables = await ReadApplicationTablesAsync(connection, transaction, cancellationToken);
        foreach (var table in tables)
        {
            await ExecuteNonQueryAsync(connection, transaction, $"DROP TABLE IF EXISTS \"{table.Replace("\"", "\"\"")}\";", cancellationToken);
        }
    }

    private static async Task<List<string>> ReadApplicationTablesAsync(SqliteConnection connection, SqliteTransaction? transaction, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name;";
        var tables = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) tables.Add(reader.GetString(0));
        return tables;
    }

    private static async Task<bool> AreAllTablesEmptyAsync(SqliteConnection connection, IReadOnlyList<string> tables, CancellationToken cancellationToken)
    {
        foreach (var table in tables)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT EXISTS(SELECT 1 FROM \"{table.Replace("\"", "\"\"")}\" LIMIT 1);";
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) != 0) return false;
        }
        return true;
    }

    private static async Task<string> ReadMasterSqlAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT group_concat(sql, '\n') FROM sqlite_master WHERE name LIKE 'timeline_events%' OR name = 'event_streams';";
        return Convert.ToString(await command.ExecuteScalarAsync(cancellationToken)) ?? string.Empty;
    }

    private static void ValidateConnectionString(string connectionString)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        if (builder.Cache == SqliteCacheMode.Shared) throw new VaultRecoveryRequiredException();
    }

    private static async Task RequirePragmaAsync(SqliteConnection connection, string set, string query, string expected, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA {set};";
        await command.ExecuteNonQueryAsync(cancellationToken);
        command.CommandText = $"PRAGMA {query};";
        var result = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken));
        if (!string.Equals(result, expected, StringComparison.OrdinalIgnoreCase)) throw new VaultRecoveryRequiredException();
    }

    private static async Task ExecuteNonQueryAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
    private static async Task<object?> ExecuteScalarAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql;
        return await command.ExecuteScalarAsync(cancellationToken);
    }
    private static async Task RollbackWithoutMaskingAsync(SqliteTransaction transaction) { try { await transaction.RollbackAsync(); } catch { } }
    private enum VaultSchemaKind { New, EmptyV1, LegacyNonEmpty, V2, Unknown, Malformed }
    private sealed record VaultSchemaInspection(VaultSchemaKind Kind);
}
