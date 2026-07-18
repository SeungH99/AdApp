using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class SqliteEventStoreSchema
{
    private const int CurrentVersion = 1;
    private const string VersionOneSql = """
        CREATE TABLE IF NOT EXISTS event_streams(
            stream_id TEXT PRIMARY KEY,
            head_version INTEGER NOT NULL CHECK(head_version >= 0)
        );
        CREATE TABLE IF NOT EXISTS timeline_events(
            global_position INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            stream_id TEXT NOT NULL,
            stream_version INTEGER NOT NULL CHECK(stream_version >= 0),
            event_type TEXT NOT NULL,
            schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
            recorded_at_utc TEXT NOT NULL,
            payload_json BLOB NOT NULL,
            UNIQUE(stream_id, stream_version),
            FOREIGN KEY(stream_id) REFERENCES event_streams(stream_id)
        );
        CREATE TABLE IF NOT EXISTS projection_checkpoints(
            projection_name TEXT PRIMARY KEY,
            last_global_position INTEGER NOT NULL CHECK(last_global_position >= 0)
        );
        CREATE TRIGGER IF NOT EXISTS timeline_events_immutable_update
        BEFORE UPDATE ON timeline_events
        BEGIN
            SELECT RAISE(ABORT, 'timeline_events is immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS timeline_events_immutable_delete
        BEFORE DELETE ON timeline_events
        BEGIN
            SELECT RAISE(ABORT, 'timeline_events is immutable');
        END;
        PRAGMA user_version = 1;
        """;

    private const string OperationIdMappingSql = """
        CREATE TABLE IF NOT EXISTS event_operation_ids(
            event_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES timeline_events(event_id)
        );
        CREATE TRIGGER IF NOT EXISTS event_operation_ids_immutable_update
        BEFORE UPDATE ON event_operation_ids
        BEGIN
            SELECT RAISE(ABORT, 'event_operation_ids is immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS event_operation_ids_immutable_delete
        BEFORE DELETE ON event_operation_ids
        BEGIN
            SELECT RAISE(ABORT, 'event_operation_ids is immutable');
        END;
        """;

    public static async Task InitializeAsync(
        string connectionString,
        IReadOnlyList<ISqliteProjection> projections,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(connectionString, cancellationToken);
        var builder = new SqliteConnectionStringBuilder(connectionString);
        if (builder.Mode != SqliteOpenMode.Memory &&
            !string.Equals(builder.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            await ExecuteNonQueryAsync(
                connection, null, "PRAGMA journal_mode = WAL;", cancellationToken);
        }

        await using var transaction = connection.BeginTransaction(deferred: false);
        try
        {
            var version = Convert.ToInt32(
                await ExecuteScalarAsync(
                    connection,
                    transaction,
                    "PRAGMA user_version;",
                    cancellationToken));
            if (version > CurrentVersion)
            {
                throw new InvalidOperationException(
                    $"Database schema version {version} is newer than supported version {CurrentVersion}.");
            }

            if (version < CurrentVersion)
            {
                await ExecuteNonQueryAsync(connection, transaction, VersionOneSql, cancellationToken);
            }

            await ExecuteNonQueryAsync(
                connection,
                transaction,
                OperationIdMappingSql,
                cancellationToken);

            foreach (var projection in projections)
            {
                await projection.InitializeAsync(connection, transaction, cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            try
            {
                await transaction.RollbackAsync();
            }
            catch
            {
                // Preserve the initialization failure.
            }

            throw;
        }
    }

    public static async Task<SqliteConnection> OpenConnectionAsync(
        string connectionString,
        CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            await ExecuteNonQueryAsync(
                connection, null, "PRAGMA foreign_keys = ON;", cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private static async Task<int> ExecuteNonQueryAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string commandText,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = commandText;
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<object?> ExecuteScalarAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string commandText,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = commandText;
        return await command.ExecuteScalarAsync(cancellationToken);
    }
}
