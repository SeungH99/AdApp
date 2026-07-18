using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class SqliteProjectionCheckpointStore
{
    public static async Task ClearAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<ISqliteProjection> projections,
        CancellationToken cancellationToken)
    {
        foreach (var projection in projections)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                DELETE FROM projection_checkpoints
                WHERE projection_name = $projection_name;
                """;
            command.Parameters.AddWithValue("$projection_name", projection.Name);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public static async Task AdvanceAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string projectionName,
        long globalPosition,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO projection_checkpoints(projection_name, last_global_position)
            VALUES ($projection_name, $global_position)
            ON CONFLICT(projection_name) DO UPDATE SET
                last_global_position = excluded.last_global_position;
            """;
        command.Parameters.AddWithValue("$projection_name", projectionName);
        command.Parameters.AddWithValue("$global_position", globalPosition);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
