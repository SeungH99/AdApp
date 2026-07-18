using Microsoft.Data.Sqlite;
using System.Globalization;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class SqliteProjectionCheckpointStore
{
    public static async Task<(long RequiredGlobalPosition, IReadOnlyList<string> ProjectionNames)>
        FindRebuildRequirementAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            IReadOnlyList<ISqliteProjection> projections,
            CancellationToken cancellationToken)
    {
        await using var positionCommand = connection.CreateCommand();
        positionCommand.Transaction = transaction;
        positionCommand.CommandText =
            "SELECT COALESCE(MAX(global_position), 0) FROM timeline_events;";
        var requiredGlobalPosition = Convert.ToInt64(
            await positionCommand.ExecuteScalarAsync(cancellationToken),
            CultureInfo.InvariantCulture);

        var projectionNames = new List<string>();
        foreach (var projection in projections)
        {
            await using var checkpointCommand = connection.CreateCommand();
            checkpointCommand.Transaction = transaction;
            checkpointCommand.CommandText = """
                SELECT last_global_position
                FROM projection_checkpoints
                WHERE projection_name = $projection_name;
                """;
            checkpointCommand.Parameters.AddWithValue("$projection_name", projection.Name);
            var checkpoint = await checkpointCommand.ExecuteScalarAsync(cancellationToken);
            if (checkpoint is null)
            {
                if (requiredGlobalPosition != 0)
                {
                    projectionNames.Add(projection.Name);
                }

                continue;
            }

            if (Convert.ToInt64(checkpoint, CultureInfo.InvariantCulture) != requiredGlobalPosition)
            {
                projectionNames.Add(projection.Name);
            }
        }

        return (requiredGlobalPosition, projectionNames);
    }

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
