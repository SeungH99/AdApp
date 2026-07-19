using Microsoft.Data.Sqlite;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class SqliteProjectionCheckpointStore
{
    internal static async Task ValidateMembershipAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<SqliteProjectionRegistration> projections,
        CancellationToken cancellationToken)
    {
        var registered = projections
            .Select(projection => projection.Name)
            .ToHashSet(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT projection_name
            FROM main.projection_checkpoints
            ORDER BY projection_name COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.GetValue(0) is not string name || !registered.Contains(name))
                throw new VaultRecoveryRequiredException();
        }
    }

    public static async Task<(long RequiredGlobalPosition, IReadOnlyList<string> ProjectionNames)>
        FindRebuildRequirementAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            IReadOnlyList<SqliteProjectionRegistration> projections,
            CancellationToken cancellationToken)
    {
        await using var positionCommand = connection.CreateCommand();
        positionCommand.Transaction = transaction;
        positionCommand.CommandText =
            "SELECT COALESCE(MAX(global_position), 0) FROM main.timeline_events;";
        if (await positionCommand.ExecuteScalarAsync(cancellationToken) is not long requiredGlobalPosition
            || requiredGlobalPosition < 0)
        {
            throw new VaultRecoveryRequiredException();
        }

        var registeredNames = projections
            .Select(projection => projection.Name)
            .ToHashSet(StringComparer.Ordinal);
        var checkpoints = new Dictionary<string, (int SchemaVersion, int EncryptionVersion, long Position)>(
            StringComparer.Ordinal);
        await using (var allCommand = connection.CreateCommand())
        {
            allCommand.Transaction = transaction;
            allCommand.CommandText = """
                SELECT projection_name, projection_schema_version, encryption_version, last_global_position
                FROM main.projection_checkpoints
                ORDER BY projection_name COLLATE BINARY;
                """;
            await using var reader = await allCommand.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (reader.GetValue(0) is not string name
                    || string.IsNullOrWhiteSpace(name)
                    || reader.GetValue(1) is not long rawSchema
                    || rawSchema is <= 0 or > int.MaxValue
                    || reader.GetValue(2) is not long rawEncryption
                    || rawEncryption is <= 0 or > int.MaxValue
                    || reader.GetValue(3) is not long position
                    || position < 0
                    || !registeredNames.Contains(name)
                    || !checkpoints.TryAdd(
                        name,
                        (checked((int)rawSchema), checked((int)rawEncryption), position)))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
        }

        var projectionNames = new List<string>();
        foreach (var projection in projections)
        {
            if (!checkpoints.TryGetValue(projection.Name, out var checkpoint))
            {
                if (requiredGlobalPosition != 0)
                {
                    projectionNames.Add(projection.Name);
                }

                continue;
            }

            if (checkpoint.SchemaVersion != projection.SchemaVersion
                || checkpoint.EncryptionVersion != projection.EncryptionVersion
                || checkpoint.Position != requiredGlobalPosition)
            {
                projectionNames.Add(projection.Name);
            }
        }

        return (requiredGlobalPosition, projectionNames);
    }

    public static async Task ClearAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<SqliteProjectionRegistration> projections,
        CancellationToken cancellationToken)
    {
        foreach (var projection in projections)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                DELETE FROM main.projection_checkpoints
                WHERE projection_name = $projection_name;
                """;
            command.Parameters.AddWithValue("$projection_name", projection.Name);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public static async Task AdvanceAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SqliteProjectionRegistration projection,
        long globalPosition,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO main.projection_checkpoints(
                projection_name, projection_schema_version, encryption_version, last_global_position)
            VALUES ($projection_name, $projection_schema_version, $encryption_version, $global_position)
            ON CONFLICT(projection_name) DO UPDATE SET
                projection_schema_version = excluded.projection_schema_version,
                encryption_version = excluded.encryption_version,
                last_global_position = excluded.last_global_position;
            """;
        command.Parameters.AddWithValue("$projection_name", projection.Name);
        command.Parameters.AddWithValue("$projection_schema_version", projection.SchemaVersion);
        command.Parameters.AddWithValue("$encryption_version", projection.EncryptionVersion);
        command.Parameters.AddWithValue("$global_position", globalPosition);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
