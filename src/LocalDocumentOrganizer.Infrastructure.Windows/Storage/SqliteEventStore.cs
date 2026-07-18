using LocalDocumentOrganizer.Core.Events;
using Microsoft.Data.Sqlite;
using System.Globalization;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public sealed class SqliteEventStore : IEventStore
{
    private readonly string _connectionString;
    private readonly EventSchemaRegistry _schemaRegistry;
    private readonly IReadOnlyList<ISqliteProjection> _projections;
    private readonly TimeProvider _timeProvider;

    public SqliteEventStore(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        IEnumerable<ISqliteProjection> projections,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(schemaRegistry);
        ArgumentNullException.ThrowIfNull(projections);

        var projectionSnapshot = projections.ToArray();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var projection in projectionSnapshot)
        {
            ArgumentNullException.ThrowIfNull(projection);
            if (string.IsNullOrWhiteSpace(projection.Name))
            {
                throw new ArgumentException("A stable projection name is required.", nameof(projections));
            }

            if (!names.Add(projection.Name))
            {
                throw new ArgumentException(
                    $"Projection name '{projection.Name}' is registered more than once.",
                    nameof(projections));
            }
        }

        _connectionString = connectionString;
        _schemaRegistry = schemaRegistry;
        _projections = projectionSnapshot
            .OrderBy(projection => projection.Name, StringComparer.Ordinal)
            .ToArray();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        SqliteEventStoreSchema.InitializeAsync(
            _connectionString, _projections, cancellationToken);

    public async Task<IReadOnlyList<StoredEvent>> ReadStreamAsync(
        StreamId streamId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString, cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT stream_version, event_id, event_type, schema_version, payload_json, recorded_at_utc
            FROM timeline_events
            WHERE stream_id = $stream_id
            ORDER BY stream_version;
            """;
        command.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));

        var events = new List<StoredEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(new StoredEvent(
                streamId,
                new StreamVersion(reader.GetInt64(0)),
                new EventId(Guid.Parse(reader.GetString(1))),
                reader.GetString(2),
                reader.GetInt32(3),
                reader.GetFieldValue<byte[]>(4),
                DateTimeOffset.Parse(
                    reader.GetString(5),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind)));
        }

        return events;
    }

    public async Task<AppendEventsResult> AppendAsync(
        AppendEventsCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ValidateAppendBatch(command.Events);

        SqliteConnection? connection = null;
        SqliteTransaction? transaction = null;
        try
        {
            connection = await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString, cancellationToken);
            transaction = connection.BeginTransaction(deferred: false);

            var newVersion = new StreamVersion(
                checked(command.ExpectedVersion.Value + command.Events.Count));
            var actualVersion = await ReserveStreamAsync(
                connection,
                transaction,
                command.StreamId,
                command.ExpectedVersion,
                newVersion,
                cancellationToken);
            if (actualVersion is not null)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new ConcurrencyConflict(command.ExpectedVersion, actualVersion.Value);
            }

            var streamVersion = command.ExpectedVersion;
            foreach (var eventToAppend in command.Events)
            {
                streamVersion = streamVersion.Next();
                var recordedAtUtc = _timeProvider.GetUtcNow();
                var globalPosition = await InsertEventAsync(
                    connection,
                    transaction,
                    command.StreamId,
                    streamVersion,
                    eventToAppend,
                    recordedAtUtc,
                    cancellationToken);
                var storedEvent = new StoredEvent(
                    command.StreamId,
                    streamVersion,
                    eventToAppend.EventId,
                    eventToAppend.EventType,
                    eventToAppend.SchemaVersion,
                    eventToAppend.Payload,
                    recordedAtUtc);
                foreach (var projection in _projections)
                {
                    await projection.ApplyAsync(
                        storedEvent,
                        globalPosition,
                        connection,
                        transaction,
                        cancellationToken);
                    await UpdateCheckpointAsync(
                        connection,
                        transaction,
                        projection.Name,
                        globalPosition,
                        cancellationToken);
                }
            }

            await transaction.CommitAsync(cancellationToken);
            return new Appended(newVersion);
        }
        catch (SqliteException exception) when (IsBusyOrLocked(exception))
        {
            if (transaction is not null)
            {
                await RollbackWithoutMaskingAsync(transaction);
            }

            return new StorageBusy();
        }
        catch
        {
            if (transaction is not null)
            {
                await RollbackWithoutMaskingAsync(transaction);
            }

            throw;
        }
        finally
        {
            if (transaction is not null)
            {
                await transaction.DisposeAsync();
            }

            if (connection is not null)
            {
                await connection.DisposeAsync();
            }
        }
    }

    private void ValidateAppendBatch(IReadOnlyList<EventToAppend> events)
    {
        var eventIds = new HashSet<Guid>();
        foreach (var eventToAppend in events)
        {
            if (!eventIds.Add(eventToAppend.EventId.Value))
            {
                throw new ArgumentException(
                    $"Event ID '{eventToAppend.EventId.Value:D}' occurs more than once in the batch.",
                    nameof(events));
            }

            var currentVersion = _schemaRegistry.GetCurrentVersion(eventToAppend.EventType);
            if (eventToAppend.SchemaVersion != currentVersion)
            {
                throw new ArgumentException(
                    $"Event type '{eventToAppend.EventType}' must be appended at current schema " +
                    $"version {currentVersion}, but version {eventToAppend.SchemaVersion} was supplied.",
                    nameof(events));
            }
        }
    }

    private static async Task<StreamVersion?> ReserveStreamAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        StreamId streamId,
        StreamVersion expectedVersion,
        StreamVersion newVersion,
        CancellationToken cancellationToken)
    {
        if (expectedVersion == StreamVersion.NoStream)
        {
            var existingHead = await ReadHeadAsync(
                connection, transaction, streamId, cancellationToken);
            if (existingHead is not null)
            {
                return existingHead;
            }

            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO event_streams(stream_id, head_version)
                VALUES ($stream_id, $head_version);
                """;
            insert.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
            insert.Parameters.AddWithValue("$head_version", newVersion.Value);
            await insert.ExecuteNonQueryAsync(cancellationToken);
            return null;
        }

        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE event_streams
            SET head_version = $new_head
            WHERE stream_id = $stream_id AND head_version = $expected_head;
            """;
        update.Parameters.AddWithValue("$new_head", newVersion.Value);
        update.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
        update.Parameters.AddWithValue("$expected_head", expectedVersion.Value);
        if (await update.ExecuteNonQueryAsync(cancellationToken) == 1)
        {
            return null;
        }

        return await ReadHeadAsync(connection, transaction, streamId, cancellationToken) ??
            StreamVersion.NoStream;
    }

    private static async Task<StreamVersion?> ReadHeadAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        StreamId streamId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT head_version FROM event_streams WHERE stream_id = $stream_id;";
        command.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is null ? null : new StreamVersion(Convert.ToInt64(result, CultureInfo.InvariantCulture));
    }

    private static async Task<long> InsertEventAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        StreamId streamId,
        StreamVersion streamVersion,
        EventToAppend eventToAppend,
        DateTimeOffset recordedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO timeline_events(
                event_id, stream_id, stream_version, event_type, schema_version,
                recorded_at_utc, payload_json)
            VALUES (
                $event_id, $stream_id, $stream_version, $event_type, $schema_version,
                $recorded_at_utc, $payload_json)
            RETURNING global_position;
            """;
        command.Parameters.AddWithValue("$event_id", eventToAppend.EventId.Value.ToString("D"));
        command.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
        command.Parameters.AddWithValue("$stream_version", streamVersion.Value);
        command.Parameters.AddWithValue("$event_type", eventToAppend.EventType);
        command.Parameters.AddWithValue("$schema_version", eventToAppend.SchemaVersion);
        command.Parameters.AddWithValue(
            "$recorded_at_utc",
            recordedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.Add("$payload_json", SqliteType.Blob).Value = eventToAppend.Payload.ToArray();
        return Convert.ToInt64(
            await command.ExecuteScalarAsync(cancellationToken),
            CultureInfo.InvariantCulture);
    }

    private static async Task UpdateCheckpointAsync(
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

    private static bool IsBusyOrLocked(SqliteException exception) =>
        exception.SqliteErrorCode is 5 or 6;

    private static async Task RollbackWithoutMaskingAsync(SqliteTransaction transaction)
    {
        try
        {
            await transaction.RollbackAsync();
        }
        catch
        {
            // Preserve the operation's original exception.
        }
    }
}
