using LocalDocumentOrganizer.Core.Events;
using Microsoft.Data.Sqlite;
using System.Globalization;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal sealed class SqliteProjectionRebuilder
{
    private const int BatchSize = 256;

    private readonly string _connectionString;
    private readonly EventSchemaRegistry _schemaRegistry;
    private readonly IReadOnlyList<ISqliteProjection> _projections;

    public SqliteProjectionRebuilder(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        IReadOnlyList<ISqliteProjection> projections)
    {
        _connectionString = connectionString;
        _schemaRegistry = schemaRegistry;
        _projections = projections;
    }

    public async Task<ProjectionRebuildResult> RebuildAsync(
        CancellationToken cancellationToken)
    {
        SqliteConnection? connection = null;
        SqliteTransaction? transaction = null;
        try
        {
            connection = await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString,
                cancellationToken);
            transaction = connection.BeginTransaction(deferred: false);

            foreach (var projection in _projections)
            {
                await projection.ResetAsync(connection, transaction, cancellationToken);
            }

            await SqliteProjectionCheckpointStore.ClearAsync(
                connection,
                transaction,
                _projections,
                cancellationToken);

            var streamHeads = new Dictionary<StreamId, StreamVersion>();
            long totalEventCount = 0;
            long lastGlobalPosition = 0;
            while (true)
            {
                var batch = await ReadBatchAsync(
                    connection,
                    transaction,
                    lastGlobalPosition,
                    cancellationToken);
                if (batch.Count == 0)
                {
                    break;
                }

                foreach (var rawEvent in batch)
                {
                    ValidateAndAdvanceHead(streamHeads, rawEvent.StoredEvent);
                    var currentEvent = Upcast(rawEvent.StoredEvent);
                    foreach (var projection in _projections)
                    {
                        await projection.ApplyAsync(
                            currentEvent,
                            rawEvent.GlobalPosition,
                            connection,
                            transaction,
                            cancellationToken);
                        await SqliteProjectionCheckpointStore.AdvanceAsync(
                            connection,
                            transaction,
                            projection.Name,
                            rawEvent.GlobalPosition,
                            cancellationToken);
                    }

                    totalEventCount = checked(totalEventCount + 1);
                    lastGlobalPosition = rawEvent.GlobalPosition;
                }
            }

            await ValidateStreamHeadsAsync(
                connection,
                transaction,
                streamHeads,
                cancellationToken);

            var checksums = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var projection in _projections)
            {
                var checksum = await projection.CalculateChecksumAsync(
                    connection,
                    transaction,
                    cancellationToken);
                if (!IsValidChecksum(checksum))
                {
                    throw new InvalidProjectionChecksumException(projection.Name, checksum);
                }

                checksums.Add(projection.Name, checksum);
            }

            await transaction.CommitAsync(cancellationToken);
            return new ProjectionRebuildResult(totalEventCount, streamHeads, checksums);
        }
        catch (SqliteException exception) when (IsBusyOrLocked(exception))
        {
            if (transaction is not null)
            {
                await RollbackWithoutMaskingAsync(transaction);
            }

            throw new StorageBusyException(
                "Projection rebuild could not acquire the SQLite write lock.",
                exception);
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

    private StoredEvent Upcast(StoredEvent rawEvent) =>
        new(
            rawEvent.StreamId,
            rawEvent.StreamVersion,
            rawEvent.EventId,
            rawEvent.EventType,
            _schemaRegistry.GetCurrentVersion(rawEvent.EventType),
            _schemaRegistry.UpcastToCurrent(rawEvent),
            rawEvent.RecordedAtUtc);

    private static void ValidateAndAdvanceHead(
        IDictionary<StreamId, StreamVersion> streamHeads,
        StoredEvent storedEvent)
    {
        var expectedVersion = streamHeads.TryGetValue(storedEvent.StreamId, out var head)
            ? head.Next()
            : new StreamVersion(0);
        if (storedEvent.StreamVersion != expectedVersion)
        {
            throw new EventStreamCorruptionException(
                $"Stream '{storedEvent.StreamId.Value:D}' expected event version " +
                $"{expectedVersion.Value}, but found {storedEvent.StreamVersion.Value}.");
        }

        streamHeads[storedEvent.StreamId] = storedEvent.StreamVersion;
    }

    private static async Task<IReadOnlyList<RawTimelineEvent>> ReadBatchAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        long afterGlobalPosition,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT global_position, stream_id, stream_version, event_id, event_type,
                   schema_version, payload_json, recorded_at_utc
            FROM timeline_events
            WHERE global_position > $after_global_position
            ORDER BY global_position ASC
            LIMIT $batch_size;
            """;
        command.Parameters.AddWithValue("$after_global_position", afterGlobalPosition);
        command.Parameters.AddWithValue("$batch_size", BatchSize);

        var batch = new List<RawTimelineEvent>(BatchSize);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            batch.Add(new RawTimelineEvent(
                reader.GetInt64(0),
                new StoredEvent(
                    new StreamId(Guid.Parse(reader.GetString(1))),
                    new StreamVersion(reader.GetInt64(2)),
                    new EventId(Guid.Parse(reader.GetString(3))),
                    reader.GetString(4),
                    reader.GetInt32(5),
                    reader.GetFieldValue<byte[]>(6),
                    DateTimeOffset.Parse(
                        reader.GetString(7),
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind))));
        }

        return batch;
    }

    private static async Task ValidateStreamHeadsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyDictionary<StreamId, StreamVersion> computedHeads,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT stream_id, head_version
            FROM event_streams
            ORDER BY stream_id COLLATE BINARY;
            """;

        var storedHeads = new Dictionary<StreamId, StreamVersion>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                storedHeads.Add(
                    new StreamId(Guid.Parse(reader.GetString(0))),
                    new StreamVersion(reader.GetInt64(1)));
            }
        }

        foreach (var computedHead in computedHeads)
        {
            if (!storedHeads.TryGetValue(computedHead.Key, out var storedHead))
            {
                throw new EventStreamCorruptionException(
                    $"Stream '{computedHead.Key.Value:D}' is missing from event_streams.");
            }

            if (storedHead != computedHead.Value)
            {
                throw new EventStreamCorruptionException(
                    $"Stream '{computedHead.Key.Value:D}' has stored head {storedHead.Value}, " +
                    $"but replay computed {computedHead.Value.Value}.");
            }
        }

        foreach (var storedHead in storedHeads)
        {
            if (!computedHeads.ContainsKey(storedHead.Key))
            {
                throw new EventStreamCorruptionException(
                    $"Stream '{storedHead.Key.Value:D}' has no timeline events.");
            }
        }
    }

    private static bool IsValidChecksum(string? checksum) =>
        checksum is { Length: 64 } &&
        checksum.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

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

    private sealed record RawTimelineEvent(long GlobalPosition, StoredEvent StoredEvent);
}
