using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;
using System.Globalization;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal sealed class SqliteProjectionRebuilder
{
    private const int BatchSize = 256;

    private readonly string _connectionString;
    private readonly EventSchemaRegistry _schemaRegistry;
    private readonly IReadOnlyList<ISqliteProjection> _projections;
    private readonly SqliteEventPayloadProtectionProvider _payloads;

    public SqliteProjectionRebuilder(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        IReadOnlyList<ISqliteProjection> projections,
        SqliteEventPayloadProtectionProvider payloads)
    {
        _connectionString = connectionString;
        _schemaRegistry = schemaRegistry;
        _projections = projections;
        _payloads = payloads;
    }

    public async Task<ProjectionRebuildResult> RebuildAsync(
        CancellationToken cancellationToken)
    {
        await using var lease = await _payloads.KeyRing.MaintenanceGate.AcquireAsync(cancellationToken);
        await using var payloadSession = _payloads.CreateReadSession(lease);

        SqliteConnection? connection = null;
        SqliteTransaction? transaction = null;
        try
        {
            connection = await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString,
                cancellationToken);
            transaction = connection.BeginTransaction(deferred: false);
            await SqliteEventStoreSchema.ValidateExistingVersionTwoAsync(connection, transaction, cancellationToken);

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
            var operationGroups = new OperationGroupSequenceValidator();
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
                    operationGroups.Accept(rawEvent.Coordinates);
                    ValidateAndAdvanceHead(streamHeads, rawEvent.Persisted.Metadata);
                    var replayEvent = await payloadSession.UnprotectAsync(
                        rawEvent.Persisted, cancellationToken);
                    if (replayEvent is ShreddedEvent) throw new ShreddedProjectionReplayNotSupportedException();

                    var currentEvent = _schemaRegistry.UpcastToCurrent((DecryptedEvent)replayEvent);
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

            operationGroups.Complete();
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

            await SqliteEventStoreSchema.ValidateExistingVersionTwoAsync(connection, transaction, cancellationToken);
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

    private static void ValidateAndAdvanceHead(
        IDictionary<StreamId, StreamVersion> streamHeads,
        EventMetadata storedEvent)
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
            SELECT e.global_position, e.stream_id, e.stream_version, e.event_id, e.event_type,
                   e.schema_version, e.recorded_at_utc, e.operation_id, e.operation_index,
                   e.operation_count, e.protection_kind, e.owner_kind, e.owner_id, e.key_id,
                   e.envelope_version, e.payload_nonce,
                   e.payload_ciphertext, e.payload_tag
            FROM timeline_events e
            WHERE e.global_position > $after_global_position
            ORDER BY e.global_position ASC
            LIMIT $batch_size;
            """;
        command.Parameters.AddWithValue("$after_global_position", afterGlobalPosition);
        command.Parameters.AddWithValue("$batch_size", BatchSize);

        var batch = new List<RawTimelineEvent>(BatchSize);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var row = SqliteEventStore.ReadPersistedTimelineRow(reader);
            batch.Add(new RawTimelineEvent(row.Coordinates, row.Event));
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
                try
                {
                    var headValue = SqliteEventStore.ReadRequiredInteger(reader, 1);
                    if (headValue < 0) throw new VaultRecoveryRequiredException();
                    storedHeads.Add(
                        new StreamId(SqliteEventStore.ParseCanonicalGuid(
                            SqliteEventStore.ReadRequiredText(reader, 0))),
                        new StreamVersion(headValue));
                }
                catch (VaultRecoveryRequiredException) { throw; }
                catch (Exception exception) when (exception is ArgumentException or InvalidCastException
                    or FormatException or OverflowException or SqliteException
                    or InvalidOperationException or NotSupportedException)
                {
                    throw new VaultRecoveryRequiredException(exception);
                }
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

    private sealed record RawTimelineEvent(
        PersistedOperationCoordinates Coordinates,
        PersistedProtectedEvent Persisted)
    {
        public long GlobalPosition => Coordinates.GlobalPosition;
    }
}

public sealed class ShreddedProjectionReplayNotSupportedException : InvalidOperationException
{
    public ShreddedProjectionReplayNotSupportedException()
        : base("Projection replay requires shredded-event handling.") { }
}
