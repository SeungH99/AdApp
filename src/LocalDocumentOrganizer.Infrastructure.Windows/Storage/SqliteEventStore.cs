using System.Globalization;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public sealed class SqliteEventStore : IEventStore
{
    private readonly string _connectionString;
    private readonly EventSchemaRegistry _schemaRegistry;
    private readonly IReadOnlyList<ISqliteProjection> _projections;
    private readonly TimeProvider _timeProvider;
    private readonly SqliteEventPayloadProtectionProvider _payloads;

    public SqliteEventStore(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        IEnumerable<ISqliteProjection> projections,
        TimeProvider? timeProvider = null,
        VaultKeyRingStore? keyRing = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(schemaRegistry);
        ArgumentNullException.ThrowIfNull(projections);
        _connectionString = connectionString;
        _schemaRegistry = schemaRegistry;
        _projections = ValidateProjections(projections);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _payloads = new SqliteEventPayloadProtectionProvider(keyRing ?? CreateDefaultKeyRing(connectionString));
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        SqliteEventStoreSchema.InitializeAsync(_connectionString, _projections, _payloads.KeyRing, cancellationToken);

    public Task<ProjectionRebuildResult> RebuildProjectionsAsync(CancellationToken cancellationToken = default) =>
        new SqliteProjectionRebuilder(_connectionString, _schemaRegistry, _projections, _payloads).RebuildAsync(cancellationToken);

    public async Task<IReadOnlyList<EventForReplay>> ReadStreamAsync(StreamId streamId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        await using var lease = await _payloads.KeyRing.MaintenanceGate.AcquireAsync(cancellationToken);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(_connectionString, cancellationToken);
        await using var schemaTransaction = connection.BeginTransaction(deferred: true);
        try
        {
            await SqliteEventStoreSchema.ValidateExistingVersionTwoAsync(connection, schemaTransaction, cancellationToken);
            await ValidateAllOperationGroupsAsync(connection, schemaTransaction, cancellationToken);
            await using var command = connection.CreateCommand();
            command.Transaction = schemaTransaction;
            command.CommandText = """
                SELECT global_position, stream_id, stream_version, event_id, event_type, schema_version,
                       recorded_at_utc, operation_id, operation_index, operation_count,
                       protection_kind, owner_kind, owner_id, key_id, envelope_version, payload_nonce,
                       payload_ciphertext, payload_tag
                FROM timeline_events WHERE stream_id = $stream_id ORDER BY stream_version;
                """;
            command.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
            var persistedRows = new List<PersistedTimelineRow>();
            await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    var row = ReadPersistedTimelineRow(reader);
                    if (row.Event.Metadata.StreamId != streamId) throw new VaultRecoveryRequiredException();
                    persistedRows.Add(row);
                }
            }

            var storedHead = await ReadHeadAsync(connection, schemaTransaction, streamId, cancellationToken);
            if (persistedRows.Count == 0)
            {
                if (storedHead is not null) throw new EventStreamCorruptionException("A stream head has no timeline events.");
            }
            else
            {
                for (var index = 0; index < persistedRows.Count; index++)
                {
                    if (persistedRows[index].Event.Metadata.StreamVersion != new StreamVersion(index))
                        throw new EventStreamCorruptionException("A stream contains a noncontiguous version sequence.");
                }

                if (storedHead != persistedRows[^1].Event.Metadata.StreamVersion)
                    throw new EventStreamCorruptionException("A stream head does not match its timeline events.");
            }

            var events = new List<EventForReplay>(persistedRows.Count);
            foreach (var row in persistedRows)
            {
                var replay = await _payloads.UnprotectAsync(row.Event, lease, cancellationToken);
                if (replay is ShreddedEvent) events.Add(replay);
                else events.Add(_schemaRegistry.UpcastToCurrent((DecryptedEvent)replay));
            }
            await schemaTransaction.CommitAsync(cancellationToken);
            return events;
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (SqliteException exception) { throw new VaultRecoveryRequiredException(exception); }
    }

    public async Task<AppendEventsResult> AppendAsync(AppendEventsCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ValidateAppendBatchIdentifiers(command.Events);
        await using var lease = await _payloads.KeyRing.MaintenanceGate.AcquireAsync(cancellationToken);
        await ValidateKeyRingOrThrowAsync(cancellationToken);
        SqliteConnection? connection = null;
        SqliteTransaction? transaction = null;
        try
        {
            connection = await SqliteEventStoreSchema.OpenConnectionAsync(_connectionString, cancellationToken);
            transaction = connection.BeginTransaction(deferred: false);
            await SqliteEventStoreSchema.ValidateExistingVersionTwoAsync(connection, transaction, cancellationToken);
            await ValidateAllOperationGroupsAsync(connection, transaction, cancellationToken);
            var existing = await ReadOperationAsync(connection, transaction, command.OperationId, cancellationToken);
            if (existing.Count != 0)
            {
                ValidateOperationGroup(existing, command.OperationId);
                var comparison = await CompareRetryAsync(existing, command, lease, cancellationToken);
                await transaction.RollbackAsync(cancellationToken);
                return comparison switch
                {
                    RetryComparison.Exact => new AlreadyApplied(existing[^1].Event.Metadata.StreamVersion),
                    RetryComparison.Unavailable => new OperationComparisonUnavailable(command.OperationId),
                    _ => new OperationConflict(command.OperationId),
                };
            }
            ValidateCurrentEventSchemas(command.Events);
            var rebuildRequirement = await SqliteProjectionCheckpointStore.FindRebuildRequirementAsync(connection, transaction, _projections, cancellationToken);
            if (rebuildRequirement.ProjectionNames.Count != 0)
                throw new ProjectionRebuildRequiredException(rebuildRequirement.ProjectionNames, rebuildRequirement.RequiredGlobalPosition);

            var newVersion = new StreamVersion(checked(command.ExpectedVersion.Value + command.Events.Count));
            var actualVersion = await ReserveStreamAsync(connection, transaction, command.StreamId, command.ExpectedVersion, newVersion, cancellationToken);
            if (actualVersion is not null)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new ConcurrencyConflict(command.ExpectedVersion, actualVersion.Value);
            }
            var streamVersion = command.ExpectedVersion;
            for (var operationIndex = 0; operationIndex < command.Events.Count; operationIndex++)
            {
                var eventToAppend = command.Events[operationIndex];
                streamVersion = streamVersion.Next();
                var recordedAtUtc = _timeProvider.GetUtcNow();
                var protectedPayload = await _payloads.ProtectAsync(eventToAppend, command.StreamId, streamVersion, command.OperationId, lease, cancellationToken);
                var globalPosition = await InsertEventAsync(connection, transaction, command.StreamId, streamVersion,
                    eventToAppend, command.OperationId, operationIndex, command.Events.Count,
                    recordedAtUtc, protectedPayload, cancellationToken);
                var metadata = new EventMetadata(command.StreamId, streamVersion, eventToAppend.EventId, eventToAppend.EventType, eventToAppend.SchemaVersion, recordedAtUtc, command.OperationId, protectedPayload.KeyId, protectedPayload.EnvelopeVersion);
                var decrypted = new DecryptedEvent(metadata, eventToAppend.Payload);
                foreach (var projection in _projections)
                {
                    await projection.ApplyAsync(decrypted, globalPosition, connection, transaction, cancellationToken);
                    await SqliteProjectionCheckpointStore.AdvanceAsync(connection, transaction, projection.Name, globalPosition, cancellationToken);
                }
            }
            await SqliteEventStoreSchema.ValidateExistingVersionTwoAsync(connection, transaction, cancellationToken);
            await ValidateAllOperationGroupsAsync(connection, transaction, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new Appended(newVersion);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode is 5 or 6)
        {
            if (transaction is not null) await RollbackWithoutMaskingAsync(transaction);
            return new StorageBusy();
        }
        catch
        {
            if (transaction is not null) await RollbackWithoutMaskingAsync(transaction);
            throw;
        }
        finally
        {
            if (transaction is not null) await transaction.DisposeAsync();
            if (connection is not null) await connection.DisposeAsync();
        }
    }

    private async Task<RetryComparison> CompareRetryAsync(
        IReadOnlyList<PersistedOperationEvent> existing,
        AppendEventsCommand command,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        var metadataConflict = existing.Count != command.Events.Count;
        var payloadConflict = false;
        var unavailable = false;
        for (var index = 0; index < existing.Count; index++)
        {
            var row = existing[index].Event;
            EventToAppend? desired = index < command.Events.Count ? command.Events[index] : null;
            StreamVersion? desiredVersion = null;
            try
            {
                desiredVersion = new StreamVersion(checked(command.ExpectedVersion.Value + index + 1));
            }
            catch (OverflowException)
            {
                metadataConflict = true;
            }
            if (desired is null
                || row.Metadata.StreamId != command.StreamId
                || desiredVersion is null
                || row.Metadata.StreamVersion != desiredVersion
                || row.Metadata.EventId != desired.EventId
                || row.Metadata.EventType != desired.EventType
                || row.Metadata.SchemaVersion != desired.SchemaVersion
                || !SameProtection(row, desired))
            {
                metadataConflict = true;
            }

            var replay = await _payloads.UnprotectAsync(row, lease, cancellationToken);
            if (replay is ShreddedEvent)
            {
                unavailable = true;
            }
            else if (desired is not null && !PayloadEqualsAndZero((DecryptedEvent)replay, desired))
            {
                payloadConflict = true;
            }
        }

        if (metadataConflict) return RetryComparison.Conflict;
        if (unavailable) return RetryComparison.Unavailable;
        return payloadConflict ? RetryComparison.Conflict : RetryComparison.Exact;
    }

    private static void ValidateOperationGroup(IReadOnlyList<PersistedOperationEvent> rows, OperationId operationId)
    {
        if (rows.Count == 0) throw new VaultRecoveryRequiredException();
        var declaredCount = rows[0].OperationCount;
        if (declaredCount != rows.Count) throw new VaultRecoveryRequiredException();
        var stream = rows[0].Event.Metadata.StreamId;
        var previous = rows[0].Event.Metadata.StreamVersion;
        var position = rows[0].GlobalPosition;
        if (rows[0].Event.Metadata.OperationId != operationId
            || rows[0].OperationIndex != 0)
            throw new VaultRecoveryRequiredException();
        for (var index = 1; index < rows.Count; index++)
        {
            var current = rows[index].Event.Metadata;
            if (rows[index].OperationIndex != index
                || rows[index].OperationCount != declaredCount
                || position == long.MaxValue
                || rows[index].GlobalPosition != position + 1
                || current.OperationId != operationId
                || current.StreamId != stream
                || previous.Value == long.MaxValue
                || current.StreamVersion.Value != previous.Value + 1)
                throw new VaultRecoveryRequiredException();
            previous = current.StreamVersion; position = rows[index].GlobalPosition;
        }
    }

    private static bool SameProtection(PersistedProtectedEvent row, EventToAppend desired) => desired.Protection switch
    {
        PayloadProtection.DurableStructural => row.Kind == PersistedProtectionKind.Structural,
        PayloadProtection.Shreddable shreddable => row.Kind == PersistedProtectionKind.Shreddable && row.Owner == shreddable.Owner,
        _ => false,
    };

    private static bool PayloadEqualsAndZero(DecryptedEvent actual, EventToAppend expected)
    {
        var actualPayload = actual.Payload;
        var expectedPayload = expected.Payload;
        try { return actualPayload.Span.SequenceEqual(expectedPayload.Span); }
        finally { ZeroMemory(actualPayload); ZeroMemory(expectedPayload); }
    }

    private static void ZeroMemory(ReadOnlyMemory<byte> value)
    {
        if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment)
            && segment.Array is not null)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(segment.Array.AsSpan(segment.Offset, segment.Count));
        }
    }

    private async Task ValidateKeyRingOrThrowAsync(CancellationToken cancellationToken)
    {
        try { await _payloads.ValidateKeyRingAsync(cancellationToken); }
        catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
    }

    private static void ValidateAppendBatchIdentifiers(IReadOnlyList<EventToAppend> events)
    {
        var eventIds = new HashSet<Guid>();
        foreach (var eventToAppend in events)
        {
            if (!eventIds.Add(eventToAppend.EventId.Value)) throw new ArgumentException("An event ID occurs more than once in the batch.", nameof(events));
        }
    }

    private void ValidateCurrentEventSchemas(IReadOnlyList<EventToAppend> events)
    {
        foreach (var eventToAppend in events)
        {
            if (eventToAppend.SchemaVersion != _schemaRegistry.GetCurrentVersion(eventToAppend.EventType))
                throw new ArgumentException("Events must use their registered current schema version.", nameof(events));
        }
    }

    private static IReadOnlyList<ISqliteProjection> ValidateProjections(IEnumerable<ISqliteProjection> projections)
    {
        var values = projections.ToArray(); var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var projection in values)
        {
            ArgumentNullException.ThrowIfNull(projection);
            if (string.IsNullOrWhiteSpace(projection.Name) || !names.Add(projection.Name))
                throw new ArgumentException("Projection names must be stable and unique.", nameof(projections));
        }
        return values.OrderBy(projection => projection.Name, StringComparer.Ordinal).ToArray();
    }

    private static VaultKeyRingStore CreateDefaultKeyRing(string connectionString)
    {
        var source = new SqliteConnectionStringBuilder(connectionString).DataSource;
        if (string.IsNullOrWhiteSpace(source) || source == ":memory:") throw new ArgumentException("Encrypted Vault storage requires a file-backed data source.", nameof(connectionString));
        return new VaultKeyRingStore(Path.GetFullPath(source) + ".keyring");
    }

    private static async Task<StreamVersion?> ReserveStreamAsync(SqliteConnection c, SqliteTransaction t, StreamId stream, StreamVersion expected, StreamVersion next, CancellationToken ct)
    {
        if (expected == StreamVersion.NoStream)
        {
            var existing = await ReadHeadAsync(c, t, stream, ct); if (existing is not null) return existing;
            await using var insert = c.CreateCommand(); insert.Transaction = t; insert.CommandText = "INSERT INTO event_streams(stream_id, head_version) VALUES($id, $version);";
            insert.Parameters.AddWithValue("$id", stream.Value.ToString("D")); insert.Parameters.AddWithValue("$version", next.Value); await insert.ExecuteNonQueryAsync(ct); return null;
        }
        await using var update = c.CreateCommand(); update.Transaction = t; update.CommandText = "UPDATE event_streams SET head_version=$next WHERE stream_id=$id AND head_version=$expected;";
        update.Parameters.AddWithValue("$next", next.Value); update.Parameters.AddWithValue("$id", stream.Value.ToString("D")); update.Parameters.AddWithValue("$expected", expected.Value);
        return await update.ExecuteNonQueryAsync(ct) == 1 ? null : await ReadHeadAsync(c, t, stream, ct) ?? StreamVersion.NoStream;
    }

    private static async Task<StreamVersion?> ReadHeadAsync(SqliteConnection c, SqliteTransaction t, StreamId stream, CancellationToken ct)
    {
        try
        {
            await using var command = c.CreateCommand(); command.Transaction = t; command.CommandText = "SELECT head_version FROM event_streams WHERE stream_id=$id;"; command.Parameters.AddWithValue("$id", stream.Value.ToString("D"));
            var value = await command.ExecuteScalarAsync(ct);
            if (value is null) return null;
            var head = Convert.ToInt64(value, CultureInfo.InvariantCulture);
            if (head < 0) throw new VaultRecoveryRequiredException();
            return new StreamVersion(head);
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException or FormatException or OverflowException or ArgumentOutOfRangeException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static async Task<long> InsertEventAsync(
        SqliteConnection c,
        SqliteTransaction t,
        StreamId stream,
        StreamVersion version,
        EventToAppend e,
        OperationId operation,
        int operationIndex,
        int operationCount,
        DateTimeOffset recorded,
        ProtectedEventPayload p,
        CancellationToken ct)
    {
        await using var command = c.CreateCommand(); command.Transaction = t;
        command.CommandText = "INSERT INTO timeline_events(event_id,stream_id,stream_version,event_type,schema_version,recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag) VALUES($event,$stream,$version,$type,$schema,$recorded,$operation,$operationIndex,$operationCount,$kind,$ownerKind,$ownerId,$key,$envelope,$nonce,$cipher,$tag) RETURNING global_position;";
        command.Parameters.AddWithValue("$event", e.EventId.Value.ToString("D")); command.Parameters.AddWithValue("$stream", stream.Value.ToString("D")); command.Parameters.AddWithValue("$version", version.Value); command.Parameters.AddWithValue("$type", e.EventType); command.Parameters.AddWithValue("$schema", e.SchemaVersion); command.Parameters.AddWithValue("$recorded", recorded.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)); command.Parameters.AddWithValue("$operation", operation.Value.ToString("D")); command.Parameters.AddWithValue("$operationIndex", operationIndex); command.Parameters.AddWithValue("$operationCount", operationCount); command.Parameters.AddWithValue("$kind", (int)p.Kind); command.Parameters.AddWithValue("$ownerKind", p.Owner is null ? DBNull.Value : (object)(int)p.Owner.Value.Kind); command.Parameters.AddWithValue("$ownerId", p.Owner is null ? DBNull.Value : p.Owner.Value.Id.Value.ToString("D")); command.Parameters.AddWithValue("$key", p.KeyId is null ? DBNull.Value : p.KeyId.Value.Value.ToString("D")); command.Parameters.AddWithValue("$envelope", p.EnvelopeVersion);
        command.Parameters.Add("$nonce", SqliteType.Blob).Value = p.Nonce ?? (object)DBNull.Value; command.Parameters.Add("$cipher", SqliteType.Blob).Value = p.Ciphertext; command.Parameters.Add("$tag", SqliteType.Blob).Value = p.Tag ?? (object)DBNull.Value;
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
    }

    internal static async Task ValidateAllOperationGroupsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT global_position,stream_id,stream_version,event_id,event_type,schema_version,
                   recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,
                   owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag
            FROM timeline_events
            ORDER BY global_position;
            """;
        var completedOperations = new HashSet<OperationId>();
        OperationId? currentOperation = null;
        var currentGroup = new List<PersistedOperationEvent>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var row = ReadPersistedTimelineRow(reader);
            var operationId = row.Event.Metadata.OperationId;
            if (currentOperation is not null && currentOperation != operationId)
            {
                ValidateOperationGroup(currentGroup, currentOperation.Value);
                completedOperations.Add(currentOperation.Value);
                currentGroup.Clear();
            }

            if (completedOperations.Contains(operationId)) throw new VaultRecoveryRequiredException();
            currentOperation = operationId;
            currentGroup.Add(new PersistedOperationEvent(
                row.GlobalPosition, row.OperationIndex, row.OperationCount, row.Event));
        }

        if (currentOperation is not null)
        {
            ValidateOperationGroup(currentGroup, currentOperation.Value);
        }
    }

    private static async Task<IReadOnlyList<PersistedOperationEvent>> ReadOperationAsync(SqliteConnection c, SqliteTransaction t, OperationId operation, CancellationToken ct)
    {
        await using var command = c.CreateCommand(); command.Transaction = t; command.CommandText = "SELECT global_position,stream_id,stream_version,event_id,event_type,schema_version,recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag FROM timeline_events WHERE operation_id=$operation ORDER BY operation_index;"; command.Parameters.AddWithValue("$operation", operation.Value.ToString("D"));
        var values = new List<PersistedOperationEvent>(); await using var reader = await command.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) { var row = ReadPersistedTimelineRow(reader); values.Add(new PersistedOperationEvent(row.GlobalPosition, row.OperationIndex, row.OperationCount, row.Event)); } return values;
    }

    internal static PersistedTimelineRow ReadPersistedTimelineRow(SqliteDataReader reader)
    {
        try
        {
            var globalPosition = reader.GetInt64(0);
            if (globalPosition <= 0) throw new VaultRecoveryRequiredException();
            var stream = new StreamId(ParseCanonicalGuid(reader.GetString(1)));
            var streamVersionValue = reader.GetInt64(2);
            if (streamVersionValue < 0) throw new VaultRecoveryRequiredException();
            var streamVersion = new StreamVersion(streamVersionValue);
            var eventId = new EventId(ParseCanonicalGuid(reader.GetString(3)));
            var eventType = reader.GetString(4);
            if (string.IsNullOrWhiteSpace(eventType)) throw new VaultRecoveryRequiredException();
            var schemaVersion = reader.GetInt32(5);
            if (schemaVersion < 1) throw new VaultRecoveryRequiredException();
            var recordedText = reader.GetString(6);
            if (!DateTimeOffset.TryParseExact(recordedText, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var recorded)
                || recorded.Offset != TimeSpan.Zero
                || !string.Equals(recordedText, recorded.ToString("O", CultureInfo.InvariantCulture), StringComparison.Ordinal))
                throw new VaultRecoveryRequiredException();
            var operationId = new OperationId(ParseCanonicalGuid(reader.GetString(7)));
            var operationIndex = reader.GetInt32(8);
            var operationCount = reader.GetInt32(9);
            if (operationIndex < 0 || operationCount <= 0 || operationIndex >= operationCount)
                throw new VaultRecoveryRequiredException();
            var kind = reader.GetInt32(10) switch
            {
                0 => PersistedProtectionKind.Structural,
                1 => PersistedProtectionKind.Shreddable,
                _ => throw new VaultRecoveryRequiredException(),
            };
            SensitiveObjectRef? owner = null;
            DataKeyId? keyId = null;
            var envelopeVersion = reader.GetInt32(14);
            byte[]? nonce;
            byte[] ciphertext;
            byte[]? tag;
            if (kind == PersistedProtectionKind.Structural)
            {
                if (!reader.IsDBNull(11) || !reader.IsDBNull(12) || !reader.IsDBNull(13)
                    || envelopeVersion != 0 || !reader.IsDBNull(15) || !reader.IsDBNull(17))
                    throw new VaultRecoveryRequiredException();
                nonce = null;
                ciphertext = ReadBlob(reader, 16);
                tag = null;
            }
            else
            {
                if (reader.IsDBNull(11) || reader.IsDBNull(12) || reader.IsDBNull(13)
                    || envelopeVersion != 1 || reader.IsDBNull(15) || reader.IsDBNull(17))
                    throw new VaultRecoveryRequiredException();
                var rawOwnerKind = reader.GetInt32(11);
                if (!Enum.IsDefined((SensitiveObjectKind)rawOwnerKind)) throw new VaultRecoveryRequiredException();
                owner = new SensitiveObjectRef((SensitiveObjectKind)rawOwnerKind,
                    new SensitiveObjectId(ParseCanonicalGuid(reader.GetString(12))));
                keyId = new DataKeyId(ParseCanonicalGuid(reader.GetString(13)));
                nonce = ReadBlob(reader, 15);
                ciphertext = ReadBlob(reader, 16);
                tag = ReadBlob(reader, 17);
                if (nonce.Length != AesGcmRecordProtector.NonceSize || tag.Length != AesGcmRecordProtector.TagSize)
                    throw new VaultRecoveryRequiredException();
            }
            var metadata = new EventMetadata(stream, streamVersion, eventId, eventType, schemaVersion,
                recorded, operationId, keyId, envelopeVersion);
            return new PersistedTimelineRow(globalPosition, operationIndex, operationCount,
                new PersistedProtectedEvent(metadata, kind, owner, nonce, ciphertext, tag));
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidCastException
            or OverflowException or SqliteException or IndexOutOfRangeException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static byte[] ReadBlob(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal) || !string.Equals(reader.GetDataTypeName(ordinal), "BLOB", StringComparison.OrdinalIgnoreCase))
            throw new VaultRecoveryRequiredException();
        return reader.GetFieldValue<byte[]>(ordinal);
    }

    internal static Guid ParseCanonicalGuid(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed) || parsed == Guid.Empty || !string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal)) throw new VaultRecoveryRequiredException();
        return parsed;
    }

    private static async Task RollbackWithoutMaskingAsync(SqliteTransaction t) { try { await t.RollbackAsync(); } catch { } }
    private enum RetryComparison { Exact, Conflict, Unavailable }
    private sealed record PersistedOperationEvent(
        long GlobalPosition,
        int OperationIndex,
        int OperationCount,
        PersistedProtectedEvent Event);
}

internal sealed record PersistedTimelineRow(
    long GlobalPosition,
    int OperationIndex,
    int OperationCount,
    PersistedProtectedEvent Event);
