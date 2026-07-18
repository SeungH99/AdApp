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
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(_connectionString, cancellationToken);
        await using var schemaTransaction = connection.BeginTransaction(deferred: true);
        try
        {
            await SqliteEventStoreSchema.ValidateExistingVersionTwoAsync(connection, schemaTransaction, cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = schemaTransaction;
        command.CommandText = """
            SELECT stream_version, event_id, event_type, schema_version, recorded_at_utc, operation_id,
                   protection_kind, owner_kind, owner_id, key_id, envelope_version, payload_nonce,
                   payload_ciphertext, payload_tag
            FROM timeline_events WHERE stream_id = $stream_id ORDER BY stream_version;
            """;
        command.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
        var events = new List<EventForReplay>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var replay = await _payloads.UnprotectAsync(ReadPersisted(reader, streamId), cancellationToken);
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
        ValidateAppendBatch(command.Events);
        await using var lease = await _payloads.KeyRing.MaintenanceGate.AcquireAsync(cancellationToken);
        await ValidateKeyRingOrThrowAsync(cancellationToken);
        SqliteConnection? connection = null;
        SqliteTransaction? transaction = null;
        try
        {
            connection = await SqliteEventStoreSchema.OpenConnectionAsync(_connectionString, cancellationToken);
            transaction = connection.BeginTransaction(deferred: false);
            await SqliteEventStoreSchema.ValidateExistingVersionTwoAsync(connection, transaction, cancellationToken);
            var existing = await ReadOperationAsync(connection, transaction, command.OperationId, cancellationToken);
            if (existing.Count != 0)
            {
                ValidateOperationGroup(existing, command.OperationId);
                var comparison = await CompareRetryAsync(existing, command, cancellationToken);
                await transaction.RollbackAsync(cancellationToken);
                return comparison switch
                {
                    RetryComparison.Exact => new AlreadyApplied(existing[^1].Event.Metadata.StreamVersion),
                    RetryComparison.Unavailable => new OperationComparisonUnavailable(command.OperationId),
                    _ => new OperationConflict(command.OperationId),
                };
            }
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
            foreach (var eventToAppend in command.Events)
            {
                streamVersion = streamVersion.Next();
                var recordedAtUtc = _timeProvider.GetUtcNow();
                var protectedPayload = await _payloads.ProtectAsync(eventToAppend, command.StreamId, streamVersion, command.OperationId, lease, cancellationToken);
                var globalPosition = await InsertEventAsync(connection, transaction, command.StreamId, streamVersion, eventToAppend, command.OperationId, recordedAtUtc, protectedPayload, cancellationToken);
                var metadata = new EventMetadata(command.StreamId, streamVersion, eventToAppend.EventId, eventToAppend.EventType, eventToAppend.SchemaVersion, recordedAtUtc, command.OperationId, protectedPayload.KeyId, protectedPayload.EnvelopeVersion);
                var decrypted = new DecryptedEvent(metadata, eventToAppend.Payload);
                foreach (var projection in _projections)
                {
                    await projection.ApplyAsync(decrypted, globalPosition, connection, transaction, cancellationToken);
                    await SqliteProjectionCheckpointStore.AdvanceAsync(connection, transaction, projection.Name, globalPosition, cancellationToken);
                }
            }
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

    private async Task<RetryComparison> CompareRetryAsync(IReadOnlyList<PersistedOperationEvent> existing, AppendEventsCommand command, CancellationToken cancellationToken)
    {
        if (existing.Count != command.Events.Count) return RetryComparison.Conflict;
        for (var index = 0; index < existing.Count; index++)
        {
            var row = existing[index].Event; var desired = command.Events[index];
            if (row.Metadata.StreamId != command.StreamId || row.Metadata.StreamVersion != new StreamVersion(command.ExpectedVersion.Value + index + 1)
                || row.Metadata.EventId != desired.EventId || row.Metadata.EventType != desired.EventType || row.Metadata.SchemaVersion != desired.SchemaVersion
                || !SameProtection(row, desired)) return RetryComparison.Conflict;
            var replay = await _payloads.UnprotectAsync(row, cancellationToken);
            if (replay is ShreddedEvent) return RetryComparison.Unavailable;
            if (!PayloadEqualsAndZero((DecryptedEvent)replay, desired)) return RetryComparison.Conflict;
        }
        return RetryComparison.Exact;
    }

    private static void ValidateOperationGroup(IReadOnlyList<PersistedOperationEvent> rows, OperationId operationId)
    {
        var stream = rows[0].Event.Metadata.StreamId;
        var previous = rows[0].Event.Metadata.StreamVersion;
        var position = rows[0].GlobalPosition;
        if (rows[0].Event.Metadata.OperationId != operationId) throw new VaultRecoveryRequiredException();
        for (var index = 1; index < rows.Count; index++)
        {
            var current = rows[index].Event.Metadata;
            if (rows[index].GlobalPosition != position + 1 || current.OperationId != operationId || current.StreamId != stream || current.StreamVersion != previous.Next())
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

    private void ValidateAppendBatch(IReadOnlyList<EventToAppend> events)
    {
        var eventIds = new HashSet<Guid>();
        foreach (var eventToAppend in events)
        {
            if (!eventIds.Add(eventToAppend.EventId.Value)) throw new ArgumentException("An event ID occurs more than once in the batch.", nameof(events));
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
        await using var command = c.CreateCommand(); command.Transaction = t; command.CommandText = "SELECT head_version FROM event_streams WHERE stream_id=$id;"; command.Parameters.AddWithValue("$id", stream.Value.ToString("D"));
        var value = await command.ExecuteScalarAsync(ct); return value is null ? null : new StreamVersion(Convert.ToInt64(value, CultureInfo.InvariantCulture));
    }

    private static async Task<long> InsertEventAsync(SqliteConnection c, SqliteTransaction t, StreamId stream, StreamVersion version, EventToAppend e, OperationId operation, DateTimeOffset recorded, ProtectedEventPayload p, CancellationToken ct)
    {
        await using var command = c.CreateCommand(); command.Transaction = t;
        command.CommandText = "INSERT INTO timeline_events(event_id,stream_id,stream_version,event_type,schema_version,recorded_at_utc,operation_id,protection_kind,owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag) VALUES($event,$stream,$version,$type,$schema,$recorded,$operation,$kind,$ownerKind,$ownerId,$key,$envelope,$nonce,$cipher,$tag) RETURNING global_position;";
        command.Parameters.AddWithValue("$event", e.EventId.Value.ToString("D")); command.Parameters.AddWithValue("$stream", stream.Value.ToString("D")); command.Parameters.AddWithValue("$version", version.Value); command.Parameters.AddWithValue("$type", e.EventType); command.Parameters.AddWithValue("$schema", e.SchemaVersion); command.Parameters.AddWithValue("$recorded", recorded.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)); command.Parameters.AddWithValue("$operation", operation.Value.ToString("D")); command.Parameters.AddWithValue("$kind", (int)p.Kind); command.Parameters.AddWithValue("$ownerKind", p.Owner is null ? DBNull.Value : (object)(int)p.Owner.Value.Kind); command.Parameters.AddWithValue("$ownerId", p.Owner is null ? DBNull.Value : p.Owner.Value.Id.Value.ToString("D")); command.Parameters.AddWithValue("$key", p.KeyId is null ? DBNull.Value : p.KeyId.Value.Value.ToString("D")); command.Parameters.AddWithValue("$envelope", p.EnvelopeVersion);
        command.Parameters.Add("$nonce", SqliteType.Blob).Value = p.Nonce ?? (object)DBNull.Value; command.Parameters.Add("$cipher", SqliteType.Blob).Value = p.Ciphertext; command.Parameters.Add("$tag", SqliteType.Blob).Value = p.Tag ?? (object)DBNull.Value;
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
    }

    private static async Task<IReadOnlyList<PersistedOperationEvent>> ReadOperationAsync(SqliteConnection c, SqliteTransaction t, OperationId operation, CancellationToken ct)
    {
        await using var command = c.CreateCommand(); command.Transaction = t; command.CommandText = "SELECT global_position,stream_id,stream_version,event_id,event_type,schema_version,recorded_at_utc,operation_id,protection_kind,owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag FROM timeline_events WHERE operation_id=$operation ORDER BY global_position;"; command.Parameters.AddWithValue("$operation", operation.Value.ToString("D"));
        var values = new List<PersistedOperationEvent>(); await using var reader = await command.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) values.Add(new PersistedOperationEvent(reader.GetInt64(0), ReadPersistedOperation(reader))); return values;
    }

    internal static PersistedProtectedEvent ReadPersisted(SqliteDataReader r, StreamId? forcedStream = null)
    {
        try
        {
        StreamId stream = forcedStream ?? new StreamId(ParseCanonicalGuid(r.GetString(0)));
        int i = forcedStream is null ? 1 : 0;
        var version = new StreamVersion(r.GetInt64(i++)); var eventId = new EventId(ParseCanonicalGuid(r.GetString(i++))); var type = r.GetString(i++); var schema = r.GetInt32(i++); var recorded = DateTimeOffset.Parse(r.GetString(i++), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime(); var operation = new OperationId(ParseCanonicalGuid(r.GetString(i++))); var kindValue = r.GetInt32(i++);
        if (kindValue is < 0 or > 1) throw new VaultRecoveryRequiredException(); var kind = (PersistedProtectionKind)kindValue;
        SensitiveObjectRef? owner = null; DataKeyId? key = null;
        if (kind == PersistedProtectionKind.Structural)
        {
            if (!r.IsDBNull(i) || !r.IsDBNull(i + 1) || !r.IsDBNull(i + 2) || r.GetInt32(i + 3) != 0 || !r.IsDBNull(i + 4) || !r.IsDBNull(i + 6)) throw new VaultRecoveryRequiredException();
        }
        else
        {
            if (r.IsDBNull(i) || r.IsDBNull(i + 1) || r.IsDBNull(i + 2) || r.GetInt32(i + 3) != 1 || r.IsDBNull(i + 4) || r.IsDBNull(i + 6)) throw new VaultRecoveryRequiredException();
            var ownerKind = r.GetInt32(i); if (!Enum.IsDefined((SensitiveObjectKind)ownerKind)) throw new VaultRecoveryRequiredException(); owner = new SensitiveObjectRef((SensitiveObjectKind)ownerKind, new SensitiveObjectId(ParseCanonicalGuid(r.GetString(i + 1)))); key = new DataKeyId(ParseCanonicalGuid(r.GetString(i + 2)));
        }
        var envelope = r.GetInt32(i + 3); var nonce = r.IsDBNull(i + 4) ? null : r.GetFieldValue<byte[]>(i + 4); var cipher = r.GetFieldValue<byte[]>(i + 5); var tag = r.IsDBNull(i + 6) ? null : r.GetFieldValue<byte[]>(i + 6);
        if (cipher is null || (kind == PersistedProtectionKind.Shreddable && (nonce!.Length != 12 || tag!.Length != 16))) throw new VaultRecoveryRequiredException();
        return new PersistedProtectedEvent(new EventMetadata(stream, version, eventId, type, schema, recorded, operation, key, envelope), kind, owner, nonce, cipher, tag);
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidCastException or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static PersistedProtectedEvent ReadPersistedOperation(SqliteDataReader r)
    {
        var stream = new StreamId(ParseCanonicalGuid(r.GetString(1)));
        var metadata = new EventMetadata(stream, new StreamVersion(r.GetInt64(2)), new EventId(ParseCanonicalGuid(r.GetString(3))), r.GetString(4), r.GetInt32(5), DateTimeOffset.Parse(r.GetString(6), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime(), new OperationId(ParseCanonicalGuid(r.GetString(7))), r.IsDBNull(11) ? null : new DataKeyId(ParseCanonicalGuid(r.GetString(11))), r.GetInt32(12));
        var kind = r.GetInt32(8) switch { 0 => PersistedProtectionKind.Structural, 1 => PersistedProtectionKind.Shreddable, _ => throw new VaultRecoveryRequiredException() };
        SensitiveObjectRef? owner = kind == PersistedProtectionKind.Structural ? null : new SensitiveObjectRef((SensitiveObjectKind)r.GetInt32(9), new SensitiveObjectId(ParseCanonicalGuid(r.GetString(10))));
        return new PersistedProtectedEvent(metadata, kind, owner, r.IsDBNull(13) ? null : r.GetFieldValue<byte[]>(13), r.GetFieldValue<byte[]>(14), r.IsDBNull(15) ? null : r.GetFieldValue<byte[]>(15));
    }

    internal static Guid ParseCanonicalGuid(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed) || parsed == Guid.Empty || !string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal)) throw new VaultRecoveryRequiredException();
        return parsed;
    }

    private static async Task RollbackWithoutMaskingAsync(SqliteTransaction t) { try { await t.RollbackAsync(); } catch { } }
    private enum RetryComparison { Exact, Conflict, Unavailable }
    private sealed record PersistedOperationEvent(long GlobalPosition, PersistedProtectedEvent Event);
}
