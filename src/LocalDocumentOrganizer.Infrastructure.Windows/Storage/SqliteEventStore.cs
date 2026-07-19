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
        _schemaRegistry = schemaRegistry;
        _projections = ValidateProjections(projections);
        _connectionString = SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _payloads = new SqliteEventPayloadProtectionProvider(keyRing ?? CreateDefaultKeyRing(_connectionString));
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default) =>
        SqliteEventStoreSchema.InitializeAsync(_connectionString, _projections, _payloads.KeyRing, cancellationToken);

    public Task<ProjectionRebuildResult> RebuildProjectionsAsync(CancellationToken cancellationToken = default) =>
        new SqliteProjectionRebuilder(_connectionString, _schemaRegistry, _projections, _payloads).RebuildAsync(cancellationToken);

    public async Task<IReadOnlyList<EventForReplay>> ReadStreamAsync(StreamId streamId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        await using var lease = await _payloads.KeyRing.MaintenanceGate.AcquireAsync(cancellationToken);
        await using var payloadSession = _payloads.CreateReadSession(lease);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(_connectionString, cancellationToken);
        await using var schemaTransaction = connection.BeginTransaction(deferred: true);
        try
        {
            await SqliteEventStoreSchema.ValidateExistingVersionTwoAsync(connection, schemaTransaction, cancellationToken);
            await using var command = connection.CreateCommand();
            command.Transaction = schemaTransaction;
            command.CommandText = """
                SELECT global_position, stream_id, stream_version, event_id, event_type, schema_version,
                       recorded_at_utc, operation_id, operation_index, operation_count,
                       protection_kind, owner_kind, owner_id, key_id, envelope_version, payload_nonce,
                       payload_ciphertext, payload_tag
                FROM timeline_events WHERE stream_id = $stream_id ORDER BY global_position;
                """;
            command.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
            var persistedRows = new List<PersistedTimelineRow>();
            var operationGroups = new OperationGroupSequenceValidator();
            await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    var row = ReadPersistedTimelineRow(reader);
                    if (row.Event.Metadata.StreamId != streamId) throw new VaultRecoveryRequiredException();
                    operationGroups.Accept(row.Coordinates);
                    persistedRows.Add(row);
                }
            }
            operationGroups.Complete();

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
                var replay = await payloadSession.UnprotectAsync(row.Event, cancellationToken);
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
        await using var keySession = await _payloads.OpenWriteSessionAsync(lease, cancellationToken);
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
                var comparison = await CompareRetryAsync(existing, command, keySession, cancellationToken);
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
                var protectedPayload = await _payloads.ProtectAsync(
                    eventToAppend, command.StreamId, streamVersion, command.OperationId,
                    keySession, cancellationToken);
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
            var appended = await ReadOperationAsync(
                connection, transaction, command.OperationId, cancellationToken);
            ValidateOperationGroup(appended, command.OperationId);
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
        VaultKeyRingStore.VaultKeyRingSession keySession,
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

            var replay = await _payloads.UnprotectAsync(row, keySession, cancellationToken);
            if (replay is ShreddedEvent)
            {
                unavailable = true;
            }
            else if (desired is not null && !PayloadEqualsAndZero((DecryptedEvent)replay, desired))
            {
                payloadConflict = true;
            }
        }

        if (metadataConflict || payloadConflict) return RetryComparison.Conflict;
        if (unavailable) return RetryComparison.Unavailable;
        return RetryComparison.Exact;
    }

    private static void ValidateOperationGroup(IReadOnlyList<PersistedOperationEvent> rows, OperationId operationId)
    {
        if (rows.Count == 0) throw new VaultRecoveryRequiredException();
        var validator = new OperationGroupSequenceValidator();
        foreach (var row in rows)
        {
            if (row.Event.Metadata.OperationId != operationId) throw new VaultRecoveryRequiredException();
            validator.Accept(new PersistedOperationCoordinates(
                row.GlobalPosition,
                row.Event.Metadata.StreamId,
                row.Event.Metadata.StreamVersion,
                row.Event.Metadata.OperationId,
                row.OperationIndex,
                row.OperationCount));
        }
        validator.Complete();
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
            if (value is not long head) throw new VaultRecoveryRequiredException();
            if (head < 0) throw new VaultRecoveryRequiredException();
            return new StreamVersion(head);
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException or FormatException
            or OverflowException or ArgumentOutOfRangeException or InvalidOperationException)
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

    internal static async Task ValidateAllOperationMetadataAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT global_position,stream_id,stream_version,operation_id,operation_index,operation_count
            FROM timeline_events
            ORDER BY global_position;
            """;
        var validator = new OperationGroupSequenceValidator();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            validator.Accept(ReadOperationCoordinates(reader));
        }
        validator.Complete();
    }

    private static async Task<IReadOnlyList<PersistedOperationEvent>> ReadOperationAsync(SqliteConnection c, SqliteTransaction t, OperationId operation, CancellationToken ct)
    {
        await using var command = c.CreateCommand(); command.Transaction = t; command.CommandText = "SELECT global_position,stream_id,stream_version,event_id,event_type,schema_version,recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag FROM timeline_events WHERE operation_id COLLATE NOCASE IN ($operation,CAST($operation AS BLOB),CAST(upper($operation) AS BLOB)) ORDER BY global_position;"; command.Parameters.AddWithValue("$operation", operation.Value.ToString("D"));
        var values = new List<PersistedOperationEvent>(); await using var reader = await command.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) { var row = ReadPersistedTimelineRow(reader); values.Add(new PersistedOperationEvent(row.GlobalPosition, row.OperationIndex, row.OperationCount, row.Event)); } return values;
    }

    internal static PersistedTimelineRow ReadPersistedTimelineRow(SqliteDataReader reader)
    {
        try
        {
            var globalPosition = ReadRequiredInteger(reader, 0);
            if (globalPosition <= 0) throw new VaultRecoveryRequiredException();
            var stream = new StreamId(ParseCanonicalGuid(ReadRequiredText(reader, 1)));
            var streamVersionValue = ReadRequiredInteger(reader, 2);
            if (streamVersionValue < 0) throw new VaultRecoveryRequiredException();
            var streamVersion = new StreamVersion(streamVersionValue);
            var eventId = new EventId(ParseCanonicalGuid(ReadRequiredText(reader, 3)));
            var eventType = ReadRequiredText(reader, 4);
            if (string.IsNullOrWhiteSpace(eventType)) throw new VaultRecoveryRequiredException();
            var schemaVersion = ReadRequiredInt32(reader, 5);
            if (schemaVersion < 1) throw new VaultRecoveryRequiredException();
            var recordedText = ReadRequiredText(reader, 6);
            if (!DateTimeOffset.TryParseExact(recordedText, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var recorded)
                || recorded.Offset != TimeSpan.Zero
                || !string.Equals(recordedText, recorded.ToString("O", CultureInfo.InvariantCulture), StringComparison.Ordinal))
                throw new VaultRecoveryRequiredException();
            var operationId = new OperationId(ParseCanonicalGuid(ReadRequiredText(reader, 7)));
            var operationIndex = ReadRequiredInt32(reader, 8);
            var operationCount = ReadRequiredInt32(reader, 9);
            if (operationIndex < 0 || operationCount <= 0 || operationIndex >= operationCount)
                throw new VaultRecoveryRequiredException();
            var kind = ReadRequiredInt32(reader, 10) switch
            {
                0 => PersistedProtectionKind.Structural,
                1 => PersistedProtectionKind.Shreddable,
                _ => throw new VaultRecoveryRequiredException(),
            };
            SensitiveObjectRef? owner = null;
            DataKeyId? keyId = null;
            var envelopeVersion = ReadRequiredInt32(reader, 14);
            byte[]? nonce;
            byte[] ciphertext;
            byte[]? tag;
            if (kind == PersistedProtectionKind.Structural)
            {
                if (!IsExactNull(reader, 11) || !IsExactNull(reader, 12) || !IsExactNull(reader, 13)
                    || envelopeVersion != 0 || !IsExactNull(reader, 15) || !IsExactNull(reader, 17))
                    throw new VaultRecoveryRequiredException();
                nonce = null;
                ciphertext = ReadRequiredBlob(reader, 16);
                tag = null;
            }
            else
            {
                if (IsExactNull(reader, 11) || IsExactNull(reader, 12) || IsExactNull(reader, 13)
                    || envelopeVersion != 1 || IsExactNull(reader, 15) || IsExactNull(reader, 17))
                    throw new VaultRecoveryRequiredException();
                var rawOwnerKind = ReadRequiredInt32(reader, 11);
                if (!Enum.IsDefined((SensitiveObjectKind)rawOwnerKind)) throw new VaultRecoveryRequiredException();
                owner = new SensitiveObjectRef((SensitiveObjectKind)rawOwnerKind,
                    new SensitiveObjectId(ParseCanonicalGuid(ReadRequiredText(reader, 12))));
                keyId = new DataKeyId(ParseCanonicalGuid(ReadRequiredText(reader, 13)));
                nonce = ReadRequiredBlob(reader, 15);
                ciphertext = ReadRequiredBlob(reader, 16);
                tag = ReadRequiredBlob(reader, 17);
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
            or OverflowException or SqliteException or IndexOutOfRangeException
            or InvalidOperationException or NotSupportedException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    internal static PersistedOperationCoordinates ReadOperationCoordinates(SqliteDataReader reader)
    {
        try
        {
            var globalPosition = ReadRequiredInteger(reader, 0);
            var streamVersion = ReadRequiredInteger(reader, 2);
            if (globalPosition <= 0 || streamVersion < 0) throw new VaultRecoveryRequiredException();
            var operationIndex = ReadRequiredInt32(reader, 4);
            var operationCount = ReadRequiredInt32(reader, 5);
            if (operationIndex < 0 || operationCount <= 0 || operationIndex >= operationCount)
                throw new VaultRecoveryRequiredException();
            return new PersistedOperationCoordinates(
                globalPosition,
                new StreamId(ParseCanonicalGuid(ReadRequiredText(reader, 1))),
                new StreamVersion(streamVersion),
                new OperationId(ParseCanonicalGuid(ReadRequiredText(reader, 3))),
                operationIndex,
                operationCount);
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidCastException
            or OverflowException or SqliteException or IndexOutOfRangeException
            or InvalidOperationException or NotSupportedException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    internal static long ReadRequiredInteger(SqliteDataReader reader, int ordinal) =>
        reader.GetValue(ordinal) is long value ? value : throw new VaultRecoveryRequiredException();

    internal static string ReadRequiredText(SqliteDataReader reader, int ordinal) =>
        reader.GetValue(ordinal) is string value ? value : throw new VaultRecoveryRequiredException();

    private static byte[] ReadRequiredBlob(SqliteDataReader reader, int ordinal) =>
        reader.GetValue(ordinal) is byte[] value ? value : throw new VaultRecoveryRequiredException();

    private static int ReadRequiredInt32(SqliteDataReader reader, int ordinal) =>
        checked((int)ReadRequiredInteger(reader, ordinal));

    private static bool IsExactNull(SqliteDataReader reader, int ordinal) =>
        reader.GetValue(ordinal) is DBNull;

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
    PersistedProtectedEvent Event)
{
    public PersistedOperationCoordinates Coordinates => new(
        GlobalPosition,
        Event.Metadata.StreamId,
        Event.Metadata.StreamVersion,
        Event.Metadata.OperationId,
        OperationIndex,
        OperationCount);
}

internal sealed record PersistedOperationCoordinates(
    long GlobalPosition,
    StreamId StreamId,
    StreamVersion StreamVersion,
    OperationId OperationId,
    int OperationIndex,
    int OperationCount);

internal sealed class OperationGroupSequenceValidator
{
    private readonly HashSet<OperationId> _completed = [];
    private bool _hasCurrent;
    private OperationId _currentOperation;
    private StreamId? _currentStream;
    private int _declaredCount;
    private int _nextIndex;
    private long _previousGlobalPosition;
    private long _previousStreamVersion;

    public void Accept(PersistedOperationCoordinates row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (!_hasCurrent || row.OperationId != _currentOperation)
        {
            CompleteCurrent();
            if (_completed.Contains(row.OperationId)
                || row.OperationIndex != 0
                || row.OperationCount <= 0)
                throw new VaultRecoveryRequiredException();
            _hasCurrent = true;
            _currentOperation = row.OperationId;
            _currentStream = row.StreamId;
            _declaredCount = row.OperationCount;
            _nextIndex = 1;
            _previousGlobalPosition = row.GlobalPosition;
            _previousStreamVersion = row.StreamVersion.Value;
            return;
        }

        if (row.OperationIndex != _nextIndex
            || row.OperationCount != _declaredCount
            || row.StreamId != _currentStream
            || _previousGlobalPosition == long.MaxValue
            || row.GlobalPosition != _previousGlobalPosition + 1
            || _previousStreamVersion == long.MaxValue
            || row.StreamVersion.Value != _previousStreamVersion + 1)
            throw new VaultRecoveryRequiredException();

        _nextIndex++;
        _previousGlobalPosition = row.GlobalPosition;
        _previousStreamVersion = row.StreamVersion.Value;
    }

    public void Complete() => CompleteCurrent();

    private void CompleteCurrent()
    {
        if (!_hasCurrent) return;
        if (_nextIndex != _declaredCount || !_completed.Add(_currentOperation))
            throw new VaultRecoveryRequiredException();
        _hasCurrent = false;
        _currentStream = null;
    }
}
