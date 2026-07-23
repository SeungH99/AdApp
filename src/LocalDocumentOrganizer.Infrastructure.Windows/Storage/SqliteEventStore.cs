using System.Globalization;
using LocalDocumentOrganizer.Core.Deletion;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public sealed class SqliteEventStore : IEventStore, ISensitiveDataDeletionStore
{
    private readonly string _connectionString;
    private readonly EventSchemaRegistry _schemaRegistry;
    private readonly IReadOnlyList<ISqliteProjection> _projections;
    private readonly IReadOnlyList<SqliteProjectionRegistration> _projectionRegistrations;
    private readonly SqliteProjectionRegistry _projectionRegistry;
    private readonly TimeProvider _timeProvider;
    private readonly SqliteEventPayloadProtectionProvider _payloads;
    private readonly SqliteSensitiveDataDeletionStore _deletions;

    public SqliteEventStore(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        TimeProvider? timeProvider = null)
        : this(connectionString, schemaRegistry, SqliteProjectionRegistry.Empty, timeProvider)
    {
    }

    internal SqliteEventStore(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        SqliteProjectionRegistry projections,
        TimeProvider? timeProvider = null)
        : this(
            connectionString,
            schemaRegistry,
            projections,
            timeProvider,
            keyRing: null)
    {
    }

    internal SqliteEventStore(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        TimeProvider? timeProvider = null)
        : this(
            connectionString,
            schemaRegistry,
            projections,
            timeProvider,
            RequireKeyRing(keyRing))
    {
    }

    internal SqliteEventStore(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        TimeProvider? timeProvider,
        ISqliteSensitiveDataDeletionFaultInjector faultInjector)
        : this(
            connectionString,
            schemaRegistry,
            projections,
            timeProvider,
            RequireKeyRing(keyRing),
            faultInjector)
    {
    }

    private SqliteEventStore(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        SqliteProjectionRegistry projections,
        TimeProvider? timeProvider,
        VaultKeyRingStore? keyRing,
        ISqliteSensitiveDataDeletionFaultInjector? faultInjector = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(schemaRegistry);
        ArgumentNullException.ThrowIfNull(projections);
        _schemaRegistry = schemaRegistry;
        _projectionRegistry = projections;
        _projections = projections.Projections;
        _projectionRegistrations = projections.Registrations;
        _connectionString = SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _payloads = new SqliteEventPayloadProtectionProvider(
            keyRing ?? CreateDefaultKeyRing(_connectionString));
        _deletions = new SqliteSensitiveDataDeletionStore(
            _connectionString,
            _schemaRegistry,
            _projectionRegistry,
            _payloads.KeyRing,
            _timeProvider,
            faultInjector);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _payloads.KeyRing.MaintenanceGate);
        await using var lease = await _payloads.KeyRing.MaintenanceGate
            .AcquireMutationAsync(cancellationToken)
            .ConfigureAwait(false);
        await SqliteSecureCompactor.RecoverCanonicalWalAsync(
            _connectionString,
            _projectionRegistry,
            _payloads.KeyRing,
            lease,
            cancellationToken).ConfigureAwait(false);
        await ProjectionRebuildWorkspace.CleanupOrphansAsync(
            _connectionString,
            _projectionRegistry,
            _payloads.KeyRing,
            lease,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.InitializeAsync(
            _connectionString,
            _projectionRegistry,
            _payloads.KeyRing,
            lease,
            cancellationToken).ConfigureAwait(false);
        await _deletions.RecoverAsync(lease, cancellationToken).ConfigureAwait(false);
        await new SqliteSecureCompactor(
            _connectionString,
            _projectionRegistry,
            _payloads.KeyRing).RecoverAsync(lease, cancellationToken).ConfigureAwait(false);
    }

    public Task<ProjectionRebuildResult> RebuildProjectionsAsync(CancellationToken cancellationToken = default) =>
        new SqliteProjectionRebuilder(
            _connectionString, _schemaRegistry, _projectionRegistry, _payloads)
            .RebuildAsync(cancellationToken);

    public Task<DeleteSensitiveObjectResult> DeleteAsync(
        DeleteSensitiveObjectCommand command,
        CancellationToken cancellationToken) =>
        _deletions.DeleteAsync(command, cancellationToken);

    public async Task<IReadOnlyList<EventForReplay>> ReadStreamAsync(StreamId streamId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString, _payloads.KeyRing.MaintenanceGate);
        await using var lease = await _payloads.KeyRing.MaintenanceGate.AcquireReadAsync(cancellationToken);
        await using var payloadSession = _payloads.CreateReadSession(lease);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString, _payloads.KeyRing.MaintenanceGate, cancellationToken);
        await using var schemaTransaction = connection.BeginTransaction(deferred: true);
        try
        {
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(connection, schemaTransaction, cancellationToken);
            await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                connection, schemaTransaction, _projectionRegistry, cancellationToken);
            payloadSession.BindExpectedIdentity(
                await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                    connection, schemaTransaction, cancellationToken));
            var events = await ReadStreamFromValidatedConnectionAsync(
                connection,
                schemaTransaction,
                streamId,
                _schemaRegistry,
                payloadSession,
                cancellationToken).ConfigureAwait(false);
            await schemaTransaction.CommitAsync(cancellationToken);
            return events;
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (SqliteException exception) { throw new VaultRecoveryRequiredException(exception); }
    }

    internal static async Task<IReadOnlyList<EventForReplay>> ReadStreamFromValidatedConnectionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        StreamId streamId,
        EventSchemaRegistry schemaRegistry,
        SqliteEventPayloadReadSession payloadSession,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT global_position, stream_id, stream_version, event_id, event_type, schema_version,
                   recorded_at_utc, operation_id, operation_index, operation_count,
                   protection_kind, owner_kind, owner_id, key_id, envelope_version, payload_nonce,
                   payload_ciphertext, payload_tag
            FROM main.timeline_events
            WHERE CAST(stream_id AS TEXT) COLLATE NOCASE = $stream_id_text
            ORDER BY global_position;
            """;
        AddStreamLookupParameters(command, streamId);
        var persistedRows = new List<PersistedTimelineRow>();
        var operationGroups = new OperationGroupSequenceValidator();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var row = ReadPersistedTimelineRow(reader);
                if (row.Event.Metadata.StreamId != streamId)
                    throw new VaultRecoveryRequiredException();
                operationGroups.Accept(row.Coordinates);
                persistedRows.Add(row);
            }
        }
        operationGroups.Complete();

        var storedHead = await ReadHeadAsync(
            connection,
            transaction,
            streamId,
            cancellationToken);
        if (persistedRows.Count == 0)
        {
            if (storedHead is not null)
                throw new EventStreamCorruptionException("A stream head has no timeline events.");
        }
        else
        {
            for (var index = 0; index < persistedRows.Count; index++)
            {
                if (persistedRows[index].Event.Metadata.StreamVersion != new StreamVersion(index))
                    throw new EventStreamCorruptionException(
                        "A stream contains a noncontiguous version sequence.");
            }
            if (storedHead != persistedRows[^1].Event.Metadata.StreamVersion)
                throw new EventStreamCorruptionException(
                    "A stream head does not match its timeline events.");
        }

        var events = new List<EventForReplay>(persistedRows.Count);
        foreach (var row in persistedRows)
        {
            var replay = await payloadSession.UnprotectAsync(row.Event, cancellationToken)
                .ConfigureAwait(false);
            events.Add(replay is ShreddedEvent
                ? replay
                : schemaRegistry.UpcastToCurrent((DecryptedEvent)replay));
        }
        return events.AsReadOnly();
    }

    public async Task<AppendEventsResult> AppendAsync(AppendEventsCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ValidateAppendBatchIdentifiers(command.Events);
        RejectReservedDeletionEvents(command.Events);
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString, _payloads.KeyRing.MaintenanceGate);
        await using var lease = await _payloads.KeyRing.MaintenanceGate.AcquireMutationAsync(cancellationToken);
        VaultKeyRingStore.VaultKeyRingSession? keySession = null;
        SqliteConnection? connection = null;
        SqliteTransaction? transaction = null;
        try
        {
            connection = await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString, _payloads.KeyRing.MaintenanceGate, cancellationToken);
            transaction = connection.BeginTransaction(deferred: false);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(connection, transaction, cancellationToken);
            await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                connection, transaction, _projectionRegistry, cancellationToken);
            var expectedKeyRingIdentity =
                await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                    connection, transaction, cancellationToken);
            await SqliteSensitiveDataDeletionStore.RequireNoPendingReceiptsAsync(
                _payloads.KeyRing,
                expectedKeyRingIdentity,
                cancellationToken);
            keySession = await _payloads.OpenWriteSessionAsync(
                lease, expectedKeyRingIdentity, cancellationToken);
            await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
                connection, transaction, keySession.Identity, cancellationToken);
            var existing = await ReadOperationAsync(connection, transaction, command.OperationId, cancellationToken);
            if (existing.Count != 0)
            {
                ValidateOperationGroup(existing, command.OperationId);
                var comparison = await CompareRetryAsync(existing, command, keySession, cancellationToken);
                if (comparison is RetryComparison.Exact or RetryComparison.Unavailable)
                {
                    await ValidateTargetStreamMetadataAsync(
                        connection, transaction, command.StreamId, expectedHead: null,
                        cancellationToken: cancellationToken);
                }
                await transaction.RollbackAsync(cancellationToken);
                return comparison switch
                {
                    RetryComparison.Exact => new AlreadyApplied(existing[^1].Event.Metadata.StreamVersion),
                    RetryComparison.Unavailable => new OperationComparisonUnavailable(command.OperationId),
                    _ => new OperationConflict(command.OperationId),
                };
            }
            ValidateCurrentEventSchemas(command.Events);
            var rebuildRequirement = await SqliteProjectionCheckpointStore.FindRebuildRequirementAsync(
                connection, transaction, _projectionRegistrations, cancellationToken);
            if (rebuildRequirement.ProjectionNames.Count != 0)
                throw new ProjectionRebuildRequiredException(rebuildRequirement.ProjectionNames, rebuildRequirement.RequiredGlobalPosition);

            await ValidateTargetStreamMetadataAsync(
                connection, transaction, command.StreamId, expectedHead: null,
                cancellationToken: cancellationToken);
            var newVersion = new StreamVersion(checked(command.ExpectedVersion.Value + command.Events.Count));
            var actualVersion = await ReserveStreamAsync(connection, transaction, command.StreamId, command.ExpectedVersion, newVersion, cancellationToken);
            if (actualVersion is not null)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new ConcurrencyConflict(command.ExpectedVersion, actualVersion.Value);
            }
            var streamVersion = command.ExpectedVersion;
            var appendedSnapshots = new List<AppendedEventSnapshot>(command.Events.Count);
            for (var operationIndex = 0; operationIndex < command.Events.Count; operationIndex++)
            {
                var eventToAppend = command.Events[operationIndex];
                streamVersion = streamVersion.Next();
                var recordedAtUtc = _timeProvider.GetUtcNow();
                var recordedAtText = recordedAtUtc.ToUniversalTime()
                    .ToString("O", CultureInfo.InvariantCulture);
                var protectedPayload = await _payloads.ProtectAsync(
                    eventToAppend, command.StreamId, streamVersion, command.OperationId,
                    keySession, cancellationToken);
                var globalPosition = await InsertEventAsync(connection, transaction, command.StreamId, streamVersion,
                    eventToAppend, command.OperationId, operationIndex, command.Events.Count,
                    recordedAtText, protectedPayload, cancellationToken);
                appendedSnapshots.Add(AppendedEventSnapshot.Create(
                    globalPosition,
                    command.StreamId,
                    streamVersion,
                    eventToAppend,
                    command.OperationId,
                    operationIndex,
                    command.Events.Count,
                    recordedAtText,
                    protectedPayload));
                var metadata = new EventMetadata(command.StreamId, streamVersion, eventToAppend.EventId, eventToAppend.EventType, eventToAppend.SchemaVersion, recordedAtUtc, command.OperationId, protectedPayload.KeyId, protectedPayload.EnvelopeVersion);
                var decrypted = new DecryptedEvent(metadata, eventToAppend.Payload);
                foreach (var registration in _projectionRegistrations)
                {
                    var projection = registration.Projection;
                    await SqliteProjectionAuthorizer.RunAsync(
                        connection,
                        registration,
                        _projectionRegistry.AllowsLegacyTestObjects,
                        () => projection.ApplyAsync(
                            decrypted,
                            globalPosition,
                            protectedPayload.Owner is { } owner
                                && protectedPayload.KeyId is { } dataKeyId
                                ? SqliteProjectionContexts.CreateApply(
                                    connection,
                                    transaction,
                                    _payloads.KeyRing,
                                    keySession,
                                    registration,
                                    owner,
                                    dataKeyId)
                                : SqliteProjectionContexts.CreateDisabledApply(
                                    connection,
                                    transaction),
                            cancellationToken));
                    await SqliteProjectionCheckpointStore.AdvanceAsync(
                        connection, transaction, registration, globalPosition, cancellationToken);
                }
            }
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                connection, transaction, cancellationToken);
            await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                connection, transaction, _projectionRegistry, cancellationToken);
            var appended = await ReadOperationAsync(
                connection, transaction, command.OperationId, cancellationToken);
            ValidateOperationGroup(appended, command.OperationId);
            await RequireExactAppendedOperationAsync(
                appended, appendedSnapshots, command, keySession, cancellationToken);
            await ValidateTargetStreamMetadataAsync(
                connection, transaction, command.StreamId, newVersion, cancellationToken);
            await keySession.RequireCanonicalImageAsync(cancellationToken);
            await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
                connection, transaction, keySession.Identity, cancellationToken);
            SqliteEventStoreSchema.ValidateVaultPath(
                _connectionString, _payloads.KeyRing.MaintenanceGate);
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
            if (keySession is not null) await keySession.DisposeAsync();
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

    private async Task RequireExactAppendedOperationAsync(
        IReadOnlyList<PersistedOperationEvent> actual,
        IReadOnlyList<AppendedEventSnapshot> expected,
        AppendEventsCommand command,
        VaultKeyRingStore.VaultKeyRingSession keySession,
        CancellationToken cancellationToken)
    {
        if (actual.Count != expected.Count || actual.Count != command.Events.Count)
            throw new VaultRecoveryRequiredException();

        for (var index = 0; index < expected.Count; index++)
        {
            if (!expected[index].ExactEquals(actual[index]))
                throw new VaultRecoveryRequiredException();

            var replay = await _payloads.UnprotectAsync(
                actual[index].Event, keySession, cancellationToken);
            if (replay is not DecryptedEvent decrypted)
                throw new VaultRecoveryRequiredException();
            var actualPayload = decrypted.Payload;
            var expectedPayload = command.Events[index].Payload;
            try
            {
                if (!actualPayload.Span.SequenceEqual(expectedPayload.Span))
                    throw new VaultRecoveryRequiredException();
            }
            finally
            {
                ZeroMemory(actualPayload);
                ZeroMemory(expectedPayload);
            }
        }
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

    private static void RejectReservedDeletionEvents(IReadOnlyList<EventToAppend> events)
    {
        foreach (var eventToAppend in events)
        {
            if (string.Equals(
                eventToAppend.EventType,
                SensitiveObjectDeletedEventContract.EventType,
                StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The sensitive-object deletion event is reserved for the deletion store.",
                    nameof(events));
            }
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

    private static VaultKeyRingStore CreateDefaultKeyRing(string connectionString)
    {
        var source = new SqliteConnectionStringBuilder(connectionString).DataSource;
        if (string.IsNullOrWhiteSpace(source) || source == ":memory:") throw new ArgumentException("Encrypted Vault storage requires a file-backed data source.", nameof(connectionString));
        return new VaultKeyRingStore(source + ".keyring");
    }

    private static VaultKeyRingStore RequireKeyRing(VaultKeyRingStore? keyRing) =>
        keyRing ?? throw new ArgumentNullException(nameof(keyRing));

    private static async Task<StreamVersion?> ReserveStreamAsync(SqliteConnection c, SqliteTransaction t, StreamId stream, StreamVersion expected, StreamVersion next, CancellationToken ct)
    {
        var actual = await ReadHeadAsync(c, t, stream, ct);
        if (expected == StreamVersion.NoStream)
        {
            if (actual is not null) return actual;
            await using var insert = c.CreateCommand();
            insert.Transaction = t;
            insert.CommandText = "INSERT INTO main.event_streams(stream_id, head_version) VALUES($id, $version);";
            insert.Parameters.AddWithValue("$id", stream.Value.ToString("D"));
            insert.Parameters.AddWithValue("$version", next.Value);
            if (await insert.ExecuteNonQueryAsync(ct) != 1)
                throw new VaultRecoveryRequiredException();
            return null;
        }

        if (actual is null || actual != expected)
            return actual ?? StreamVersion.NoStream;

        await using var update = c.CreateCommand();
        update.Transaction = t;
        update.CommandText = "UPDATE main.event_streams SET head_version=$next WHERE stream_id=$id AND head_version=$expected;";
        update.Parameters.AddWithValue("$next", next.Value);
        update.Parameters.AddWithValue("$id", stream.Value.ToString("D"));
        update.Parameters.AddWithValue("$expected", expected.Value);
        if (await update.ExecuteNonQueryAsync(ct) != 1)
            throw new VaultRecoveryRequiredException();
        return null;
    }

    private static async Task<StreamVersion?> ReadHeadAsync(SqliteConnection c, SqliteTransaction t, StreamId stream, CancellationToken ct)
    {
        try
        {
            await using var command = c.CreateCommand();
            command.Transaction = t;
            command.CommandText = """
                SELECT stream_id, head_version
                FROM main.event_streams
                WHERE CAST(stream_id AS TEXT) COLLATE NOCASE = $stream_id_text;
                """;
            AddStreamLookupParameters(command, stream);
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) return null;
            var persistedId = ParseCanonicalGuid(ReadRequiredText(reader, 0));
            if (persistedId != stream.Value
                || reader.GetValue(1) is not long head
                || head < 0
                || await reader.ReadAsync(ct))
            {
                throw new VaultRecoveryRequiredException();
            }
            return new StreamVersion(head);
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException or FormatException
            or OverflowException or ArgumentOutOfRangeException or InvalidOperationException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static async Task ValidateTargetStreamMetadataAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        StreamId stream,
        StreamVersion? expectedHead,
        CancellationToken cancellationToken)
    {
        try
        {
            var canonical = stream.Value.ToString("D");
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT COUNT(*),
                       COALESCE(SUM(CASE WHEN typeof(stream_id) <> 'text'
                                          OR stream_id COLLATE BINARY <> $stream_id_text
                                         THEN 1 ELSE 0 END), 0),
                       MIN(CASE WHEN typeof(stream_version) = 'integer' THEN stream_version END),
                       MAX(CASE WHEN typeof(stream_version) = 'integer' THEN stream_version END),
                       COUNT(DISTINCT CASE WHEN typeof(stream_version) = 'integer'
                                           THEN stream_version END),
                       COALESCE(SUM(CASE WHEN typeof(stream_version) <> 'integer'
                                          OR stream_version < 0
                                         THEN 1 ELSE 0 END), 0)
                FROM main.timeline_events
                WHERE CAST(stream_id AS TEXT) COLLATE NOCASE = $stream_id_text;
                """;
            command.Parameters.Add("$stream_id_text", SqliteType.Text).Value = canonical;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
                throw new VaultRecoveryRequiredException();

            var total = ReadRequiredInteger(reader, 0);
            var invalidRepresentationCount = ReadRequiredInteger(reader, 1);
            var minimum = reader.GetValue(2);
            var maximum = reader.GetValue(3);
            var distinctVersionCount = ReadRequiredInteger(reader, 4);
            var invalidVersionCount = ReadRequiredInteger(reader, 5);
            if (await reader.ReadAsync(cancellationToken))
                throw new VaultRecoveryRequiredException();

            var head = await ReadHeadAsync(connection, transaction, stream, cancellationToken);
            if (expectedHead is not null && head != expectedHead)
                throw new VaultRecoveryRequiredException();
            if (total == 0)
            {
                if (invalidRepresentationCount != 0
                    || minimum is not DBNull
                    || maximum is not DBNull
                    || distinctVersionCount != 0
                    || invalidVersionCount != 0
                    || head is not null)
                {
                    throw new VaultRecoveryRequiredException();
                }

                return;
            }

            if (total < 0
                || invalidRepresentationCount != 0
                || invalidVersionCount != 0
                || minimum is not long minimumVersion
                || maximum is not long maximumVersion
                || head is null
                || minimumVersion != 0
                || maximumVersion != head.Value.Value
                || distinctVersionCount != total
                || checked(head.Value.Value + 1) != total)
            {
                throw new VaultRecoveryRequiredException();
            }
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException
            or FormatException or OverflowException or InvalidOperationException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static void AddStreamLookupParameters(SqliteCommand command, StreamId stream)
    {
        var canonical = stream.Value.ToString("D");
        command.Parameters.Add("$stream_id_text", SqliteType.Text).Value = canonical;
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
        string recordedAtUtc,
        ProtectedEventPayload p,
        CancellationToken ct)
    {
        await using var command = c.CreateCommand(); command.Transaction = t;
        command.CommandText = "INSERT INTO main.timeline_events(event_id,stream_id,stream_version,event_type,schema_version,recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag) VALUES($event,$stream,$version,$type,$schema,$recorded,$operation,$operationIndex,$operationCount,$kind,$ownerKind,$ownerId,$key,$envelope,$nonce,$cipher,$tag) RETURNING global_position;";
        command.Parameters.AddWithValue("$event", e.EventId.Value.ToString("D")); command.Parameters.AddWithValue("$stream", stream.Value.ToString("D")); command.Parameters.AddWithValue("$version", version.Value); command.Parameters.AddWithValue("$type", e.EventType); command.Parameters.AddWithValue("$schema", e.SchemaVersion); command.Parameters.AddWithValue("$recorded", recordedAtUtc); command.Parameters.AddWithValue("$operation", operation.Value.ToString("D")); command.Parameters.AddWithValue("$operationIndex", operationIndex); command.Parameters.AddWithValue("$operationCount", operationCount); command.Parameters.AddWithValue("$kind", (int)p.Kind); command.Parameters.AddWithValue("$ownerKind", p.Owner is null ? DBNull.Value : (object)(int)p.Owner.Value.Kind); command.Parameters.AddWithValue("$ownerId", p.Owner is null ? DBNull.Value : p.Owner.Value.Id.Value.ToString("D")); command.Parameters.AddWithValue("$key", p.KeyId is null ? DBNull.Value : p.KeyId.Value.Value.ToString("D")); command.Parameters.AddWithValue("$envelope", p.EnvelopeVersion);
        command.Parameters.Add("$nonce", SqliteType.Blob).Value = p.Nonce ?? (object)DBNull.Value; command.Parameters.Add("$cipher", SqliteType.Blob).Value = p.Ciphertext; command.Parameters.Add("$tag", SqliteType.Blob).Value = p.Tag ?? (object)DBNull.Value;
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct), CultureInfo.InvariantCulture);
    }

    internal static async Task ValidateAllOperationMetadataAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken,
        bool useProjectionRebuildCorruptionContract = false)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT global_position,stream_id,stream_version,operation_id,operation_index,operation_count
            FROM main.timeline_events
            ORDER BY global_position;
            """;
        var validator = new OperationGroupSequenceValidator();
        var computedHeads = new Dictionary<StreamId, StreamVersion>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var coordinates = ReadOperationCoordinates(reader);
            try
            {
                validator.Accept(coordinates);
            }
            catch (VaultRecoveryRequiredException) when (useProjectionRebuildCorruptionContract)
            {
                throw ProjectionRebuildStreamCorruption();
            }
            StreamVersion expected;
            try
            {
                expected = computedHeads.TryGetValue(coordinates.StreamId, out var head)
                    ? head.Next()
                    : new StreamVersion(0);
            }
            catch (Exception exception) when (exception is ArgumentOutOfRangeException or OverflowException)
            {
                throw new VaultRecoveryRequiredException(exception);
            }
            if (coordinates.StreamVersion != expected)
            {
                if (useProjectionRebuildCorruptionContract)
                    throw ProjectionRebuildStreamCorruption();
                throw new VaultRecoveryRequiredException();
            }
            computedHeads[coordinates.StreamId] = coordinates.StreamVersion;
        }
        try
        {
            validator.Complete();
        }
        catch (VaultRecoveryRequiredException) when (useProjectionRebuildCorruptionContract)
        {
            throw ProjectionRebuildStreamCorruption();
        }
        await ValidateStoredStreamHeadsAsync(
            connection,
            transaction,
            computedHeads,
            cancellationToken,
            useProjectionRebuildCorruptionContract);
    }

    internal static async Task ValidateStoredStreamHeadsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyDictionary<StreamId, StreamVersion> computedHeads,
        CancellationToken cancellationToken,
        bool useProjectionRebuildCorruptionContract = false)
    {
        var unmatched = new Dictionary<StreamId, StreamVersion>(computedHeads);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT stream_id, head_version
            FROM main.event_streams
            ORDER BY stream_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            StreamId stream;
            StreamVersion head;
            try
            {
                stream = new StreamId(ParseCanonicalGuid(ReadRequiredText(reader, 0)));
                var value = ReadRequiredInteger(reader, 1);
                if (value < 0) throw new VaultRecoveryRequiredException();
                head = new StreamVersion(value);
            }
            catch (VaultRecoveryRequiredException) { throw; }
            catch (Exception exception) when (exception is ArgumentException or InvalidCastException
                or FormatException or OverflowException or InvalidOperationException)
            {
                throw new VaultRecoveryRequiredException(exception);
            }

            if (!unmatched.Remove(stream, out var expected) || head != expected)
            {
                if (useProjectionRebuildCorruptionContract)
                    throw ProjectionRebuildStreamCorruption();
                throw new VaultRecoveryRequiredException();
            }
        }

        if (unmatched.Count != 0)
        {
            if (useProjectionRebuildCorruptionContract)
                throw ProjectionRebuildStreamCorruption();
            throw new VaultRecoveryRequiredException();
        }
    }

    private static EventStreamCorruptionException ProjectionRebuildStreamCorruption() =>
        new("Stored event stream operation metadata is inconsistent.");

    private static async Task<IReadOnlyList<PersistedOperationEvent>> ReadOperationAsync(SqliteConnection c, SqliteTransaction t, OperationId operation, CancellationToken ct)
    {
        await ValidateOperationIdentifierRepresentationsAsync(c, t, operation, ct);
        await using var command = c.CreateCommand(); command.Transaction = t; command.CommandText = "SELECT global_position,stream_id,stream_version,event_id,event_type,schema_version,recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag FROM main.timeline_events WHERE operation_id COLLATE NOCASE IN ($operation,CAST($operation AS BLOB),CAST(upper($operation) AS BLOB)) ORDER BY global_position;"; command.Parameters.AddWithValue("$operation", operation.Value.ToString("D"));
        var values = new List<PersistedOperationEvent>(); await using var reader = await command.ExecuteReaderAsync(ct); while (await reader.ReadAsync(ct)) { var row = ReadPersistedTimelineRow(reader); values.Add(new PersistedOperationEvent(row.GlobalPosition, row.OperationIndex, row.OperationCount, row.RecordedAtUtcText, row.Event)); } return values;
    }

    private static async Task ValidateOperationIdentifierRepresentationsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        OperationId operation,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT operation_id
            FROM main.timeline_events
            WHERE CAST(operation_id AS TEXT) COLLATE NOCASE = $operation
            ORDER BY global_position;
            """;
        command.Parameters.AddWithValue("$operation", operation.Value.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (ParseCanonicalGuid(ReadRequiredText(reader, 0)) != operation.Value)
                throw new VaultRecoveryRequiredException();
        }
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
                var isEncryptedEnvelope = nonce.Length == AesGcmRecordProtector.NonceSize
                    && tag.Length == AesGcmRecordProtector.TagSize;
                var isStructurallyShredded = nonce.Length == 0
                    && ciphertext.Length == 0
                    && tag.Length == 0;
                if (!isEncryptedEnvelope && !isStructurallyShredded)
                    throw new VaultRecoveryRequiredException();
            }
            var metadata = new EventMetadata(stream, streamVersion, eventId, eventType, schemaVersion,
                recorded, operationId, keyId, envelopeVersion);
            return new PersistedTimelineRow(globalPosition, operationIndex, operationCount, recordedText,
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
        string RecordedAtUtcText,
        PersistedProtectedEvent Event);

    private sealed record AppendedEventSnapshot(
        long GlobalPosition,
        StreamId StreamId,
        StreamVersion StreamVersion,
        EventId EventId,
        string EventType,
        int SchemaVersion,
        string RecordedAtUtcText,
        OperationId OperationId,
        int OperationIndex,
        int OperationCount,
        PersistedProtectionKind Kind,
        SensitiveObjectRef? Owner,
        DataKeyId? KeyId,
        int EnvelopeVersion,
        byte[]? Nonce,
        byte[] Ciphertext,
        byte[]? Tag)
    {
        internal static AppendedEventSnapshot Create(
            long globalPosition,
            StreamId streamId,
            StreamVersion streamVersion,
            EventToAppend eventToAppend,
            OperationId operationId,
            int operationIndex,
            int operationCount,
            string recordedAtUtcText,
            ProtectedEventPayload payload) =>
            new(
                globalPosition,
                streamId,
                streamVersion,
                eventToAppend.EventId,
                eventToAppend.EventType,
                eventToAppend.SchemaVersion,
                recordedAtUtcText,
                operationId,
                operationIndex,
                operationCount,
                payload.Kind,
                payload.Owner,
                payload.KeyId,
                payload.EnvelopeVersion,
                payload.Nonce?.ToArray(),
                payload.Ciphertext.ToArray(),
                payload.Tag?.ToArray());

        internal bool ExactEquals(PersistedOperationEvent actual)
        {
            var persisted = actual.Event;
            return actual.GlobalPosition == GlobalPosition
                && actual.OperationIndex == OperationIndex
                && actual.OperationCount == OperationCount
                && string.Equals(actual.RecordedAtUtcText, RecordedAtUtcText, StringComparison.Ordinal)
                && persisted.Metadata.StreamId == StreamId
                && persisted.Metadata.StreamVersion == StreamVersion
                && persisted.Metadata.EventId == EventId
                && string.Equals(persisted.Metadata.EventType, EventType, StringComparison.Ordinal)
                && persisted.Metadata.SchemaVersion == SchemaVersion
                && persisted.Metadata.OperationId == OperationId
                && persisted.Kind == Kind
                && persisted.Owner == Owner
                && persisted.Metadata.DataKeyId == KeyId
                && persisted.Metadata.EncryptionEnvelopeVersion == EnvelopeVersion
                && NullableBytesEqual(persisted.Nonce, Nonce)
                && persisted.Ciphertext.AsSpan().SequenceEqual(Ciphertext)
                && NullableBytesEqual(persisted.Tag, Tag);
        }

        private static bool NullableBytesEqual(byte[]? left, byte[]? right) =>
            left is null ? right is null : right is not null && left.AsSpan().SequenceEqual(right);
    }
}

internal sealed record PersistedTimelineRow(
    long GlobalPosition,
    int OperationIndex,
    int OperationCount,
    string RecordedAtUtcText,
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
            if (row.OperationIndex != 0
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
        if (_nextIndex != _declaredCount)
            throw new VaultRecoveryRequiredException();
        _hasCurrent = false;
        _currentStream = null;
    }
}
