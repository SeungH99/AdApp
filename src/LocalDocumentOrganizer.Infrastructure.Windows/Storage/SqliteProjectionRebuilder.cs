using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Deletion;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal sealed class SqliteProjectionRebuilder
{
    private const int BatchSize = 256;

    private readonly string _connectionString;
    private readonly EventSchemaRegistry _schemaRegistry;
    private readonly IReadOnlyList<SqliteProjectionRegistration> _projectionRegistrations;
    private readonly SqliteProjectionRegistry _projectionRegistry;
    private readonly SqliteEventPayloadProtectionProvider _payloads;
    private readonly ProjectionRebuildValidator _validator = new();
    private readonly Action<ProjectionRebuildFaultPoint>? _injectFault;

    internal SqliteProjectionRebuilder(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        SqliteProjectionRegistry projections,
        SqliteEventPayloadProtectionProvider payloads,
        Action<ProjectionRebuildFaultPoint>? injectFault = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(schemaRegistry);
        ArgumentNullException.ThrowIfNull(projections);
        ArgumentNullException.ThrowIfNull(payloads);
        _connectionString = connectionString;
        _schemaRegistry = schemaRegistry;
        _projectionRegistry = projections;
        _projectionRegistrations = projections.Registrations;
        _payloads = payloads;
        _injectFault = injectFault;
    }

    internal async Task<ProjectionRebuildResult> RebuildAsync(
        CancellationToken cancellationToken)
    {
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _payloads.KeyRing.MaintenanceGate);
        await using var lease = await _payloads.KeyRing.MaintenanceGate
            .AcquireRebuildAsync(cancellationToken)
            .ConfigureAwait(false);

        ProjectionRebuildWorkspace? workspace = null;
        var promoted = false;
        try
        {
            var source = await ReadRebuildRequirementAndSnapshotAsync(
                lease,
                cancellationToken).ConfigureAwait(false);
            var selectedNames = source.ProjectionNames.ToHashSet(StringComparer.Ordinal);
            var selected = _projectionRegistrations
                .Where(registration => selectedNames.Contains(registration.Name))
                .ToArray();
            if (selected.Length != source.ProjectionNames.Length)
                throw new VaultRecoveryRequiredException();

            if (selected.Length == 0)
            {
                return new ProjectionRebuildResult(
                    source.TotalEventCount,
                    source.StreamHeads,
                    source.CompatibleProjectionChecksums);
            }

            workspace = await ProjectionRebuildWorkspace.CreateAsync(
                _connectionString,
                lease,
                cancellationToken,
                _injectFault).ConfigureAwait(false);
            InjectFault(ProjectionRebuildFaultPoint.AfterArtifactCreated);
            ProjectionRebuildValidationResult validated;
            IReadOnlyList<SqliteProjectionRegistration> effectiveSelected;
            await using (var temporaryTransaction = workspace.Connection.BeginTransaction(deferred: false))
            {
                effectiveSelected = await InitializeSelectedAsync(
                    workspace.Connection,
                    temporaryTransaction,
                    selected,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                InjectFault(ProjectionRebuildFaultPoint.AfterProjectionInitialized);
                var replay = await ReplaySelectedAsync(
                    workspace.Connection,
                    temporaryTransaction,
                    source,
                    effectiveSelected,
                    workspace.GenerationId,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                InjectFault(ProjectionRebuildFaultPoint.BeforeTemporaryValidation);
                validated = await _validator.ValidateTemporaryAsync(
                    workspace.Connection,
                    temporaryTransaction,
                    effectiveSelected,
                    replay,
                    _payloads.KeyRing,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                await temporaryTransaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }

            InjectFault(ProjectionRebuildFaultPoint.BeforePromotion);
            await workspace.PromoteAsync(
                _connectionString,
                effectiveSelected,
                validated,
                _projectionRegistry,
                _payloads.KeyRing,
                lease,
                cancellationToken).ConfigureAwait(false);
            promoted = true;
            await workspace.CompleteAsync(
                ProjectionRebuildCommitState.Committed,
                primaryFailure: null,
                lease,
                CancellationToken.None).ConfigureAwait(false);

            var checksums = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (var registration in _projectionRegistrations)
            {
                if (validated.ProjectionChecksums.TryGetValue(registration.Name, out var selectedChecksum))
                    checksums.Add(registration.Name, selectedChecksum);
                else if (source.CompatibleProjectionChecksums.TryGetValue(
                    registration.Name,
                    out var compatibleChecksum))
                    checksums.Add(registration.Name, compatibleChecksum);
                else
                    throw new VaultRecoveryRequiredException();
            }

            return new ProjectionRebuildResult(
                source.TotalEventCount,
                source.StreamHeads,
                checksums);
        }
        catch (ProjectionPromotionOutcomeUnknownException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
        {
            var capacityFailure = new StorageCapacityException(exception);
            if (workspace is not null && !promoted)
            {
                await workspace.CompleteAsync(
                    ProjectionRebuildCommitState.PreCommit,
                    ExceptionDispatchInfo.Capture(capacityFailure),
                    lease,
                    CancellationToken.None).ConfigureAwait(false);
            }

            throw capacityFailure;
        }
        catch (Exception exception)
        {
            var primary = ExceptionDispatchInfo.Capture(exception);
            if (workspace is not null && !promoted)
            {
                await workspace.CompleteAsync(
                    ProjectionRebuildCommitState.PreCommit,
                    primary,
                    lease,
                    CancellationToken.None).ConfigureAwait(false);
            }

            primary.Throw();
            throw;
        }
        finally
        {
            if (workspace is not null)
                await workspace.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task<ProjectionRebuildSourceSnapshot> ReadRebuildRequirementAndSnapshotAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString,
            _payloads.KeyRing.MaintenanceGate,
            cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
            connection,
            transaction,
            _projectionRegistry,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStore.ValidateAllOperationMetadataAsync(
            connection,
            transaction,
            cancellationToken,
            useProjectionRebuildCorruptionContract: true).ConfigureAwait(false);
        var identity = await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
        var keyRing = await SqliteSensitiveDataDeletionStore.RequireNoPendingReceiptsAsync(
            _payloads.KeyRing,
            identity,
            cancellationToken).ConfigureAwait(false);
        var requirement = await SqliteProjectionCheckpointStore.FindRebuildRequirementAsync(
            connection,
            transaction,
            _projectionRegistrations,
            cancellationToken).ConfigureAwait(false);
        var selectedNames = requirement.ProjectionNames.ToHashSet(StringComparer.Ordinal);
        var (totalEventCount, streamHeads) = await ReadAuthoritativeCoordinatesAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);

        var compatibleChecksums = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var registration in _projectionRegistrations)
        {
            if (selectedNames.Contains(registration.Name)) continue;
            var checksum = await RunProjectionAsync(
                connection,
                registration,
                () => registration.Projection.CalculateChecksumAsync(
                    SqliteProjectionContexts.CreateAdministrative(
                        connection,
                        transaction,
                        _payloads.KeyRing,
                        lease,
                        registration),
                    cancellationToken)).ConfigureAwait(false);
            RequireChecksum(registration.Name, checksum);
            compatibleChecksums.Add(registration.Name, checksum);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return ProjectionRebuildSourceSnapshot.Create(
            totalEventCount,
            requirement.RequiredGlobalPosition,
            requirement.ProjectionNames,
            streamHeads,
            compatibleChecksums,
            identity,
            keyRing.DestroyedReceipts);
    }

    private async Task<IReadOnlyList<SqliteProjectionRegistration>> InitializeSelectedAsync(
        SqliteConnection temporaryConnection,
        SqliteTransaction temporaryTransaction,
        IReadOnlyList<SqliteProjectionRegistration> selected,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        var effective = new List<SqliteProjectionRegistration>(selected.Count);
        foreach (var registration in selected)
        {
            var before = _projectionRegistry.AllowsLegacyTestObjects
                ? await ReadTemporaryProjectionTablesAsync(
                    temporaryConnection,
                    temporaryTransaction,
                    cancellationToken).ConfigureAwait(false)
                : null;
            _ = await SqliteProjectionAuthorizer.RunAsync(
                temporaryConnection,
                registration,
                _projectionRegistry.AllowsLegacyTestObjects,
                () => registration.Projection.InitializeAsync(
                    SqliteProjectionContexts.CreateAdministrative(
                        temporaryConnection,
                        temporaryTransaction,
                        _payloads.KeyRing,
                        lease,
                        registration),
                    cancellationToken)).ConfigureAwait(false);
            if (before is null)
            {
                effective.Add(registration);
                continue;
            }

            var after = await ReadTemporaryProjectionTablesAsync(
                temporaryConnection,
                temporaryTransaction,
                cancellationToken).ConfigureAwait(false);
            after.ExceptWith(before);
            effective.Add(new SqliteProjectionRegistration(
                registration.Projection,
                after.Select(name => new ProjectionOwnedTable(name)),
                registration.EncryptedLocations));
        }

        return effective;
    }

    private static async Task<HashSet<string>> ReadTemporaryProjectionTablesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        var tables = new HashSet<string>(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT name FROM main.sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
              AND name NOT IN ('projection_rebuild_manifest','projection_checkpoints')
            ORDER BY name COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (reader.GetValue(0) is not string name || !tables.Add(name))
                throw new VaultRecoveryRequiredException();
        }

        return tables;
    }

    private async Task<ProjectionReplayManifest> ReplaySelectedAsync(
        SqliteConnection temporaryConnection,
        SqliteTransaction temporaryTransaction,
        ProjectionRebuildSourceSnapshot source,
        IReadOnlyList<SqliteProjectionRegistration> selected,
        string generationId,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        await using var payloadSession = _payloads.CreateReadSession(lease);
        payloadSession.BindExpectedIdentity(source.KeyRingIdentity);
        await using var sourceConnection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString,
            _payloads.KeyRing.MaintenanceGate,
            cancellationToken).ConfigureAwait(false);
        await using var sourceTransaction = sourceConnection.BeginTransaction(deferred: true);
        await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
            sourceConnection,
            sourceTransaction,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
            sourceConnection,
            sourceTransaction,
            _projectionRegistry,
            cancellationToken).ConfigureAwait(false);
        var actualIdentity = await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
            sourceConnection,
            sourceTransaction,
            cancellationToken).ConfigureAwait(false);
        if (!source.KeyRingIdentity.FixedTimeEquals(actualIdentity.Export()))
            throw new VaultRecoveryRequiredException();

        var accumulator = _validator.BeginManifest(source.KeyRingIdentity);
        long? lastGlobalPosition = null;
        while (true)
        {
            var batch = await ReadBatchAsync(
                sourceConnection,
                sourceTransaction,
                lastGlobalPosition,
                cancellationToken).ConfigureAwait(false);
            if (batch.Count == 0) break;
            foreach (var rawEvent in batch)
            {
                accumulator.Accept(new ReplayEventCoordinates(
                    rawEvent.GlobalPosition,
                    rawEvent.Persisted.Metadata.StreamId,
                    rawEvent.Persisted.Metadata.StreamVersion,
                    rawEvent.Persisted.Metadata.EventId,
                    rawEvent.Coordinates.OperationId,
                    rawEvent.Coordinates.OperationIndex,
                    rawEvent.Coordinates.OperationCount));
                var replayEvent = await payloadSession.UnprotectAsync(
                    rawEvent.Persisted,
                    cancellationToken).ConfigureAwait(false);
                var currentEvent = replayEvent is DecryptedEvent decrypted
                    ? _schemaRegistry.UpcastToCurrent(decrypted)
                    : replayEvent;
                if (currentEvent is DecryptedEvent tombstone
                    && string.Equals(
                        tombstone.Metadata.EventType,
                        SensitiveObjectDeletedEventContract.EventType,
                        StringComparison.Ordinal))
                {
                    var tombstonePayload = ReadTombstonePayload(tombstone.Payload.Span);
                    RequireAuthenticatedDeletionReceipt(
                        source.DestroyedReceipts,
                        tombstonePayload,
                        rawEvent);
                    foreach (var registration in selected)
                    {
                        await RunProjectionAsync(
                            temporaryConnection,
                            registration,
                            () => registration.Projection.PurgeOwnerAsync(
                                tombstonePayload.Owner,
                                SqliteProjectionContexts.CreateAdministrative(
                                    temporaryConnection,
                                    temporaryTransaction,
                                    _payloads.KeyRing,
                                    lease,
                                    registration),
                                cancellationToken)).ConfigureAwait(false);
                    }
                }
                else
                {
                    foreach (var registration in selected)
                    {
                        await RunProjectionAsync(
                            temporaryConnection,
                            registration,
                            () => registration.Projection.ApplyAsync(
                                currentEvent,
                                rawEvent.GlobalPosition,
                                currentEvent is DecryptedEvent
                                    && rawEvent.Persisted.Owner is { } owner
                                    && rawEvent.Persisted.Metadata.DataKeyId is { } dataKeyId
                                    ? SqliteProjectionContexts.CreateApply(
                                        temporaryConnection,
                                        temporaryTransaction,
                                        _payloads.KeyRing,
                                        payloadSession,
                                        registration,
                                        owner,
                                        dataKeyId)
                                    : SqliteProjectionContexts.CreateDisabledApply(
                                        temporaryConnection,
                                        temporaryTransaction),
                                cancellationToken)).ConfigureAwait(false);
                    }
                }

                foreach (var registration in selected)
                {
                    await SqliteProjectionCheckpointStore.AdvanceAsync(
                        temporaryConnection,
                        temporaryTransaction,
                        ProjectionCheckpointSchema.Main,
                        registration,
                        rawEvent.GlobalPosition,
                        cancellationToken).ConfigureAwait(false);
                }

                lastGlobalPosition = rawEvent.GlobalPosition;
            }

            InjectFault(ProjectionRebuildFaultPoint.AfterReplayBatch);
        }

        var manifest = accumulator.Freeze(source.StreamHeads);
        if (manifest.TotalEventCount != source.TotalEventCount
            || manifest.RequiredGlobalPosition != source.RequiredGlobalPosition)
        {
            throw new VaultRecoveryRequiredException();
        }

        foreach (var registration in selected)
        {
            await SqliteProjectionCheckpointStore.AdvanceAsync(
                temporaryConnection,
                temporaryTransaction,
                ProjectionCheckpointSchema.Main,
                registration,
                manifest.RequiredGlobalPosition,
                cancellationToken).ConfigureAwait(false);
        }

        await WriteManifestAsync(
            temporaryConnection,
            temporaryTransaction,
            manifest,
            generationId,
            cancellationToken).ConfigureAwait(false);
        await payloadSession.RequireCanonicalImageIfOpenedAsync(cancellationToken).ConfigureAwait(false);
        await sourceTransaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return manifest;
    }

    private static async Task WriteManifestAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ProjectionReplayManifest manifest,
        string generationId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO projection_rebuild_manifest(
                singleton,generation_id,keyring_id,required_global_position,total_event_count,
                coordinate_digest,stream_head_digest,operation_digest)
            VALUES(1,$generation,$keyring,$position,$count,$coordinates,$heads,$operations);
            """;
        if (!Guid.TryParseExact(generationId, "N", out _))
            throw new VaultRecoveryRequiredException();
        command.Parameters.AddWithValue("$generation", generationId);
        command.Parameters.Add("$keyring", SqliteType.Blob).Value = manifest.KeyRingIdentity.Export();
        command.Parameters.AddWithValue("$position", manifest.RequiredGlobalPosition);
        command.Parameters.AddWithValue("$count", manifest.TotalEventCount);
        command.Parameters.Add("$coordinates", SqliteType.Blob).Value = manifest.CoordinateDigest.ToArray();
        command.Parameters.Add("$heads", SqliteType.Blob).Value = manifest.StreamHeadDigest.ToArray();
        command.Parameters.Add("$operations", SqliteType.Blob).Value = manifest.OperationDigest.ToArray();
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> RunProjectionAsync<T>(
        SqliteConnection connection,
        SqliteProjectionRegistration registration,
        Func<Task<T>> callback) =>
        _projectionRegistry.AllowsLegacyTestObjects
            ? await SqliteProjectionAuthorizer.RunAsync(connection, callback).ConfigureAwait(false)
            : await SqliteProjectionAuthorizer.RunAsync(
                connection,
                registration.OwnedTables,
                callback).ConfigureAwait(false);

    private async Task RunProjectionAsync(
        SqliteConnection connection,
        SqliteProjectionRegistration registration,
        Func<Task> callback)
    {
        if (_projectionRegistry.AllowsLegacyTestObjects)
        {
            await SqliteProjectionAuthorizer.RunAsync(connection, callback).ConfigureAwait(false);
            return;
        }

        await SqliteProjectionAuthorizer.RunAsync(
            connection,
            registration.OwnedTables,
            callback).ConfigureAwait(false);
    }

    private static async Task<(long TotalEventCount, IReadOnlyDictionary<StreamId, StreamVersion> StreamHeads)>
        ReadAuthoritativeCoordinatesAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            CancellationToken cancellationToken)
    {
        long count;
        await using (var countCommand = connection.CreateCommand())
        {
            countCommand.Transaction = transaction;
            countCommand.CommandText = "SELECT COUNT(*) FROM main.timeline_events;";
            count = Convert.ToInt64(
                await countCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                CultureInfo.InvariantCulture);
        }

        var heads = new Dictionary<StreamId, StreamVersion>();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT stream_id,head_version FROM main.event_streams
            ORDER BY stream_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            try
            {
                var rawHead = SqliteEventStore.ReadRequiredInteger(reader, 1);
                if (rawHead < 0) throw new VaultRecoveryRequiredException();
                heads.Add(
                    new StreamId(SqliteEventStore.ParseCanonicalGuid(
                        SqliteEventStore.ReadRequiredText(reader, 0))),
                    new StreamVersion(rawHead));
            }
            catch (VaultRecoveryRequiredException) { throw; }
            catch (Exception exception) when (exception is ArgumentException or InvalidCastException
                or FormatException or OverflowException or SqliteException
                or InvalidOperationException or NotSupportedException)
            {
                throw new VaultRecoveryRequiredException(exception);
            }
        }

        return (count, heads);
    }

    private static async Task<IReadOnlyList<RawTimelineEvent>> ReadBatchAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        long? afterGlobalPosition,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        const string select = """
            SELECT e.global_position, e.stream_id, e.stream_version, e.event_id, e.event_type,
                   e.schema_version, e.recorded_at_utc, e.operation_id, e.operation_index,
                   e.operation_count, e.protection_kind, e.owner_kind, e.owner_id, e.key_id,
                   e.envelope_version, e.payload_nonce, e.payload_ciphertext, e.payload_tag
            FROM main.timeline_events e
            """;
        command.CommandText = afterGlobalPosition is null
            ? select + " ORDER BY e.global_position ASC LIMIT $batch_size;"
            : select + " WHERE e.global_position > $after_global_position ORDER BY e.global_position ASC LIMIT $batch_size;";
        if (afterGlobalPosition is not null)
            command.Parameters.AddWithValue("$after_global_position", afterGlobalPosition.Value);
        command.Parameters.AddWithValue("$batch_size", BatchSize);

        var batch = new List<RawTimelineEvent>(BatchSize);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var row = SqliteEventStore.ReadPersistedTimelineRow(reader);
            batch.Add(new RawTimelineEvent(row.Coordinates, row.Event));
        }

        return batch;
    }

    private static DeletionTombstonePayload ReadTombstonePayload(ReadOnlySpan<byte> payload)
    {
        try
        {
            using var document = JsonDocument.Parse(payload.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || root.EnumerateObject().Count() != 3
                || root.GetProperty("targetKind").GetString() is not { } rawKind
                || root.GetProperty("targetId").GetString() is not { } rawId
                || root.GetProperty("reasonCode").GetString() is not { } reason
                || !Guid.TryParseExact(rawId, "D", out var id))
            {
                throw new VaultRecoveryRequiredException();
            }

            var kind = rawKind switch
            {
                "case" => SensitiveObjectKind.Case,
                "document-evidence" => SensitiveObjectKind.DocumentEvidence,
                "journal" => SensitiveObjectKind.Journal,
                "entitlement" => SensitiveObjectKind.Entitlement,
                _ => throw new VaultRecoveryRequiredException(),
            };
            var owner = new SensitiveObjectRef(kind, new SensitiveObjectId(id));
            _ = SensitiveObjectDeletedEventContract.CreatePayload(owner, reason);
            return new DeletionTombstonePayload(owner, reason);
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException
            or InvalidOperationException or JsonException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static void RequireAuthenticatedDeletionReceipt(
        IReadOnlyDictionary<SensitiveObjectRef, VaultDestroyedKeyReceipt> receipts,
        DeletionTombstonePayload payload,
        RawTimelineEvent rawEvent)
    {
        if (rawEvent.Persisted.Kind != PersistedProtectionKind.Structural
            || rawEvent.Persisted.Metadata.SchemaVersion
                != SensitiveObjectDeletedEventContract.SchemaVersion
            || rawEvent.Coordinates.OperationIndex != 0
            || rawEvent.Coordinates.OperationCount != 1
            || !receipts.TryGetValue(payload.Owner, out var receipt)
            || receipt.State != VaultDestroyedReceiptState.Completed
            || receipt.Owner != payload.Owner
            || receipt.StreamId != rawEvent.Persisted.Metadata.StreamId
            || receipt.OperationId != rawEvent.Coordinates.OperationId
            || receipt.TombstoneEventId != rawEvent.Persisted.Metadata.EventId
            || receipt.ExpectedStreamVersion.Value
                != rawEvent.Persisted.Metadata.StreamVersion.Value - 1
            || !string.Equals(
                receipt.ReasonCode,
                payload.ReasonCode,
                StringComparison.Ordinal))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static void RequireChecksum(string projectionName, string? checksum)
    {
        if (checksum is not { Length: 64 }
            || checksum.Any(character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
        {
            throw new InvalidProjectionChecksumException(projectionName, checksum ?? string.Empty);
        }
    }

    private void InjectFault(ProjectionRebuildFaultPoint point) => _injectFault?.Invoke(point);

    private sealed record RawTimelineEvent(
        PersistedOperationCoordinates Coordinates,
        PersistedProtectedEvent Persisted)
    {
        internal long GlobalPosition => Coordinates.GlobalPosition;
    }

    private sealed record DeletionTombstonePayload(
        SensitiveObjectRef Owner,
        string ReasonCode);
}

public sealed class ShreddedProjectionReplayNotSupportedException : InvalidOperationException
{
    public ShreddedProjectionReplayNotSupportedException()
        : base("Projection replay requires shredded-event handling.") { }
}
