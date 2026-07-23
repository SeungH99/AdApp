using System.Buffers.Binary;
using System.Runtime.ExceptionServices;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal enum SqliteSecureCompactionFaultPoint
{
    BeforeManagedOrphanDelete,
    BeforeCheckpoint,
    AfterFreshDatabaseCreated,
    AfterCiphertextScrubbed,
    BeforeAtomicReplace,
    AfterAtomicReplace,
    BeforeFinalCheckpoint,
    BeforePostSwapSidecarWait,
}

internal sealed class SqliteSecureCompactor
{
    private const string TimelineUpdateTriggerSql = """
        CREATE TRIGGER timeline_events_immutable_update
        BEFORE UPDATE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        """;
    private const string ArtifactMarker = ".secure-compaction-";
    private const int ErasureScanBlockSize = 64 * 1024;
    private const int MaxErasurePatternLength = 4 * 1024 * 1024;
    private const int MaxErasurePatternBytes = 16 * 1024 * 1024;

    private readonly string _connectionString;
    private readonly string _vaultPath;
    private readonly SqliteProjectionRegistry _projections;
    private readonly VaultKeyRingStore _keyRing;
    private readonly SqliteVaultBackupService _backups;
    private readonly Action<SqliteSecureCompactionFaultPoint>? _injectFault;

    internal SqliteSecureCompactor(
        string connectionString,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        Action<SqliteSecureCompactionFaultPoint>? injectFault = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(projections);
        ArgumentNullException.ThrowIfNull(keyRing);
        _connectionString = SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        _vaultPath = Path.GetFullPath(
            new SqliteConnectionStringBuilder(_connectionString).DataSource);
        _projections = projections;
        _keyRing = keyRing;
        _backups = new SqliteVaultBackupService(_connectionString, _projections, _keyRing);
        _injectFault = injectFault;
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);
    }

    internal async Task CompactAsync(CancellationToken cancellationToken)
    {
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireMutationAsync(cancellationToken).ConfigureAwait(false);
        await CompactAsync(
            lease,
            forceCompaction: true,
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task PrepareManagedCopyForPublicationAsync(
        string path,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        _keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        var ring = await _keyRing.OpenAsync(cancellationToken).ConfigureAwait(false);
        await CompactDatabaseAsync(
            path,
            maintenanceGate: null,
            ring,
            lease,
            cancellationToken).ConfigureAwait(false);
    }

    internal static async Task RecoverCanonicalWalAsync(
        string connectionString,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(projections);
        ArgumentNullException.ThrowIfNull(keyRing);
        keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        var canonical = SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        var path = Path.GetFullPath(new SqliteConnectionStringBuilder(canonical).DataSource);
        SqliteEventStoreSchema.ValidateVaultPath(canonical, keyRing.MaintenanceGate);
        var walPath = path + "-wal";
        var shmPath = path + "-shm";
        if (!File.Exists(walPath))
        {
            if (File.Exists(shmPath)) throw new VaultRecoveryRequiredException();
            return;
        }

        try
        {
            _ = await keyRing.OpenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
        ValidateWalImage(path, walPath);
        if (File.Exists(shmPath)) WindowsVaultPathGuard.RequireSafeForOpen(shmPath);
        cancellationToken.ThrowIfCancellationRequested();
        await using (var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            canonical,
            keyRing.MaintenanceGate,
            cancellationToken).ConfigureAwait(false))
        {
            await using (var transaction = connection.BeginTransaction(deferred: true))
            {
                await SqliteEventStoreSchema.ValidateRecoverableWalSchemaAsync(
                    connection,
                    transaction,
                    cancellationToken).ConfigureAwait(false);
                await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                    connection,
                    transaction,
                    projections,
                    cancellationToken).ConfigureAwait(false);
                await SqliteEventStore.ValidateAllOperationMetadataAsync(
                    connection,
                    transaction,
                    cancellationToken).ConfigureAwait(false);
                var identity = await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                    connection,
                    transaction,
                    cancellationToken).ConfigureAwait(false);
                await SqliteEventStoreSchema.ValidateCurrentKeyRingIdentityAsync(
                    keyRing,
                    identity,
                    cancellationToken).ConfigureAwait(false);
            }

            await using var checkpoint = connection.CreateCommand();
            checkpoint.CommandText = "PRAGMA main.wal_checkpoint(TRUNCATE);";
            await using var reader = await checkpoint.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
                || reader.GetValue(0) is not long busy
                || busy != 0
                || await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new VaultRecoveryRequiredException();
            }
        }

        SqliteConnection.ClearAllPools();
        for (var attempt = 0; attempt < 40
            && (File.Exists(walPath) || File.Exists(shmPath)); attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken)
                .ConfigureAwait(false);
        }
        if (File.Exists(walPath) || File.Exists(shmPath))
            throw new VaultRecoveryRequiredException();
    }

    internal async Task CompactAsync(
        VaultMaintenanceLease lease,
        bool forceCompaction,
        CancellationToken cancellationToken)
    {
        _keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        cancellationToken.ThrowIfCancellationRequested();
        VaultKeyRing ring;
        try
        {
            ring = await _keyRing.OpenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
        IReadOnlyList<SecureCompactionWorkItem> work;
        await using (var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString,
            _keyRing.MaintenanceGate,
            cancellationToken).ConfigureAwait(false))
        await using (var transaction = connection.BeginTransaction(deferred: true))
        {
            await ValidateDatabaseAsync(
                connection,
                transaction,
                ring,
                lease,
                cancellationToken).ConfigureAwait(false);
            work = await SecureCompactionQueue.ReadValidatedAsync(
                connection,
                transaction,
                ring,
                cancellationToken).ConfigureAwait(false);
            _ = await ReadEventsAsync(
                connection,
                transaction,
                ring,
                cancellationToken).ConfigureAwait(false);
        }

        var copies = await _backups.ReadRegisteredAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        foreach (var copy in copies)
        {
            var copyPath = _backups.GetPath(copy);
            if (!File.Exists(copyPath)) throw new VaultRecoveryRequiredException();
            await using var connection = await OpenOperationalAsync(
                copyPath,
                maintenanceGate: null,
                cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: true);
            await ValidateDatabaseAsync(
                connection,
                transaction,
                ring,
                lease,
                cancellationToken).ConfigureAwait(false);
            _ = await ReadEventsAsync(
                connection,
                transaction,
                ring,
                cancellationToken).ConfigureAwait(false);
        }

        await CleanupArtifactsAsync(lease, cancellationToken).ConfigureAwait(false);
        RequireExactManagedCopySet(copies);
        if (!forceCompaction && work.Count == 0 && copies.Count == 0) return;

        foreach (var copy in copies)
        {
            await CompactDatabaseAsync(
                _backups.GetPath(copy),
                maintenanceGate: null,
                ring,
                lease,
                cancellationToken).ConfigureAwait(false);
        }

        await CompactDatabaseAsync(
            _vaultPath,
            _keyRing.MaintenanceGate,
            ring,
            lease,
            cancellationToken).ConfigureAwait(false);
    }

    internal async Task RecoverAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        _keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        await CompactAsync(
            lease,
            forceCompaction: false,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task CompactDatabaseAsync(
        string path,
        VaultMaintenanceGate? maintenanceGate,
        VaultKeyRing ring,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        _injectFault?.Invoke(SqliteSecureCompactionFaultPoint.BeforeCheckpoint);
        await CheckpointAndWaitForSidecarsAsync(
            path,
            maintenanceGate,
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var artifact = CreateArtifactPath(path);
        List<byte[]> destroyedCiphertexts = [];
        try
        {
            await CloneAndScrubAsync(
                path,
                artifact,
                maintenanceGate,
                ring,
                lease,
                destroyedCiphertexts,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (await FileContainsAnyAsync(
                artifact,
                destroyedCiphertexts,
                cancellationToken).ConfigureAwait(false))
            {
                throw new VaultRecoveryRequiredException();
            }

            _injectFault?.Invoke(SqliteSecureCompactionFaultPoint.BeforeAtomicReplace);
            cancellationToken.ThrowIfCancellationRequested();
            SqliteConnection.ClearAllPools();
            File.Replace(artifact, path, destinationBackupFileName: null);
            _injectFault?.Invoke(SqliteSecureCompactionFaultPoint.AfterAtomicReplace);
            _injectFault?.Invoke(SqliteSecureCompactionFaultPoint.BeforeFinalCheckpoint);
            await CheckpointAndWaitForSidecarsAsync(
                path,
                maintenanceGate,
                CancellationToken.None,
                () => _injectFault?.Invoke(
                    SqliteSecureCompactionFaultPoint.BeforePostSwapSidecarWait),
                maxAttempts: 40)
                .ConfigureAwait(false);
            await ValidatePublishedAsync(path, maintenanceGate, ring, lease)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var primary = ExceptionDispatchInfo.Capture(MapStorageFailure(exception));
            try { await DeleteDatabaseSetAsync(artifact).ConfigureAwait(false); }
            catch { }
            primary.Throw();
            throw;
        }
        finally
        {
            foreach (var ciphertext in destroyedCiphertexts)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private async Task CloneAndScrubAsync(
        string sourcePath,
        string artifactPath,
        VaultMaintenanceGate? maintenanceGate,
        VaultKeyRing ring,
        VaultMaintenanceLease lease,
        List<byte[]> destroyedCiphertexts,
        CancellationToken cancellationToken)
    {
        WindowsVaultPathGuard.RequireSafeDatabaseSet(sourcePath);
        WindowsVaultPathGuard.RequireSafeDatabaseSet(artifactPath);
        IReadOnlyList<CompactionEventImage> sourceEvents;
        IReadOnlyDictionary<string, string> sourceProjectionState;
        await using (var source = await OpenOperationalAsync(
            sourcePath,
            maintenanceGate,
            cancellationToken).ConfigureAwait(false))
        {
            await using (var transaction = source.BeginTransaction(deferred: true))
            {
                await ValidateDatabaseAsync(
                    source,
                    transaction,
                    ring,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                sourceProjectionState = await ReadProjectionStateAsync(
                    source,
                    transaction,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                sourceEvents = await ReadEventsAsync(
                    source,
                    transaction,
                    ring,
                    cancellationToken).ConfigureAwait(false);
            }

            await using var destination = await OpenFreshAsync(
                artifactPath,
                cancellationToken).ConfigureAwait(false);
            source.BackupDatabase(destination);
        }

        _injectFault?.Invoke(SqliteSecureCompactionFaultPoint.AfterFreshDatabaseCreated);
        await using (var destination = await OpenRawAsync(
            artifactPath,
            cancellationToken).ConfigureAwait(false))
        {
            await using (var transaction = destination.BeginTransaction(deferred: false))
            {
                await ValidateDatabaseAsync(
                    destination,
                    transaction,
                    ring,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                var copiedProjectionState = await ReadProjectionStateAsync(
                    destination,
                    transaction,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                RequireProjectionStateEqual(
                    sourceProjectionState,
                    copiedProjectionState);
                var copiedEvents = await ReadEventsAsync(
                    destination,
                    transaction,
                    ring,
                    cancellationToken).ConfigureAwait(false);
                RequireExactClone(sourceEvents, copiedEvents, afterScrub: false);
                foreach (var item in sourceEvents.Where(item => item.IsDestroyed))
                {
                    if (item.PayloadNonce is { Length: > 0 })
                        destroyedCiphertexts.Add(item.PayloadNonce);
                    if (item.PayloadCiphertext.Length != 0)
                        destroyedCiphertexts.Add(item.PayloadCiphertext);
                    if (item.PayloadTag is { Length: > 0 })
                        destroyedCiphertexts.Add(item.PayloadTag);
                }

                await ExecuteAsync(
                    destination,
                    transaction,
                    "DROP TRIGGER main.timeline_events_immutable_update;",
                    cancellationToken).ConfigureAwait(false);
                foreach (var group in sourceEvents
                    .Where(item => item.IsDestroyed)
                    .GroupBy(item => new { item.OwnerKind, item.OwnerId, item.KeyId }))
                {
                    await using var scrub = destination.CreateCommand();
                    scrub.Transaction = transaction;
                    scrub.CommandText = """
                        UPDATE main.timeline_events
                        SET payload_nonce=X'',payload_ciphertext=X'',payload_tag=X''
                        WHERE protection_kind=1 AND owner_kind=$owner_kind
                          AND owner_id=$owner_id AND key_id=$key_id;
                        """;
                    scrub.Parameters.AddWithValue("$owner_kind", group.Key.OwnerKind);
                    scrub.Parameters.AddWithValue("$owner_id", group.Key.OwnerId!);
                    scrub.Parameters.AddWithValue("$key_id", group.Key.KeyId!);
                    if (await scrub.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false)
                        != group.Count())
                    {
                        throw new VaultRecoveryRequiredException();
                    }
                }
                await ExecuteAsync(
                    destination,
                    transaction,
                    TimelineUpdateTriggerSql,
                    cancellationToken).ConfigureAwait(false);
                var localQueue = await SecureCompactionQueue.ReadValidatedAsync(
                    destination,
                    transaction,
                    ring,
                    cancellationToken).ConfigureAwait(false);
                await SecureCompactionQueue.DeleteValidatedAsync(
                    destination,
                    transaction,
                    localQueue,
                    cancellationToken).ConfigureAwait(false);
                _injectFault?.Invoke(SqliteSecureCompactionFaultPoint.AfterCiphertextScrubbed);

                var scrubbedEvents = await ReadEventsAsync(
                    destination,
                    transaction,
                    ring,
                    cancellationToken).ConfigureAwait(false);
                RequireExactClone(sourceEvents, scrubbedEvents, afterScrub: true);
                await ValidateDatabaseAsync(
                    destination,
                    transaction,
                    ring,
                    lease,
                    cancellationToken).ConfigureAwait(false);
                RequireProjectionStateEqual(
                    sourceProjectionState,
                    await ReadProjectionStateAsync(
                        destination,
                        transaction,
                        lease,
                        cancellationToken).ConfigureAwait(false));
                cancellationToken.ThrowIfCancellationRequested();
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }

            await ExecuteAsync(
                destination,
                transaction: null,
                "PRAGMA main.wal_checkpoint(TRUNCATE);",
                cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(
                destination,
                transaction: null,
                "PRAGMA main.journal_mode=DELETE;",
                cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(
                destination,
                transaction: null,
                "VACUUM main;",
                cancellationToken).ConfigureAwait(false);
            await RequireIntegrityAsync(destination, cancellationToken).ConfigureAwait(false);
        }

        await WaitForSidecarsAsync(artifactPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task ValidatePublishedAsync(
        string path,
        VaultMaintenanceGate? maintenanceGate,
        VaultKeyRing ring,
        VaultMaintenanceLease lease)
    {
        await using var connection = await OpenOperationalAsync(
            path,
            maintenanceGate,
            CancellationToken.None).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await ValidateDatabaseAsync(
            connection,
            transaction,
            ring,
            lease,
            CancellationToken.None).ConfigureAwait(false);
        var queue = await SecureCompactionQueue.ReadValidatedAsync(
            connection,
            transaction,
            ring,
            CancellationToken.None).ConfigureAwait(false);
        if (queue.Count != 0) throw new VaultRecoveryRequiredException();
        _ = await ReadEventsAsync(
            connection,
            transaction,
            ring,
            CancellationToken.None).ConfigureAwait(false);
        _ = await ReadProjectionStateAsync(
            connection,
            transaction,
            lease,
            CancellationToken.None).ConfigureAwait(false);
    }

    private async Task ValidateDatabaseAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRing ring,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
            connection,
            transaction,
            _projections,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStore.ValidateAllOperationMetadataAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
            connection,
            transaction,
            ring.Identity,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateCurrentKeyRingIdentityAsync(
            _keyRing,
            ring.Identity,
            cancellationToken).ConfigureAwait(false);
        await RequireForeignKeysAsync(connection, transaction, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<IReadOnlyDictionary<string, string>> ReadProjectionStateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        await using var headCommand = connection.CreateCommand();
        headCommand.Transaction = transaction;
        headCommand.CommandText =
            "SELECT COALESCE(MAX(global_position),0) FROM main.timeline_events;";
        if (await headCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)
                is not long timelineHead
            || timelineHead < 0)
        {
            throw new VaultRecoveryRequiredException();
        }

        var expected = timelineHead == 0
            ? Array.Empty<SqliteProjectionRegistration>()
            : _projections.Registrations.ToArray();
        await SqliteProjectionCheckpointStore.RequireExactSelectedAsync(
            connection,
            transaction,
            ProjectionCheckpointSchema.Main,
            expected,
            timelineHead,
            requireOnlySelected: true,
            cancellationToken).ConfigureAwait(false);

        var checksums = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var registration in _projections.Registrations)
        {
            var checksum = await SqliteProjectionAuthorizer.RunAsync(
                connection,
                registration.OwnedTables,
                () => registration.Projection.CalculateChecksumAsync(
                    SqliteProjectionContexts.CreateAdministrative(
                        connection,
                        transaction,
                        _keyRing,
                        lease,
                        registration),
                    cancellationToken)).ConfigureAwait(false);
            if (checksum is not { Length: 64 }
                || checksum.Any(character =>
                    character is not (>= '0' and <= '9' or >= 'a' and <= 'f'))
                || !checksums.TryAdd(registration.Name, checksum))
            {
                throw new VaultRecoveryRequiredException();
            }
        }
        return checksums;
    }

    private static void RequireProjectionStateEqual(
        IReadOnlyDictionary<string, string> expected,
        IReadOnlyDictionary<string, string> actual)
    {
        if (expected.Count != actual.Count
            || expected.Any(pair =>
                !actual.TryGetValue(pair.Key, out var checksum)
                || !string.Equals(pair.Value, checksum, StringComparison.Ordinal)))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task<IReadOnlyList<CompactionEventImage>> ReadEventsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRing ring,
        CancellationToken cancellationToken)
    {
        var active = ring.ActiveKeys.ToDictionary(entry => entry.Owner);
        var destroyed = ring.DestroyedReceipts.ToDictionary(receipt => receipt.Owner);
        var result = new List<CompactionEventImage>();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT global_position,event_id,stream_id,stream_version,event_type,schema_version,
                   recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,
                   owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag
            FROM main.timeline_events ORDER BY global_position;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var protectionKind = reader.GetInt64(10);
            var isDestroyed = false;
            if (protectionKind == 1)
            {
                var owner = new SensitiveObjectRef(
                    (SensitiveObjectKind)reader.GetInt64(11),
                    new SensitiveObjectId(SqliteEventStore.ParseCanonicalGuid(reader.GetString(12))));
                var keyId = new DataKeyId(
                    SqliteEventStore.ParseCanonicalGuid(reader.GetString(13)));
                var isActive = active.TryGetValue(owner, out var activeKey)
                    && activeKey.KeyId == keyId;
                isDestroyed = destroyed.TryGetValue(owner, out var receipt)
                    && receipt.KeyId == keyId
                    && receipt.State == VaultDestroyedReceiptState.Completed;
                if (isActive == isDestroyed) throw new VaultRecoveryRequiredException();
            }

            result.Add(new CompactionEventImage(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetInt64(3),
                reader.GetString(4),
                reader.GetInt64(5),
                reader.GetString(6),
                reader.GetString(7),
                reader.GetInt64(8),
                reader.GetInt64(9),
                protectionKind,
                reader.IsDBNull(11) ? null : reader.GetInt64(11),
                reader.IsDBNull(12) ? null : reader.GetString(12),
                reader.IsDBNull(13) ? null : reader.GetString(13),
                reader.GetInt64(14),
                reader.IsDBNull(15) ? null : reader.GetFieldValue<byte[]>(15).ToArray(),
                reader.GetFieldValue<byte[]>(16).ToArray(),
                reader.IsDBNull(17) ? null : reader.GetFieldValue<byte[]>(17).ToArray(),
                isDestroyed));
        }
        return result.AsReadOnly();
    }

    internal static async Task ValidateProtectedKeyStateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRing ring,
        CancellationToken cancellationToken)
    {
        _ = await ReadEventsAsync(
            connection,
            transaction,
            ring,
            cancellationToken).ConfigureAwait(false);
    }

    private static void RequireExactClone(
        IReadOnlyList<CompactionEventImage> source,
        IReadOnlyList<CompactionEventImage> candidate,
        bool afterScrub)
    {
        if (source.Count != candidate.Count) throw new VaultRecoveryRequiredException();
        for (var index = 0; index < source.Count; index++)
        {
            var expected = source[index];
            var actual = candidate[index];
            if (!expected.HeaderEquals(actual)
                || expected.IsDestroyed != actual.IsDestroyed
                || (afterScrub && expected.IsDestroyed
                    ? actual.PayloadNonce is not { Length: 0 }
                        || actual.PayloadCiphertext.Length != 0
                        || actual.PayloadTag is not { Length: 0 }
                    : !expected.PayloadCiphertext.AsSpan()
                        .SequenceEqual(actual.PayloadCiphertext)
                        || !CompactionEventImage.NullableBytesEqual(
                            expected.PayloadNonce, actual.PayloadNonce)
                        || !CompactionEventImage.NullableBytesEqual(
                            expected.PayloadTag, actual.PayloadTag)))
            {
                throw new VaultRecoveryRequiredException();
            }
        }
    }

    private void RequireExactManagedCopySet(IReadOnlyList<ManagedVaultCopyId> copies)
    {
        var directory = _vaultPath + SqliteVaultBackupService.DirectorySuffix;
        if (!Directory.Exists(directory))
        {
            if (copies.Count == 0) return;
            throw new VaultRecoveryRequiredException();
        }

        var expected = copies.Select(copy => Path.GetFullPath(_backups.GetPath(copy)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var actual = Directory.EnumerateFiles(directory, "*.db", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFullPath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!actual.SetEquals(expected)) throw new VaultRecoveryRequiredException();
        foreach (var path in actual) WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
    }

    private async Task CleanupArtifactsAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        _keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        await _backups.CleanupOrphansAsync(
            lease,
            cancellationToken,
            () => _injectFault?.Invoke(
                SqliteSecureCompactionFaultPoint.BeforeManagedOrphanDelete))
            .ConfigureAwait(false);
        await DeleteArtifactsForAsync(_vaultPath, cancellationToken).ConfigureAwait(false);
        var copies = await _backups.ReadRegisteredAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        foreach (var copy in copies)
            await DeleteArtifactsForAsync(_backups.GetPath(copy), cancellationToken)
                .ConfigureAwait(false);
    }

    private static async Task DeleteArtifactsForAsync(
        string databasePath,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(databasePath)!;
        if (!Directory.Exists(directory)) return;
        var prefix = Path.GetFileName(databasePath) + ArtifactMarker;
        foreach (var candidate in Directory.EnumerateFileSystemEntries(
            directory,
            prefix + "*.tmp*",
            SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Directory.Exists(candidate))
                throw new VaultRecoveryRequiredException();
            var name = Path.GetFileName(candidate);
            var coreName = name.EndsWith("-wal", StringComparison.Ordinal)
                || name.EndsWith("-shm", StringComparison.Ordinal)
                || name.EndsWith("-journal", StringComparison.Ordinal)
                ? name[..name.LastIndexOf('-')]
                : name;
            if (!coreName.StartsWith(prefix, StringComparison.Ordinal)
                || !coreName.EndsWith(".tmp", StringComparison.Ordinal)
                || coreName.Length != prefix.Length + 32 + ".tmp".Length
                || coreName.AsSpan(prefix.Length, 32).IndexOfAnyExcept(
                    "0123456789abcdef".AsSpan()) >= 0)
            {
                throw new VaultRecoveryRequiredException();
            }
            WindowsVaultPathGuard.RequireSafeEntryShape(candidate);
            File.Delete(candidate);
        }
        await Task.CompletedTask;
    }

    private static string CreateArtifactPath(string sourcePath)
    {
        var path = Path.Combine(
            Path.GetDirectoryName(sourcePath)!,
            Path.GetFileName(sourcePath)
            + ArtifactMarker
            + Guid.NewGuid().ToString("N")
            + ".tmp");
        WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
        return path;
    }

    private static async Task CheckpointAndWaitForSidecarsAsync(
        string path,
        VaultMaintenanceGate? maintenanceGate,
        CancellationToken cancellationToken,
        Action? beforeSidecarWait = null,
        int? maxAttempts = null)
    {
        var checkpointAttempts = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await using var connection = await OpenOperationalAsync(
                path,
                maintenanceGate,
                cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA main.wal_checkpoint(TRUNCATE);";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
                || reader.GetValue(0) is not long busy
                || await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new VaultRecoveryRequiredException();
            }
            if (busy == 0) break;
            checkpointAttempts++;
            if (maxAttempts is int checkpointLimit
                && checkpointAttempts >= checkpointLimit)
            {
                throw new VaultRecoveryRequiredException();
            }
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken)
                .ConfigureAwait(false);
        }
        SqliteConnection.ClearAllPools();
        beforeSidecarWait?.Invoke();
        await WaitForSidecarsAsync(
            path,
            cancellationToken,
            maxAttempts).ConfigureAwait(false);
    }

    private static async Task WaitForSidecarsAsync(
        string path,
        CancellationToken cancellationToken,
        int? maxAttempts = null)
    {
        var attempts = 0;
        while (File.Exists(path + "-wal") || File.Exists(path + "-shm"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            attempts++;
            if (maxAttempts is int limit && attempts >= limit)
                throw new VaultRecoveryRequiredException();
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static Task<SqliteConnection> OpenOperationalAsync(
        string path,
        VaultMaintenanceGate? maintenanceGate,
        CancellationToken cancellationToken) =>
        SqliteEventStoreSchema.OpenConnectionAsync(
            ConnectionString(path),
            maintenanceGate,
            cancellationToken);

    private static async Task<SqliteConnection> OpenFreshAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using (var reservation = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 1,
            FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(
                path,
                reservation.SafeFileHandle);
            await reservation.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        return await OpenRawAsync(path, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<SqliteConnection> OpenRawAsync(
        string path,
        CancellationToken cancellationToken) =>
        await SqliteEventStoreSchema.OpenHardenedPathAsync(
            path,
            cancellationToken).ConfigureAwait(false);

    private static async Task RequireForeignKeysAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA main.foreign_key_check;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            throw new VaultRecoveryRequiredException();
    }

    private static async Task RequireIntegrityAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA main.integrity_check;";
        if (!string.Equals(
            await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string,
            "ok",
            StringComparison.Ordinal))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<bool> FileContainsAnyAsync(
        string path,
        IReadOnlyList<byte[]> patterns,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(patterns);
        var unique = new HashSet<byte[]>(ByteArrayComparer.Instance);
        var totalPatternBytes = 0;
        var maximumPatternLength = 0;
        foreach (var pattern in patterns)
        {
            if (pattern.Length == 0 || !unique.Add(pattern)) continue;
            if (pattern.Length > MaxErasurePatternLength)
                throw new VaultRecoveryRequiredException();
            totalPatternBytes = checked(totalPatternBytes + pattern.Length);
            if (totalPatternBytes > MaxErasurePatternBytes)
                throw new VaultRecoveryRequiredException();
            maximumPatternLength = Math.Max(maximumPatternLength, pattern.Length);
        }
        if (unique.Count == 0) return false;

        var buffer = new byte[checked(
            ErasureScanBlockSize + maximumPatternLength - 1)];
        var retained = 0;
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            ErasureScanBlockSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        while (true)
        {
            var read = await stream.ReadAsync(
                buffer.AsMemory(retained, ErasureScanBlockSize),
                cancellationToken).ConfigureAwait(false);
            var available = retained + read;
            var window = buffer.AsSpan(0, available);
            foreach (var pattern in unique)
            {
                if (window.IndexOf(pattern) >= 0) return true;
            }
            if (read == 0) return false;
            retained = Math.Min(maximumPatternLength - 1, available);
            buffer.AsSpan(available - retained, retained).CopyTo(buffer);
        }
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();

        public bool Equals(byte[]? left, byte[]? right) =>
            ReferenceEquals(left, right)
            || left is not null
                && right is not null
                && left.AsSpan().SequenceEqual(right);

        public int GetHashCode(byte[] value)
        {
            ArgumentNullException.ThrowIfNull(value);
            var hash = new HashCode();
            hash.Add(value.Length);
            foreach (var item in value.AsSpan())
                hash.Add(item);
            return hash.ToHashCode();
        }
    }

    private static void ValidateWalImage(string databasePath, string walPath)
    {
        try
        {
            WindowsVaultPathGuard.RequireSafeForOpen(walPath);
            Span<byte> databaseHeader = stackalloc byte[100];
            using (var database = new FileStream(
                databasePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: databaseHeader.Length,
                FileOptions.SequentialScan))
            {
                database.ReadExactly(databaseHeader);
            }
            if (!databaseHeader[..16].SequenceEqual("SQLite format 3\0"u8)
                || databaseHeader[18] != 2
                || databaseHeader[19] != 2)
            {
                throw new VaultRecoveryRequiredException();
            }

            using var wal = new FileStream(
                walPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
            Span<byte> header = stackalloc byte[32];
            wal.ReadExactly(header);
            var magic = BinaryPrimitives.ReadUInt32BigEndian(header);
            if (magic is not (0x377f0682u or 0x377f0683u)
                || BinaryPrimitives.ReadUInt32BigEndian(header[4..]) != 3_007_000u)
            {
                throw new VaultRecoveryRequiredException();
            }
            var pageSize = BinaryPrimitives.ReadUInt32BigEndian(header[8..]);
            if (pageSize == 1) pageSize = 65_536;
            var databasePageSize = BinaryPrimitives.ReadUInt16BigEndian(databaseHeader[16..]);
            var normalizedDatabasePageSize = databasePageSize == 1 ? 65_536u : databasePageSize;
            if (pageSize != normalizedDatabasePageSize
                || pageSize is < 512 or > 65_536
                || (pageSize & (pageSize - 1)) != 0)
            {
                throw new VaultRecoveryRequiredException();
            }
            var frameSize = checked(24L + pageSize);
            if (wal.Length < header.Length
                || (wal.Length - header.Length) % frameSize != 0)
            {
                throw new VaultRecoveryRequiredException();
            }

            uint checksumOne = 0;
            uint checksumTwo = 0;
            UpdateWalChecksum(
                header[..24],
                bigEndianWords: magic == 0x377f0683u,
                ref checksumOne,
                ref checksumTwo);
            if (BinaryPrimitives.ReadUInt32BigEndian(header[24..]) != checksumOne
                || BinaryPrimitives.ReadUInt32BigEndian(header[28..]) != checksumTwo)
            {
                throw new VaultRecoveryRequiredException();
            }

            var saltOne = BinaryPrimitives.ReadUInt32BigEndian(header[16..]);
            var saltTwo = BinaryPrimitives.ReadUInt32BigEndian(header[20..]);
            var frameHeader = new byte[24];
            var page = new byte[checked((int)pageSize)];
            while (wal.Position < wal.Length)
            {
                wal.ReadExactly(frameHeader);
                wal.ReadExactly(page);
                if (BinaryPrimitives.ReadUInt32BigEndian(frameHeader) == 0
                    || BinaryPrimitives.ReadUInt32BigEndian(frameHeader.AsSpan(8)) != saltOne
                    || BinaryPrimitives.ReadUInt32BigEndian(frameHeader.AsSpan(12)) != saltTwo)
                {
                    throw new VaultRecoveryRequiredException();
                }
                UpdateWalChecksum(
                    frameHeader.AsSpan(0, 8),
                    bigEndianWords: magic == 0x377f0683u,
                    ref checksumOne,
                    ref checksumTwo);
                UpdateWalChecksum(
                    page,
                    bigEndianWords: magic == 0x377f0683u,
                    ref checksumOne,
                    ref checksumTwo);
                if (BinaryPrimitives.ReadUInt32BigEndian(frameHeader.AsSpan(16)) != checksumOne
                    || BinaryPrimitives.ReadUInt32BigEndian(frameHeader.AsSpan(20)) != checksumTwo)
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is EndOfStreamException
            or IOException or OverflowException or UnauthorizedAccessException)
        {
            _ = exception;
            throw new VaultRecoveryRequiredException();
        }
    }

    private static void UpdateWalChecksum(
        ReadOnlySpan<byte> input,
        bool bigEndianWords,
        ref uint checksumOne,
        ref uint checksumTwo)
    {
        if (input.Length == 0 || input.Length % 8 != 0)
            throw new VaultRecoveryRequiredException();
        for (var offset = 0; offset < input.Length; offset += 8)
        {
            var first = bigEndianWords
                ? BinaryPrimitives.ReadUInt32BigEndian(input[offset..])
                : BinaryPrimitives.ReadUInt32LittleEndian(input[offset..]);
            var second = bigEndianWords
                ? BinaryPrimitives.ReadUInt32BigEndian(input[(offset + 4)..])
                : BinaryPrimitives.ReadUInt32LittleEndian(input[(offset + 4)..]);
            unchecked
            {
                checksumOne += first + checksumTwo;
                checksumTwo += second + checksumOne;
            }
        }
    }

    private static Task DeleteDatabaseSetAsync(string path)
    {
        SqliteConnection.ClearAllPools();
        foreach (var candidate in new[] { path + "-shm", path + "-wal", path + "-journal", path })
        {
            if (File.Exists(candidate)) File.Delete(candidate);
        }
        return Task.CompletedTask;
    }

    private static Exception MapStorageFailure(Exception exception)
    {
        if (exception is SqliteException { SqliteErrorCode: 13 })
            return new StorageCapacityException(exception);
        if (exception is SqliteException { SqliteErrorCode: 5 or 6 } busy)
            return new StorageBusyException("Secure compaction could not acquire storage access.", busy);
        return exception;
    }

    private static string ConnectionString(string path) =>
        new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();

    private sealed record CompactionEventImage(
        long GlobalPosition,
        string EventId,
        string StreamId,
        long StreamVersion,
        string EventType,
        long SchemaVersion,
        string RecordedAtUtc,
        string OperationId,
        long OperationIndex,
        long OperationCount,
        long ProtectionKind,
        long? OwnerKind,
        string? OwnerId,
        string? KeyId,
        long EnvelopeVersion,
        byte[]? PayloadNonce,
        byte[] PayloadCiphertext,
        byte[]? PayloadTag,
        bool IsDestroyed)
    {
        internal bool HeaderEquals(CompactionEventImage other) =>
            GlobalPosition == other.GlobalPosition
            && string.Equals(EventId, other.EventId, StringComparison.Ordinal)
            && string.Equals(StreamId, other.StreamId, StringComparison.Ordinal)
            && StreamVersion == other.StreamVersion
            && string.Equals(EventType, other.EventType, StringComparison.Ordinal)
            && SchemaVersion == other.SchemaVersion
            && string.Equals(RecordedAtUtc, other.RecordedAtUtc, StringComparison.Ordinal)
            && string.Equals(OperationId, other.OperationId, StringComparison.Ordinal)
            && OperationIndex == other.OperationIndex
            && OperationCount == other.OperationCount
            && ProtectionKind == other.ProtectionKind
            && OwnerKind == other.OwnerKind
            && string.Equals(OwnerId, other.OwnerId, StringComparison.Ordinal)
            && string.Equals(KeyId, other.KeyId, StringComparison.Ordinal)
            && EnvelopeVersion == other.EnvelopeVersion;

        internal static bool NullableBytesEqual(byte[]? left, byte[]? right) =>
            left is null ? right is null : right is not null && left.AsSpan().SequenceEqual(right);
    }
}
