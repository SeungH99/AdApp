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

internal enum SqliteCanonicalWalRecoveryPhase
{
    BeforeShmRestoreOpen,
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
    private const int ErasureScanBatchPatternCount = 128;
    private const int ErasureScanBatchByteCount = 256 * 1024;
    // Very short ciphertext is not unique physical-erasure evidence: the same
    // bytes can legitimately occur in retained structural content. Logical
    // clone validation remains exact, and the 96/128-bit nonce/tag are still
    // scanned independently.
    private const int MinimumIndependentCiphertextScanLength = 16;

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
        await ValidateManagedCopyCandidateBeforeCheckpointAsync(
            path,
            ring,
            lease,
            cancellationToken).ConfigureAwait(false);
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
        CancellationToken cancellationToken,
        Action<SqliteCanonicalWalRecoveryPhase>? observeRecovery = null)
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
            if (!File.Exists(path) || new FileInfo(path).Length == 0) return;
            var version = await ReadImmutableUserVersionAsync(
                path,
                cancellationToken).ConfigureAwait(false);
            if (version is null) throw new VaultRecoveryRequiredException();
            if (version is 0 or 1)
            {
                await ValidateBootstrapNoWalPreflightAsync(
                    path,
                    cancellationToken).ConfigureAwait(false);
                return;
            }
            if (version is not (2 or 3 or 4 or 5 or 6))
                throw new VaultRecoveryRequiredException();
            VaultKeyRing noWalRing;
            try
            {
                noWalRing = await keyRing.OpenAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (VaultKeyRingException exception)
            {
                throw new VaultRecoveryRequiredException(exception);
            }
            await ValidateNoWalPreflightAsync(
                path,
                projections,
                keyRing,
                noWalRing,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        VaultKeyRing ring;
        try
        {
            ring = await keyRing.OpenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
        ValidateWalImage(path, walPath);
        if (File.Exists(shmPath)) WindowsVaultPathGuard.RequireSafeForOpen(shmPath);
        cancellationToken.ThrowIfCancellationRequested();
        var hadShm = File.Exists(shmPath);
        var shmImage = hadShm ? File.ReadAllBytes(shmPath) : null;
        try
        {
            await ValidateWalPreflightAsync(
                path,
                projections,
                keyRing,
                ring,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            SqliteConnection.ClearAllPools();
            await RestoreSidecarImageAsync(
                shmPath,
                hadShm,
                shmImage,
                CancellationToken.None,
                observeRecovery).ConfigureAwait(false);
            if (exception is VaultRecoveryRequiredException) throw;
            if (exception is SqliteException sqliteException)
                throw new VaultRecoveryRequiredException(sqliteException);
            throw;
        }
        finally
        {
            if (shmImage is not null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(shmImage);
        }

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
                await ValidateProtectedKeyStateAsync(
                    connection,
                    transaction,
                    ring,
                    cancellationToken,
                    allowPendingReceipts: true).ConfigureAwait(false);
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

    private static async Task ValidateWalPreflightAsync(
        string path,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        VaultKeyRing ring,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenRecoveryReadOnlyAsync(
            path,
            cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
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
        await ValidateProtectedKeyStateAsync(
            connection,
            transaction,
            ring,
            cancellationToken,
            allowPendingReceipts: true).ConfigureAwait(false);
    }

    private static async Task ValidateNoWalPreflightAsync(
        string path,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        VaultKeyRing ring,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenImmutableReadOnlyAsync(
            path,
            cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
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
        await ValidateProtectedKeyStateAsync(
            connection,
            transaction,
            ring,
            cancellationToken,
            allowPendingReceipts: true).ConfigureAwait(false);
    }

    private static async Task ValidateBootstrapNoWalPreflightAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenImmutableReadOnlyAsync(
            path,
            cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await SqliteEventStoreSchema.ValidateBootstrapSchemaAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int?> ReadImmutableUserVersionAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await OpenImmutableReadOnlyAsync(
                path,
                cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA main.user_version;";
            return Convert.ToInt32(
                await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                System.Globalization.CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is SqliteException
            or InvalidCastException
            or FormatException
            or OverflowException)
        {
            return null;
        }
    }

    private static async Task<SqliteConnection> OpenImmutableReadOnlyAsync(
        string path,
        CancellationToken cancellationToken)
    {
        WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = new Uri(path).AbsoluteUri + "?immutable=1",
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString());
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var queryOnly = connection.CreateCommand();
            queryOnly.CommandText = "PRAGMA query_only=ON;";
            await queryOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<SqliteConnection> OpenRecoveryReadOnlyAsync(
        string path,
        CancellationToken cancellationToken)
    {
        WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString());
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var queryOnly = connection.CreateCommand();
            queryOnly.CommandText = "PRAGMA query_only=ON;";
            await queryOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task RestoreSidecarImageAsync(
        string path,
        bool existed,
        byte[]? image,
        CancellationToken cancellationToken,
        Action<SqliteCanonicalWalRecoveryPhase>? observeRecovery)
    {
        if (!existed)
        {
            if (File.Exists(path))
            {
                WindowsVaultPathGuard.RequireSafeForOpen(path);
                File.Delete(path);
            }
            return;
        }
        if (image is null) throw new VaultRecoveryRequiredException();
        WindowsVaultPathGuard.RequireSafeForOpen(path);
        observeRecovery?.Invoke(SqliteCanonicalWalRecoveryPhase.BeforeShmRestoreOpen);
        FileStream output;
        try
        {
            output = new FileStream(
                path,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
        }
        catch (FileNotFoundException)
        {
            WindowsVaultPathGuard.RequireSafeForOpen(path);
            output = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
        }
        await using (output)
        {
            WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(
                path,
                output.SafeFileHandle);
            output.SetLength(0);
            output.Position = 0;
            await output.WriteAsync(image, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ValidateManagedCopyCandidateBeforeCheckpointAsync(
        string path,
        VaultKeyRing ring,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
        if (File.Exists(path + "-wal")
            || File.Exists(path + "-shm")
            || File.Exists(path + "-journal"))
        {
            throw new VaultRecoveryRequiredException();
        }
        await using var connection = await OpenImmutableReadOnlyAsync(
            path,
            cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await ValidateDatabaseAsync(
            connection,
            transaction,
            ring,
            lease,
            cancellationToken).ConfigureAwait(false);
        _ = await ReadEventPreflightAsync(
            connection,
            transaction,
            ring,
            cancellationToken).ConfigureAwait(false);
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
        EventPreflight canonicalPreflight;
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
            canonicalPreflight = await ReadEventPreflightAsync(
                connection,
                transaction,
                ring,
                cancellationToken).ConfigureAwait(false);
        }

        var copies = await _backups.ReadRegisteredAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        var copyPreflights = new List<ManagedCopyPreflight>(copies.Count);
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
            var preflight = await ReadEventPreflightAsync(
                connection,
                transaction,
                ring,
                cancellationToken).ConfigureAwait(false);
            copyPreflights.Add(new ManagedCopyPreflight(copyPath, preflight));
        }

        await CleanupArtifactsAsync(lease, cancellationToken).ConfigureAwait(false);
        RequireExactManagedCopySet(copies);
        var canonicalRequiresCompaction =
            forceCompaction || work.Count != 0 || canonicalPreflight.RequiresScrub;
        var copiesRequiringCompaction = copyPreflights
            .Where(copy => forceCompaction || copy.Preflight.RequiresScrub)
            .ToArray();
        if (!canonicalRequiresCompaction && copiesRequiringCompaction.Length == 0)
            return;

        foreach (var copy in copiesRequiringCompaction)
        {
            await CompactDatabaseAsync(
                copy.Path,
                maintenanceGate: null,
                ring,
                lease,
                cancellationToken).ConfigureAwait(false);
        }

        if (canonicalRequiresCompaction)
        {
            await CompactDatabaseAsync(
                _vaultPath,
                _keyRing.MaintenanceGate,
                ring,
                lease,
                cancellationToken).ConfigureAwait(false);
        }
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
        try
        {
            await CloneAndScrubAsync(
                path,
                artifact,
                maintenanceGate,
                ring,
                lease,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

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
    }

    private async Task CloneAndScrubAsync(
        string sourcePath,
        string artifactPath,
        VaultMaintenanceGate? maintenanceGate,
        VaultKeyRing ring,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        WindowsVaultPathGuard.RequireSafeDatabaseSet(sourcePath);
        WindowsVaultPathGuard.RequireSafeDatabaseSet(artifactPath);
        await using var source = await OpenOperationalAsync(
            sourcePath,
            maintenanceGate,
            cancellationToken).ConfigureAwait(false);
        await using var sourceTransaction = source.BeginTransaction(deferred: true);
        await ValidateDatabaseAsync(
            source,
            sourceTransaction,
            ring,
            lease,
            cancellationToken).ConfigureAwait(false);
        var sourceProjectionState = await ReadProjectionStateAsync(
            source,
            sourceTransaction,
            lease,
            cancellationToken).ConfigureAwait(false);
        var sourcePreflight = await ReadEventPreflightAsync(
            source,
            sourceTransaction,
            ring,
            cancellationToken).ConfigureAwait(false);

        await using (var destination = await OpenFreshAsync(
            artifactPath,
            cancellationToken).ConfigureAwait(false))
        {
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
                await RequireExactCloneAsync(
                    source,
                    sourceTransaction,
                    destination,
                    transaction,
                    ring,
                    afterScrub: false,
                    cancellationToken).ConfigureAwait(false);

                await ExecuteAsync(
                    destination,
                    transaction,
                    "DROP TRIGGER main.timeline_events_immutable_update;",
                    cancellationToken).ConfigureAwait(false);
                foreach (var group in sourcePreflight.DestroyedGroups)
                {
                    await using var scrub = destination.CreateCommand();
                    scrub.Transaction = transaction;
                    scrub.CommandText = """
                        UPDATE main.timeline_events
                        SET payload_nonce=X'',payload_ciphertext=X'',payload_tag=X''
                        WHERE protection_kind=1 AND owner_kind=$owner_kind
                          AND owner_id=$owner_id AND key_id=$key_id;
                        """;
                    scrub.Parameters.AddWithValue("$owner_kind", group.OwnerKind);
                    scrub.Parameters.AddWithValue("$owner_id", group.OwnerId);
                    scrub.Parameters.AddWithValue("$key_id", group.KeyId);
                    if (await scrub.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false)
                        != group.EventCount)
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

                await RequireExactCloneAsync(
                    source,
                    sourceTransaction,
                    destination,
                    transaction,
                    ring,
                    afterScrub: true,
                    cancellationToken).ConfigureAwait(false);
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

            await SqliteEventStoreSchema.RequireCheckpointAsync(
                destination,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStoreSchema.RequireJournalModeAsync(
                destination,
                "delete",
                cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(
                destination,
                transaction: null,
                "VACUUM main;",
                cancellationToken).ConfigureAwait(false);
            await RequireIntegrityAsync(destination, cancellationToken).ConfigureAwait(false);
        }

        await WaitForSidecarsAsync(artifactPath, cancellationToken).ConfigureAwait(false);
        await RequireDestroyedPayloadsAbsentAsync(
            source,
            sourceTransaction,
            artifactPath,
            ring,
            cancellationToken).ConfigureAwait(false);
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
        _ = await ReadEventPreflightAsync(
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

    private static async Task<EventPreflight> ReadEventPreflightAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRing ring,
        CancellationToken cancellationToken,
        bool allowPendingReceipts = false)
    {
        var active = ring.ActiveKeys.ToDictionary(entry => entry.Owner);
        var destroyed = ring.DestroyedReceipts.ToDictionary(receipt => receipt.Owner);
        var groups = new Dictionary<(long OwnerKind, string OwnerId, string KeyId), int>();
        var requiresScrub = false;
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT protection_kind,owner_kind,owner_id,key_id,envelope_version,
                   length(payload_nonce),length(payload_ciphertext),length(payload_tag)
            FROM main.timeline_events ORDER BY global_position;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var protectionKind = reader.GetInt64(0);
            var nonceLength = protectionKind == 1 ? ReadBlobLength(reader, 5) : 0;
            var ciphertextLength = protectionKind == 1 ? ReadBlobLength(reader, 6) : 0;
            var tagLength = protectionKind == 1 ? ReadBlobLength(reader, 7) : 0;
            var isDestroyed = ClassifyDestroyed(
                protectionKind,
                reader.IsDBNull(1) ? null : reader.GetInt64(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.GetInt64(4),
                nonceLength,
                ciphertextLength,
                tagLength,
                active,
                destroyed,
                allowPendingReceipts);
            if (isDestroyed)
            {
                var ownerKind = reader.GetInt64(1);
                var ownerId = reader.GetString(2);
                var keyId = reader.GetString(3);
                var key = (ownerKind, ownerId, keyId);
                groups[key] = groups.TryGetValue(key, out var count)
                    ? checked(count + 1)
                    : 1;
                requiresScrub |= nonceLength != 0
                    || ciphertextLength != 0
                    || tagLength != 0;
            }
        }
        return new EventPreflight(
            requiresScrub,
            groups.Select(pair => new DestroyedEnvelopeGroup(
                    pair.Key.OwnerKind,
                    pair.Key.OwnerId,
                    pair.Key.KeyId,
                    pair.Value))
                .ToArray());
    }

    internal static async Task ValidateProtectedKeyStateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRing ring,
        CancellationToken cancellationToken,
        bool allowPendingReceipts = false)
    {
        _ = await ReadEventPreflightAsync(
            connection,
            transaction,
            ring,
            cancellationToken,
            allowPendingReceipts).ConfigureAwait(false);
    }

    private static long ReadBlobLength(SqliteDataReader reader, int ordinal)
    {
        if (reader.GetValue(ordinal) is not long length || length < 0)
            throw new VaultRecoveryRequiredException();
        return length;
    }

    private static bool ClassifyDestroyed(
        long protectionKind,
        long? ownerKind,
        string? ownerId,
        string? keyId,
        long envelopeVersion,
        long nonceLength,
        long ciphertextLength,
        long tagLength,
        IReadOnlyDictionary<SensitiveObjectRef, VaultActiveKeyMetadata> active,
        IReadOnlyDictionary<SensitiveObjectRef, VaultDestroyedKeyReceipt> destroyed,
        bool allowPendingReceipts = false)
    {
        if (protectionKind != 1) return false;
        if (ownerKind is null
            || ownerId is null
            || keyId is null
            || envelopeVersion != 1)
            throw new VaultRecoveryRequiredException();
        var owner = new SensitiveObjectRef(
            (SensitiveObjectKind)ownerKind.Value,
            new SensitiveObjectId(SqliteEventStore.ParseCanonicalGuid(ownerId)));
        var parsedKeyId = new DataKeyId(
            SqliteEventStore.ParseCanonicalGuid(keyId));
        var isActive = active.TryGetValue(owner, out var activeKey)
            && activeKey.KeyId == parsedKeyId;
        var hasReceipt = destroyed.TryGetValue(owner, out var receipt)
            && receipt.KeyId == parsedKeyId;
        var isDestroyed = hasReceipt
            && receipt!.State == VaultDestroyedReceiptState.Completed;
        var isPending = hasReceipt && !isDestroyed;
        var recognizedStates = (isActive ? 1 : 0)
            + (isDestroyed ? 1 : 0)
            + (isPending ? 1 : 0);
        if (recognizedStates != 1) throw new VaultRecoveryRequiredException();
        var encryptedShape = nonceLength == 12 && tagLength == 16;
        var structuralShape =
            nonceLength == 0 && ciphertextLength == 0 && tagLength == 0;
        if (isDestroyed
            ? !encryptedShape && !structuralShape
            : !encryptedShape)
        {
            throw new VaultRecoveryRequiredException();
        }
        if (isPending && !allowPendingReceipts)
            throw new VaultRecoveryRequiredException();
        return isDestroyed;
    }

    private static async Task RequireExactCloneAsync(
        SqliteConnection source,
        SqliteTransaction sourceTransaction,
        SqliteConnection candidate,
        SqliteTransaction candidateTransaction,
        VaultKeyRing ring,
        bool afterScrub,
        CancellationToken cancellationToken)
    {
        var active = ring.ActiveKeys.ToDictionary(entry => entry.Owner);
        var destroyed = ring.DestroyedReceipts.ToDictionary(receipt => receipt.Owner);
        const string sql = """
            SELECT global_position,event_id,stream_id,stream_version,event_type,schema_version,
                   recorded_at_utc,operation_id,operation_index,operation_count,protection_kind,
                   owner_kind,owner_id,key_id,envelope_version,payload_nonce,payload_ciphertext,payload_tag
            FROM main.timeline_events ORDER BY global_position;
            """;
        await using var sourceCommand = source.CreateCommand();
        sourceCommand.Transaction = sourceTransaction;
        sourceCommand.CommandText = sql;
        await using var candidateCommand = candidate.CreateCommand();
        candidateCommand.Transaction = candidateTransaction;
        candidateCommand.CommandText = sql;
        await using var sourceReader = await sourceCommand.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var candidateReader = await candidateCommand
            .ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (true)
        {
            var sourceHasRow = await sourceReader.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            var candidateHasRow = await candidateReader.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            if (sourceHasRow != candidateHasRow)
                throw new VaultRecoveryRequiredException();
            if (!sourceHasRow) return;
            CompactionEventImage? expected = null;
            CompactionEventImage? actual = null;
            try
            {
                expected = ReadCompactionEventImage(sourceReader, active, destroyed);
                actual = ReadCompactionEventImage(candidateReader, active, destroyed);
                if (!expected.HeaderEquals(actual)
                    || expected.IsDestroyed != actual.IsDestroyed
                    || (afterScrub && expected.IsDestroyed
                        ? actual.PayloadNonce is not { Length: 0 }
                            || actual.PayloadCiphertext.Length != 0
                            || actual.PayloadTag is not { Length: 0 }
                        : !expected.PayloadCiphertext.AsSpan()
                            .SequenceEqual(actual.PayloadCiphertext)
                            || !CompactionEventImage.NullableBytesEqual(
                                expected.PayloadNonce,
                                actual.PayloadNonce)
                            || !CompactionEventImage.NullableBytesEqual(
                                expected.PayloadTag,
                                actual.PayloadTag)))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
            finally
            {
                expected?.ZeroPayload();
                actual?.ZeroPayload();
            }
        }
    }

    private static CompactionEventImage ReadCompactionEventImage(
        SqliteDataReader reader,
        IReadOnlyDictionary<SensitiveObjectRef, VaultActiveKeyMetadata> active,
        IReadOnlyDictionary<SensitiveObjectRef, VaultDestroyedKeyReceipt> destroyed)
    {
        var protectionKind = reader.GetInt64(10);
        long? ownerKind = reader.IsDBNull(11) ? null : reader.GetInt64(11);
        var ownerId = reader.IsDBNull(12) ? null : reader.GetString(12);
        var keyId = reader.IsDBNull(13) ? null : reader.GetString(13);
        var nonce = reader.IsDBNull(15) ? null : reader.GetFieldValue<byte[]>(15);
        var ciphertext = reader.GetFieldValue<byte[]>(16);
        var tag = reader.IsDBNull(17) ? null : reader.GetFieldValue<byte[]>(17);
        var isDestroyed = ClassifyDestroyed(
            protectionKind,
            ownerKind,
            ownerId,
            keyId,
            reader.GetInt64(14),
            nonce?.LongLength ?? -1,
            ciphertext.LongLength,
            tag?.LongLength ?? -1,
            active,
            destroyed);
        return new CompactionEventImage(
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
            ownerKind,
            ownerId,
            keyId,
            reader.GetInt64(14),
            nonce,
            ciphertext,
            tag,
            isDestroyed);
    }

    private static async Task RequireDestroyedPayloadsAbsentAsync(
        SqliteConnection source,
        SqliteTransaction sourceTransaction,
        string artifactPath,
        VaultKeyRing ring,
        CancellationToken cancellationToken)
    {
        var active = ring.ActiveKeys.ToDictionary(entry => entry.Owner);
        var destroyed = ring.DestroyedReceipts.ToDictionary(receipt => receipt.Owner);
        await using var command = source.CreateCommand();
        command.Transaction = sourceTransaction;
        command.CommandText = """
            SELECT owner_kind,owner_id,key_id,envelope_version,
                   payload_nonce,payload_ciphertext,payload_tag
            FROM main.timeline_events
            WHERE protection_kind=1
            ORDER BY global_position;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        var patterns = new List<byte[]>(ErasureScanBatchPatternCount);
        var patternBytes = 0;
        try
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var nonceLength = reader.GetBytes(4, 0, null, 0, 0);
                var ciphertextLength = reader.GetBytes(5, 0, null, 0, 0);
                var tagLength = reader.GetBytes(6, 0, null, 0, 0);
                if (!ClassifyDestroyed(
                        protectionKind: 1,
                        reader.GetInt64(0),
                        reader.GetString(1),
                        reader.GetString(2),
                        reader.GetInt64(3),
                        nonceLength,
                        ciphertextLength,
                        tagLength,
                        active,
                        destroyed))
                {
                    continue;
                }

                for (var ordinal = 4; ordinal <= 6; ordinal++)
                {
                    var pattern = reader.GetFieldValue<byte[]>(ordinal);
                    var ownedByBatch = false;
                    try
                    {
                        if (pattern.Length == 0
                            || ordinal == 5
                            && pattern.Length < MinimumIndependentCiphertextScanLength)
                        {
                            continue;
                        }

                        if (pattern.Length > ErasureScanBatchByteCount)
                        {
                            await FlushOwnedPatternBatchAsync(
                                artifactPath,
                                patterns,
                                cancellationToken).ConfigureAwait(false);
                            patternBytes = 0;
                            if (await FileContainsPatternAsync(
                                    artifactPath,
                                    pattern,
                                    cancellationToken).ConfigureAwait(false))
                            {
                                throw new VaultRecoveryRequiredException();
                            }
                            continue;
                        }

                        if (patterns.Any(
                            candidate => candidate.AsSpan().SequenceEqual(pattern)))
                        {
                            continue;
                        }
                        if (patterns.Count == ErasureScanBatchPatternCount
                            || patternBytes + pattern.Length > ErasureScanBatchByteCount)
                        {
                            await FlushOwnedPatternBatchAsync(
                                artifactPath,
                                patterns,
                                cancellationToken).ConfigureAwait(false);
                            patternBytes = 0;
                        }

                        patterns.Add(pattern);
                        patternBytes += pattern.Length;
                        ownedByBatch = true;
                    }
                    finally
                    {
                        if (!ownedByBatch)
                        {
                            System.Security.Cryptography.CryptographicOperations
                                .ZeroMemory(pattern);
                        }
                    }
                }
            }

            await FlushOwnedPatternBatchAsync(
                artifactPath,
                patterns,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ZeroOwnedPatterns(patterns);
        }
    }

    private static async Task FlushOwnedPatternBatchAsync(
        string artifactPath,
        List<byte[]> patterns,
        CancellationToken cancellationToken)
    {
        if (patterns.Count == 0) return;
        try
        {
            if (await FileContainsPatternBatchAsync(
                artifactPath,
                patterns,
                cancellationToken).ConfigureAwait(false))
            {
                throw new VaultRecoveryRequiredException();
            }
        }
        finally
        {
            ZeroOwnedPatterns(patterns);
        }
    }

    private static void ZeroOwnedPatterns(List<byte[]> patterns)
    {
        foreach (var pattern in patterns)
        {
            System.Security.Cryptography.CryptographicOperations
                .ZeroMemory(pattern);
        }
        patterns.Clear();
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
        CancellationToken cancellationToken,
        Action? beforeScanPass = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(patterns);
        var batch = new List<byte[]>(ErasureScanBatchPatternCount);
        var unique = new HashSet<byte[]>(ByteArrayComparer.Instance);
        var batchBytes = 0;
        foreach (var pattern in patterns)
        {
            ArgumentNullException.ThrowIfNull(pattern);
            if (pattern.Length == 0 || !unique.Add(pattern)) continue;
            if (pattern.Length > ErasureScanBatchByteCount)
            {
                if (batch.Count != 0
                    && await FileContainsPatternBatchAsync(
                        path,
                        batch,
                        cancellationToken,
                        beforeScanPass).ConfigureAwait(false))
                {
                    return true;
                }
                batch.Clear();
                batchBytes = 0;
                if (await FileContainsPatternAsync(
                    path,
                    pattern,
                    cancellationToken,
                    beforeScanPass).ConfigureAwait(false))
                    return true;
                continue;
            }

            if (batch.Count == ErasureScanBatchPatternCount
                || batchBytes + pattern.Length > ErasureScanBatchByteCount)
            {
                if (await FileContainsPatternBatchAsync(
                    path,
                    batch,
                    cancellationToken,
                    beforeScanPass).ConfigureAwait(false))
                {
                    return true;
                }
                batch.Clear();
                batchBytes = 0;
            }

            batch.Add(pattern);
            batchBytes += pattern.Length;
        }
        return batch.Count != 0
            && await FileContainsPatternBatchAsync(
                path,
                batch,
                cancellationToken,
                beforeScanPass).ConfigureAwait(false);
    }

    private static async Task<bool> FileContainsPatternBatchAsync(
        string path,
        IReadOnlyList<byte[]> patterns,
        CancellationToken cancellationToken,
        Action? beforeScanPass = null)
    {
        if (patterns.Count == 0) return false;
        using var matcher = new ExactMultiPatternMatcher(patterns);
        var buffer = new byte[ErasureScanBlockSize];
        try
        {
            beforeScanPass?.Invoke();
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
                    buffer,
                    cancellationToken).ConfigureAwait(false);
                if (read == 0) return false;
                if (matcher.Accept(buffer.AsSpan(0, read))) return true;
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations
                .ZeroMemory(buffer);
        }
    }

    private static async Task<bool> FileContainsPatternAsync(
        string path,
        byte[] pattern,
        CancellationToken cancellationToken,
        Action? beforeScanPass = null)
    {
        if (pattern.Length == 0) return false;
        var prefix = new int[pattern.Length];
        for (int index = 1, matched = 0; index < pattern.Length; index++)
        {
            while (matched > 0 && pattern[index] != pattern[matched])
                matched = prefix[matched - 1];
            if (pattern[index] == pattern[matched]) matched++;
            prefix[index] = matched;
        }
        var buffer = new byte[ErasureScanBlockSize];
        var matchedLength = 0;
        try
        {
            beforeScanPass?.Invoke();
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
                    buffer,
                    cancellationToken).ConfigureAwait(false);
                if (read == 0) return false;
                foreach (var value in buffer.AsSpan(0, read))
                {
                    while (matchedLength > 0 && value != pattern[matchedLength])
                        matchedLength = prefix[matchedLength - 1];
                    if (value == pattern[matchedLength]) matchedLength++;
                    if (matchedLength == pattern.Length) return true;
                }
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations
                .ZeroMemory(buffer);
            Array.Clear(prefix);
        }
    }

    private sealed class ExactMultiPatternMatcher : IDisposable
    {
        private readonly List<ExactMultiPatternNode> _nodes = [new()];
        private int _state;

        internal ExactMultiPatternMatcher(IReadOnlyList<byte[]> patterns)
        {
            try
            {
                foreach (var pattern in patterns)
                {
                    if (pattern.Length == 0)
                        throw new ArgumentException("Scan patterns must not be empty.", nameof(patterns));
                    var nodeIndex = 0;
                    foreach (var value in pattern)
                    {
                        if (!_nodes[nodeIndex].Transitions.TryGetValue(value, out var next))
                        {
                            next = _nodes.Count;
                            _nodes[nodeIndex].Transitions.Add(value, next);
                            _nodes.Add(new ExactMultiPatternNode());
                        }
                        nodeIndex = next;
                    }
                    _nodes[nodeIndex].Terminal = true;
                }
                BuildFailureLinks();
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        internal bool Accept(ReadOnlySpan<byte> input)
        {
            foreach (var value in input)
            {
                while (_state != 0
                    && !_nodes[_state].Transitions.ContainsKey(value))
                {
                    _state = _nodes[_state].Failure;
                }
                if (_nodes[_state].Transitions.TryGetValue(value, out var next))
                    _state = next;
                if (_nodes[_state].Terminal) return true;
            }
            return false;
        }

        private void BuildFailureLinks()
        {
            var pending = new Queue<int>();
            foreach (var child in _nodes[0].Transitions.Values)
                pending.Enqueue(child);
            while (pending.Count != 0)
            {
                var parentIndex = pending.Dequeue();
                foreach (var (value, childIndex) in _nodes[parentIndex].Transitions)
                {
                    pending.Enqueue(childIndex);
                    var fallback = _nodes[parentIndex].Failure;
                    while (fallback != 0
                        && !_nodes[fallback].Transitions.ContainsKey(value))
                    {
                        fallback = _nodes[fallback].Failure;
                    }
                    if (_nodes[fallback].Transitions.TryGetValue(value, out var next)
                        && next != childIndex)
                    {
                        fallback = next;
                    }
                    _nodes[childIndex].Failure = fallback;
                    _nodes[childIndex].Terminal |= _nodes[fallback].Terminal;
                }
            }
        }

        public void Dispose()
        {
            foreach (var node in _nodes)
                node.Transitions.Clear();
            _nodes.Clear();
            _state = 0;
        }
    }

    private sealed class ExactMultiPatternNode
    {
        internal Dictionary<byte, int> Transitions { get; } = [];
        internal int Failure { get; set; }
        internal bool Terminal { get; set; }
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
            var hash = new HashCode();
            hash.AddBytes(value);
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

    private sealed record EventPreflight(
        bool RequiresScrub,
        IReadOnlyList<DestroyedEnvelopeGroup> DestroyedGroups);

    private sealed record ManagedCopyPreflight(
        string Path,
        EventPreflight Preflight);

    private sealed record DestroyedEnvelopeGroup(
        long OwnerKind,
        string OwnerId,
        string KeyId,
        int EventCount);

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

        internal void ZeroPayload()
        {
            if (PayloadNonce is not null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(PayloadNonce);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(PayloadCiphertext);
            if (PayloadTag is not null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(PayloadTag);
        }
    }
}
