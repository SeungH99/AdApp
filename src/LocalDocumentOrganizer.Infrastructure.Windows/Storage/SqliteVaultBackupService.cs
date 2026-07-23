using System.Runtime.ExceptionServices;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal enum SqliteVaultBackupFaultPoint
{
    BeforeBackup,
    AfterBackup,
    AfterPublish,
    BeforeRegistration,
    AfterRegistration,
}

internal readonly record struct ManagedVaultCopyId
{
    internal ManagedVaultCopyId(string value)
    {
        if (!Guid.TryParseExact(value, "N", out var parsed)
            || parsed == Guid.Empty
            || !string.Equals(value, value.ToLowerInvariant(), StringComparison.Ordinal))
        {
            throw new ArgumentException("A canonical managed-copy identifier is required.", nameof(value));
        }

        Value = value;
    }

    internal string Value { get; }

    internal static ManagedVaultCopyId Create() => new(Guid.NewGuid().ToString("N"));
}

internal sealed class SqliteVaultBackupService
{
    internal const string DirectorySuffix = ".managed-copies";

    private readonly string _connectionString;
    private readonly string _vaultPath;
    private readonly string _managedDirectory;
    private readonly SqliteProjectionRegistry _projections;
    private readonly VaultKeyRingStore _keyRing;
    private readonly Action<SqliteVaultBackupFaultPoint>? _injectFault;

    internal SqliteVaultBackupService(
        string connectionString,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        Action<SqliteVaultBackupFaultPoint>? injectFault = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(projections);
        ArgumentNullException.ThrowIfNull(keyRing);
        _connectionString = SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        _vaultPath = Path.GetFullPath(
            new SqliteConnectionStringBuilder(_connectionString).DataSource);
        _managedDirectory = _vaultPath + DirectorySuffix;
        _projections = projections;
        _keyRing = keyRing;
        _injectFault = injectFault;
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);
    }

    internal async Task<ManagedVaultCopyId> CreateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireManagedDirectory();
        var copyId = ManagedVaultCopyId.Create();
        var finalPath = GetPath(copyId);
        var temporaryPath = finalPath + ".creating-" + Guid.NewGuid().ToString("N");
        WindowsVaultPathGuard.RequireSafeDatabaseSet(temporaryPath);
        WindowsVaultPathGuard.RequireSafeDatabaseSet(finalPath);

        try
        {
            await CreateConsistentDatabaseAsync(temporaryPath, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await using var lease = await _keyRing.MaintenanceGate
                .AcquireMutationAsync(cancellationToken).ConfigureAwait(false);
            File.Move(temporaryPath, finalPath);
            _injectFault?.Invoke(SqliteVaultBackupFaultPoint.AfterPublish);
            _injectFault?.Invoke(SqliteVaultBackupFaultPoint.BeforeRegistration);
            await RegisterAsync(copyId, lease, cancellationToken).ConfigureAwait(false);
            _injectFault?.Invoke(SqliteVaultBackupFaultPoint.AfterRegistration);
            return copyId;
        }
        catch (Exception exception)
        {
            var primary = ExceptionDispatchInfo.Capture(MapStorageFailure(exception));
            try
            {
                await DeleteDatabaseSetAsync(temporaryPath).ConfigureAwait(false);
                if (!await IsRegisteredAsync(copyId).ConfigureAwait(false))
                {
                    await DeleteDatabaseSetAsync(finalPath).ConfigureAwait(false);
                }
            }
            catch
            {
                // The primary failure wins. A published-but-unregistered database has
                // an unguessable reserved name and startup cleanup treats it as an orphan.
            }
            primary.Throw();
            throw;
        }
    }

    internal SqliteEventStore Open(
        ManagedVaultCopyId copyId,
        EventSchemaRegistry schemaRegistry)
    {
        ArgumentNullException.ThrowIfNull(schemaRegistry);
        var path = GetPath(copyId);
        if (!File.Exists(path)) throw new VaultRecoveryRequiredException();
        return new SqliteEventStore(
            ConnectionString(path),
            schemaRegistry,
            _projections,
            _keyRing);
    }

    internal string GetPath(ManagedVaultCopyId copyId)
    {
        _ = new ManagedVaultCopyId(copyId.Value);
        var path = Path.Combine(_managedDirectory, copyId.Value + ".db");
        WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
        return path;
    }

    internal async Task<IReadOnlyList<ManagedVaultCopyId>> ReadRegisteredAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        _keyRing.MaintenanceGate.Validate(
            lease,
            VaultLeaseMode.Read,
            VaultLeaseMode.Mutation,
            VaultLeaseMode.Rebuild);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString,
            _keyRing.MaintenanceGate,
            cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        await ValidateAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        var result = new List<ManagedVaultCopyId>();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT copy_id FROM main.managed_vault_copies ORDER BY copy_id COLLATE BINARY;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (reader.GetValue(0) is not string value)
                throw new VaultRecoveryRequiredException();
            try { result.Add(new ManagedVaultCopyId(value)); }
            catch (ArgumentException exception) { throw new VaultRecoveryRequiredException(exception); }
        }
        return result.AsReadOnly();
    }

    internal async Task CleanupOrphansAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken,
        Action? beforeDelete = null)
    {
        _keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        if (!Directory.Exists(_managedDirectory)) return;
        RequireExistingManagedDirectory();
        var registered = (await ReadRegisteredAsync(lease, cancellationToken)
                .ConfigureAwait(false))
            .Select(copy => Path.GetFullPath(GetPath(copy)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var orphanCores = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in Directory.EnumerateFileSystemEntries(
            _managedDirectory,
            "*",
            SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Directory.Exists(candidate)) throw new VaultRecoveryRequiredException();
            var fullPath = Path.GetFullPath(candidate);
            var corePath = StripSqliteSidecar(fullPath);
            if (registered.Contains(corePath)) continue;
            var coreName = Path.GetFileName(corePath);
            if (IsCreatingArtifactName(coreName) || IsManagedCopyFileName(coreName))
            {
                orphanCores.Add(corePath);
                continue;
            }
            throw new VaultRecoveryRequiredException();
        }

        foreach (var orphan in orphanCores.OrderBy(path => path, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            WindowsVaultPathGuard.RequireSafeDatabaseSet(orphan);
            beforeDelete?.Invoke();
            try { await DeleteDatabaseSetAsync(orphan).ConfigureAwait(false); }
            catch (Exception) { throw new VaultRecoveryRequiredException(); }
            if (File.Exists(orphan)
                || File.Exists(orphan + "-journal")
                || File.Exists(orphan + "-wal")
                || File.Exists(orphan + "-shm"))
            {
                throw new VaultRecoveryRequiredException();
            }
        }
    }

    private async Task CreateConsistentDatabaseAsync(
        string destinationPath,
        CancellationToken cancellationToken)
    {
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireReadAsync(cancellationToken).ConfigureAwait(false);
        await using var source = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString,
            _keyRing.MaintenanceGate,
            cancellationToken).ConfigureAwait(false);
        await using var sourceTransaction = source.BeginTransaction(deferred: true);
        await ValidateAsync(source, sourceTransaction, cancellationToken).ConfigureAwait(false);
        var expectedIdentity = await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
            source,
            sourceTransaction,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateCurrentKeyRingIdentityAsync(
            _keyRing,
            expectedIdentity,
            cancellationToken).ConfigureAwait(false);

        _injectFault?.Invoke(SqliteVaultBackupFaultPoint.BeforeBackup);

        await using (var destination = new SqliteConnection(ConnectionString(destinationPath)))
        {
            await destination.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(destination, "PRAGMA main.secure_delete=ON;", cancellationToken)
                .ConfigureAwait(false);
            await ExecuteAsync(destination, "PRAGMA main.synchronous=FULL;", cancellationToken)
                .ConfigureAwait(false);
            source.BackupDatabase(destination);
        }
        _injectFault?.Invoke(SqliteVaultBackupFaultPoint.AfterBackup);

        cancellationToken.ThrowIfCancellationRequested();
        await using var verification = await SqliteEventStoreSchema.OpenConnectionAsync(
            ConnectionString(destinationPath),
            maintenanceGate: null,
            cancellationToken).ConfigureAwait(false);
        await using var verificationTransaction = verification.BeginTransaction(deferred: true);
        await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
            verification,
            verificationTransaction,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
            verification,
            verificationTransaction,
            _projections,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
            verification,
            verificationTransaction,
            expectedIdentity,
            cancellationToken).ConfigureAwait(false);
        await RequireIntegrityAsync(verification, verificationTransaction, cancellationToken)
            .ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateCurrentKeyRingIdentityAsync(
            _keyRing,
            expectedIdentity,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task RegisterAsync(
        ManagedVaultCopyId copyId,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        _keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            _connectionString,
            _keyRing.MaintenanceGate,
            cancellationToken).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: false);
        await ValidateAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO main.managed_vault_copies(copy_id) VALUES($copy_id);";
        command.Parameters.AddWithValue("$copy_id", copyId.Value);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private async Task<bool> IsRegisteredAsync(ManagedVaultCopyId copyId)
    {
        try
        {
            await using var lease = await _keyRing.MaintenanceGate
                .AcquireReadAsync(CancellationToken.None).ConfigureAwait(false);
            await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString,
                _keyRing.MaintenanceGate,
                CancellationToken.None).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                "SELECT COUNT(*) FROM main.managed_vault_copies WHERE copy_id=$copy_id;";
            command.Parameters.AddWithValue("$copy_id", copyId.Value);
            return Convert.ToInt64(await command.ExecuteScalarAsync()) == 1;
        }
        catch
        {
            return true;
        }
    }

    private async Task ValidateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
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
        var identity = await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
            connection,
            transaction,
            cancellationToken).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateCurrentKeyRingIdentityAsync(
            _keyRing,
            identity,
            cancellationToken).ConfigureAwait(false);
    }

    private void RequireManagedDirectory()
    {
        WindowsVaultPathGuard.RequireSafeEntryShape(_managedDirectory);
        Directory.CreateDirectory(_managedDirectory);
        var info = new DirectoryInfo(_managedDirectory);
        if (!info.Exists
            || (info.Attributes & FileAttributes.ReparsePoint) != 0
            || info.LinkTarget is not null)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private void RequireExistingManagedDirectory()
    {
        var info = new DirectoryInfo(_managedDirectory);
        if (!info.Exists
            || (info.Attributes & FileAttributes.ReparsePoint) != 0
            || info.LinkTarget is not null
            || !string.Equals(info.FullName, _managedDirectory, StringComparison.OrdinalIgnoreCase))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static string StripSqliteSidecar(string path)
    {
        foreach (var suffix in new[] { "-journal", "-wal", "-shm" })
        {
            if (path.EndsWith(suffix, StringComparison.Ordinal))
                return path[..^suffix.Length];
        }
        return path;
    }

    private static bool IsCreatingArtifactName(string name)
    {
        const string marker = ".db.creating-";
        return name.Length == 32 + marker.Length + 32
            && name.AsSpan(32, marker.Length).Equals(marker, StringComparison.Ordinal)
            && IsRandomId(name.AsSpan(0, 32))
            && IsRandomId(name.AsSpan(32 + marker.Length, 32));
    }

    private static bool IsManagedCopyFileName(string name) =>
        name.Length == 35
        && name.EndsWith(".db", StringComparison.Ordinal)
        && IsRandomId(name.AsSpan(0, 32));

    private static bool IsRandomId(ReadOnlySpan<char> value) =>
        value.IndexOfAnyExcept("0123456789abcdef".AsSpan()) < 0
        && !value.SequenceEqual("00000000000000000000000000000000".AsSpan());

    private static async Task RequireIntegrityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA main.integrity_check;";
        var result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(result as string, "ok", StringComparison.Ordinal))
            throw new VaultRecoveryRequiredException();
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static Task DeleteDatabaseSetAsync(string path)
    {
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
            return new StorageBusyException("The managed copy could not acquire storage access.", busy);
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
}
