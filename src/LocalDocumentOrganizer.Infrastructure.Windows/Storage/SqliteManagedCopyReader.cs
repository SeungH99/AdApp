using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal sealed class SqliteManagedCopyReader
{
    private readonly string _path;
    private readonly EventSchemaRegistry _schemas;
    private readonly SqliteProjectionRegistry _projections;
    private readonly VaultKeyRingStore _keyRing;
    private readonly SqliteEventPayloadProtectionProvider _payloads;

    internal SqliteManagedCopyReader(
        string path,
        EventSchemaRegistry schemas,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(schemas);
        ArgumentNullException.ThrowIfNull(projections);
        ArgumentNullException.ThrowIfNull(keyRing);
        _path = Path.GetFullPath(path);
        _schemas = schemas;
        _projections = projections;
        _keyRing = keyRing;
        _payloads = new SqliteEventPayloadProtectionProvider(keyRing);
        WindowsVaultPathGuard.RequireSafeDatabaseSet(_path);
    }

    public async Task<IReadOnlyList<EventForReplay>> ReadStreamAsync(
        StreamId streamId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        WindowsVaultPathGuard.RequireSafeDatabaseSet(_path);
        if (File.Exists(_path + "-wal") || File.Exists(_path + "-shm"))
            throw new VaultRecoveryRequiredException();
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireReadAsync(cancellationToken).ConfigureAwait(false);
        await using var payloadSession = _payloads.CreateReadSession(lease);
        await using var connection = await OpenImmutableAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        try
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
            payloadSession.BindExpectedIdentity(identity);
            var events = await SqliteEventStore.ReadStreamFromValidatedConnectionAsync(
                connection,
                transaction,
                streamId,
                _schemas,
                payloadSession,
                cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return events;
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (SqliteException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private async Task<SqliteConnection> OpenImmutableAsync(
        CancellationToken cancellationToken)
    {
        RequireWalDatabaseHeader();
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = new Uri(_path).AbsoluteUri + "?immutable=1",
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString());
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await RequirePragmaAsync(
                connection,
                "PRAGMA foreign_keys=ON;",
                "PRAGMA foreign_keys;",
                "1",
                cancellationToken).ConfigureAwait(false);
            await RequirePragmaAsync(
                connection,
                "PRAGMA secure_delete=ON;",
                "PRAGMA secure_delete;",
                "1",
                cancellationToken).ConfigureAwait(false);
            await RequirePragmaAsync(
                connection,
                "PRAGMA query_only=ON;",
                "PRAGMA query_only;",
                "1",
                cancellationToken).ConfigureAwait(false);
            WindowsVaultPathGuard.RequireSafeDatabaseSet(_path);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private void RequireWalDatabaseHeader()
    {
        Span<byte> header = stackalloc byte[20];
        using var stream = new FileStream(
            _path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            header.Length,
            FileOptions.SequentialScan);
        stream.ReadExactly(header);
        if (!header[..16].SequenceEqual("SQLite format 3\0"u8)
            || header[18] != 2
            || header[19] != 2)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task RequirePragmaAsync(
        SqliteConnection connection,
        string? setupSql,
        string querySql,
        string expected,
        CancellationToken cancellationToken)
    {
        if (setupSql is not null)
        {
            await using var setup = connection.CreateCommand();
            setup.CommandText = setupSql;
            await setup.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await using var query = connection.CreateCommand();
        query.CommandText = querySql;
        var actual = Convert.ToString(
            await query.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture);
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new VaultRecoveryRequiredException();
    }
}
