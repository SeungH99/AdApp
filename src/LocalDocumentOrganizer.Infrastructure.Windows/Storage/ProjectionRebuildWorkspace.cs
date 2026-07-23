using System.Runtime.ExceptionServices;
using System.Globalization;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal enum ProjectionRebuildCommitState
{
    PreCommit,
    Committed,
}

internal enum ProjectionRebuildFaultPoint
{
    AfterWorkspaceFileCreated,
    AfterWorkspaceConnectionOpened,
    AfterWorkspacePragmasApplied,
    AfterWorkspaceManifestCreated,
    BeforePartialWorkspaceCleanup,
    AfterArtifactCreated,
    AfterProjectionInitialized,
    AfterReplayBatch,
    BeforeTemporaryValidation,
    BeforePromotion,
    AfterLiveRowsCleared,
    AfterLiveRowsCopied,
    BeforeLiveCommit,
    AfterLiveCommit,
    BeforeOutcomeClassifierOpen,
    DuringOutcomeClassifierSchemaValidation,
    DuringOutcomeClassifierSnapshotRead,
    DuringOutcomeClassifierChecksumValidation,
    BeforeArtifactCleanup,
}

internal sealed class ProjectionPromotionOutcomeUnknownException : Exception
{
    internal ProjectionPromotionOutcomeUnknownException(Exception innerException)
        : base("Projection promotion outcome is unknown.", innerException)
    {
    }
}

internal sealed class ProjectionRebuildWorkspace : IAsyncDisposable
{
    internal const string FileMarker = ".projection-rebuild-";

    private const string ManifestTableSql = """
        CREATE TABLE projection_rebuild_manifest(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            generation_id TEXT NOT NULL,
            keyring_id BLOB NOT NULL CHECK(length(keyring_id)=32),
            required_global_position INTEGER NOT NULL CHECK(required_global_position>=0),
            total_event_count INTEGER NOT NULL CHECK(total_event_count>=0),
            coordinate_digest BLOB NOT NULL CHECK(length(coordinate_digest)=32),
            stream_head_digest BLOB NOT NULL CHECK(length(stream_head_digest)=32),
            operation_digest BLOB NOT NULL CHECK(length(operation_digest)=32),
            promotion_started INTEGER NOT NULL DEFAULT 0 CHECK(promotion_started IN (0,1))
        ) STRICT
        """;

    private const string CheckpointTableSql = """
        CREATE TABLE projection_checkpoints(
            projection_name TEXT PRIMARY KEY,
            projection_schema_version INTEGER NOT NULL CHECK(projection_schema_version>0),
            encryption_version INTEGER NOT NULL CHECK(encryption_version>0),
            last_global_position INTEGER NOT NULL CHECK(last_global_position>=0)
        ) STRICT
        """;

    private readonly object _completionSync = new();
    private readonly string _vaultPath;
    private readonly VaultMaintenanceGate _gate;
    private readonly Action<ProjectionRebuildFaultPoint>? _injectFault;
    private SqliteConnection? _connection;
    private ProjectionRebuildCommitState? _completionState;
    private Task? _completionTask;

    private ProjectionRebuildWorkspace(
        string vaultPath,
        string path,
        string generationId,
        VaultMaintenanceGate gate,
        SqliteConnection connection,
        Action<ProjectionRebuildFaultPoint>? injectFault)
    {
        _vaultPath = vaultPath;
        Path = path;
        GenerationId = generationId;
        _gate = gate;
        _connection = connection;
        _injectFault = injectFault;
    }

    internal string Path { get; }

    internal string GenerationId { get; }

    internal SqliteConnection Connection =>
        Volatile.Read(ref _connection) ?? throw new ObjectDisposedException(nameof(ProjectionRebuildWorkspace));

    internal static async Task<ProjectionRebuildWorkspace> CreateAsync(
        string vaultConnectionString,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken,
        Action<ProjectionRebuildFaultPoint>? injectFault = null)
    {
        var vaultPath = GetVaultPath(vaultConnectionString);
        var gate = new VaultMaintenanceGate(vaultPath + ".keyring");
        gate.Validate(lease, VaultLeaseMode.Rebuild);
        cancellationToken.ThrowIfCancellationRequested();

        var generationId = Guid.NewGuid().ToString("N");
        var path = System.IO.Path.Combine(
            System.IO.Path.GetDirectoryName(vaultPath)!,
            System.IO.Path.GetFileName(vaultPath)
            + FileMarker
            + generationId
            + ".tmp");
        WindowsVaultPathGuard.RequireReservedProjectionRebuildArtifact(vaultPath, path);

        SqliteConnection? connection = null;
        try
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

            injectFault?.Invoke(ProjectionRebuildFaultPoint.AfterWorkspaceFileCreated);
            connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
            }.ToString());
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            injectFault?.Invoke(ProjectionRebuildFaultPoint.AfterWorkspaceConnectionOpened);

            await ExecuteAsync(connection, "PRAGMA journal_mode=WAL;", cancellationToken)
                .ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA synchronous=FULL;", cancellationToken)
                .ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA secure_delete=ON;", cancellationToken)
                .ConfigureAwait(false);
            injectFault?.Invoke(ProjectionRebuildFaultPoint.AfterWorkspacePragmasApplied);

            await ExecuteAsync(
                connection,
                $"{ManifestTableSql};{CheckpointTableSql};PRAGMA user_version=1;",
                cancellationToken).ConfigureAwait(false);
            injectFault?.Invoke(ProjectionRebuildFaultPoint.AfterWorkspaceManifestCreated);
            return new ProjectionRebuildWorkspace(
                vaultPath,
                path,
                generationId,
                gate,
                connection,
                injectFault);
        }
        catch (Exception exception)
        {
            var primaryFailure = ExceptionDispatchInfo.Capture(exception);
            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }

            try
            {
                injectFault?.Invoke(ProjectionRebuildFaultPoint.BeforePartialWorkspaceCleanup);
                DeleteArtifactSet(vaultPath, path);
            }
            catch
            {
                // The original creation failure is canonical. A recognizable orphan is recoverable.
            }

            primaryFailure.Throw();
            throw;
        }
    }

    internal async Task<SqliteConnection> OpenReadOnlyAsync(CancellationToken cancellationToken)
    {
        WindowsVaultPathGuard.RequireReservedProjectionRebuildArtifact(_vaultPath, Path);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString());
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal string CreateAttachUri()
    {
        WindowsVaultPathGuard.RequireReservedProjectionRebuildArtifact(_vaultPath, Path);
        return "file:" + new Uri(Path).AbsolutePath + "?mode=ro";
    }

    internal async Task PromoteAsync(
        string liveConnectionString,
        IReadOnlyList<SqliteProjectionRegistration> selected,
        ProjectionRebuildValidationResult validated,
        SqliteProjectionRegistry registry,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(liveConnectionString);
        ArgumentNullException.ThrowIfNull(selected);
        ArgumentNullException.ThrowIfNull(validated);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(keyRing);
        _gate.Validate(lease, VaultLeaseMode.Rebuild);
        cancellationToken.ThrowIfCancellationRequested();
        WindowsVaultPathGuard.RequireReservedProjectionRebuildArtifact(_vaultPath, Path);
        RequirePromotionCapacity();
        await MarkPromotionStartedAsync(cancellationToken).ConfigureAwait(false);
        await CloseConnectionAsync().ConfigureAwait(false);

        SqliteConnection? live = null;
        SqliteTransaction? transaction = null;
        var committed = false;
        try
        {
            live = await OpenPromotionConnectionAsync(cancellationToken).ConfigureAwait(false);
            transaction = live.BeginTransaction(deferred: false);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                live,
                transaction,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                live,
                transaction,
                registry,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStore.ValidateAllOperationMetadataAsync(
                live,
                transaction,
                cancellationToken).ConfigureAwait(false);
            var identity = await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                live,
                transaction,
                cancellationToken).ConfigureAwait(false);
            if (!validated.Manifest.KeyRingIdentity.FixedTimeEquals(identity.Export()))
                throw new VaultRecoveryRequiredException();
            await SqliteSensitiveDataDeletionStore.RequireNoPendingReceiptsAsync(
                keyRing,
                identity,
                cancellationToken).ConfigureAwait(false);

            var validator = new ProjectionRebuildValidator();
            await validator.RequireAuthoritativeSnapshotAsync(
                live,
                transaction,
                validated.Manifest,
                cancellationToken).ConfigureAwait(false);
            var selectedNames = selected
                .Select(registration => registration.Name)
                .ToHashSet(StringComparer.Ordinal);
            var unselectedBefore = await SqliteProjectionCheckpointStore.ReadUnselectedAsync(
                live,
                transaction,
                selectedNames,
                cancellationToken).ConfigureAwait(false);
            var unselectedNames = registry.Registrations
                .Select(registration => registration.Name)
                .Where(name => !selectedNames.Contains(name))
                .ToHashSet(StringComparer.Ordinal);
            var selectedBefore = await SqliteProjectionCheckpointStore.ReadUnselectedAsync(
                live,
                transaction,
                unselectedNames,
                cancellationToken).ConfigureAwait(false);

            await AttachReadOnlyAsync(live, transaction, cancellationToken).ConfigureAwait(false);
            var schemas = new Dictionary<string, ProjectionTableSchema>(StringComparer.Ordinal);
            foreach (var registration in selected)
            {
                foreach (var table in registration.OwnedTables)
                {
                    var liveSchema = await ReadTableSchemaAsync(
                        live,
                        transaction,
                        "main",
                        table.Name,
                        cancellationToken).ConfigureAwait(false);
                    var temporarySchema = await ReadTableSchemaAsync(
                        live,
                        transaction,
                        "rebuild",
                        table.Name,
                        cancellationToken).ConfigureAwait(false);
                    if (!SchemasEqual(liveSchema, temporarySchema))
                        throw new VaultRecoveryRequiredException();
                    if (liveSchema.ForeignTableNames.Any(referenced =>
                        !registration.OwnedTables.Any(owned => owned.Name == referenced)))
                    {
                        throw new VaultRecoveryRequiredException();
                    }

                    schemas.Add(table.Name, liveSchema);
                }
            }

            await ExecuteAsync(live, transaction, "PRAGMA defer_foreign_keys=ON;", cancellationToken)
                .ConfigureAwait(false);
            foreach (var schema in schemas.Values)
            {
                foreach (var trigger in schema.Triggers.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                {
                    await ExecuteAsync(
                        live,
                        transaction,
                        $"DROP TRIGGER {QuoteIdentifier(trigger.Key)};",
                        cancellationToken).ConfigureAwait(false);
                }
            }

            foreach (var registration in selected.Reverse())
            {
                foreach (var table in registration.OwnedTables.Reverse())
                {
                    await ExecuteAsync(
                        live,
                        transaction,
                        $"DELETE FROM main.{QuoteOwnedTable(table)};",
                        cancellationToken).ConfigureAwait(false);
                }
            }

            _injectFault?.Invoke(ProjectionRebuildFaultPoint.AfterLiveRowsCleared);
            foreach (var registration in selected)
            {
                foreach (var table in registration.OwnedTables)
                {
                    var columns = schemas[table.Name].Columns
                        .Where(column => column.Hidden == 0)
                        .Select(column => QuoteIdentifier(column.Name))
                        .ToArray();
                    if (columns.Length == 0) throw new VaultRecoveryRequiredException();
                    var list = string.Join(",", columns);
                    await ExecuteAsync(
                        live,
                        transaction,
                        $"INSERT INTO main.{QuoteOwnedTable(table)}({list}) "
                        + $"SELECT {list} FROM rebuild.{QuoteOwnedTable(table)};",
                        cancellationToken).ConfigureAwait(false);
                }
            }

            _injectFault?.Invoke(ProjectionRebuildFaultPoint.AfterLiveRowsCopied);
            foreach (var schema in schemas.Values)
            {
                foreach (var trigger in schema.Triggers.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                {
                    await ExecuteAsync(
                        live,
                        transaction,
                        trigger.Value,
                        cancellationToken).ConfigureAwait(false);
                }
            }

            foreach (var registration in selected)
            {
                await using var replace = live.CreateCommand();
                replace.Transaction = transaction;
                replace.CommandText = """
                    DELETE FROM main.projection_checkpoints WHERE projection_name=$name;
                    INSERT INTO main.projection_checkpoints(
                        projection_name,projection_schema_version,encryption_version,last_global_position)
                    SELECT projection_name,projection_schema_version,encryption_version,last_global_position
                    FROM rebuild.projection_checkpoints WHERE projection_name=$name;
                    """;
                replace.Parameters.AddWithValue("$name", registration.Name);
                if (await replace.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) is < 1 or > 2)
                    throw new VaultRecoveryRequiredException();
            }

            await SqliteProjectionCheckpointStore.RequireExactSelectedAsync(
                live,
                transaction,
                ProjectionCheckpointSchema.Main,
                selected,
                validated.Manifest.RequiredGlobalPosition,
                cancellationToken).ConfigureAwait(false);
            foreach (var registration in selected)
            {
                foreach (var table in registration.OwnedTables
                    .Where(table => schemas[table.Name].ForeignTableNames.Count != 0))
                {
                    await RequireNoForeignKeyViolationsAsync(
                        live,
                        transaction,
                        table,
                        cancellationToken).ConfigureAwait(false);
                }

                var checksum = await SqliteProjectionAuthorizer.RunAsync(
                    live,
                    registration.OwnedTables,
                    () => registration.Projection.CalculateChecksumAsync(
                        SqliteProjectionContexts.CreateAdministrative(
                            live,
                            transaction,
                            keyRing,
                            lease,
                            registration),
                        cancellationToken)).ConfigureAwait(false);
                if (!validated.ProjectionChecksums.TryGetValue(registration.Name, out var expected)
                    || !string.Equals(checksum, expected, StringComparison.Ordinal))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }

            var unselectedAfter = await SqliteProjectionCheckpointStore.ReadUnselectedAsync(
                live,
                transaction,
                selectedNames,
                cancellationToken).ConfigureAwait(false);
            if (!CheckpointSnapshotsEqual(unselectedBefore, unselectedAfter))
                throw new VaultRecoveryRequiredException();
            await validator.RequireAuthoritativeSnapshotAsync(
                live,
                transaction,
                validated.Manifest,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                live,
                transaction,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                live,
                transaction,
                registry,
                cancellationToken).ConfigureAwait(false);
            await SqliteSensitiveDataDeletionStore.RequireNoPendingReceiptsAsync(
                keyRing,
                validated.Manifest.KeyRingIdentity,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            _injectFault?.Invoke(ProjectionRebuildFaultPoint.BeforeLiveCommit);
            try
            {
                await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(false);
                committed = true;
            }
            catch (Exception commitException)
            {
                var primary = ExceptionDispatchInfo.Capture(commitException);
                await transaction.DisposeAsync().ConfigureAwait(false);
                transaction = null;
                await live.DisposeAsync().ConfigureAwait(false);
                live = null;
                PromotionOutcome outcome;
                try
                {
                    outcome = await ClassifyPromotionOutcomeAsync(
                        registry,
                        selected,
                        selectedBefore,
                        validated,
                        keyRing,
                        lease).ConfigureAwait(false);
                }
                catch (Exception classifierException)
                {
                    throw new ProjectionPromotionOutcomeUnknownException(classifierException);
                }

                if (outcome == PromotionOutcome.New)
                {
                    committed = true;
                }
                else if (outcome == PromotionOutcome.Old)
                {
                    primary.Throw();
                }
                else
                {
                    throw new ProjectionPromotionOutcomeUnknownException(commitException);
                }
            }
            _injectFault?.Invoke(ProjectionRebuildFaultPoint.AfterLiveCommit);
        }
        catch (SqliteException exception) when (!committed && exception.SqliteErrorCode == 13)
        {
            if (transaction is not null) await RollbackWithoutMaskingAsync(transaction).ConfigureAwait(false);
            throw new StorageCapacityException(exception);
        }
        catch (SqliteException exception) when (!committed && exception.SqliteErrorCode is 5 or 6)
        {
            if (transaction is not null) await RollbackWithoutMaskingAsync(transaction).ConfigureAwait(false);
            throw new StorageBusyException(
                "Projection promotion could not acquire the SQLite write lock.",
                exception);
        }
        catch
        {
            if (!committed && transaction is not null)
                await RollbackWithoutMaskingAsync(transaction).ConfigureAwait(false);
            if (!committed) throw;
        }
        finally
        {
            if (transaction is not null) await transaction.DisposeAsync().ConfigureAwait(false);
            if (live is not null) await live.DisposeAsync().ConfigureAwait(false);
            if (committed) await TryPassiveCheckpointAsync().ConfigureAwait(false);
        }
    }

    private async Task<PromotionOutcome> ClassifyPromotionOutcomeAsync(
        SqliteProjectionRegistry registry,
        IReadOnlyList<SqliteProjectionRegistration> selected,
        IReadOnlyDictionary<string, ProjectionCheckpointSnapshot> selectedBefore,
        ProjectionRebuildValidationResult validated,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease)
    {
        _injectFault?.Invoke(ProjectionRebuildFaultPoint.BeforeOutcomeClassifierOpen);
        await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
            new SqliteConnectionStringBuilder
            {
                DataSource = _vaultPath,
                Pooling = false,
            }.ToString(),
            _gate,
            CancellationToken.None).ConfigureAwait(false);
        await using var transaction = connection.BeginTransaction(deferred: true);
        _injectFault?.Invoke(ProjectionRebuildFaultPoint.DuringOutcomeClassifierSchemaValidation);
        await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
            connection,
            transaction,
            CancellationToken.None).ConfigureAwait(false);
        await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
            connection,
            transaction,
            registry,
            CancellationToken.None).ConfigureAwait(false);
        await SqliteEventStore.ValidateAllOperationMetadataAsync(
            connection,
            transaction,
            CancellationToken.None).ConfigureAwait(false);
        var identity = await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
            connection,
            transaction,
            CancellationToken.None).ConfigureAwait(false);
        if (!validated.Manifest.KeyRingIdentity.FixedTimeEquals(identity.Export()))
            throw new VaultRecoveryRequiredException();
        await new ProjectionRebuildValidator().RequireAuthoritativeSnapshotAsync(
            connection,
            transaction,
            validated.Manifest,
            CancellationToken.None).ConfigureAwait(false);

        _injectFault?.Invoke(ProjectionRebuildFaultPoint.DuringOutcomeClassifierSnapshotRead);
        var selectedNames = selected.Select(registration => registration.Name)
            .ToHashSet(StringComparer.Ordinal);
        var unselectedNames = registry.Registrations
            .Select(registration => registration.Name)
            .Where(name => !selectedNames.Contains(name))
            .ToHashSet(StringComparer.Ordinal);
        var currentSelected = await SqliteProjectionCheckpointStore.ReadUnselectedAsync(
            connection,
            transaction,
            unselectedNames,
            CancellationToken.None).ConfigureAwait(false);
        if (CheckpointSnapshotsEqual(selectedBefore, currentSelected))
        {
            await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(false);
            return PromotionOutcome.Old;
        }

        try
        {
            await SqliteProjectionCheckpointStore.RequireExactSelectedAsync(
                connection,
                transaction,
                ProjectionCheckpointSchema.Main,
                selected,
                validated.Manifest.RequiredGlobalPosition,
                CancellationToken.None).ConfigureAwait(false);
            _injectFault?.Invoke(ProjectionRebuildFaultPoint.DuringOutcomeClassifierChecksumValidation);
            foreach (var registration in selected)
            {
                var checksum = await SqliteProjectionAuthorizer.RunAsync(
                    connection,
                    registration.OwnedTables,
                    () => registration.Projection.CalculateChecksumAsync(
                        SqliteProjectionContexts.CreateAdministrative(
                            connection,
                            transaction,
                            keyRing,
                            lease,
                            registration),
                        CancellationToken.None)).ConfigureAwait(false);
                if (!validated.ProjectionChecksums.TryGetValue(registration.Name, out var expected)
                    || !string.Equals(checksum, expected, StringComparison.Ordinal))
                {
                    return PromotionOutcome.Unknown;
                }
            }

            await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(false);
            return PromotionOutcome.New;
        }
        catch (VaultRecoveryRequiredException)
        {
            return PromotionOutcome.Unknown;
        }
    }

    private async Task<SqliteConnection> OpenPromotionConnectionAsync(
        CancellationToken cancellationToken)
    {
        SqliteEventStoreSchema.ValidateVaultPath(
            new SqliteConnectionStringBuilder
            {
                DataSource = _vaultPath,
                Pooling = false,
            }.ToString(),
            _gate);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = "file:" + new Uri(_vaultPath).AbsolutePath + "?mode=rw",
            Mode = SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString());
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA foreign_keys=ON;", cancellationToken)
                .ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA main.secure_delete=ON;", cancellationToken)
                .ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA main.journal_mode=WAL;", cancellationToken)
                .ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task MarkPromotionStartedAsync(CancellationToken cancellationToken)
    {
        await using var transaction = Connection.BeginTransaction(deferred: false);
        await using var command = Connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE projection_rebuild_manifest
            SET promotion_started=1
            WHERE singleton=1 AND generation_id=$generation AND promotion_started=0;
            """;
        command.Parameters.AddWithValue("$generation", GenerationId);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            throw new VaultRecoveryRequiredException();
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task AttachReadOnlyAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "ATTACH DATABASE $uri AS rebuild;";
        command.Parameters.AddWithValue("$uri", CreateAttachUri());
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<ProjectionTableSchema> ReadTableSchemaAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string schema,
        string tableName,
        CancellationToken cancellationToken)
    {
        if (schema is not ("main" or "rebuild"))
            throw new ArgumentOutOfRangeException(nameof(schema));
        _ = new ProjectionOwnedTable(tableName);

        string tableSql;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = $"""
                SELECT sql FROM {schema}.sqlite_master
                WHERE type='table' AND name=$table AND tbl_name=$table;
                """;
            command.Parameters.AddWithValue("$table", tableName);
            var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            tableSql = value as string ?? throw new VaultRecoveryRequiredException();
        }

        var columns = new List<ProjectionColumnSchema>();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = $"PRAGMA {schema}.table_xinfo({QuoteIdentifier(tableName)});";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (reader.GetValue(1) is not string name
                    || reader.GetValue(2) is not string type
                    || reader.GetValue(3) is not long notNull
                    || reader.GetValue(5) is not long primaryKey
                    || reader.GetValue(6) is not long hidden)
                {
                    throw new VaultRecoveryRequiredException();
                }

                columns.Add(new ProjectionColumnSchema(
                    name,
                    type,
                    notNull,
                    reader.IsDBNull(4) ? null : reader.GetString(4),
                    primaryKey,
                    hidden));
            }
        }

        if (columns.Count == 0) throw new VaultRecoveryRequiredException();
        var indexes = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var triggers = new SortedDictionary<string, string>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = $"""
                SELECT type,name,sql FROM {schema}.sqlite_master
                WHERE tbl_name=$table AND type IN ('index','trigger')
                  AND name NOT LIKE 'sqlite_%'
                ORDER BY type COLLATE BINARY,name COLLATE BINARY;
                """;
            command.Parameters.AddWithValue("$table", tableName);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (reader.GetValue(0) is not string type
                    || reader.GetValue(1) is not string name
                    || reader.GetValue(2) is not string sql)
                {
                    throw new VaultRecoveryRequiredException();
                }

                var target = type == "index" ? indexes : type == "trigger"
                    ? triggers
                    : throw new VaultRecoveryRequiredException();
                if (!target.TryAdd(name, sql)) throw new VaultRecoveryRequiredException();
            }
        }

        var foreignTables = new SortedSet<string>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = $"PRAGMA {schema}.foreign_key_list({QuoteIdentifier(tableName)});";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (reader.GetValue(2) is not string referenced)
                {
                    throw new VaultRecoveryRequiredException();
                }


                foreignTables.Add(referenced);
            }
        }

        return new ProjectionTableSchema(tableSql, columns, indexes, triggers, foreignTables);
    }

    private static bool SchemasEqual(ProjectionTableSchema left, ProjectionTableSchema right) =>
        string.Equals(left.TableSql, right.TableSql, StringComparison.Ordinal)
        && left.Columns.SequenceEqual(right.Columns)
        && left.Indexes.SequenceEqual(right.Indexes)
        && left.Triggers.SequenceEqual(right.Triggers)
        && left.ForeignTableNames.SetEquals(right.ForeignTableNames);

    private static async Task RequireNoForeignKeyViolationsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ProjectionOwnedTable table,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA main.foreign_key_check({QuoteOwnedTable(table)});";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            throw new VaultRecoveryRequiredException();
    }

    private void RequirePromotionCapacity()
    {
        try
        {
            long bytes = new FileInfo(Path).Length;
            if (File.Exists(Path + "-wal")) bytes = checked(bytes + new FileInfo(Path + "-wal").Length);
            if (File.Exists(Path + "-shm")) bytes = checked(bytes + new FileInfo(Path + "-shm").Length);
            var required = checked(checked(bytes * 2) + (16L * 1024 * 1024));
            var root = System.IO.Path.GetPathRoot(_vaultPath)
                ?? throw new VaultRecoveryRequiredException();
            if (new DriveInfo(root).AvailableFreeSpace < required)
                throw new StorageCapacityException();
        }
        catch (StorageCapacityException) { throw; }
        catch (OverflowException exception) { throw new StorageCapacityException(exception); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private async Task TryPassiveCheckpointAsync()
    {
        try
        {
            await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
                new SqliteConnectionStringBuilder
                {
                    DataSource = _vaultPath,
                    Pooling = false,
                }.ToString(),
                _gate,
                CancellationToken.None).ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA main.wal_checkpoint(PASSIVE);", CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch
        {
            // A committed generation remains authoritative when a passive checkpoint cannot run.
        }
    }

    private static bool CheckpointSnapshotsEqual(
        IReadOnlyDictionary<string, ProjectionCheckpointSnapshot> left,
        IReadOnlyDictionary<string, ProjectionCheckpointSnapshot> right) =>
        left.Count == right.Count
        && left.All(pair => right.TryGetValue(pair.Key, out var value) && value == pair.Value);

    private static string QuoteOwnedTable(ProjectionOwnedTable table) =>
        QuoteIdentifier(table.Name);

    private static string QuoteIdentifier(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        if (!(identifier[0] == '_' || char.IsAsciiLetter(identifier[0]))
            || identifier.AsSpan(1).ContainsAnyExcept(
                "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
        {
            throw new VaultRecoveryRequiredException();
        }

        return '"' + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task RollbackWithoutMaskingAsync(SqliteTransaction transaction)
    {
        try { await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false); }
        catch { }
    }

    private sealed record ProjectionColumnSchema(
        string Name,
        string Type,
        long NotNull,
        string? DefaultValue,
        long PrimaryKey,
        long Hidden);

    private sealed record ProjectionTableSchema(
        string TableSql,
        IReadOnlyList<ProjectionColumnSchema> Columns,
        IReadOnlyDictionary<string, string> Indexes,
        IReadOnlyDictionary<string, string> Triggers,
        SortedSet<string> ForeignTableNames);

    private enum PromotionOutcome
    {
        Unknown,
        Old,
        New,
    }

    internal Task CompleteAsync(
        ProjectionRebuildCommitState commitState,
        ExceptionDispatchInfo? primaryFailure,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        _gate.Validate(lease, VaultLeaseMode.Rebuild);
        lock (_completionSync)
        {
            if (_completionTask is not null)
            {
                return _completionState == commitState
                    ? _completionTask
                    : Task.FromException(new VaultRecoveryRequiredException());
            }

            _completionState = commitState;
            _completionTask = CompleteCoreAsync(
                commitState,
                primaryFailure,
                cancellationToken);
            return _completionTask;
        }
    }

    internal static async Task CleanupOrphansAsync(
        string vaultConnectionString,
        SqliteProjectionRegistry registry,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(keyRing);
        var vaultPath = GetVaultPath(vaultConnectionString);
        var gate = new VaultMaintenanceGate(vaultPath + ".keyring");
        gate.Validate(lease, VaultLeaseMode.Mutation);
        cancellationToken.ThrowIfCancellationRequested();
        var directory = System.IO.Path.GetDirectoryName(vaultPath)!;
        var prefix = System.IO.Path.GetFileName(vaultPath) + FileMarker;
        var candidates = Directory.EnumerateFiles(directory, prefix + "*").ToArray();
        var artifacts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (candidate.EndsWith("-wal", StringComparison.Ordinal)
                || candidate.EndsWith("-shm", StringComparison.Ordinal))
            {
                var artifact = candidate[..^4];
                WindowsVaultPathGuard.RequireReservedProjectionRebuildArtifact(vaultPath, artifact);
                if (!File.Exists(artifact))
                {
                    throw new VaultRecoveryRequiredException();
                }

                artifacts.Add(artifact);
                continue;
            }

            artifacts.Add(
                WindowsVaultPathGuard.RequireReservedProjectionRebuildArtifact(vaultPath, candidate));
        }

        foreach (var artifact in artifacts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await RequireRecognizableOrphanAsync(
                vaultConnectionString,
                artifact,
                registry,
                keyRing,
                lease,
                cancellationToken).ConfigureAwait(false);
        }

        // Every candidate is proven before the first deletion. Once cleanup begins,
        // cancellation cannot leave a partially classified artifact set behind.
        foreach (var artifact in artifacts)
        {
            DeleteArtifactSet(vaultPath, artifact);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await CloseConnectionAsync().ConfigureAwait(false);
    }

    private async Task CompleteCoreAsync(
        ProjectionRebuildCommitState commitState,
        ExceptionDispatchInfo? primaryFailure,
        CancellationToken cancellationToken)
    {
        if (commitState == ProjectionRebuildCommitState.PreCommit)
        {
            cancellationToken.ThrowIfCancellationRequested();
        }

        await CloseConnectionAsync().ConfigureAwait(false);
        Exception? cleanupFailure = null;
        try
        {
            _injectFault?.Invoke(ProjectionRebuildFaultPoint.BeforeArtifactCleanup);
            DeleteArtifactSet(_vaultPath, Path);
        }
        catch (Exception exception)
        {
            cleanupFailure = exception;
        }

        if (commitState == ProjectionRebuildCommitState.Committed)
        {
            return;
        }

        primaryFailure?.Throw();
        if (cleanupFailure is not null)
        {
            throw new VaultRecoveryRequiredException(cleanupFailure);
        }
    }

    private async ValueTask CloseConnectionAsync()
    {
        var connection = Interlocked.Exchange(ref _connection, null);
        if (connection is not null)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static string GetVaultPath(string connectionString)
    {
        var canonical = SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        return WindowsVaultPathGuard.NormalizeLocalDrivePath(
            new SqliteConnectionStringBuilder(canonical).DataSource);
    }

    private static void DeleteArtifactSet(string vaultPath, string artifactPath)
    {
        var canonical = WindowsVaultPathGuard.RequireReservedProjectionRebuildArtifact(
            vaultPath,
            artifactPath);
        var directory = System.IO.Path.GetDirectoryName(canonical)!;
        var fileName = System.IO.Path.GetFileName(canonical);
        foreach (var sidecar in Directory.EnumerateFiles(directory, fileName + "-*"))
        {
            if (!string.Equals(sidecar, canonical + "-wal", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(sidecar, canonical + "-shm", StringComparison.OrdinalIgnoreCase))
            {
                throw new VaultRecoveryRequiredException();
            }
        }

        foreach (var candidate in new[] { canonical + "-shm", canonical + "-wal", canonical })
        {
            if (File.Exists(candidate))
            {
                File.Delete(candidate);
            }
        }
    }

    private static async Task RequireRecognizableOrphanAsync(
        string vaultConnectionString,
        string artifactPath,
        SqliteProjectionRegistry registry,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        try
        {
            WindowsVaultPathGuard.RequireSafeDatabaseSet(artifactPath);
            var fileLength = new FileInfo(artifactPath).Length;
            if (fileLength == 0)
            {
                if (File.Exists(artifactPath + "-wal") || File.Exists(artifactPath + "-shm"))
                {
                    throw new VaultRecoveryRequiredException();
                }

                return;
            }

            await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = artifactPath,
                Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
            }.ToString());
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

            if (await ReadInt64Async(connection, "PRAGMA user_version;", cancellationToken)
                    .ConfigureAwait(false) != 1)
            {
                throw new VaultRecoveryRequiredException();
            }

            var manifestSql = await ReadSchemaSqlAsync(
                connection,
                "projection_rebuild_manifest",
                cancellationToken).ConfigureAwait(false);
            var checkpointSql = await ReadSchemaSqlAsync(
                connection,
                "projection_checkpoints",
                cancellationToken).ConfigureAwait(false);
            if (!SchemaSqlEquals(manifestSql, ManifestTableSql)
                || !SchemaSqlEquals(checkpointSql, CheckpointTableSql))
            {
                throw new VaultRecoveryRequiredException();
            }

            await using var forbiddenCommand = connection.CreateCommand();
            forbiddenCommand.CommandText = """
                SELECT COUNT(*)
                FROM sqlite_schema
                WHERE type='table'
                  AND name IN (
                      'timeline_events',
                      'event_streams',
                      'vault_metadata',
                      'secure_compaction_queue');
                """;
            if (Convert.ToInt64(
                    await forbiddenCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                    CultureInfo.InvariantCulture) != 0)
            {
                throw new VaultRecoveryRequiredException();
            }

            await using var integrityCommand = connection.CreateCommand();
            integrityCommand.CommandText = "PRAGMA quick_check;";
            var integrity = await integrityCommand.ExecuteScalarAsync(cancellationToken)
                .ConfigureAwait(false) as string;
            if (!string.Equals(integrity, "ok", StringComparison.Ordinal))
            {
                throw new VaultRecoveryRequiredException();
            }


            if (await ReadInt64Async(
                    connection,
                    "SELECT COUNT(*) FROM projection_rebuild_manifest;",
                    cancellationToken).ConfigureAwait(false) == 0)
            {
                return;
            }

            var artifactTransaction = connection.BeginTransaction(deferred: true);
            await using (artifactTransaction.ConfigureAwait(false))
            {
                var manifestIdentity = await ReadOrphanManifestIdentityAsync(
                    connection,
                    artifactTransaction,
                    artifactPath,
                    cancellationToken).ConfigureAwait(false);
                keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
                await keyRing.RequireCanonicalIdentityAsync(
                    manifestIdentity.KeyRingIdentity,
                    cancellationToken).ConfigureAwait(false);

                await using var live = await SqliteEventStoreSchema.OpenConnectionAsync(
                    vaultConnectionString,
                    keyRing.MaintenanceGate,
                    cancellationToken).ConfigureAwait(false);
                await using var liveTransaction = live.BeginTransaction(deferred: true);
                await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                    live,
                    liveTransaction,
                    cancellationToken).ConfigureAwait(false);
                await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                    live,
                    liveTransaction,
                    registry,
                    cancellationToken).ConfigureAwait(false);
                await SqliteEventStore.ValidateAllOperationMetadataAsync(
                    live,
                    liveTransaction,
                    cancellationToken).ConfigureAwait(false);
                var liveIdentity = await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                    live,
                    liveTransaction,
                    cancellationToken).ConfigureAwait(false);
                if (!liveIdentity.FixedTimeEquals(manifestIdentity.KeyRingIdentity.Export()))
                    throw new VaultRecoveryRequiredException();
                await SqliteSensitiveDataDeletionStore.RequireNoPendingReceiptsAsync(
                    keyRing,
                    liveIdentity,
                    cancellationToken).ConfigureAwait(false);

                var validator = new ProjectionRebuildValidator();
                var expectedManifest = await validator.ReadAuthoritativeManifestAsync(
                    live,
                    liveTransaction,
                    liveIdentity,
                    cancellationToken).ConfigureAwait(false);
                await ProjectionRebuildValidator.RequireManifestRowAsync(
                    connection,
                    artifactTransaction,
                    expectedManifest,
                    cancellationToken).ConfigureAwait(false);
                var selected = await ReadOrphanSelectedRegistrationsAsync(
                    connection,
                    artifactTransaction,
                    registry,
                    cancellationToken).ConfigureAwait(false);
                await ProjectionRebuildValidator.RequireExactSchemaAsync(
                    connection,
                    artifactTransaction,
                    selected,
                    cancellationToken).ConfigureAwait(false);
                await SqliteProjectionCheckpointStore.RequireExactSelectedAsync(
                    connection,
                    artifactTransaction,
                    ProjectionCheckpointSchema.Main,
                    selected,
                    expectedManifest.RequiredGlobalPosition,
                    requireOnlySelected: true,
                    cancellationToken).ConfigureAwait(false);

                if (manifestIdentity.PromotionStarted)
                {
                    await RequireLiveMatchesPromotedArtifactAsync(
                        live,
                        liveTransaction,
                        connection,
                        artifactTransaction,
                        selected,
                        expectedManifest.RequiredGlobalPosition,
                        keyRing,
                        lease,
                        cancellationToken).ConfigureAwait(false);
                }

                await artifactTransaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                await liveTransaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (VaultKeyRingRecoveryRequiredException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or SqliteException
            or InvalidOperationException
            or FormatException
            or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static async Task<OrphanManifestIdentity> ReadOrphanManifestIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string artifactPath,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT generation_id,keyring_id,promotion_started
            FROM projection_rebuild_manifest
            WHERE singleton=1;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        var fileName = System.IO.Path.GetFileName(artifactPath);
        var marker = fileName.LastIndexOf(FileMarker, StringComparison.Ordinal);
        var expectedGeneration = marker >= 0
            ? fileName.Substring(marker + FileMarker.Length, 32)
            : string.Empty;
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            || reader.GetValue(0) is not string generation
            || !string.Equals(generation, expectedGeneration, StringComparison.Ordinal)
            || !Guid.TryParseExact(generation, "N", out _)
            || reader.GetValue(1) is not byte[] keyRingIdentity
            || keyRingIdentity.Length != VaultKeyRingIdentity.Size
            || reader.GetValue(2) is not long promotionStarted
            || promotionStarted is not (0 or 1)
            || await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new VaultRecoveryRequiredException();
        }

        return new OrphanManifestIdentity(
            new VaultKeyRingIdentity(keyRingIdentity),
            promotionStarted == 1);
    }

    private static async Task<IReadOnlyList<SqliteProjectionRegistration>>
        ReadOrphanSelectedRegistrationsAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            SqliteProjectionRegistry registry,
            CancellationToken cancellationToken)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT projection_name
            FROM projection_checkpoints
            ORDER BY projection_name COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (reader.GetValue(0) is not string name || !names.Add(name))
                throw new VaultRecoveryRequiredException();
        }

        var selected = registry.Registrations
            .Where(registration => names.Contains(registration.Name))
            .ToArray();
        if (selected.Length == 0 || selected.Length != names.Count)
            throw new VaultRecoveryRequiredException();
        return selected;
    }

    private static async Task RequireLiveMatchesPromotedArtifactAsync(
        SqliteConnection live,
        SqliteTransaction liveTransaction,
        SqliteConnection artifact,
        SqliteTransaction artifactTransaction,
        IReadOnlyList<SqliteProjectionRegistration> selected,
        long requiredGlobalPosition,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        await SqliteProjectionCheckpointStore.RequireExactSelectedAsync(
            live,
            liveTransaction,
            ProjectionCheckpointSchema.Main,
            selected,
            requiredGlobalPosition,
            cancellationToken).ConfigureAwait(false);

        foreach (var registration in selected)
        {
            foreach (var table in registration.OwnedTables)
            {
                var liveSchema = await ReadTableSchemaAsync(
                    live,
                    liveTransaction,
                    "main",
                    table.Name,
                    cancellationToken).ConfigureAwait(false);
                var artifactSchema = await ReadTableSchemaAsync(
                    artifact,
                    artifactTransaction,
                    "main",
                    table.Name,
                    cancellationToken).ConfigureAwait(false);
                if (!SchemasEqual(liveSchema, artifactSchema))
                    throw new VaultRecoveryRequiredException();
            }

            var artifactChecksum = await SqliteProjectionAuthorizer.RunAsync(
                artifact,
                registration.OwnedTables,
                () => registration.Projection.CalculateChecksumAsync(
                    SqliteProjectionContexts.CreateAdministrative(
                        artifact,
                        artifactTransaction,
                        keyRing,
                        lease,
                        registration),
                    cancellationToken)).ConfigureAwait(false);
            var liveChecksum = await SqliteProjectionAuthorizer.RunAsync(
                live,
                registration.OwnedTables,
                () => registration.Projection.CalculateChecksumAsync(
                    SqliteProjectionContexts.CreateAdministrative(
                        live,
                        liveTransaction,
                        keyRing,
                        lease,
                        registration),
                    cancellationToken)).ConfigureAwait(false);
            if (!IsLowerSha256(artifactChecksum)
                || !string.Equals(artifactChecksum, liveChecksum, StringComparison.Ordinal))
            {
                throw new VaultRecoveryRequiredException();
            }
        }
    }

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private sealed record OrphanManifestIdentity(
        VaultKeyRingIdentity KeyRingIdentity,
        bool PromotionStarted);

    private static async Task<long> ReadInt64Async(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(
            await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            CultureInfo.InvariantCulture);
    }

    private static async Task<string> ReadSchemaSqlAsync(
        SqliteConnection connection,
        string tableName,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT sql
            FROM sqlite_schema
            WHERE type='table' AND name=$table_name;
            """;
        command.Parameters.AddWithValue("$table_name", tableName);
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string
            ?? throw new VaultRecoveryRequiredException();
    }

    private static bool SchemaSqlEquals(string actual, string expected)
    {
        static string RemoveWhitespace(string value) =>
            string.Concat(value.Where(character => !char.IsWhiteSpace(character)));

        return string.Equals(
            RemoveWhitespace(actual).TrimEnd(';'),
            RemoveWhitespace(expected).TrimEnd(';'),
            StringComparison.Ordinal);
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
}
