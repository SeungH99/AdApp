using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class SqliteEventStoreSchema
{
    private const int CurrentVersion = 3;
    private const string VersionTwoSql = """
        CREATE TABLE event_streams(
            stream_id TEXT PRIMARY KEY CHECK(stream_id <> '00000000-0000-0000-0000-000000000000' AND length(stream_id) = 36 AND stream_id = lower(stream_id) AND substr(stream_id,9,1)='-' AND substr(stream_id,14,1)='-' AND substr(stream_id,19,1)='-' AND substr(stream_id,24,1)='-' AND length(replace(stream_id,'-','')) = 32 AND replace(stream_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            head_version INTEGER NOT NULL CHECK(head_version >= 0)
        ) STRICT;
        CREATE UNIQUE INDEX event_streams_stream_id_nocase
            ON event_streams(CAST(stream_id AS TEXT) COLLATE NOCASE);
        CREATE TABLE timeline_events(
            global_position INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL CHECK(event_id <> '00000000-0000-0000-0000-000000000000' AND length(event_id) = 36 AND event_id = lower(event_id) AND substr(event_id,9,1)='-' AND substr(event_id,14,1)='-' AND substr(event_id,19,1)='-' AND substr(event_id,24,1)='-' AND length(replace(event_id,'-','')) = 32 AND replace(event_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_id TEXT NOT NULL CHECK(stream_id <> '00000000-0000-0000-0000-000000000000' AND length(stream_id) = 36 AND stream_id = lower(stream_id) AND substr(stream_id,9,1)='-' AND substr(stream_id,14,1)='-' AND substr(stream_id,19,1)='-' AND substr(stream_id,24,1)='-' AND length(replace(stream_id,'-','')) = 32 AND replace(stream_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            stream_version INTEGER NOT NULL CHECK(stream_version >= 0),
            event_type TEXT NOT NULL CHECK(length(event_type) > 0),
            schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
            recorded_at_utc TEXT NOT NULL CHECK(length(recorded_at_utc) > 0),
            operation_id TEXT NOT NULL CHECK(operation_id <> '00000000-0000-0000-0000-000000000000' AND length(operation_id) = 36 AND operation_id = lower(operation_id) AND substr(operation_id,9,1)='-' AND substr(operation_id,14,1)='-' AND substr(operation_id,19,1)='-' AND substr(operation_id,24,1)='-' AND length(replace(operation_id,'-','')) = 32 AND replace(operation_id,'-','') NOT GLOB '*[^0-9a-f]*'),
            operation_index INTEGER NOT NULL CHECK(operation_index >= 0),
            operation_count INTEGER NOT NULL CHECK(operation_count > 0),
            protection_kind INTEGER NOT NULL CHECK(protection_kind IN (0, 1)),
            owner_kind INTEGER,
            owner_id TEXT,
            key_id TEXT,
            envelope_version INTEGER NOT NULL,
            payload_nonce BLOB,
            payload_ciphertext BLOB NOT NULL CHECK(typeof(payload_ciphertext) = 'blob'),
            payload_tag BLOB,
            UNIQUE(stream_id, stream_version),
            UNIQUE(operation_id, operation_index),
            FOREIGN KEY(stream_id) REFERENCES event_streams(stream_id),
            CHECK(operation_index < operation_count),
            CHECK(
                (protection_kind = 0
                    AND owner_kind IS NULL AND owner_id IS NULL AND key_id IS NULL
                    AND envelope_version = 0 AND payload_nonce IS NULL AND payload_tag IS NULL)
                OR
                (protection_kind = 1
                    AND owner_kind IS NOT NULL AND owner_kind IN (0, 1, 2, 3)
                    AND owner_id IS NOT NULL AND key_id IS NOT NULL
                    AND owner_id <> '00000000-0000-0000-0000-000000000000' AND length(owner_id) = 36 AND owner_id = lower(owner_id) AND substr(owner_id,9,1)='-' AND substr(owner_id,14,1)='-' AND substr(owner_id,19,1)='-' AND substr(owner_id,24,1)='-' AND length(replace(owner_id,'-','')) = 32 AND replace(owner_id,'-','') NOT GLOB '*[^0-9a-f]*'
                    AND key_id <> '00000000-0000-0000-0000-000000000000' AND length(key_id) = 36 AND key_id = lower(key_id) AND substr(key_id,9,1)='-' AND substr(key_id,14,1)='-' AND substr(key_id,19,1)='-' AND substr(key_id,24,1)='-' AND length(replace(key_id,'-','')) = 32 AND replace(key_id,'-','') NOT GLOB '*[^0-9a-f]*'
                    AND envelope_version = 1
                    AND payload_nonce IS NOT NULL AND typeof(payload_nonce) = 'blob' AND length(payload_nonce) = 12
                    AND payload_tag IS NOT NULL AND typeof(payload_tag) = 'blob' AND length(payload_tag) = 16)
            )
        ) STRICT;
        CREATE INDEX timeline_events_stream_position_nocase
            ON timeline_events(CAST(stream_id AS TEXT) COLLATE NOCASE, global_position);
        CREATE INDEX timeline_events_operation_position
            ON timeline_events(operation_id COLLATE NOCASE, global_position);
        CREATE INDEX timeline_events_operation_representation
            ON timeline_events(CAST(operation_id AS TEXT) COLLATE NOCASE, global_position);
        CREATE TABLE vault_metadata(
            singleton INTEGER PRIMARY KEY CHECK(typeof(singleton) = 'integer' AND singleton = 1),
            keyring_id BLOB NOT NULL CHECK(typeof(keyring_id) = 'blob' AND length(keyring_id) = 32)
        ) STRICT;
        CREATE TRIGGER vault_metadata_immutable_update
        BEFORE UPDATE ON vault_metadata
        BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END;
        CREATE TRIGGER vault_metadata_immutable_delete
        BEFORE DELETE ON vault_metadata
        BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END;
        CREATE TABLE projection_checkpoints(
            projection_name TEXT PRIMARY KEY,
            last_global_position INTEGER NOT NULL CHECK(last_global_position >= 0)
        ) STRICT;
        CREATE TRIGGER timeline_events_immutable_update
        BEFORE UPDATE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TRIGGER timeline_events_immutable_delete
        BEFORE DELETE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        PRAGMA main.user_version = 2;
        """;

    private const string VersionThreeProjectionSql = """
        DROP TABLE projection_checkpoints;
        CREATE TABLE projection_checkpoints(
            projection_name TEXT PRIMARY KEY CHECK(length(projection_name) > 0),
            projection_schema_version INTEGER NOT NULL CHECK(projection_schema_version > 0),
            encryption_version INTEGER NOT NULL CHECK(encryption_version = 1),
            last_global_position INTEGER NOT NULL CHECK(last_global_position >= 0)
        ) STRICT;
        PRAGMA main.user_version = 3;
        """;

    private const string VersionOneSql = """
        CREATE TABLE event_streams(
            stream_id TEXT PRIMARY KEY,
            head_version INTEGER NOT NULL CHECK(head_version >= 0)
        );
        CREATE TABLE timeline_events(
            global_position INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            stream_id TEXT NOT NULL,
            stream_version INTEGER NOT NULL CHECK(stream_version >= 0),
            event_type TEXT NOT NULL,
            schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
            recorded_at_utc TEXT NOT NULL,
            payload_json BLOB NOT NULL,
            UNIQUE(stream_id, stream_version),
            FOREIGN KEY(stream_id) REFERENCES event_streams(stream_id)
        );
        CREATE TABLE projection_checkpoints(
            projection_name TEXT PRIMARY KEY,
            last_global_position INTEGER NOT NULL CHECK(last_global_position >= 0)
        );
        CREATE TABLE event_operation_ids(
            event_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES timeline_events(event_id)
        );
        CREATE TRIGGER timeline_events_immutable_update
        BEFORE UPDATE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TRIGGER timeline_events_immutable_delete
        BEFORE DELETE ON timeline_events
        BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END;
        CREATE TRIGGER event_operation_ids_immutable_update
        BEFORE UPDATE ON event_operation_ids
        BEGIN SELECT RAISE(ABORT, 'event_operation_ids is immutable'); END;
        CREATE TRIGGER event_operation_ids_immutable_delete
        BEFORE DELETE ON event_operation_ids
        BEGIN SELECT RAISE(ABORT, 'event_operation_ids is immutable'); END;
        PRAGMA main.user_version = 1;
        """;

    public static async Task InitializeAsync(
        string connectionString,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        CancellationToken cancellationToken)
    {
        ValidateConnectionString(connectionString);
        ValidateVaultPath(connectionString, keyRing.MaintenanceGate);
        VaultSchemaInspection inspection;
        await using (var firstLease = await keyRing.MaintenanceGate.AcquireAsync(cancellationToken))
        {
            inspection = await InspectBeforeMutationAsync(connectionString, cancellationToken);
        }

        if (inspection.Kind == VaultSchemaKind.LegacyProjection)
        {
            throw new LegacyProjectionRecoveryRequiredException();
        }

        if (inspection.Kind == VaultSchemaKind.LegacyNonEmpty)
        {
            throw new LegacyPlaintextVaultRecoveryRequiredException();
        }

        if (inspection.Kind is VaultSchemaKind.Unknown or VaultSchemaKind.Malformed)
        {
            throw new VaultRecoveryRequiredException();
        }

        VaultKeyRing bootstrapRing;
        if (inspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1)
        {
            try
            {
                try { bootstrapRing = await keyRing.CreateAsync(cancellationToken); }
                catch (VaultKeyRingPersistenceException) { bootstrapRing = await keyRing.OpenAsync(cancellationToken); }
            }
            catch (VaultKeyRingException exception)
            {
                throw new VaultRecoveryRequiredException(exception);
            }
            if (!IsEmpty(bootstrapRing)) throw new VaultRecoveryRequiredException();
        }
        else
        {
            try { bootstrapRing = await keyRing.OpenAsync(cancellationToken); }
            catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
        }

        if (inspection.Kind is VaultSchemaKind.V3 or VaultSchemaKind.EligibleV2)
            RequireKeyRingIdentity(inspection.KeyRingIdentity, bootstrapRing.Identity);

        await using var lease = await keyRing.MaintenanceGate.AcquireAsync(cancellationToken);
        VaultKeyRing ringBeforeDatabaseOpen;
        try { ringBeforeDatabaseOpen = await keyRing.OpenAsync(cancellationToken); }
        catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
        RequireKeyRingIdentity(bootstrapRing.Identity, ringBeforeDatabaseOpen.Identity);
        if (inspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1
            && !IsEmpty(ringBeforeDatabaseOpen))
        {
            throw new VaultRecoveryRequiredException();
        }

        var preOpenInspection = await InspectBeforeMutationAsync(
            connectionString, cancellationToken);
        RequireCompatiblePreOpenInspection(
            inspection, preOpenInspection, ringBeforeDatabaseOpen.Identity);

        await using var connection = await OpenConnectionAsync(
            connectionString, keyRing.MaintenanceGate, cancellationToken);
        await using var transaction = connection.BeginTransaction(deferred: false);
        try
        {
            var finalInspection = await InspectInsideTransactionAsync(connection, transaction, cancellationToken);
            if (finalInspection.Kind == VaultSchemaKind.LegacyProjection)
                throw new LegacyProjectionRecoveryRequiredException();
            if (finalInspection.Kind is VaultSchemaKind.Unknown or VaultSchemaKind.Malformed or VaultSchemaKind.LegacyNonEmpty)
                throw new VaultRecoveryRequiredException();
            RequireCompatibleFinalInspection(preOpenInspection, finalInspection);

            VaultKeyRing authoritativeRing;
            try { authoritativeRing = await keyRing.OpenAsync(cancellationToken); }
            catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }
            RequireKeyRingIdentity(ringBeforeDatabaseOpen.Identity, authoritativeRing.Identity);
            if (finalInspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1)
            {
                if (!IsEmpty(authoritativeRing)
                    || !bootstrapRing.Identity.FixedTimeEquals(authoritativeRing.Identity))
                {
                    throw new VaultRecoveryRequiredException();
                }
            }
            else
            {
                RequireKeyRingIdentity(finalInspection.KeyRingIdentity, authoritativeRing.Identity);
            }

            if (finalInspection.Kind == VaultSchemaKind.EmptyV1)
            {
                await DropVersionOneCoreAsync(connection, transaction, cancellationToken);
            }

            if (finalInspection.Kind is VaultSchemaKind.New or VaultSchemaKind.EmptyV1)
            {
                await ExecuteNonQueryAsync(connection, transaction, VersionTwoSql, cancellationToken);
                await ExecuteNonQueryAsync(
                    connection, transaction, VersionThreeProjectionSql, cancellationToken);
                await InsertKeyRingIdentityAsync(
                    connection, transaction, authoritativeRing.Identity, cancellationToken);
            }
            else if (finalInspection.Kind == VaultSchemaKind.EligibleV2)
            {
                await ExecuteNonQueryAsync(
                    connection, transaction, VersionThreeProjectionSql, cancellationToken);
            }
            else
            {
                await ValidateExistingVersionThreeAsync(connection, transaction, cancellationToken);
            }

            foreach (var registration in projections.Registrations)
            {
                var projection = registration.Projection;
                var compatibility = await SqliteProjectionAuthorizer.RunAsync(
                    connection,
                    () => projection.InitializeAsync(
                        SqliteProjectionContexts.CreateAdministrative(
                            connection,
                            transaction,
                            keyRing,
                            lease,
                            registration),
                        cancellationToken));
                if (!Enum.IsDefined(compatibility.Compatibility))
                    throw new VaultRecoveryRequiredException();
                if (compatibility.RequiresCheckpointInvalidation)
                {
                    await SqliteProjectionCheckpointStore.ClearAsync(
                        connection,
                        transaction,
                        [registration],
                        cancellationToken);
                }
            }

            await ValidateProjectionMembershipAsync(
                connection, transaction, projections, cancellationToken);

            await ValidateExistingVersionThreeAsync(connection, transaction, cancellationToken);
            await SqliteEventStore.ValidateAllOperationMetadataAsync(connection, transaction, cancellationToken);
            await ValidateCurrentKeyRingIdentityAsync(
                keyRing, authoritativeRing.Identity, cancellationToken);
            await ValidateKeyRingIdentityAsync(
                connection, transaction, authoritativeRing.Identity, cancellationToken);
            ValidateVaultPath(connectionString, keyRing.MaintenanceGate);
            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await RollbackWithoutMaskingAsync(transaction);
            throw;
        }
    }

    private static bool IsEmpty(VaultKeyRing ring) =>
        ring.ActiveKeys.Count == 0 && ring.DestroyedReceipts.Count == 0;

    private static void RequireCompatiblePreOpenInspection(
        VaultSchemaInspection original,
        VaultSchemaInspection current,
        VaultKeyRingIdentity authoritativeIdentity)
    {
        if (original.Kind is VaultSchemaKind.V3 or VaultSchemaKind.EligibleV2)
        {
            if (current.Kind != original.Kind)
                throw new VaultRecoveryRequiredException();
            RequireKeyRingIdentity(original.KeyRingIdentity, authoritativeIdentity);
            RequireKeyRingIdentity(current.KeyRingIdentity, authoritativeIdentity);
            return;
        }

        if (original.Kind is not (VaultSchemaKind.New or VaultSchemaKind.EmptyV1))
            throw new VaultRecoveryRequiredException();
        if (current.Kind == original.Kind) return;
        if (current.Kind == VaultSchemaKind.V3)
        {
            RequireKeyRingIdentity(current.KeyRingIdentity, authoritativeIdentity);
            return;
        }

        throw new VaultRecoveryRequiredException();
    }

    private static void RequireCompatibleFinalInspection(
        VaultSchemaInspection preOpen,
        VaultSchemaInspection final)
    {
        if (preOpen.Kind != final.Kind)
            throw new VaultRecoveryRequiredException();
        if (preOpen.Kind is VaultSchemaKind.V3 or VaultSchemaKind.EligibleV2)
            RequireKeyRingIdentity(preOpen.KeyRingIdentity, final.KeyRingIdentity!);
    }

    internal static string CanonicalizeConnectionString(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        try
        {
            var builder = new SqliteConnectionStringBuilder(connectionString);
            var source = builder.DataSource;
            if (string.IsNullOrWhiteSpace(source)
                || string.Equals(source, ":memory:", StringComparison.OrdinalIgnoreCase)
                || source.StartsWith("file:", StringComparison.OrdinalIgnoreCase)
                || source.Contains('|', StringComparison.Ordinal)
                || builder.Mode == SqliteOpenMode.Memory
                || builder.Cache == SqliteCacheMode.Shared)
            {
                throw new VaultRecoveryRequiredException();
            }

            var resolved = WindowsVaultPathGuard.NormalizeLocalDrivePath(source);
            builder.DataSource = resolved;
            builder.Pooling = false;
            return builder.ToString();
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException
            or PathTooLongException or System.Security.SecurityException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    public static async Task<SqliteConnection> OpenConnectionAsync(
        string connectionString,
        CancellationToken cancellationToken) =>
        await OpenConnectionAsync(connectionString, maintenanceGate: null, cancellationToken);

    internal static async Task<SqliteConnection> OpenConnectionAsync(
        string connectionString,
        VaultMaintenanceGate? maintenanceGate,
        CancellationToken cancellationToken)
    {
        ValidateConnectionString(connectionString);
        ValidateVaultPath(connectionString, maintenanceGate);
        var connection = new SqliteConnection(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            ValidateVaultPath(connectionString, maintenanceGate);
            await RequirePragmaAsync(connection, "foreign_keys = ON", "foreign_keys", "1", cancellationToken);
            await RequirePragmaAsync(connection, "main.secure_delete = ON", "main.secure_delete", "1", cancellationToken);
            await RequirePragmaAsync(connection, "main.journal_mode = WAL", "main.journal_mode", "wal", cancellationToken);
            ValidateVaultPath(connectionString, maintenanceGate);

            return connection;
        }
        catch (Exception exception)
        {
            await connection.DisposeAsync();
            if (exception is VaultRecoveryRequiredException) throw;
            if (exception is SqliteException sqliteException && sqliteException.SqliteErrorCode is 5 or 6) throw;
            if (exception is SqliteException or InvalidCastException or FormatException or OverflowException)
                throw new VaultRecoveryRequiredException(exception);
            throw;
        }
    }

    private static async Task<VaultSchemaInspection> InspectBeforeMutationAsync(string connectionString, CancellationToken cancellationToken)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        var path = Path.GetFullPath(builder.DataSource);
        WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
        if (HasDatabaseSidecar(path)) return new VaultSchemaInspection(VaultSchemaKind.Malformed);
        if (!File.Exists(path)) return new VaultSchemaInspection(VaultSchemaKind.New);
        if (new FileInfo(path).Length == 0) return new VaultSchemaInspection(VaultSchemaKind.New);

        VaultSchemaInspection inspection;
        try
        {
            builder.DataSource = new Uri(path).AbsoluteUri + "?immutable=1";
            builder.Mode = SqliteOpenMode.ReadOnly;
            builder.Cache = SqliteCacheMode.Private;
            builder.Pooling = false;
            await using (var connection = new SqliteConnection(builder.ToString()))
            {
                await connection.OpenAsync(cancellationToken);
                var version = Convert.ToInt32(await ExecuteScalarAsync(connection, null, "PRAGMA main.user_version;", cancellationToken));
                if (version == 0)
                {
                    inspection = await CountApplicationObjectsAsync(connection, null, cancellationToken) == 0
                        ? new VaultSchemaInspection(VaultSchemaKind.New)
                        : new VaultSchemaInspection(VaultSchemaKind.Malformed);
                }
                else if (version == 1)
                {
                    inspection = new VaultSchemaInspection(
                        await ClassifyExactVersionOneAsync(connection, null, cancellationToken));
                }
                else if (version == 2)
                {
                    try
                    {
                        await ValidateEligibleVersionTwoAsync(connection, null, cancellationToken);
                        inspection = new VaultSchemaInspection(
                            VaultSchemaKind.EligibleV2,
                            await ReadPersistedKeyRingIdentityAsync(connection, null, cancellationToken));
                    }
                    catch (LegacyProjectionRecoveryRequiredException)
                    {
                        inspection = new VaultSchemaInspection(VaultSchemaKind.LegacyProjection);
                    }
                }
                else if (version == CurrentVersion)
                {
                    await ValidateExistingVersionThreeAsync(connection, null, cancellationToken);
                    inspection = new VaultSchemaInspection(
                        VaultSchemaKind.V3,
                        await ReadPersistedKeyRingIdentityAsync(connection, null, cancellationToken));
                }
                else
                {
                    inspection = new VaultSchemaInspection(VaultSchemaKind.Unknown);
                }
            }
        }
        catch (VaultRecoveryRequiredException)
        {
            inspection = new VaultSchemaInspection(VaultSchemaKind.Malformed);
        }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException
            or FormatException or OverflowException or InvalidOperationException)
        {
            _ = exception;
            inspection = new VaultSchemaInspection(VaultSchemaKind.Malformed);
        }

        return HasDatabaseSidecar(path)
            ? new VaultSchemaInspection(VaultSchemaKind.Malformed)
            : inspection;
    }

    private static bool HasDatabaseSidecar(string path) =>
        WindowsVaultPathGuard.EntryExists(path + "-journal")
        || WindowsVaultPathGuard.EntryExists(path + "-wal")
        || WindowsVaultPathGuard.EntryExists(path + "-shm");

    internal static void ValidateVaultPath(string connectionString)
        => ValidateVaultPath(connectionString, maintenanceGate: null);

    internal static void ValidateVaultPath(
        string connectionString,
        VaultMaintenanceGate? maintenanceGate)
    {
        try
        {
            var path = new SqliteConnectionStringBuilder(connectionString).DataSource;
            if (maintenanceGate is null)
            {
                WindowsVaultPathGuard.RequireSafeDatabaseSet(path);
            }
            else
            {
                WindowsVaultPathGuard.RequireSafeVaultSet(
                    path,
                    maintenanceGate.KeyRingPath,
                    maintenanceGate.LockPath);
            }
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException
            or InvalidOperationException
            or NotSupportedException)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task<VaultSchemaInspection> InspectInsideTransactionAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken cancellationToken)
    {
        var version = Convert.ToInt32(await ExecuteScalarAsync(connection, transaction, "PRAGMA main.user_version;", cancellationToken));
        if (version == 0 && await CountApplicationObjectsAsync(connection, transaction, cancellationToken) == 0)
            return new VaultSchemaInspection(VaultSchemaKind.New);
        if (version == 1)
        {
            return new VaultSchemaInspection(await ClassifyExactVersionOneAsync(connection, transaction, cancellationToken));
        }
        if (version == 2)
        {
            await ValidateEligibleVersionTwoAsync(connection, transaction, cancellationToken);
            return new VaultSchemaInspection(
                VaultSchemaKind.EligibleV2,
                await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken));
        }
        if (version == CurrentVersion)
        {
            await ValidateExistingVersionThreeAsync(connection, transaction, cancellationToken);
            return new VaultSchemaInspection(
                VaultSchemaKind.V3,
                await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken));
        }

        return new VaultSchemaInspection(VaultSchemaKind.Unknown);
    }

    internal static async Task ValidateExistingVersionThreeAsync(SqliteConnection connection, SqliteTransaction? transaction, CancellationToken cancellationToken)
    {
        try
        {
            var version = Convert.ToInt32(await ExecuteScalarAsync(connection, transaction, "PRAGMA main.user_version;", cancellationToken));
            if (version != CurrentVersion) throw new VaultRecoveryRequiredException();

            await RequireExactObjectSqlAsync(connection, transaction, "table", "event_streams",
                ExtractExpectedStatement("CREATE TABLE event_streams("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "timeline_events",
                ExtractExpectedStatement("CREATE TABLE timeline_events("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "projection_checkpoints",
                ExtractExpectedStatement(
                    VersionThreeProjectionSql,
                    "CREATE TABLE projection_checkpoints("),
                cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "vault_metadata",
                ExtractExpectedStatement("CREATE TABLE vault_metadata("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "event_streams_stream_id_nocase",
                ExtractExpectedStatement("CREATE UNIQUE INDEX event_streams_stream_id_nocase"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_stream_position_nocase",
                ExtractExpectedStatement("CREATE INDEX timeline_events_stream_position_nocase"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_operation_position",
                ExtractExpectedStatement("CREATE INDEX timeline_events_operation_position"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_operation_representation",
                ExtractExpectedStatement("CREATE INDEX timeline_events_operation_representation"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_update",
                "CREATE TRIGGER timeline_events_immutable_update BEFORE UPDATE ON timeline_events BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_delete",
                "CREATE TRIGGER timeline_events_immutable_delete BEFORE DELETE ON timeline_events BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "vault_metadata_immutable_update",
                "CREATE TRIGGER vault_metadata_immutable_update BEFORE UPDATE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "vault_metadata_immutable_delete",
                "CREATE TRIGGER vault_metadata_immutable_delete BEFORE DELETE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END", cancellationToken);
            _ = await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken);

            await using var forbidden = connection.CreateCommand();
            forbidden.Transaction = transaction;
            forbidden.CommandText = """
                SELECT COUNT(*) FROM main.sqlite_master
                WHERE substr(lower(name), 1, 7) <> 'sqlite_'
                  AND (
                    lower(name) = 'payload_json'
                    OR lower(name) = 'event_operation_ids'
                    OR lower(name) GLOB 'event_operation_ids_*'
                    OR (lower(name) GLOB 'event_streams_*' AND lower(name) NOT IN (
                        'event_streams_stream_id_nocase'))
                    OR (lower(name) GLOB 'timeline_events_*' AND lower(name) NOT IN (
                        'timeline_events_stream_position_nocase',
                        'timeline_events_operation_position',
                        'timeline_events_operation_representation',
                        'timeline_events_immutable_update',
                        'timeline_events_immutable_delete'))
                    OR (lower(name) GLOB 'vault_metadata_*' AND lower(name) NOT IN (
                        'vault_metadata_immutable_update',
                        'vault_metadata_immutable_delete'))
                    OR (lower(tbl_name) IN ('event_streams', 'timeline_events', 'projection_checkpoints', 'vault_metadata')
                        AND lower(name) NOT IN (
                            'event_streams',
                            'timeline_events',
                            'projection_checkpoints',
                            'vault_metadata',
                            'event_streams_stream_id_nocase',
                            'timeline_events_stream_position_nocase',
                            'timeline_events_operation_position',
                            'timeline_events_operation_representation',
                            'timeline_events_immutable_update',
                            'timeline_events_immutable_delete',
                            'vault_metadata_immutable_update',
                            'vault_metadata_immutable_delete'))
                  );
                """;
            if (Convert.ToInt64(await forbidden.ExecuteScalarAsync(cancellationToken)) != 0)
                throw new VaultRecoveryRequiredException();

            await using var forbiddenTemp = connection.CreateCommand();
            forbiddenTemp.Transaction = transaction;
            forbiddenTemp.CommandText = """
                SELECT COUNT(*) FROM temp.sqlite_master
                WHERE name COLLATE NOCASE IN (
                    'event_streams', 'timeline_events', 'projection_checkpoints',
                    'vault_metadata', 'event_streams_stream_id_nocase',
                    'timeline_events_stream_position_nocase',
                    'timeline_events_operation_position',
                    'timeline_events_operation_representation',
                    'timeline_events_immutable_update',
                    'timeline_events_immutable_delete',
                    'vault_metadata_immutable_update',
                    'vault_metadata_immutable_delete')
                   OR tbl_name COLLATE NOCASE IN (
                    'event_streams', 'timeline_events', 'projection_checkpoints',
                    'vault_metadata');
                """;
            if (Convert.ToInt64(await forbiddenTemp.ExecuteScalarAsync(cancellationToken)) != 0)
                throw new VaultRecoveryRequiredException();
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException or FormatException or OverflowException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static async Task ValidateEligibleVersionTwoAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            var version = Convert.ToInt32(await ExecuteScalarAsync(
                connection, transaction, "PRAGMA main.user_version;", cancellationToken));
            if (version != 2) throw new LegacyProjectionRecoveryRequiredException();

            await RequireExactObjectSqlAsync(connection, transaction, "table", "event_streams",
                ExtractExpectedStatement(VersionTwoSql, "CREATE TABLE event_streams("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "timeline_events",
                ExtractExpectedStatement(VersionTwoSql, "CREATE TABLE timeline_events("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "projection_checkpoints",
                ExtractExpectedStatement(VersionTwoSql, "CREATE TABLE projection_checkpoints("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "table", "vault_metadata",
                ExtractExpectedStatement(VersionTwoSql, "CREATE TABLE vault_metadata("), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "event_streams_stream_id_nocase",
                ExtractExpectedStatement(VersionTwoSql, "CREATE UNIQUE INDEX event_streams_stream_id_nocase"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_stream_position_nocase",
                ExtractExpectedStatement(VersionTwoSql, "CREATE INDEX timeline_events_stream_position_nocase"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_operation_position",
                ExtractExpectedStatement(VersionTwoSql, "CREATE INDEX timeline_events_operation_position"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "index", "timeline_events_operation_representation",
                ExtractExpectedStatement(VersionTwoSql, "CREATE INDEX timeline_events_operation_representation"), cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_update",
                "CREATE TRIGGER timeline_events_immutable_update BEFORE UPDATE ON timeline_events BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_delete",
                "CREATE TRIGGER timeline_events_immutable_delete BEFORE DELETE ON timeline_events BEGIN SELECT RAISE(ABORT, 'timeline_events is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "vault_metadata_immutable_update",
                "CREATE TRIGGER vault_metadata_immutable_update BEFORE UPDATE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END", cancellationToken);
            await RequireExactObjectSqlAsync(connection, transaction, "trigger", "vault_metadata_immutable_delete",
                "CREATE TRIGGER vault_metadata_immutable_delete BEFORE DELETE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'vault_metadata is immutable'); END", cancellationToken);
            _ = await ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken);

            if (Convert.ToInt64(await ExecuteScalarAsync(
                    connection,
                    transaction,
                    "SELECT COUNT(*) FROM main.projection_checkpoints;",
                    cancellationToken)) != 0
                || Convert.ToInt64(await ExecuteScalarAsync(
                    connection,
                    transaction,
                    "SELECT COUNT(*) FROM main.sqlite_master WHERE substr(lower(name),1,7) <> 'sqlite_';",
                    cancellationToken)) != 12)
            {
                throw new LegacyProjectionRecoveryRequiredException();
            }
        }
        catch (LegacyProjectionRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is VaultRecoveryRequiredException
            or SqliteException or InvalidCastException or FormatException or OverflowException)
        {
            throw new LegacyProjectionRecoveryRequiredException(exception);
        }
    }

    private static async Task ValidateProjectionObjectMembershipAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SqliteProjectionRegistry projections,
        CancellationToken cancellationToken)
    {
        if (projections.AllowsLegacyTestObjects) return;

        var coreObjects = new HashSet<string>(StringComparer.Ordinal)
        {
            "event_streams",
            "timeline_events",
            "projection_checkpoints",
            "vault_metadata",
            "event_streams_stream_id_nocase",
            "timeline_events_stream_position_nocase",
            "timeline_events_operation_position",
            "timeline_events_operation_representation",
            "timeline_events_immutable_update",
            "timeline_events_immutable_delete",
            "vault_metadata_immutable_update",
            "vault_metadata_immutable_delete",
        };
        var registeredTables = projections.Registrations
            .SelectMany(registration => registration.EncryptedLocations)
            .Select(location => location.TableName)
            .ToHashSet(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT type, name, tbl_name
            FROM main.sqlite_master
            WHERE substr(lower(name),1,7) <> 'sqlite_'
            ORDER BY type COLLATE BINARY, name COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.GetValue(0) is not string type
                || reader.GetValue(1) is not string name
                || reader.GetValue(2) is not string tableName)
                throw new VaultRecoveryRequiredException();
            if (coreObjects.Contains(name)) continue;
            if (type == "table" && name == tableName && registeredTables.Contains(name)) continue;
            if (type is "index" or "trigger" && registeredTables.Contains(tableName)) continue;
            throw new VaultRecoveryRequiredException();
        }
    }

    internal static async Task ValidateProjectionMembershipAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SqliteProjectionRegistry projections,
        CancellationToken cancellationToken)
    {
        await SqliteProjectionCheckpointStore.ValidateMembershipAsync(
            connection, transaction, projections.Registrations, cancellationToken);
        await ValidateProjectionObjectMembershipAsync(
            connection, transaction, projections, cancellationToken);
    }

    internal static async Task<VaultKeyRingIdentity> ReadPersistedKeyRingIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT singleton, keyring_id FROM main.vault_metadata ORDER BY singleton;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)
                || reader.GetValue(0) is not long singleton
                || singleton != 1
                || reader.GetValue(1) is not byte[] identity
                || identity.Length != VaultKeyRingIdentity.Size
                || await reader.ReadAsync(cancellationToken))
            {
                throw new VaultRecoveryRequiredException();
            }

            return new VaultKeyRingIdentity(identity);
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is SqliteException or InvalidCastException
            or FormatException or OverflowException or InvalidOperationException or NotSupportedException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    internal static async Task ValidateKeyRingIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        VaultKeyRingIdentity expectedIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        var persisted = await ReadPersistedKeyRingIdentityAsync(
            connection, transaction, cancellationToken);
        RequireKeyRingIdentity(persisted, expectedIdentity);
    }

    internal static async Task ValidateCurrentKeyRingIdentityAsync(
        VaultKeyRingStore keyRing,
        VaultKeyRingIdentity expectedIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        try
        {
            await keyRing.RequireCanonicalIdentityAsync(expectedIdentity, cancellationToken);
        }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static async Task InsertKeyRingIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRingIdentity identity,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO main.vault_metadata(singleton, keyring_id) VALUES(1, $keyring_id);";
        command.Parameters.Add("$keyring_id", SqliteType.Blob).Value = identity.Export();
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new VaultRecoveryRequiredException();
    }

    private static void RequireKeyRingIdentity(
        VaultKeyRingIdentity? persistedIdentity,
        VaultKeyRingIdentity authoritativeIdentity)
    {
        ArgumentNullException.ThrowIfNull(authoritativeIdentity);
        if (persistedIdentity is null || !authoritativeIdentity.FixedTimeEquals(persistedIdentity))
            throw new VaultRecoveryRequiredException();
    }

    private static async Task RequireExactObjectSqlAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string type,
        string name,
        string expectedSql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT sql FROM main.sqlite_master WHERE type = $type AND name = $name;";
        command.Parameters.AddWithValue("$type", type);
        command.Parameters.AddWithValue("$name", name);
        var actual = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken));
        if (actual is null || !string.Equals(NormalizeSql(actual), NormalizeSql(expectedSql), StringComparison.Ordinal))
            throw new VaultRecoveryRequiredException();
    }

    private static string ExtractExpectedStatement(string prefix)
        => ExtractExpectedStatement(VersionTwoSql, prefix);

    private static string ExtractExpectedStatement(string schemaSql, string prefix)
    {
        var start = schemaSql.IndexOf(prefix, StringComparison.Ordinal);
        if (start < 0) throw new InvalidOperationException("The canonical schema definition is incomplete.");
        if (prefix.StartsWith("CREATE TRIGGER", StringComparison.Ordinal))
        {
            var triggerEnd = schemaSql.IndexOf("END;", start, StringComparison.Ordinal);
            if (triggerEnd < 0) throw new InvalidOperationException("The canonical trigger is unterminated.");
            return schemaSql[start..(triggerEnd + "END".Length)];
        }
        var end = schemaSql.IndexOf(';', start);
        if (end < 0) throw new InvalidOperationException("The canonical schema statement is unterminated.");
        return schemaSql[start..end];
    }

    private static string NormalizeSql(string sql)
    {
        var normalized = new System.Text.StringBuilder(sql.Length);
        var inSingleQuote = false;
        var inDoubleQuote = false;
        for (var index = 0; index < sql.Length; index++)
        {
            var character = sql[index];
            if (character == '\'' && !inDoubleQuote)
            {
                normalized.Append(character);
                if (inSingleQuote && index + 1 < sql.Length && sql[index + 1] == '\'')
                {
                    normalized.Append(sql[++index]);
                }
                else
                {
                    inSingleQuote = !inSingleQuote;
                }
                continue;
            }

            if (character == '"' && !inSingleQuote)
            {
                normalized.Append(character);
                if (inDoubleQuote && index + 1 < sql.Length && sql[index + 1] == '"')
                {
                    normalized.Append(sql[++index]);
                }
                else
                {
                    inDoubleQuote = !inDoubleQuote;
                }
                continue;
            }

            if (!inSingleQuote && !inDoubleQuote)
            {
                if (char.IsWhiteSpace(character) || character == ';') continue;
                normalized.Append(char.ToLowerInvariant(character));
            }
            else
            {
                normalized.Append(character);
            }
        }

        return normalized.ToString();
    }

    private static async Task<VaultSchemaKind> ClassifyExactVersionOneAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await RequireExactObjectSqlAsync(connection, transaction, "table", "event_streams",
            ExtractExpectedStatement(VersionOneSql, "CREATE TABLE event_streams("), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "table", "timeline_events",
            ExtractExpectedStatement(VersionOneSql, "CREATE TABLE timeline_events("), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "table", "projection_checkpoints",
            ExtractExpectedStatement(VersionOneSql, "CREATE TABLE projection_checkpoints("), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "table", "event_operation_ids",
            ExtractExpectedStatement(VersionOneSql, "CREATE TABLE event_operation_ids("), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_update",
            ExtractExpectedStatement(VersionOneSql, "CREATE TRIGGER timeline_events_immutable_update"), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "trigger", "timeline_events_immutable_delete",
            ExtractExpectedStatement(VersionOneSql, "CREATE TRIGGER timeline_events_immutable_delete"), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "trigger", "event_operation_ids_immutable_update",
            ExtractExpectedStatement(VersionOneSql, "CREATE TRIGGER event_operation_ids_immutable_update"), cancellationToken);
        await RequireExactObjectSqlAsync(connection, transaction, "trigger", "event_operation_ids_immutable_delete",
            ExtractExpectedStatement(VersionOneSql, "CREATE TRIGGER event_operation_ids_immutable_delete"), cancellationToken);

        if (await CountApplicationObjectsAsync(connection, transaction, cancellationToken) != 8)
            throw new VaultRecoveryRequiredException();

        foreach (var table in new[] { "event_streams", "timeline_events", "projection_checkpoints", "event_operation_ids" })
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"SELECT EXISTS(SELECT 1 FROM main.\"{table}\" LIMIT 1);";
            if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) != 0)
                return VaultSchemaKind.LegacyNonEmpty;
        }

        return VaultSchemaKind.EmptyV1;
    }

    private static async Task<long> CountApplicationObjectsAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT COUNT(*)
            FROM main.sqlite_master
            WHERE substr(lower(name), 1, 7) <> 'sqlite_'
              AND type IN ('table', 'view', 'index', 'trigger');
            """;
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
    }

    private static async Task DropVersionOneCoreAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await ExecuteNonQueryAsync(connection, transaction, """
            DROP TRIGGER main.event_operation_ids_immutable_update;
            DROP TRIGGER main.event_operation_ids_immutable_delete;
            DROP TRIGGER main.timeline_events_immutable_update;
            DROP TRIGGER main.timeline_events_immutable_delete;
            DROP TABLE main.event_operation_ids;
            DROP TABLE main.timeline_events;
            DROP TABLE main.event_streams;
            DROP TABLE main.projection_checkpoints;
            """, cancellationToken);
    }

    private static void ValidateConnectionString(string connectionString)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        if (builder.Cache == SqliteCacheMode.Shared
            || builder.Mode == SqliteOpenMode.Memory
            || string.IsNullOrWhiteSpace(builder.DataSource)
            || string.Equals(builder.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase)
            || builder.DataSource.StartsWith("file:", StringComparison.OrdinalIgnoreCase)
            || builder.DataSource.Contains('|', StringComparison.Ordinal)
            || !Path.IsPathFullyQualified(builder.DataSource))
            throw new VaultRecoveryRequiredException();
    }

    private static async Task RequirePragmaAsync(SqliteConnection connection, string set, string query, string expected, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA {set};";
        await command.ExecuteNonQueryAsync(cancellationToken);
        command.CommandText = $"PRAGMA {query};";
        var result = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken));
        if (!string.Equals(result, expected, StringComparison.OrdinalIgnoreCase)) throw new VaultRecoveryRequiredException();
    }

    private static async Task ExecuteNonQueryAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
    private static async Task<object?> ExecuteScalarAsync(SqliteConnection connection, SqliteTransaction? transaction, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql;
        return await command.ExecuteScalarAsync(cancellationToken);
    }
    private static async Task RollbackWithoutMaskingAsync(SqliteTransaction transaction) { try { await transaction.RollbackAsync(); } catch { } }
    private enum VaultSchemaKind
    {
        New,
        EmptyV1,
        LegacyNonEmpty,
        EligibleV2,
        V3,
        LegacyProjection,
        Unknown,
        Malformed,
    }
    private sealed record VaultSchemaInspection(
        VaultSchemaKind Kind,
        VaultKeyRingIdentity? KeyRingIdentity = null);
}

public sealed class LegacyProjectionRecoveryRequiredException : InvalidOperationException
{
    public LegacyProjectionRecoveryRequiredException()
        : base("Legacy projection state requires explicit recovery before this Vault can be upgraded.")
    {
    }

    public LegacyProjectionRecoveryRequiredException(Exception innerException)
        : base("Legacy projection state requires explicit recovery before this Vault can be upgraded.", innerException)
    {
    }
}
