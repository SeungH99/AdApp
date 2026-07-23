using System.Runtime.ExceptionServices;
using System.Collections.Frozen;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class SqliteProjectionAuthorizer
{
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "event_streams",
        "timeline_events",
        "vault_metadata",
        "projection_checkpoints",
        "projection_rebuild_manifest",
        "secure_compaction_queue",
        "managed_vault_copies",
        "sqlite_sequence",
        "event_streams_stream_id_nocase",
        "timeline_events_stream_position_nocase",
        "timeline_events_operation_position",
        "timeline_events_operation_representation",
        "vault_metadata_immutable_update",
        "vault_metadata_immutable_delete",
        "timeline_events_immutable_update",
        "timeline_events_immutable_delete",
        "secure_compaction_queue_immutable_update",
        "managed_vault_copies_immutable_update",
    };

    private static readonly strdelegate_authorizer Authorizer = Authorize;

    internal static Task RunAsync(
        SqliteConnection connection,
        Func<Task> callback) =>
        RunCoreAsync(connection, allowedTables: null, async () =>
        {
            await callback().ConfigureAwait(false);
            return true;
        });

    internal static Task RunAsync(
        SqliteConnection connection,
        IEnumerable<ProjectionOwnedTable> ownedTables,
        Func<Task> callback)
    {
        ArgumentNullException.ThrowIfNull(ownedTables);
        return RunCoreAsync(
            connection,
            ownedTables.Select(table => table.Name).ToFrozenSet(StringComparer.OrdinalIgnoreCase),
            async () =>
            {
                await callback().ConfigureAwait(false);
                return true;
            });
    }

    internal static Task RunAsync(
        SqliteConnection connection,
        SqliteProjectionRegistration registration,
        bool allowsLegacyTestObjects,
        Func<Task> callback) =>
        allowsLegacyTestObjects
            ? RunAsync(connection, callback)
            : RunAsync(connection, registration.OwnedTables, callback);

    internal static async Task<T> RunAsync<T>(
        SqliteConnection connection,
        Func<Task<T>> callback) =>
        await RunCoreAsync(connection, allowedTables: null, callback).ConfigureAwait(false);

    internal static Task<T> RunAsync<T>(
        SqliteConnection connection,
        IEnumerable<ProjectionOwnedTable> ownedTables,
        Func<Task<T>> callback)
    {
        ArgumentNullException.ThrowIfNull(ownedTables);
        return RunCoreAsync(
            connection,
            ownedTables.Select(table => table.Name).ToFrozenSet(StringComparer.OrdinalIgnoreCase),
            callback);
    }

    internal static Task<T> RunAsync<T>(
        SqliteConnection connection,
        SqliteProjectionRegistration registration,
        bool allowsLegacyTestObjects,
        Func<Task<T>> callback) =>
        allowsLegacyTestObjects
            ? RunAsync(connection, callback)
            : RunAsync(connection, registration.OwnedTables, callback);

    private static async Task<T> RunCoreAsync<T>(
        SqliteConnection connection,
        IReadOnlySet<string>? allowedTables,
        Func<Task<T>> callback)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(callback);
        var state = new AuthorizerState(allowedTables);
        if (raw.sqlite3_set_authorizer(connection.Handle, Authorizer, state) != raw.SQLITE_OK)
            throw new VaultRecoveryRequiredException();

        T? result = default;
        ExceptionDispatchInfo? failure = null;
        var unsetResult = raw.SQLITE_ERROR;
        var unsetFailed = false;
        try
        {
            try
            {
                result = await callback().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                failure = ExceptionDispatchInfo.Capture(exception);
            }
        }
        finally
        {
            try
            {
                unsetResult = raw.sqlite3_set_authorizer(
                    connection.Handle,
                    (strdelegate_authorizer)null!,
                    null!);
            }
            catch (Exception)
            {
                unsetFailed = true;
            }
        }
        if (state.Denied || unsetFailed || unsetResult != raw.SQLITE_OK)
            throw new VaultRecoveryRequiredException();

        failure?.Throw();
        return result!;
    }

    private static int Authorize(
        object userData,
        int action,
        string parameterOne,
        string parameterTwo,
        string databaseName,
        string triggerOrView)
    {
        var state = (AuthorizerState)userData;
        if (!ShouldDeny(state, action, parameterOne, parameterTwo, databaseName))
            return raw.SQLITE_OK;

        state.Denied = true;
        return raw.SQLITE_DENY;
    }

    private static bool ShouldDeny(
        AuthorizerState state,
        int action,
        string? parameterOne,
        string? parameterTwo,
        string? databaseName)
    {
        if (action is raw.SQLITE_ATTACH or raw.SQLITE_DETACH
            or raw.SQLITE_TRANSACTION or raw.SQLITE_SAVEPOINT)
            return true;

        if (action == raw.SQLITE_PRAGMA)
            return true;

        if (action is raw.SQLITE_INSERT or raw.SQLITE_UPDATE or raw.SQLITE_DELETE)
        {
            if (IsSchemaCatalog(parameterOne)) return false;
            return (IsMain(databaseName) && IsProtected(parameterOne))
                || IsOutsideScope(state, databaseName, parameterOne);
        }

        if (action == raw.SQLITE_READ
            && !IsSchemaCatalog(parameterOne)
            && IsOutsideScope(state, databaseName, parameterOne))
        {
            return true;
        }

        if (action == raw.SQLITE_ALTER_TABLE)
        {
            var isProtectedSchema = string.Equals(parameterOne, "main", StringComparison.OrdinalIgnoreCase)
                || string.Equals(parameterOne, "temp", StringComparison.OrdinalIgnoreCase)
                || IsMain(databaseName)
                || string.Equals(databaseName, "temp", StringComparison.OrdinalIgnoreCase);
            return (isProtectedSchema && IsProtected(parameterTwo))
                || IsOutsideScope(state, parameterOne, parameterTwo);
        }

        if (!IsSchemaAction(action)) return false;

        var isMainOrTemp = IsMain(databaseName)
            || string.Equals(databaseName, "temp", StringComparison.OrdinalIgnoreCase)
            || IsTemporarySchemaAction(action);
        return (isMainOrTemp && (IsProtected(parameterOne) || IsProtected(parameterTwo)))
            || IsSchemaOutsideScope(state, action, databaseName, parameterOne, parameterTwo);
    }

    private static bool IsSchemaAction(int action) => action is
        raw.SQLITE_CREATE_INDEX or raw.SQLITE_CREATE_TABLE or raw.SQLITE_CREATE_TEMP_INDEX
        or raw.SQLITE_CREATE_TEMP_TABLE or raw.SQLITE_CREATE_TEMP_TRIGGER
        or raw.SQLITE_CREATE_TEMP_VIEW or raw.SQLITE_CREATE_TRIGGER or raw.SQLITE_CREATE_VIEW
        or raw.SQLITE_CREATE_VTABLE or raw.SQLITE_DROP_INDEX or raw.SQLITE_DROP_TABLE
        or raw.SQLITE_DROP_TEMP_INDEX or raw.SQLITE_DROP_TEMP_TABLE
        or raw.SQLITE_DROP_TEMP_TRIGGER or raw.SQLITE_DROP_TEMP_VIEW
        or raw.SQLITE_DROP_TRIGGER or raw.SQLITE_DROP_VIEW or raw.SQLITE_DROP_VTABLE;

    private static bool IsTemporarySchemaAction(int action) => action is
        raw.SQLITE_CREATE_TEMP_INDEX or raw.SQLITE_CREATE_TEMP_TABLE
        or raw.SQLITE_CREATE_TEMP_TRIGGER or raw.SQLITE_CREATE_TEMP_VIEW
        or raw.SQLITE_DROP_TEMP_INDEX or raw.SQLITE_DROP_TEMP_TABLE
        or raw.SQLITE_DROP_TEMP_TRIGGER or raw.SQLITE_DROP_TEMP_VIEW;

    private static bool IsMain(string? databaseName) =>
        string.Equals(databaseName, "main", StringComparison.OrdinalIgnoreCase);

    private static bool IsProtected(string? name) =>
        name is not null && ProtectedNames.Contains(name);

    private static bool IsSchemaCatalog(string? name) =>
        string.Equals(name, "sqlite_master", StringComparison.OrdinalIgnoreCase)
        || string.Equals(name, "sqlite_schema", StringComparison.OrdinalIgnoreCase);

    private static bool IsOutsideScope(
        AuthorizerState state,
        string? databaseName,
        string? tableName) =>
        state.AllowedTables is not null
        && (!IsMain(databaseName)
            || tableName is null
            || !state.AllowedTables.Contains(tableName));

    private static bool IsSchemaOutsideScope(
        AuthorizerState state,
        int action,
        string? databaseName,
        string? objectName,
        string? tableName)
    {
        if (state.AllowedTables is null) return false;
        if (!IsMain(databaseName) || IsTemporarySchemaAction(action)) return true;

        var ownedName = action is raw.SQLITE_CREATE_INDEX or raw.SQLITE_CREATE_TRIGGER
            or raw.SQLITE_DROP_INDEX or raw.SQLITE_DROP_TRIGGER
            ? tableName
            : objectName;
        return ownedName is null || !state.AllowedTables.Contains(ownedName);
    }

    private sealed class AuthorizerState
    {
        internal AuthorizerState(IReadOnlySet<string>? allowedTables)
        {
            AllowedTables = allowedTables;
        }

        internal IReadOnlySet<string>? AllowedTables { get; }

        internal bool Denied { get; set; }
    }
}
