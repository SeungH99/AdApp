using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal interface IProjectionApplyValues
{
    SensitiveObjectRef BoundOwner { get; }

    DataKeyId BoundDataKeyId { get; }

    ValueTask<EncryptedProjectionValue> ProtectAsync(
        string tableName,
        string fieldName,
        string logicalValueKey,
        SensitiveObjectRef owner,
        DataKeyId dataKeyId,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken);

    ValueTask<TResult> UnprotectAsync<TResult>(
        string tableName,
        string fieldName,
        string logicalValueKey,
        SensitiveObjectRef owner,
        DataKeyId dataKeyId,
        EncryptedProjectionValue encryptedValue,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken);
}

internal interface IProjectionAdministrativeValues
{
    ValueTask<TResult> UnprotectAsync<TResult>(
        string tableName,
        string fieldName,
        string logicalValueKey,
        SensitiveObjectRef owner,
        DataKeyId dataKeyId,
        EncryptedProjectionValue encryptedValue,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken);
}

internal sealed class SqliteProjectionApplyContext
{
    internal SqliteProjectionApplyContext(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IProjectionApplyValues values)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(values);
        if (!ReferenceEquals(transaction.Connection, connection))
            throw new ArgumentException("The transaction must belong to the supplied connection.", nameof(transaction));

        Connection = connection;
        Transaction = transaction;
        Values = values;
    }

    public SqliteConnection Connection { get; }

    public SqliteTransaction Transaction { get; }

    public IProjectionApplyValues Values { get; }
}

internal sealed class SqliteProjectionAdministrativeContext
{
    internal SqliteProjectionAdministrativeContext(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IProjectionAdministrativeValues values)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(values);
        if (!ReferenceEquals(transaction.Connection, connection))
            throw new ArgumentException("The transaction must belong to the supplied connection.", nameof(transaction));

        Connection = connection;
        Transaction = transaction;
        Values = values;
    }

    public SqliteConnection Connection { get; }

    public SqliteTransaction Transaction { get; }

    public IProjectionAdministrativeValues Values { get; }
}

internal enum ProjectionCompatibility
{
    Compatible = 0,
    CreatedEmpty = 1,
    RecreatedProvenEmpty = 2,
}

internal readonly record struct ProjectionCompatibilityResult(
    ProjectionCompatibility Compatibility)
{
    public bool RequiresCheckpointInvalidation =>
        Compatibility is not ProjectionCompatibility.Compatible;
}

internal static class SqliteProjectionContexts
{
    internal static SqliteProjectionApplyContext CreateApply(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRingStore keyRing,
        VaultKeyRingStore.VaultKeyRingSession session,
        SqliteProjectionRegistration registration,
        SensitiveObjectRef owner,
        DataKeyId dataKeyId) =>
        new(
            connection,
            transaction,
            new SqliteProjectionValueProtector(keyRing, session, registration)
                .CreateApplyValues(owner, dataKeyId));

    internal static SqliteProjectionApplyContext CreateDisabledApply(
        SqliteConnection connection,
        SqliteTransaction transaction) =>
        new(connection, transaction, UnavailableProjectionValues.Instance);

    internal static SqliteProjectionApplyContext CreateApply(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRingStore keyRing,
        SqliteEventPayloadReadSession readSession,
        SqliteProjectionRegistration registration,
        SensitiveObjectRef owner,
        DataKeyId dataKeyId) =>
        new(
            connection,
            transaction,
            new SqliteProjectionValueProtector(keyRing, readSession, registration)
                .CreateApplyValues(owner, dataKeyId));

    internal static SqliteProjectionAdministrativeContext CreateAdministrative(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        SqliteProjectionRegistration registration) =>
        new(
            connection,
            transaction,
            new SqliteProjectionValueProtector(keyRing, lease, registration)
                .CreateAdministrativeValues());

    internal static SqliteProjectionAdministrativeContext CreateAdministrative(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRingStore keyRing,
        SqliteEventPayloadReadSession readSession,
        SqliteProjectionRegistration registration) =>
        new(
            connection,
            transaction,
            new SqliteProjectionValueProtector(keyRing, readSession, registration)
                .CreateAdministrativeValues());

    private sealed class UnavailableProjectionValues :
        IProjectionApplyValues,
        IProjectionAdministrativeValues
    {
        internal static UnavailableProjectionValues Instance { get; } = new();

        public SensitiveObjectRef BoundOwner => throw new ProjectionContentFreeContractException();

        public DataKeyId BoundDataKeyId => throw new ProjectionContentFreeContractException();

        public ValueTask<EncryptedProjectionValue> ProtectAsync(
            string tableName,
            string fieldName,
            string logicalValueKey,
            SensitiveObjectRef owner,
            DataKeyId dataKeyId,
            ReadOnlyMemory<byte> plaintext,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<EncryptedProjectionValue>(Unavailable());

        public ValueTask<TResult> UnprotectAsync<TResult>(
            string tableName,
            string fieldName,
            string logicalValueKey,
            SensitiveObjectRef owner,
            DataKeyId dataKeyId,
            EncryptedProjectionValue encryptedValue,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<TResult>(Unavailable());

        private static ProjectionContentFreeContractException Unavailable() => new();
    }
}
