using System.Globalization;
using LocalDocumentOrganizer.Core.Deletion;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal enum SqliteSensitiveDataDeletionFaultPoint
{
    BeforeKeyRingReplacement,
    AfterKeyRingReplacement,
    BeforeSqlCommit,
    AfterSqlCommit,
}

internal interface ISqliteSensitiveDataDeletionFaultInjector
{
    void ThrowIfRequested(SqliteSensitiveDataDeletionFaultPoint point);
}

internal sealed class NoOpSqliteSensitiveDataDeletionFaultInjector :
    ISqliteSensitiveDataDeletionFaultInjector
{
    internal static NoOpSqliteSensitiveDataDeletionFaultInjector Instance { get; } = new();

    private NoOpSqliteSensitiveDataDeletionFaultInjector()
    {
    }

    public void ThrowIfRequested(SqliteSensitiveDataDeletionFaultPoint point)
    {
    }
}

internal sealed class SqliteSensitiveDataDeletionStore
{
    private readonly string _connectionString;
    private readonly EventSchemaRegistry _schemaRegistry;
    private readonly SqliteProjectionRegistry _projections;
    private readonly VaultKeyRingStore _keyRing;
    private readonly TimeProvider _timeProvider;
    private readonly ISqliteSensitiveDataDeletionFaultInjector _faults;

    internal SqliteSensitiveDataDeletionStore(
        string connectionString,
        EventSchemaRegistry schemaRegistry,
        SqliteProjectionRegistry projections,
        VaultKeyRingStore keyRing,
        TimeProvider timeProvider,
        ISqliteSensitiveDataDeletionFaultInjector? faults = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(schemaRegistry);
        ArgumentNullException.ThrowIfNull(projections);
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _connectionString = connectionString;
        _schemaRegistry = schemaRegistry;
        _projections = projections;
        _keyRing = keyRing;
        _timeProvider = timeProvider;
        _faults = faults ?? NoOpSqliteSensitiveDataDeletionFaultInjector.Instance;
    }

    internal async Task<DeleteSensitiveObjectResult> DeleteAsync(
        DeleteSensitiveObjectCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var payload = SensitiveObjectDeletedEventContract
            .CreatePayload(command.Target, command.ReasonCode)
            .ToArray();
        _ = _schemaRegistry.GetCurrentVersion(SensitiveObjectDeletedEventContract.EventType);
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);

        await using var lease = await _keyRing.MaintenanceGate
            .AcquireMutationAsync(cancellationToken)
            .ConfigureAwait(false);
        SqliteConnection? connection = null;
        SqliteTransaction? transaction = null;
        var destructionPublished = false;
        VaultDestroyedKeyReceipt? expectedPendingReceipt = null;
        try
        {
            connection = await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString,
                _keyRing.MaintenanceGate,
                cancellationToken);
            transaction = connection.BeginTransaction(deferred: false);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                connection,
                transaction,
                cancellationToken);
            await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                connection,
                transaction,
                _projections,
                cancellationToken);

            var persistedIdentity = await SqliteEventStoreSchema
                .ReadPersistedKeyRingIdentityAsync(connection, transaction, cancellationToken);
            var ring = await _keyRing.OpenAsync(cancellationToken);
            if (!ring.Identity.FixedTimeEquals(persistedIdentity))
                return await RollbackResultAsync(
                    transaction,
                    new DeletionRecoveryRequired("keyring-identity-mismatch"));

            if (ring.DestroyedReceipts.Any(
                    receipt => receipt.State == VaultDestroyedReceiptState.PendingSqlCompletion))
            {
                return await RollbackResultAsync(
                    transaction,
                    new DeletionRecoveryRequired("pending-deletion-recovery"));
            }

            var existingReceipt = ring.DestroyedReceipts
                .SingleOrDefault(receipt => receipt.Owner == command.Target);
            if (existingReceipt is not null)
            {
                var retryResult = await ClassifyExistingReceiptAsync(
                    connection,
                    transaction,
                    lease,
                    command,
                    payload,
                    existingReceipt,
                    cancellationToken);
                return await RollbackResultAsync(transaction, retryResult);
            }

            if (ring.DestroyedReceipts.Any(receipt =>
                    receipt.OperationId == command.OperationId
                    || receipt.TombstoneEventId == command.TombstoneEventId)
                || await HasCompactionQueueConflictAsync(
                    connection,
                    transaction,
                    command,
                    cancellationToken))
            {
                return await RollbackResultAsync(
                    transaction,
                    new DeletionRecoveryRequired("deletion-identifier-conflict"));
            }

            var head = await ReadHeadAsync(
                connection,
                transaction,
                command.StreamId,
                cancellationToken);
            if (head is null)
            {
                return await RollbackResultAsync(
                    transaction,
                    new DeletionRecoveryRequired("target-stream-missing"));
            }
            if (head.Value != command.ExpectedVersion)
            {
                return await RollbackResultAsync(
                    transaction,
                    new DeletionConcurrencyConflict(command.ExpectedVersion, head.Value));
            }

            if (await IdentifierExistsAsync(
                    connection,
                    transaction,
                    command.OperationId,
                    command.TombstoneEventId,
                    cancellationToken))
            {
                return await RollbackResultAsync(
                    transaction,
                    new DeletionRecoveryRequired("deletion-identifier-conflict"));
            }

            var keyId = await ReadAndValidateTargetKeyAsync(
                connection,
                transaction,
                command.Target,
                command.StreamId,
                cancellationToken);
            if (keyId is null)
            {
                return await RollbackResultAsync(
                    transaction,
                    new DeletionRecoveryRequired("target-binding-invalid"));
            }

            var active = ring.ActiveKeys.SingleOrDefault(entry => entry.Owner == command.Target);
            if (active is null || active.KeyId != keyId.Value)
            {
                return await RollbackResultAsync(
                    transaction,
                    new DeletionRecoveryRequired("active-key-mismatch"));
            }

            var rebuild = await SqliteProjectionCheckpointStore.FindRebuildRequirementAsync(
                connection,
                transaction,
                _projections.Registrations,
                cancellationToken);
            if (rebuild.ProjectionNames.Count != 0)
            {
                return await RollbackResultAsync(
                    transaction,
                    new DeletionRecoveryRequired("projection-rebuild-required"));
            }

            expectedPendingReceipt = CreateReceipt(
                command,
                keyId.Value,
                VaultDestroyedReceiptState.PendingSqlCompletion);
            _faults.ThrowIfRequested(
                SqliteSensitiveDataDeletionFaultPoint.BeforeKeyRingReplacement);
            try
            {
                await _keyRing.DestroyDataKeyAsync(
                    expectedPendingReceipt,
                    lease,
                    cancellationToken);
                destructionPublished = true;
            }
            catch (VaultKeyRingException)
            {
                destructionPublished = await HasExactCanonicalReceiptAsync(
                    expectedPendingReceipt,
                    cancellationToken: CancellationToken.None);
                if (!destructionPublished)
                {
                    return await RollbackResultAsync(
                        transaction,
                        new DeletionRecoveryRequired("key-destruction-failed"));
                }
            }
            _faults.ThrowIfRequested(
                SqliteSensitiveDataDeletionFaultPoint.AfterKeyRingReplacement);

            var completionToken = CancellationToken.None;
            var tombstoneVersion = command.ExpectedVersion.Next();
            await AdvanceHeadAsync(
                connection,
                transaction,
                command.StreamId,
                command.ExpectedVersion,
                tombstoneVersion,
                completionToken);
            var recordedAtUtc = _timeProvider.GetUtcNow().ToUniversalTime();
            var globalPosition = await InsertTombstoneAsync(
                connection,
                transaction,
                command,
                tombstoneVersion,
                recordedAtUtc,
                payload,
                completionToken);
            var replay = new DecryptedEvent(
                new EventMetadata(
                    command.StreamId,
                    tombstoneVersion,
                    command.TombstoneEventId,
                    SensitiveObjectDeletedEventContract.EventType,
                    SensitiveObjectDeletedEventContract.SchemaVersion,
                    recordedAtUtc,
                    command.OperationId,
                    dataKeyId: null,
                    encryptionEnvelopeVersion: 0),
                payload);

            foreach (var registration in _projections.Registrations)
            {
                await SqliteProjectionAuthorizer.RunAsync(
                    connection,
                    registration,
                    _projections.AllowsLegacyTestObjects,
                    () => registration.Projection.PurgeOwnerAsync(
                        command.Target,
                        SqliteProjectionContexts.CreateAdministrative(
                            connection,
                            transaction,
                            _keyRing,
                            lease,
                            registration),
                        completionToken));
                await SqliteProjectionAuthorizer.RunAsync(
                    connection,
                    registration,
                    _projections.AllowsLegacyTestObjects,
                    () => registration.Projection.ApplyAsync(
                        replay,
                        globalPosition,
                        SqliteProjectionContexts.CreateDisabledApply(connection, transaction),
                        completionToken));
                await SqliteProjectionCheckpointStore.AdvanceAsync(
                    connection,
                    transaction,
                    registration,
                    globalPosition,
                    completionToken);
            }

            await InsertCompactionQueueAsync(
                connection,
                transaction,
                command,
                keyId.Value,
                tombstoneVersion,
                completionToken);
            await RequireExactCommittedImageAsync(
                connection,
                transaction,
                lease,
                command,
                keyId.Value,
                payload,
                allowSubsequentHistory: false,
                completionToken);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                connection,
                transaction,
                completionToken);
            await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                connection,
                transaction,
                _projections,
                completionToken);
            await SqliteEventStore.ValidateAllOperationMetadataAsync(
                connection,
                transaction,
                completionToken);
            await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
                connection,
                transaction,
                persistedIdentity,
                completionToken);
            SqliteEventStoreSchema.ValidateVaultPath(
                _connectionString,
                _keyRing.MaintenanceGate);
            _faults.ThrowIfRequested(
                SqliteSensitiveDataDeletionFaultPoint.BeforeSqlCommit);
            await transaction.CommitAsync(completionToken);
            _faults.ThrowIfRequested(
                SqliteSensitiveDataDeletionFaultPoint.AfterSqlCommit);

            var completedReceipt = CreateReceipt(
                command,
                keyId.Value,
                VaultDestroyedReceiptState.Completed);
            try
            {
                await _keyRing.UpdateDestroyedReceiptAsync(
                    completedReceipt,
                    lease,
                    completionToken);
            }
            catch (VaultKeyRingException)
            {
                if (!await HasExactCanonicalReceiptAsync(completedReceipt, completionToken))
                    return new DeletionRecoveryRequired("receipt-completion-failed");
            }

            return new Deleted();
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode is 5 or 6)
        {
            if (transaction is not null) await RollbackWithoutMaskingAsync(transaction);
            return destructionPublished
                ? new DeletionRecoveryRequired("sqlite-busy-after-destruction")
                : new DeletionStorageBusy();
        }
        catch (Exception exception) when (exception is VaultRecoveryRequiredException
            or VaultKeyRingException
            or ProjectionRebuildRequiredException
            or InvalidOperationException
            or FormatException
            or OverflowException)
        {
            if (transaction is not null) await RollbackWithoutMaskingAsync(transaction);
            return new DeletionRecoveryRequired(
                destructionPublished ? "deletion-sql-recovery-required" : "deletion-validation-failed");
        }
        catch (Exception exception) when (expectedPendingReceipt is not null)
        {
            if (transaction is not null) await RollbackWithoutMaskingAsync(transaction);
            var boundary = await InspectCanonicalBoundaryAsync(
                expectedPendingReceipt,
                CancellationToken.None);
            if (boundary == CanonicalDeletionBoundary.OldActiveKey)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo
                    .Capture(exception)
                    .Throw();
            }
            return boundary is CanonicalDeletionBoundary.PendingReceipt
                or CanonicalDeletionBoundary.CompletedReceipt
                ? new DeletionRecoveryRequired("sql-completion-required")
                : new DeletionRecoveryRequired("keyring-state-ambiguous");
        }
        finally
        {
            if (transaction is not null) await transaction.DisposeAsync();
            if (connection is not null) await connection.DisposeAsync();
        }
    }

    internal static async Task RequireNoPendingReceiptsAsync(
        VaultKeyRingStore keyRing,
        VaultKeyRingIdentity expectedIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        try
        {
            var ring = await keyRing.OpenAsync(cancellationToken);
            if (!ring.Identity.FixedTimeEquals(expectedIdentity)
                || ring.DestroyedReceipts.Any(
                    receipt => receipt.State == VaultDestroyedReceiptState.PendingSqlCompletion))
            {
                throw new VaultRecoveryRequiredException();
            }
        }
        catch (VaultRecoveryRequiredException) { throw; }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    internal async Task RecoverAsync(CancellationToken cancellationToken)
    {
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);
        await using var lease = await _keyRing.MaintenanceGate
            .AcquireMutationAsync(cancellationToken)
            .ConfigureAwait(false);
        await RecoverAsync(lease, cancellationToken).ConfigureAwait(false);
    }

    internal async Task RecoverAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        _keyRing.MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);
        VaultKeyRing initialRing;
        try { initialRing = await _keyRing.OpenAsync(cancellationToken); }
        catch (VaultKeyRingException exception) { throw new VaultRecoveryRequiredException(exception); }

        var receipts = initialRing.DestroyedReceipts
            .OrderBy(receipt => (int)receipt.Owner.Kind)
            .ThenBy(receipt => receipt.Owner.Id.Value)
            .ThenBy(receipt => receipt.OperationId.Value)
            .ToArray();
        foreach (var receipt in receipts)
        {
            var recoveryToken = receipt.State == VaultDestroyedReceiptState.PendingSqlCompletion
                ? CancellationToken.None
                : cancellationToken;
            var command = new DeleteSensitiveObjectCommand(
                receipt.Owner,
                receipt.StreamId,
                receipt.ExpectedStreamVersion,
                receipt.OperationId,
                receipt.TombstoneEventId,
                receipt.ReasonCode);
            var payload = SensitiveObjectDeletedEventContract
                .CreatePayload(receipt.Owner, receipt.ReasonCode)
                .ToArray();
            await using var connection = await SqliteEventStoreSchema.OpenConnectionAsync(
                _connectionString,
                _keyRing.MaintenanceGate,
                recoveryToken);
            await using var transaction = connection.BeginTransaction(deferred: false);
            try
            {
                await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                    connection,
                    transaction,
                    recoveryToken);
                await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                    connection,
                    transaction,
                    _projections,
                    recoveryToken);
                var persistedIdentity = await SqliteEventStoreSchema
                    .ReadPersistedKeyRingIdentityAsync(connection, transaction, recoveryToken);
                var canonicalRing = await _keyRing.OpenAsync(recoveryToken);
                if (!canonicalRing.Identity.FixedTimeEquals(persistedIdentity))
                    throw new VaultRecoveryRequiredException();
                var canonicalReceipt = canonicalRing.DestroyedReceipts
                    .SingleOrDefault(candidate => candidate.Owner == receipt.Owner);
                if (canonicalReceipt != receipt
                    || canonicalRing.ActiveKeys.Any(candidate => candidate.Owner == receipt.Owner))
                {
                    throw new VaultRecoveryRequiredException();
                }

                if (receipt.State == VaultDestroyedReceiptState.PendingSqlCompletion)
                {
                    await CompletePendingSqlAsync(
                        connection,
                        transaction,
                        lease,
                        command,
                        receipt.KeyId,
                        payload,
                        recoveryToken);
                }
                else
                {
                    await RequireExactCommittedImageAsync(
                        connection,
                        transaction,
                        lease,
                        command,
                        receipt.KeyId,
                        payload,
                        allowSubsequentHistory: true,
                        recoveryToken);
                }

                await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                    connection,
                    transaction,
                    recoveryToken);
                await SqliteEventStoreSchema.ValidateProjectionMembershipAsync(
                    connection,
                    transaction,
                    _projections,
                    recoveryToken);
                await SqliteEventStore.ValidateAllOperationMetadataAsync(
                    connection,
                    transaction,
                    recoveryToken);
                await transaction.CommitAsync(recoveryToken);
            }
            catch
            {
                await RollbackWithoutMaskingAsync(transaction);
                throw new VaultRecoveryRequiredException();
            }

            if (receipt.State == VaultDestroyedReceiptState.PendingSqlCompletion)
            {
                var completed = CreateReceipt(
                    command,
                    receipt.KeyId,
                    VaultDestroyedReceiptState.Completed);
                try
                {
                    await _keyRing.UpdateDestroyedReceiptAsync(
                        completed,
                        lease,
                        CancellationToken.None);
                }
                catch (VaultKeyRingException exception)
                {
                    if (!await HasExactCanonicalReceiptAsync(completed, CancellationToken.None))
                        throw new VaultRecoveryRequiredException(exception);
                }
            }
        }

        var finalRing = await _keyRing.OpenAsync(CancellationToken.None);
        if (finalRing.DestroyedReceipts.Any(
                receipt => receipt.State == VaultDestroyedReceiptState.PendingSqlCompletion))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private async Task CompletePendingSqlAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultMaintenanceLease lease,
        DeleteSensitiveObjectCommand command,
        DataKeyId keyId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        if (await IdentifierExistsAsync(
                connection,
                transaction,
                command.OperationId,
                command.TombstoneEventId,
                cancellationToken))
        {
            await RequireExactCommittedImageAsync(
                connection,
                transaction,
                lease,
                command,
                keyId,
                payload,
                allowSubsequentHistory: false,
                cancellationToken);
            return;
        }

        var head = await ReadHeadAsync(
            connection,
            transaction,
            command.StreamId,
            cancellationToken);
        if (head != command.ExpectedVersion)
            throw new VaultRecoveryRequiredException();
        var persistedKey = await ReadAndValidateTargetKeyAsync(
            connection,
            transaction,
            command.Target,
            command.StreamId,
            cancellationToken);
        if (persistedKey != keyId) throw new VaultRecoveryRequiredException();

        var tombstoneVersion = command.ExpectedVersion.Next();
        await AdvanceHeadAsync(
            connection,
            transaction,
            command.StreamId,
            command.ExpectedVersion,
            tombstoneVersion,
            cancellationToken);
        var recordedAtUtc = _timeProvider.GetUtcNow().ToUniversalTime();
        var globalPosition = await InsertTombstoneAsync(
            connection,
            transaction,
            command,
            tombstoneVersion,
            recordedAtUtc,
            payload,
            cancellationToken);
        var replay = new DecryptedEvent(
            new EventMetadata(
                command.StreamId,
                tombstoneVersion,
                command.TombstoneEventId,
                SensitiveObjectDeletedEventContract.EventType,
                SensitiveObjectDeletedEventContract.SchemaVersion,
                recordedAtUtc,
                command.OperationId,
                dataKeyId: null,
                encryptionEnvelopeVersion: 0),
            payload);
        foreach (var registration in _projections.Registrations)
        {
            await SqliteProjectionAuthorizer.RunAsync(
                connection,
                registration,
                _projections.AllowsLegacyTestObjects,
                () => registration.Projection.PurgeOwnerAsync(
                    command.Target,
                    SqliteProjectionContexts.CreateAdministrative(
                        connection,
                        transaction,
                        _keyRing,
                        lease,
                        registration),
                    cancellationToken));
            await SqliteProjectionAuthorizer.RunAsync(
                connection,
                registration,
                _projections.AllowsLegacyTestObjects,
                () => registration.Projection.ApplyAsync(
                    replay,
                    globalPosition,
                    SqliteProjectionContexts.CreateDisabledApply(connection, transaction),
                    cancellationToken));
            await SqliteProjectionCheckpointStore.AdvanceAsync(
                connection,
                transaction,
                registration,
                globalPosition,
                cancellationToken);
        }
        await InsertCompactionQueueAsync(
            connection,
            transaction,
            command,
            keyId,
            tombstoneVersion,
            cancellationToken);
        await RequireExactCommittedImageAsync(
            connection,
            transaction,
            lease,
            command,
            keyId,
            payload,
            allowSubsequentHistory: false,
            cancellationToken);
    }

    private async Task<DeleteSensitiveObjectResult> ClassifyExistingReceiptAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultMaintenanceLease lease,
        DeleteSensitiveObjectCommand command,
        byte[] payload,
        VaultDestroyedKeyReceipt receipt,
        CancellationToken cancellationToken)
    {
        var expected = CreateReceipt(command, receipt.KeyId, receipt.State);
        if (receipt != expected)
            return new DeletionRecoveryRequired("receipt-command-mismatch");
        if (receipt.State != VaultDestroyedReceiptState.Completed)
            return new DeletionRecoveryRequired("pending-deletion-recovery");
        try
        {
            await RequireExactCommittedImageAsync(
                connection,
                transaction,
                lease,
                command,
                receipt.KeyId,
                payload,
                allowSubsequentHistory: true,
                cancellationToken);
            return new DeletionAlreadyApplied();
        }
        catch (Exception exception) when (exception is VaultRecoveryRequiredException
            or SqliteException
            or InvalidOperationException
            or FormatException
            or OverflowException)
        {
            return new DeletionRecoveryRequired("completed-deletion-mismatch");
        }
    }

    private async Task<bool> HasExactCanonicalReceiptAsync(
        VaultDestroyedKeyReceipt expected,
        CancellationToken cancellationToken)
    {
        try
        {
            var ring = await _keyRing.OpenAsync(cancellationToken);
            var receipt = ring.DestroyedReceipts.SingleOrDefault(x => x.Owner == expected.Owner);
            return receipt == expected
                && ring.ActiveKeys.All(x => x.Owner != expected.Owner);
        }
        catch (VaultKeyRingException)
        {
            return false;
        }
    }

    private async Task<CanonicalDeletionBoundary> InspectCanonicalBoundaryAsync(
        VaultDestroyedKeyReceipt expectedPending,
        CancellationToken cancellationToken)
    {
        try
        {
            var ring = await _keyRing.OpenAsync(cancellationToken);
            var active = ring.ActiveKeys.SingleOrDefault(
                candidate => candidate.Owner == expectedPending.Owner);
            var receipt = ring.DestroyedReceipts.SingleOrDefault(
                candidate => candidate.Owner == expectedPending.Owner);
            if (active is not null
                && active.KeyId == expectedPending.KeyId
                && receipt is null)
            {
                return CanonicalDeletionBoundary.OldActiveKey;
            }
            if (active is not null || receipt is null)
                return CanonicalDeletionBoundary.Ambiguous;
            if (receipt == expectedPending)
                return CanonicalDeletionBoundary.PendingReceipt;
            var completed = new VaultDestroyedKeyReceipt(
                expectedPending.Owner,
                expectedPending.KeyId,
                expectedPending.StreamId,
                expectedPending.OperationId,
                expectedPending.TombstoneEventId,
                expectedPending.ExpectedStreamVersion,
                expectedPending.ReasonCode,
                VaultDestroyedReceiptState.Completed);
            return receipt == completed
                ? CanonicalDeletionBoundary.CompletedReceipt
                : CanonicalDeletionBoundary.Ambiguous;
        }
        catch (VaultKeyRingException)
        {
            return CanonicalDeletionBoundary.Ambiguous;
        }
    }

    private static VaultDestroyedKeyReceipt CreateReceipt(
        DeleteSensitiveObjectCommand command,
        DataKeyId keyId,
        VaultDestroyedReceiptState state) =>
        new(
            command.Target,
            keyId,
            command.StreamId,
            command.OperationId,
            command.TombstoneEventId,
            command.ExpectedVersion,
            command.ReasonCode,
            state);

    private static async Task<StreamVersion?> ReadHeadAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        StreamId streamId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT stream_id, head_version
            FROM main.event_streams
            WHERE CAST(stream_id AS TEXT) COLLATE NOCASE = $stream_id;
            """;
        command.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        if (reader.GetValue(0) is not string persisted
            || persisted != streamId.Value.ToString("D")
            || reader.GetValue(1) is not long head
            || head < 0
            || await reader.ReadAsync(cancellationToken))
        {
            throw new VaultRecoveryRequiredException();
        }
        return new StreamVersion(head);
    }

    private static async Task<bool> IdentifierExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        OperationId operationId,
        EventId eventId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT COUNT(*)
            FROM main.timeline_events
            WHERE CAST(operation_id AS TEXT) COLLATE NOCASE = $operation_id
               OR CAST(event_id AS TEXT) COLLATE NOCASE = $event_id;
            """;
        command.Parameters.AddWithValue("$operation_id", operationId.Value.ToString("D"));
        command.Parameters.AddWithValue("$event_id", eventId.Value.ToString("D"));
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) != 0;
    }

    private static async Task<bool> HasCompactionQueueConflictAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeleteSensitiveObjectCommand command,
        CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.Transaction = transaction;
        query.CommandText = """
            SELECT COUNT(*)
            FROM main.secure_compaction_queue
            WHERE (owner_kind = $owner_kind AND owner_id = $owner_id)
               OR operation_id = $operation_id
               OR tombstone_event_id = $event_id;
            """;
        query.Parameters.AddWithValue("$owner_kind", (int)command.Target.Kind);
        query.Parameters.AddWithValue("$owner_id", command.Target.Id.Value.ToString("D"));
        query.Parameters.AddWithValue("$operation_id", command.OperationId.Value.ToString("D"));
        query.Parameters.AddWithValue("$event_id", command.TombstoneEventId.Value.ToString("D"));
        return Convert.ToInt64(
            await query.ExecuteScalarAsync(cancellationToken),
            CultureInfo.InvariantCulture) != 0;
    }

    private static async Task<DataKeyId?> ReadAndValidateTargetKeyAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SensitiveObjectRef target,
        StreamId requiredStream,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT stream_id, owner_id, key_id, protection_kind
            FROM main.timeline_events
            WHERE owner_kind = $owner_kind
              AND CAST(owner_id AS TEXT) COLLATE NOCASE = $owner_id
            ORDER BY global_position;
            """;
        command.Parameters.AddWithValue("$owner_kind", (int)target.Kind);
        command.Parameters.AddWithValue("$owner_id", target.Id.Value.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        DataKeyId? keyId = null;
        var foundInRequiredStream = false;
        var rowCount = 0;
        while (await reader.ReadAsync(cancellationToken))
        {
            rowCount++;
            if (reader.GetValue(0) is not string streamText
                || reader.GetValue(1) is not string ownerText
                || reader.GetValue(2) is not string keyText
                || reader.GetValue(3) is not long protectionKind
                || protectionKind != 1
                || ownerText != target.Id.Value.ToString("D")
                || !Guid.TryParseExact(streamText, "D", out var streamGuid)
                || streamText != streamGuid.ToString("D")
                || !Guid.TryParseExact(keyText, "D", out var keyGuid)
                || keyText != keyGuid.ToString("D")
                || keyGuid == Guid.Empty)
            {
                throw new VaultRecoveryRequiredException();
            }

            var rowKey = new DataKeyId(keyGuid);
            if (keyId is not null && keyId.Value != rowKey)
                return null;
            keyId = rowKey;
            if (streamGuid == requiredStream.Value) foundInRequiredStream = true;
        }
        return rowCount > 0 && foundInRequiredStream ? keyId : null;
    }

    private static async Task AdvanceHeadAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        StreamId streamId,
        StreamVersion expected,
        StreamVersion next,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE main.event_streams
            SET head_version = $next
            WHERE stream_id = $stream_id AND head_version = $expected;
            """;
        command.Parameters.AddWithValue("$next", next.Value);
        command.Parameters.AddWithValue("$stream_id", streamId.Value.ToString("D"));
        command.Parameters.AddWithValue("$expected", expected.Value);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new VaultRecoveryRequiredException();
    }

    private static async Task<long> InsertTombstoneAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeleteSensitiveObjectCommand command,
        StreamVersion tombstoneVersion,
        DateTimeOffset recordedAtUtc,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO main.timeline_events(
                event_id, stream_id, stream_version, event_type, schema_version,
                recorded_at_utc, operation_id, operation_index, operation_count,
                protection_kind, owner_kind, owner_id, key_id, envelope_version,
                payload_nonce, payload_ciphertext, payload_tag)
            VALUES(
                $event_id, $stream_id, $stream_version, $event_type, $schema_version,
                $recorded_at_utc, $operation_id, 0, 1,
                0, NULL, NULL, NULL, 0, NULL, $payload, NULL)
            RETURNING global_position;
            """;
        insert.Parameters.AddWithValue("$event_id", command.TombstoneEventId.Value.ToString("D"));
        insert.Parameters.AddWithValue("$stream_id", command.StreamId.Value.ToString("D"));
        insert.Parameters.AddWithValue("$stream_version", tombstoneVersion.Value);
        insert.Parameters.AddWithValue("$event_type", SensitiveObjectDeletedEventContract.EventType);
        insert.Parameters.AddWithValue("$schema_version", SensitiveObjectDeletedEventContract.SchemaVersion);
        insert.Parameters.AddWithValue(
            "$recorded_at_utc",
            recordedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        insert.Parameters.AddWithValue("$operation_id", command.OperationId.Value.ToString("D"));
        insert.Parameters.Add("$payload", SqliteType.Blob).Value = payload;
        return Convert.ToInt64(await insert.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    private static async Task InsertCompactionQueueAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DeleteSensitiveObjectCommand command,
        DataKeyId keyId,
        StreamVersion tombstoneVersion,
        CancellationToken cancellationToken)
    {
        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO main.secure_compaction_queue(
                owner_kind, owner_id, destroyed_key_id, stream_id,
                tombstone_stream_version, operation_id, tombstone_event_id)
            VALUES(
                $owner_kind, $owner_id, $key_id, $stream_id,
                $stream_version, $operation_id, $event_id);
            """;
        insert.Parameters.AddWithValue("$owner_kind", (int)command.Target.Kind);
        insert.Parameters.AddWithValue("$owner_id", command.Target.Id.Value.ToString("D"));
        insert.Parameters.AddWithValue("$key_id", keyId.Value.ToString("D"));
        insert.Parameters.AddWithValue("$stream_id", command.StreamId.Value.ToString("D"));
        insert.Parameters.AddWithValue("$stream_version", tombstoneVersion.Value);
        insert.Parameters.AddWithValue("$operation_id", command.OperationId.Value.ToString("D"));
        insert.Parameters.AddWithValue("$event_id", command.TombstoneEventId.Value.ToString("D"));
        if (await insert.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new VaultRecoveryRequiredException();
    }

    private async Task RequireExactCommittedImageAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultMaintenanceLease lease,
        DeleteSensitiveObjectCommand command,
        DataKeyId keyId,
        byte[] payload,
        bool allowSubsequentHistory,
        CancellationToken cancellationToken)
    {
        await SqliteEventStore.ValidateAllOperationMetadataAsync(
            connection,
            transaction,
            cancellationToken);
        var tombstoneVersion = command.ExpectedVersion.Next();
        var head = await ReadHeadAsync(connection, transaction, command.StreamId, cancellationToken);
        if (head is null
            || (allowSubsequentHistory
                ? head.Value.Value < tombstoneVersion.Value
                : head.Value != tombstoneVersion))
        {
            throw new VaultRecoveryRequiredException();
        }

        long globalPosition;
        await using (var eventCommand = connection.CreateCommand())
        {
            eventCommand.Transaction = transaction;
            eventCommand.CommandText = """
                SELECT event_id, stream_id, stream_version, event_type, schema_version,
                       operation_id, operation_index, operation_count, protection_kind,
                       owner_kind, owner_id, key_id, envelope_version,
                       payload_nonce, payload_ciphertext, payload_tag, global_position
                FROM main.timeline_events
                WHERE CAST(operation_id AS TEXT) COLLATE NOCASE = $operation_id;
                """;
            eventCommand.Parameters.AddWithValue("$operation_id", command.OperationId.Value.ToString("D"));
            await using var reader = await eventCommand.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)
                || reader.GetValue(0) is not string eventId
                || eventId != command.TombstoneEventId.Value.ToString("D")
                || reader.GetValue(1) is not string streamId
                || streamId != command.StreamId.Value.ToString("D")
                || reader.GetValue(2) is not long streamVersion
                || streamVersion != tombstoneVersion.Value
                || reader.GetValue(3) is not string eventType
                || eventType != SensitiveObjectDeletedEventContract.EventType
                || reader.GetValue(4) is not long schemaVersion
                || schemaVersion != SensitiveObjectDeletedEventContract.SchemaVersion
                || reader.GetValue(5) is not string operationId
                || operationId != command.OperationId.Value.ToString("D")
                || reader.GetValue(6) is not long operationIndex
                || operationIndex != 0
                || reader.GetValue(7) is not long operationCount
                || operationCount != 1
                || reader.GetValue(8) is not long protectionKind
                || protectionKind != 0
                || reader.GetValue(9) is not DBNull
                || reader.GetValue(10) is not DBNull
                || reader.GetValue(11) is not DBNull
                || reader.GetValue(12) is not long envelopeVersion
                || envelopeVersion != 0
                || reader.GetValue(13) is not DBNull
                || reader.GetValue(14) is not byte[] actualPayload
                || !actualPayload.AsSpan().SequenceEqual(payload)
                || reader.GetValue(15) is not DBNull
                || reader.GetValue(16) is not long persistedGlobalPosition
                || persistedGlobalPosition <= 0
                || await reader.ReadAsync(cancellationToken))
            {
                throw new VaultRecoveryRequiredException();
            }
            globalPosition = persistedGlobalPosition;
        }

        await RequireOwnerPurgedAsync(
            connection,
            transaction,
            lease,
            command.Target,
            cancellationToken);
        var currentGlobalPosition = await ReadCurrentGlobalPositionAsync(
            connection,
            transaction,
            cancellationToken);
        if (currentGlobalPosition < globalPosition)
            throw new VaultRecoveryRequiredException();
        foreach (var registration in _projections.Registrations)
        {
            await RequireCheckpointAsync(
                connection,
                transaction,
                registration,
                globalPosition,
                currentGlobalPosition,
                cancellationToken);
        }

        await using var queue = connection.CreateCommand();
        queue.Transaction = transaction;
        queue.CommandText = """
            SELECT owner_kind, owner_id, destroyed_key_id, stream_id,
                   tombstone_stream_version, operation_id, tombstone_event_id
            FROM main.secure_compaction_queue
            WHERE owner_kind = $owner_kind
              AND owner_id = $owner_id;
            """;
        queue.Parameters.AddWithValue("$owner_kind", (int)command.Target.Kind);
        queue.Parameters.AddWithValue("$owner_id", command.Target.Id.Value.ToString("D"));
        await using var queueReader = await queue.ExecuteReaderAsync(cancellationToken);
        if (!await queueReader.ReadAsync(cancellationToken)
            || queueReader.GetValue(0) is not long ownerKind
            || ownerKind != (int)command.Target.Kind
            || queueReader.GetValue(1) is not string ownerId
            || ownerId != command.Target.Id.Value.ToString("D")
            || queueReader.GetValue(2) is not string destroyedKeyId
            || destroyedKeyId != keyId.Value.ToString("D")
            || queueReader.GetValue(3) is not string queueStreamId
            || queueStreamId != command.StreamId.Value.ToString("D")
            || queueReader.GetValue(4) is not long queueStreamVersion
            || queueStreamVersion != tombstoneVersion.Value
            || queueReader.GetValue(5) is not string queueOperationId
            || queueOperationId != command.OperationId.Value.ToString("D")
            || queueReader.GetValue(6) is not string queueEventId
            || queueEventId != command.TombstoneEventId.Value.ToString("D")
            || await queueReader.ReadAsync(cancellationToken))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task RequireCheckpointAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SqliteProjectionRegistration registration,
        long tombstoneGlobalPosition,
        long currentGlobalPosition,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT projection_schema_version, encryption_version, last_global_position
            FROM main.projection_checkpoints
            WHERE projection_name = $projection_name;
            """;
        command.Parameters.AddWithValue("$projection_name", registration.Name);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)
            || reader.GetValue(0) is not long schemaVersion
            || schemaVersion != registration.SchemaVersion
            || reader.GetValue(1) is not long encryptionVersion
            || encryptionVersion != registration.EncryptionVersion
            || reader.GetValue(2) is not long checkpoint
            || checkpoint < tombstoneGlobalPosition
            || checkpoint != currentGlobalPosition
            || await reader.ReadAsync(cancellationToken))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task<long> ReadCurrentGlobalPositionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            "SELECT COALESCE(MAX(global_position), 0) FROM main.timeline_events;";
        if (await command.ExecuteScalarAsync(cancellationToken) is not long position
            || position < 0)
        {
            throw new VaultRecoveryRequiredException();
        }
        return position;
    }

    private async Task RequireOwnerPurgedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultMaintenanceLease lease,
        SensitiveObjectRef owner,
        CancellationToken cancellationToken)
    {
        foreach (var registration in _projections.Registrations)
        {
            var before = await ReadTotalChangesAsync(
                connection,
                transaction,
                cancellationToken);
            await SqliteProjectionAuthorizer.RunAsync(
                connection,
                registration,
                _projections.AllowsLegacyTestObjects,
                () => registration.Projection.PurgeOwnerAsync(
                    owner,
                    SqliteProjectionContexts.CreateAdministrative(
                        connection,
                        transaction,
                        _keyRing,
                        lease,
                        registration),
                    cancellationToken));
            var after = await ReadTotalChangesAsync(
                connection,
                transaction,
                cancellationToken);
            if (after != before) throw new VaultRecoveryRequiredException();
        }
    }

    private static async Task<long> ReadTotalChangesAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT total_changes();";
        return Convert.ToInt64(
            await command.ExecuteScalarAsync(cancellationToken),
            CultureInfo.InvariantCulture);
    }

    private static async Task<T> RollbackResultAsync<T>(
        SqliteTransaction transaction,
        T result)
    {
        await RollbackWithoutMaskingAsync(transaction);
        return result;
    }

    private static async Task RollbackWithoutMaskingAsync(SqliteTransaction transaction)
    {
        try { await transaction.RollbackAsync(); }
        catch { }
    }

    private enum CanonicalDeletionBoundary
    {
        OldActiveKey,
        PendingReceipt,
        CompletedReceipt,
        Ambiguous,
    }
}
