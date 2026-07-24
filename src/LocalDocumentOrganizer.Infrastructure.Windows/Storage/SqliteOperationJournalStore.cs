using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Core.Transactions;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public interface IOperationJournalStore
{
    Task<PersistOperationIntentResult> PersistIntentAsync(
        FileOperationIntent intent,
        CancellationToken cancellationToken);

    Task<TransitionOperationResult> TransitionAsync(
        TransitionOperationCommand command,
        CancellationToken cancellationToken);

    Task<OperationJournalEntry?> GetAsync(
        OperationId operationId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<OperationJournalEntry>> GetNonTerminalAsync(
        CancellationToken cancellationToken);
}

public enum PersistOperationIntentStatus
{
    Persisted = 0,
    AlreadyPersisted = 1,
    Conflict = 2,
}

public sealed record PersistOperationIntentResult
{
    internal PersistOperationIntentResult(
        PersistOperationIntentStatus status,
        OperationJournalEntry? entry)
    {
        Status = status;
        Entry = entry;
    }

    public PersistOperationIntentStatus Status { get; }

    public OperationJournalEntry? Entry { get; }
}

public enum TransitionOperationStatus
{
    Transitioned = 0,
    AlreadyApplied = 1,
    RevisionConflict = 2,
    NotFound = 3,
}

public sealed record TransitionOperationResult
{
    internal TransitionOperationResult(
        TransitionOperationStatus status,
        OperationJournalEntry? entry,
        long? actualRevision)
    {
        Status = status;
        Entry = entry;
        ActualRevision = actualRevision;
    }

    public TransitionOperationStatus Status { get; }

    public OperationJournalEntry? Entry { get; }

    public long? ActualRevision { get; }
}

public sealed record TransitionOperationCommand
{
    public TransitionOperationCommand(
        OperationId operationId,
        long expectedRevision,
        OperationJournalState nextState,
        OperationSourceHealth sourceHealth)
    {
        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation ID cannot be empty.",
                nameof(operationId));
        }

        if (expectedRevision <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedRevision),
                expectedRevision,
                "The expected Journal revision must be positive.");
        }

        if (!Enum.IsDefined(nextState))
        {
            throw new ArgumentOutOfRangeException(
                nameof(nextState),
                "The next Journal state is not defined.");
        }

        if (!Enum.IsDefined(sourceHealth))
        {
            throw new ArgumentOutOfRangeException(
                nameof(sourceHealth),
                "The source-health state is not defined.");
        }

        OperationId = operationId;
        ExpectedRevision = expectedRevision;
        NextState = nextState;
        SourceHealth = sourceHealth;
    }

    public OperationId OperationId { get; }

    public long ExpectedRevision { get; }

    public OperationJournalState NextState { get; }

    public OperationSourceHealth SourceHealth { get; }
}

public sealed class OperationJournalEntry : IEquatable<OperationJournalEntry>
{
    internal OperationJournalEntry(
        FileOperationIntent intent,
        OperationJournalState state,
        long revision,
        OperationSourceHealth sourceHealth,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc)
    {
        Intent = intent;
        State = state;
        Revision = revision;
        SourceHealth = sourceHealth;
        CreatedAtUtc = createdAtUtc;
        UpdatedAtUtc = updatedAtUtc;
    }

    public FileOperationIntent Intent { get; }

    public OperationId OperationId => Intent.OperationId;

    public SensitiveObjectRef Owner => Intent.Owner;

    public FileOperationKind Kind => Intent.Kind;

    public OperationJournalState State { get; }

    public long Revision { get; }

    public OperationSourceHealth SourceHealth { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }

    public bool Equals(OperationJournalEntry? other) =>
        other is not null
        && SqliteOperationJournalStore.IntentsEqual(Intent, other.Intent)
        && State == other.State
        && Revision == other.Revision
        && SourceHealth == other.SourceHealth
        && CreatedAtUtc == other.CreatedAtUtc
        && UpdatedAtUtc == other.UpdatedAtUtc;

    public override bool Equals(object? obj) =>
        obj is OperationJournalEntry other && Equals(other);

    public override int GetHashCode() =>
        HashCode.Combine(
            OperationId,
            Owner,
            Kind,
            State,
            Revision,
            SourceHealth,
            CreatedAtUtc,
            UpdatedAtUtc);
}

public sealed class OperationJournalRecoveryRequiredException : InvalidOperationException
{
    public OperationJournalRecoveryRequiredException()
        : base("Operation Journal recovery is required.")
    {
    }

    internal OperationJournalRecoveryRequiredException(Exception innerException)
        : base("Operation Journal recovery is required.", innerException)
    {
    }
}

public sealed class SqliteOperationJournalStore : IOperationJournalStore
{
    private const int PayloadSchemaVersion = 1;
    private const int EnvelopeVersion = 1;

    private readonly string _connectionString;
    private readonly VaultKeyRingStore _keyRing;
    private readonly TimeProvider _timeProvider;
    private readonly SqliteOperationJournalPayloadProtector _protector;

    public SqliteOperationJournalStore(
        string connectionString,
        TimeProvider? timeProvider = null)
        : this(
            connectionString,
            CreateDefaultKeyRing(connectionString),
            timeProvider)
    {
    }

    internal SqliteOperationJournalStore(
        string connectionString,
        VaultKeyRingStore keyRing,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(keyRing);
        _connectionString =
            SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        _keyRing = keyRing;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _protector = new SqliteOperationJournalPayloadProtector();
    }

    public async Task<PersistOperationIntentResult> PersistIntentAsync(
        FileOperationIntent intent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(intent);
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);

        try
        {
            await using var lease = await _keyRing.MaintenanceGate
                .AcquireMutationAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var connection =
                await SqliteEventStoreSchema.OpenConnectionAsync(
                    _connectionString,
                    _keyRing.MaintenanceGate,
                    cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            var expectedIdentity =
                await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                    connection,
                    transaction,
                    cancellationToken).ConfigureAwait(false);
            await SqliteSensitiveDataDeletionStore.RequireNoPendingReceiptsAsync(
                _keyRing,
                expectedIdentity,
                cancellationToken).ConfigureAwait(false);
            await using var keySession = await _keyRing.OpenWriteSessionAsync(
                lease,
                expectedIdentity,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
                connection,
                transaction,
                keySession.Identity,
                cancellationToken).ConfigureAwait(false);

            var existing = await ReadPersistedRowAsync(
                connection,
                transaction,
                intent.OperationId,
                cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                var existingEntry = await DecryptAsync(
                    existing,
                    keySession,
                    cancellationToken).ConfigureAwait(false);
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return IntentsEqual(existingEntry.Intent, intent)
                    ? new PersistOperationIntentResult(
                        PersistOperationIntentStatus.AlreadyPersisted,
                        existingEntry)
                    : new PersistOperationIntentResult(
                        PersistOperationIntentStatus.Conflict,
                        entry: null);
            }

            var now = _timeProvider.GetUtcNow().ToUniversalTime();
            var entry = await keySession.GetOrCreateDataKeyAsync(
                intent.Owner,
                async (keyId, dataKey, callbackToken) =>
                {
                    var envelope = Protect(
                        intent,
                        keyId,
                        dataKey.Span,
                        OperationJournalState.IntentPersisted,
                        revision: 1);
                    await InsertAsync(
                        connection,
                        transaction,
                        intent,
                        keyId,
                        envelope,
                        now,
                        callbackToken).ConfigureAwait(false);
                    return new OperationJournalEntry(
                        intent,
                        OperationJournalState.IntentPersisted,
                        revision: 1,
                        OperationSourceHealth.Healthy,
                        now,
                        now);
                },
                cancellationToken).ConfigureAwait(false);

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new PersistOperationIntentResult(
                PersistOperationIntentStatus.Persisted,
                entry);
        }
        catch (OperationJournalRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (IsRecoveryFailure(exception))
        {
            throw new OperationJournalRecoveryRequiredException(exception);
        }
    }

    public async Task<PersistOperationIntentResult> PersistIntentAsync(
        FileOperationIntent intent,
        Func<CancellationToken, ValueTask> filesystemCallback,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filesystemCallback);
        var result = await PersistIntentAsync(intent, cancellationToken)
            .ConfigureAwait(false);
        if (result.Status == PersistOperationIntentStatus.Persisted
            || result is
            {
                Status: PersistOperationIntentStatus.AlreadyPersisted,
                Entry.State: OperationJournalState.IntentPersisted,
            })
        {
            await filesystemCallback(CancellationToken.None).ConfigureAwait(false);
        }

        return result;
    }

    public async Task<TransitionOperationResult> TransitionAsync(
        TransitionOperationCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);

        try
        {
            await using var lease = await _keyRing.MaintenanceGate
                .AcquireMutationAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var connection =
                await SqliteEventStoreSchema.OpenConnectionAsync(
                    _connectionString,
                    _keyRing.MaintenanceGate,
                    cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: false);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            var expectedIdentity =
                await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                    connection,
                    transaction,
                    cancellationToken).ConfigureAwait(false);
            await SqliteSensitiveDataDeletionStore.RequireNoPendingReceiptsAsync(
                _keyRing,
                expectedIdentity,
                cancellationToken).ConfigureAwait(false);

            var row = await ReadPersistedRowAsync(
                connection,
                transaction,
                command.OperationId,
                cancellationToken).ConfigureAwait(false);
            if (row is null)
            {
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return new TransitionOperationResult(
                    TransitionOperationStatus.NotFound,
                    entry: null,
                    actualRevision: null);
            }

            await using var keySession = await _keyRing.OpenWriteSessionAsync(
                lease,
                expectedIdentity,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
                connection,
                transaction,
                keySession.Identity,
                cancellationToken).ConfigureAwait(false);
            var currentPayload = await DecryptPayloadAsync(
                row,
                keySession,
                cancellationToken).ConfigureAwait(false);
            var current = currentPayload.Entry;
            var isExactReplay = row.State == command.NextState
                && row.Revision == checked(command.ExpectedRevision + 1)
                && row.SourceHealth == command.SourceHealth;
            if (isExactReplay)
            {
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return new TransitionOperationResult(
                    TransitionOperationStatus.AlreadyApplied,
                    current,
                    row.Revision);
            }

            OperationJournalStateMachine.EnsureCanTransition(
                row.Kind,
                row.State,
                command.NextState);
            if (row.Revision != command.ExpectedRevision)
            {
                await transaction.RollbackAsync(cancellationToken)
                    .ConfigureAwait(false);
                return new TransitionOperationResult(
                    TransitionOperationStatus.RevisionConflict,
                    entry: null,
                    row.Revision);
            }

            var nextRevision = checked(row.Revision + 1);
            RequireCanonicalCommitFingerprint(
                row.Kind,
                command.NextState,
                nextRevision,
                currentPayload.CommitFingerprint);
            var updatedAtUtc = NextTimestamp(row.UpdatedAtUtc);
            var nextEnvelope = await keySession.ResolveDataKeyAsync(
                row.Owner,
                row.Envelope.KeyId,
                static () =>
                    throw new OperationJournalRecoveryRequiredException(),
                (keyId, dataKey, _) =>
                {
                    if (keyId != row.Envelope.KeyId)
                    {
                        throw new OperationJournalRecoveryRequiredException();
                    }

                    return ValueTask.FromResult(Protect(
                        current.Intent,
                        keyId,
                        dataKey.Span,
                        command.NextState,
                        nextRevision,
                        currentPayload.CommitFingerprint));
                },
                cancellationToken).ConfigureAwait(false);

            var affected = await UpdateAsync(
                connection,
                transaction,
                command,
                nextRevision,
                nextEnvelope,
                updatedAtUtc,
                cancellationToken).ConfigureAwait(false);
            if (affected != 1)
            {
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
                var actual = await ReadRevisionAsync(
                    connection,
                    transaction: null,
                    command.OperationId,
                    cancellationToken).ConfigureAwait(false);
                return new TransitionOperationResult(
                    TransitionOperationStatus.RevisionConflict,
                    entry: null,
                    actual);
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            var next = new OperationJournalEntry(
                current.Intent,
                command.NextState,
                nextRevision,
                command.SourceHealth,
                row.CreatedAtUtc,
                updatedAtUtc);
            return new TransitionOperationResult(
                TransitionOperationStatus.Transitioned,
                next,
                nextRevision);
        }
        catch (OperationJournalRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (IsRecoveryFailure(exception))
        {
            throw new OperationJournalRecoveryRequiredException(exception);
        }
    }

    public async Task<OperationJournalEntry?> GetAsync(
        OperationId operationId,
        CancellationToken cancellationToken)
    {
        ValidateOperationId(operationId);
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);

        try
        {
            await using var lease = await _keyRing.MaintenanceGate
                .AcquireReadAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var connection =
                await SqliteEventStoreSchema.OpenConnectionAsync(
                    _connectionString,
                    _keyRing.MaintenanceGate,
                    cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: true);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            var expectedIdentity =
                await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                    connection,
                    transaction,
                    cancellationToken).ConfigureAwait(false);
            var row = await ReadPersistedRowAsync(
                connection,
                transaction,
                operationId,
                cancellationToken).ConfigureAwait(false);
            if (row is null)
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return null;
            }

            await using var keySession = await _keyRing.OpenReadSessionAsync(
                lease,
                expectedIdentity,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
                connection,
                transaction,
                keySession.Identity,
                cancellationToken).ConfigureAwait(false);
            var entry = await DecryptAsync(
                row,
                keySession,
                cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return entry;
        }
        catch (OperationJournalRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (IsRecoveryFailure(exception))
        {
            throw new OperationJournalRecoveryRequiredException(exception);
        }
    }

    public async Task<IReadOnlyList<OperationJournalEntry>> GetNonTerminalAsync(
        CancellationToken cancellationToken)
    {
        SqliteEventStoreSchema.ValidateVaultPath(
            _connectionString,
            _keyRing.MaintenanceGate);

        try
        {
            await using var lease = await _keyRing.MaintenanceGate
                .AcquireReadAsync(cancellationToken)
                .ConfigureAwait(false);
            await using var connection =
                await SqliteEventStoreSchema.OpenConnectionAsync(
                    _connectionString,
                    _keyRing.MaintenanceGate,
                    cancellationToken).ConfigureAwait(false);
            await using var transaction = connection.BeginTransaction(deferred: true);
            await SqliteEventStoreSchema.ValidateExistingVersionThreeAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            var expectedIdentity =
                await SqliteEventStoreSchema.ReadPersistedKeyRingIdentityAsync(
                    connection,
                    transaction,
                    cancellationToken).ConfigureAwait(false);
            var rows = await ReadNonTerminalRowsAsync(
                connection,
                transaction,
                cancellationToken).ConfigureAwait(false);
            await using var keySession = await _keyRing.OpenReadSessionAsync(
                lease,
                expectedIdentity,
                cancellationToken).ConfigureAwait(false);
            await SqliteEventStoreSchema.ValidateKeyRingIdentityAsync(
                connection,
                transaction,
                keySession.Identity,
                cancellationToken).ConfigureAwait(false);

            var entries = new List<OperationJournalEntry>(rows.Count);
            foreach (var row in rows)
            {
                entries.Add(await DecryptAsync(
                    row,
                    keySession,
                    cancellationToken).ConfigureAwait(false));
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return entries.AsReadOnly();
        }
        catch (OperationJournalRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (IsRecoveryFailure(exception))
        {
            throw new OperationJournalRecoveryRequiredException(exception);
        }
    }

    internal static bool IntentsEqual(
        FileOperationIntent left,
        FileOperationIntent right) =>
        left.OperationId == right.OperationId
        && left.Owner == right.Owner
        && left.Kind == right.Kind
        && string.Equals(left.SourcePath, right.SourcePath, StringComparison.Ordinal)
        && string.Equals(
            left.DestinationPath,
            right.DestinationPath,
            StringComparison.Ordinal)
        && string.Equals(left.SourceRoot, right.SourceRoot, StringComparison.Ordinal)
        && string.Equals(
            left.DestinationRoot,
            right.DestinationRoot,
            StringComparison.Ordinal)
        && left.StreamId == right.StreamId
        && left.ExpectedStreamVersion == right.ExpectedStreamVersion
        && left.ApprovedProposal.Span.SequenceEqual(right.ApprovedProposal.Span);

    internal async Task<OperationJournalCommitCandidate?> ReadCommitCandidateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        OperationId operationId,
        VaultKeyRingStore.VaultKeyRingSession keySession,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(keySession);
        ValidateOperationId(operationId);
        var row = await ReadPersistedRowAsync(
            connection,
            transaction,
            operationId,
            cancellationToken).ConfigureAwait(false);
        if (row is null)
        {
            return null;
        }

        var payload = await DecryptPayloadAsync(
            row,
            keySession,
            cancellationToken).ConfigureAwait(false);
        return new OperationJournalCommitCandidate(
            payload.Entry,
            row.Envelope.KeyId,
            payload.CommitFingerprint);
    }

    internal async Task<OperationJournalEntry> CommitAppliedInTransactionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        OperationJournalCommitCandidate candidate,
        long expectedRevision,
        ReadOnlyMemory<byte> commitFingerprint,
        VaultKeyRingStore.VaultKeyRingSession keySession,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(keySession);
        var current = candidate.Entry;
        if (current.State != OperationJournalState.FileApplied
            || current.Revision != expectedRevision)
        {
            throw new InvalidOperationException(
                "The operation Journal is not at the commit boundary.");
        }

        OperationJournalStateMachine.EnsureCanTransition(
            current.Kind,
            current.State,
            OperationJournalState.EventAndProjectionCommitted);
        var nextRevision = checked(expectedRevision + 1);
        var updatedAtUtc = NextTimestamp(current.UpdatedAtUtc);
        var nextEnvelope = await keySession.ResolveDataKeyAsync(
            current.Owner,
            candidate.KeyId,
            static () => throw new OperationJournalRecoveryRequiredException(),
            (keyId, dataKey, _) =>
            {
                if (keyId != candidate.KeyId)
                {
                    throw new OperationJournalRecoveryRequiredException();
                }

                return ValueTask.FromResult(Protect(
                    current.Intent,
                    keyId,
                    dataKey.Span,
                    OperationJournalState.EventAndProjectionCommitted,
                    nextRevision,
                    commitFingerprint.Span));
            },
            cancellationToken).ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE main.operation_journal
            SET state=$next_state,
                revision=$next_revision,
                source_health=$source_health,
                payload_nonce=$payload_nonce,
                payload_ciphertext=$payload_ciphertext,
                payload_tag=$payload_tag,
                updated_at_utc=$updated_at_utc
            WHERE operation_id=$operation_id
              AND state=$expected_state
              AND revision=$expected_revision;
            """;
        command.Parameters.Add("$next_state", SqliteType.Integer).Value =
            (int)OperationJournalState.EventAndProjectionCommitted;
        command.Parameters.Add("$next_revision", SqliteType.Integer).Value =
            nextRevision;
        command.Parameters.Add("$source_health", SqliteType.Integer).Value =
            (int)current.SourceHealth;
        command.Parameters.Add("$payload_nonce", SqliteType.Blob).Value =
            nextEnvelope.Nonce.ToArray();
        command.Parameters.Add("$payload_ciphertext", SqliteType.Blob).Value =
            nextEnvelope.Ciphertext.ToArray();
        command.Parameters.Add("$payload_tag", SqliteType.Blob).Value =
            nextEnvelope.Tag.ToArray();
        command.Parameters.Add("$updated_at_utc", SqliteType.Text).Value =
            FormatTimestamp(updatedAtUtc);
        command.Parameters.Add("$operation_id", SqliteType.Text).Value =
            current.OperationId.Value.ToString("D");
        command.Parameters.Add("$expected_state", SqliteType.Integer).Value =
            (int)OperationJournalState.FileApplied;
        command.Parameters.Add("$expected_revision", SqliteType.Integer).Value =
            expectedRevision;
        if (await command.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false) != 1)
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        return new OperationJournalEntry(
            current.Intent,
            OperationJournalState.EventAndProjectionCommitted,
            nextRevision,
            current.SourceHealth,
            current.CreatedAtUtc,
            updatedAtUtc);
    }

    private EncryptedOperationJournalPayload Protect(
        FileOperationIntent intent,
        DataKeyId keyId,
        ReadOnlySpan<byte> dataKey,
        OperationJournalState state,
        long revision,
        ReadOnlySpan<byte> commitFingerprint = default)
    {
        var plaintext = SerializeIntent(intent, commitFingerprint);
        try
        {
            return _protector.Protect(
                dataKey,
                plaintext,
                CreateContext(intent, keyId, state, revision));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async ValueTask<OperationJournalEntry> DecryptAsync(
        PersistedOperationJournalRow row,
        VaultKeyRingStore.VaultKeyRingSession keySession,
        CancellationToken cancellationToken) =>
        (await DecryptPayloadAsync(
            row,
            keySession,
            cancellationToken).ConfigureAwait(false)).Entry;

    private async ValueTask<DecryptedOperationJournalPayload> DecryptPayloadAsync(
        PersistedOperationJournalRow row,
        VaultKeyRingStore.VaultKeyRingSession keySession,
        CancellationToken cancellationToken)
    {
        return await keySession.ResolveDataKeyAsync(
            row.Owner,
            row.Envelope.KeyId,
            static () => throw new OperationJournalRecoveryRequiredException(),
            (keyId, dataKey, _) =>
            {
                if (keyId != row.Envelope.KeyId)
                {
                    throw new OperationJournalRecoveryRequiredException();
                }

                byte[]? plaintext = null;
                try
                {
                    plaintext = _protector.Unprotect(
                        dataKey.Span,
                        row.Envelope,
                        CreateContext(row, keyId));
                    var payload = DeserializePayload(plaintext);
                    var intent = payload.Intent;
                    if (intent.OperationId != row.OperationId
                        || intent.Owner != row.Owner
                        || intent.Kind != row.Kind)
                    {
                        throw new OperationJournalRecoveryRequiredException();
                    }

                    RequireCanonicalCommitFingerprint(
                        row.Kind,
                        row.State,
                        row.Revision,
                        payload.CommitFingerprint);
                    return ValueTask.FromResult(
                        new DecryptedOperationJournalPayload(
                            new OperationJournalEntry(
                                intent,
                                row.State,
                                row.Revision,
                                row.SourceHealth,
                                row.CreatedAtUtc,
                                row.UpdatedAtUtc),
                            payload.CommitFingerprint));
                }
                finally
                {
                    if (plaintext is not null)
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                    }
                }
            },
            cancellationToken).ConfigureAwait(false);
    }

    private static void RequireCanonicalCommitFingerprint(
        FileOperationKind kind,
        OperationJournalState state,
        long revision,
        byte[]? commitFingerprint)
    {
        var requiresFingerprint = state is
                OperationJournalState.EventAndProjectionCommitted
                or OperationJournalState.SideEffectsPending
                or OperationJournalState.Completed
            || state == OperationJournalState.ManualRecovery
                && revision > CommittedRevision(kind);
        if (requiresFingerprint != (commitFingerprint is not null))
        {
            throw new OperationJournalRecoveryRequiredException();
        }
    }

    private static long CommittedRevision(FileOperationKind kind) =>
        kind switch
        {
            FileOperationKind.SameVolumeMove
                or FileOperationKind.UndoSameVolumeMove => 5,
            FileOperationKind.CrossVolumeMove
                or FileOperationKind.UndoCrossVolumeMove => 8,
            _ => throw new OperationJournalRecoveryRequiredException(),
        };

    private static OperationJournalEncryptionContext CreateContext(
        FileOperationIntent intent,
        DataKeyId keyId,
        OperationJournalState state,
        long revision) =>
        new(
            EnvelopeVersion,
            keyId,
            intent.Owner,
            intent.OperationId,
            intent.Kind,
            state,
            revision,
            PayloadSchemaVersion);

    private static OperationJournalEncryptionContext CreateContext(
        PersistedOperationJournalRow row,
        DataKeyId keyId) =>
        new(
            row.Envelope.EnvelopeVersion,
            keyId,
            row.Owner,
            row.OperationId,
            row.Kind,
            row.State,
            row.Revision,
            row.PayloadSchemaVersion);

    private static async Task InsertAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        FileOperationIntent intent,
        DataKeyId keyId,
        EncryptedOperationJournalPayload envelope,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO main.operation_journal(
                operation_id, operation_kind, state, revision, source_health,
                owner_kind, owner_id, key_id, envelope_version,
                payload_schema_version, payload_nonce, payload_ciphertext,
                payload_tag, created_at_utc, updated_at_utc)
            VALUES(
                $operation_id, $operation_kind, $state, $revision, $source_health,
                $owner_kind, $owner_id, $key_id, $envelope_version,
                $payload_schema_version, $payload_nonce, $payload_ciphertext,
                $payload_tag, $created_at_utc, $updated_at_utc);
            """;
        command.Parameters.Add("$operation_id", SqliteType.Text).Value =
            intent.OperationId.Value.ToString("D");
        command.Parameters.Add("$operation_kind", SqliteType.Integer).Value =
            (int)intent.Kind;
        command.Parameters.Add("$state", SqliteType.Integer).Value =
            (int)OperationJournalState.IntentPersisted;
        command.Parameters.Add("$revision", SqliteType.Integer).Value = 1L;
        command.Parameters.Add("$source_health", SqliteType.Integer).Value =
            (int)OperationSourceHealth.Healthy;
        command.Parameters.Add("$owner_kind", SqliteType.Integer).Value =
            (int)intent.Owner.Kind;
        command.Parameters.Add("$owner_id", SqliteType.Text).Value =
            intent.Owner.Id.Value.ToString("D");
        command.Parameters.Add("$key_id", SqliteType.Text).Value =
            keyId.Value.ToString("D");
        command.Parameters.Add("$envelope_version", SqliteType.Integer).Value =
            envelope.EnvelopeVersion;
        command.Parameters.Add("$payload_schema_version", SqliteType.Integer).Value =
            PayloadSchemaVersion;
        command.Parameters.Add("$payload_nonce", SqliteType.Blob).Value =
            envelope.Nonce.ToArray();
        command.Parameters.Add("$payload_ciphertext", SqliteType.Blob).Value =
            envelope.Ciphertext.ToArray();
        command.Parameters.Add("$payload_tag", SqliteType.Blob).Value =
            envelope.Tag.ToArray();
        var timestamp = FormatTimestamp(now);
        command.Parameters.Add("$created_at_utc", SqliteType.Text).Value = timestamp;
        command.Parameters.Add("$updated_at_utc", SqliteType.Text).Value = timestamp;
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false)
            != 1)
        {
            throw new OperationJournalRecoveryRequiredException();
        }
    }

    private static async Task<int> UpdateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        TransitionOperationCommand transition,
        long nextRevision,
        EncryptedOperationJournalPayload envelope,
        DateTimeOffset updatedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE main.operation_journal
            SET state=$next_state,
                revision=$next_revision,
                source_health=$source_health,
                payload_nonce=$payload_nonce,
                payload_ciphertext=$payload_ciphertext,
                payload_tag=$payload_tag,
                updated_at_utc=$updated_at_utc
            WHERE operation_id=$operation_id
              AND revision=$expected_revision;
            """;
        command.Parameters.Add("$next_state", SqliteType.Integer).Value =
            (int)transition.NextState;
        command.Parameters.Add("$next_revision", SqliteType.Integer).Value =
            nextRevision;
        command.Parameters.Add("$source_health", SqliteType.Integer).Value =
            (int)transition.SourceHealth;
        command.Parameters.Add("$payload_nonce", SqliteType.Blob).Value =
            envelope.Nonce.ToArray();
        command.Parameters.Add("$payload_ciphertext", SqliteType.Blob).Value =
            envelope.Ciphertext.ToArray();
        command.Parameters.Add("$payload_tag", SqliteType.Blob).Value =
            envelope.Tag.ToArray();
        command.Parameters.Add("$updated_at_utc", SqliteType.Text).Value =
            FormatTimestamp(updatedAtUtc);
        command.Parameters.Add("$operation_id", SqliteType.Text).Value =
            transition.OperationId.Value.ToString("D");
        command.Parameters.Add("$expected_revision", SqliteType.Integer).Value =
            transition.ExpectedRevision;
        return await command.ExecuteNonQueryAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<PersistedOperationJournalRow?> ReadPersistedRowAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        OperationId operationId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT operation_id, operation_kind, state, revision, source_health,
                   owner_kind, owner_id, key_id, envelope_version,
                   payload_schema_version, payload_nonce, payload_ciphertext,
                   payload_tag, created_at_utc, updated_at_utc
            FROM main.operation_journal
            WHERE operation_id=$operation_id;
            """;
        command.Parameters.Add("$operation_id", SqliteType.Text).Value =
            operationId.Value.ToString("D");
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var row = ReadRow(reader);
        if (row.OperationId != operationId
            || await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        return row;
    }

    private static async Task<IReadOnlyList<PersistedOperationJournalRow>>
        ReadNonTerminalRowsAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT operation_id, operation_kind, state, revision, source_health,
                   owner_kind, owner_id, key_id, envelope_version,
                   payload_schema_version, payload_nonce, payload_ciphertext,
                   payload_tag, created_at_utc, updated_at_utc
            FROM main.operation_journal
            WHERE state NOT IN ($completed, $manual_recovery)
            ORDER BY created_at_utc, operation_id;
            """;
        command.Parameters.Add("$completed", SqliteType.Integer).Value =
            (int)OperationJournalState.Completed;
        command.Parameters.Add("$manual_recovery", SqliteType.Integer).Value =
            (int)OperationJournalState.ManualRecovery;
        var rows = new List<PersistedOperationJournalRow>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(ReadRow(reader));
        }

        return rows.AsReadOnly();
    }

    private static PersistedOperationJournalRow ReadRow(SqliteDataReader reader)
    {
        try
        {
            var operationId = new OperationId(SqliteEventStore.ParseCanonicalGuid(
                ReadText(reader, 0)));
            var kind = ReadEnum<FileOperationKind>(reader, 1);
            var state = ReadEnum<OperationJournalState>(reader, 2);
            var revision = ReadPositiveInt64(reader, 3);
            var sourceHealth = ReadEnum<OperationSourceHealth>(reader, 4);
            var owner = new SensitiveObjectRef(
                ReadEnum<SensitiveObjectKind>(reader, 5),
                new SensitiveObjectId(SqliteEventStore.ParseCanonicalGuid(
                    ReadText(reader, 6))));
            var keyId = new DataKeyId(SqliteEventStore.ParseCanonicalGuid(
                ReadText(reader, 7)));
            var envelopeVersion = ReadPositiveInt32(reader, 8);
            var payloadSchemaVersion = ReadPositiveInt32(reader, 9);
            var envelope = new EncryptedOperationJournalPayload(
                envelopeVersion,
                keyId,
                ReadBlob(reader, 10),
                ReadBlob(reader, 11),
                ReadBlob(reader, 12));
            var createdAtUtc = ParseTimestamp(ReadText(reader, 13));
            var updatedAtUtc = ParseTimestamp(ReadText(reader, 14));
            if (payloadSchemaVersion != PayloadSchemaVersion
                || updatedAtUtc < createdAtUtc)
            {
                throw new OperationJournalRecoveryRequiredException();
            }

            return new PersistedOperationJournalRow(
                operationId,
                kind,
                state,
                revision,
                sourceHealth,
                owner,
                payloadSchemaVersion,
                envelope,
                createdAtUtc,
                updatedAtUtc);
        }
        catch (OperationJournalRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or InvalidCastException
                or FormatException
                or OverflowException
                or IndexOutOfRangeException)
        {
            throw new OperationJournalRecoveryRequiredException(exception);
        }
    }

    private static async Task<long?> ReadRevisionAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        OperationId operationId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT revision
            FROM main.operation_journal
            WHERE operation_id=$operation_id;
            """;
        command.Parameters.Add("$operation_id", SqliteType.Text).Value =
            operationId.Value.ToString("D");
        var value = await command.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false);
        return value switch
        {
            null or DBNull => null,
            long revision when revision > 0 => revision,
            _ => throw new OperationJournalRecoveryRequiredException(),
        };
    }

    private static byte[] SerializeIntent(
        FileOperationIntent intent,
        ReadOnlySpan<byte> commitFingerprint = default)
    {
        if (!commitFingerprint.IsEmpty
            && commitFingerprint.Length != SHA256.HashSizeInBytes)
        {
            throw new ArgumentException(
                "The commit fingerprint must be a SHA-256 digest.",
                nameof(commitFingerprint));
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", PayloadSchemaVersion);
            writer.WriteString("operationId", intent.OperationId.Value);
            writer.WriteNumber("ownerKind", (int)intent.Owner.Kind);
            writer.WriteString("ownerId", intent.Owner.Id.Value);
            writer.WriteNumber("operationKind", (int)intent.Kind);
            writer.WriteString("sourcePath", intent.SourcePath);
            writer.WriteString("destinationPath", intent.DestinationPath);
            writer.WriteString("sourceRoot", intent.SourceRoot);
            writer.WriteString("destinationRoot", intent.DestinationRoot);
            writer.WriteString("streamId", intent.StreamId.Value);
            writer.WriteNumber(
                "expectedStreamVersion",
                intent.ExpectedStreamVersion.Value);
            writer.WriteBase64String(
                "approvedProposal",
                intent.ApprovedProposal.Span);
            if (!commitFingerprint.IsEmpty)
            {
                writer.WriteBase64String(
                    "commitFingerprint",
                    commitFingerprint);
            }

            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static DeserializedOperationJournalPayload DeserializePayload(
        ReadOnlyMemory<byte> payload)
    {
        try
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || root.GetProperty("schemaVersion").GetInt32()
                    != PayloadSchemaVersion)
            {
                throw new OperationJournalRecoveryRequiredException();
            }

            var intent = new FileOperationIntent(
                new OperationId(root.GetProperty("operationId").GetGuid()),
                new SensitiveObjectRef(
                    (SensitiveObjectKind)root.GetProperty("ownerKind").GetInt32(),
                    new SensitiveObjectId(root.GetProperty("ownerId").GetGuid())),
                (FileOperationKind)root.GetProperty("operationKind").GetInt32(),
                root.GetProperty("sourcePath").GetString()
                    ?? throw new OperationJournalRecoveryRequiredException(),
                root.GetProperty("destinationPath").GetString()
                    ?? throw new OperationJournalRecoveryRequiredException(),
                root.GetProperty("sourceRoot").GetString()
                    ?? throw new OperationJournalRecoveryRequiredException(),
                root.GetProperty("destinationRoot").GetString()
                    ?? throw new OperationJournalRecoveryRequiredException(),
                new StreamId(root.GetProperty("streamId").GetGuid()),
                new StreamVersion(
                    root.GetProperty("expectedStreamVersion").GetInt64()),
                root.GetProperty("approvedProposal").GetBytesFromBase64());
            byte[]? commitFingerprint = null;
            if (root.TryGetProperty("commitFingerprint", out var fingerprintElement))
            {
                commitFingerprint = fingerprintElement.GetBytesFromBase64();
                if (commitFingerprint.Length != SHA256.HashSizeInBytes)
                {
                    throw new OperationJournalRecoveryRequiredException();
                }
            }

            return new DeserializedOperationJournalPayload(
                intent,
                commitFingerprint);
        }
        catch (OperationJournalRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or FormatException
                or InvalidOperationException
                or JsonException
                or KeyNotFoundException
                or OverflowException)
        {
            throw new OperationJournalRecoveryRequiredException(exception);
        }
    }

    private DateTimeOffset NextTimestamp(DateTimeOffset previous)
    {
        var now = _timeProvider.GetUtcNow().ToUniversalTime();
        return now > previous ? now : previous.AddTicks(1);
    }

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTimestamp(string value)
    {
        if (!DateTimeOffset.TryParseExact(
                value,
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var parsed)
            || parsed.Offset != TimeSpan.Zero
            || !string.Equals(
                value,
                parsed.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
                StringComparison.Ordinal))
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        return parsed;
    }

    private static string ReadText(SqliteDataReader reader, int ordinal) =>
        reader.GetValue(ordinal) is string value
            ? value
            : throw new OperationJournalRecoveryRequiredException();

    private static byte[] ReadBlob(SqliteDataReader reader, int ordinal) =>
        reader.GetValue(ordinal) is byte[] value
            ? value
            : throw new OperationJournalRecoveryRequiredException();

    private static long ReadPositiveInt64(SqliteDataReader reader, int ordinal) =>
        reader.GetValue(ordinal) is long value && value > 0
            ? value
            : throw new OperationJournalRecoveryRequiredException();

    private static int ReadPositiveInt32(SqliteDataReader reader, int ordinal)
    {
        var value = ReadPositiveInt64(reader, ordinal);
        return value <= int.MaxValue
            ? (int)value
            : throw new OperationJournalRecoveryRequiredException();
    }

    private static TEnum ReadEnum<TEnum>(
        SqliteDataReader reader,
        int ordinal)
        where TEnum : struct, Enum
    {
        if (reader.GetValue(ordinal) is not long value
            || value < int.MinValue
            || value > int.MaxValue
            || !Enum.IsDefined((TEnum)(object)(int)value))
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        return (TEnum)(object)(int)value;
    }

    private static void ValidateOperationId(OperationId operationId)
    {
        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation ID cannot be empty.",
                nameof(operationId));
        }
    }

    private static bool IsRecoveryFailure(Exception exception) =>
        exception is VaultRecoveryRequiredException
            or VaultKeyRingException
            or OperationJournalPayloadAuthenticationException
            or SqliteException;

    private static VaultKeyRingStore CreateDefaultKeyRing(string connectionString)
    {
        var canonical =
            SqliteEventStoreSchema.CanonicalizeConnectionString(connectionString);
        var source = new SqliteConnectionStringBuilder(canonical).DataSource;
        if (string.IsNullOrWhiteSpace(source)
            || string.Equals(source, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Encrypted Journal storage requires a file-backed data source.",
                nameof(connectionString));
        }

        return new VaultKeyRingStore(source + ".keyring");
    }

    private sealed record PersistedOperationJournalRow(
        OperationId OperationId,
        FileOperationKind Kind,
        OperationJournalState State,
        long Revision,
        OperationSourceHealth SourceHealth,
        SensitiveObjectRef Owner,
        int PayloadSchemaVersion,
        EncryptedOperationJournalPayload Envelope,
        DateTimeOffset CreatedAtUtc,
        DateTimeOffset UpdatedAtUtc);

    internal sealed record OperationJournalCommitCandidate(
        OperationJournalEntry Entry,
        DataKeyId KeyId,
        byte[]? CommitFingerprint);

    private sealed record DecryptedOperationJournalPayload(
        OperationJournalEntry Entry,
        byte[]? CommitFingerprint);

    private sealed record DeserializedOperationJournalPayload(
        FileOperationIntent Intent,
        byte[]? CommitFingerprint);
}
