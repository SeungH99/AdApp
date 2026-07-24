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

    Task<PersistOperationIntentResult> PersistIntentAsync(
        FileOperationIntent intent,
        OperationRecoveryRecipe recoveryRecipe,
        CancellationToken cancellationToken) =>
        PersistIntentAsync(intent, cancellationToken);

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
        OperationSourceHealth sourceHealth,
        StableFileIdentity? identity = null,
        OperationManualRecoveryEvidence? manualRecoveryEvidence = null)
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
        if (nextState == OperationJournalState.IdentityLocked
            && identity is null)
        {
            throw new ArgumentException(
                "The identity-lock transition requires stable file identity.",
                nameof(identity));
        }
        if (nextState != OperationJournalState.IdentityLocked
            && identity is not null)
        {
            throw new ArgumentException(
                "Stable file identity is accepted only at the identity-lock transition.",
                nameof(identity));
        }
        if (nextState != OperationJournalState.ManualRecovery
            && manualRecoveryEvidence is not null)
        {
            throw new ArgumentException(
                "Manual-recovery evidence is accepted only for a manual-recovery transition.",
                nameof(manualRecoveryEvidence));
        }

        OperationId = operationId;
        ExpectedRevision = expectedRevision;
        NextState = nextState;
        SourceHealth = sourceHealth;
        Identity = identity is null ? null : SnapshotIdentity(identity);
        HasExplicitManualRecoveryEvidence =
            manualRecoveryEvidence is not null;
        ManualRecoveryEvidence = nextState == OperationJournalState.ManualRecovery
            ? manualRecoveryEvidence
                ?? CreateUnspecifiedEvidence(
                    OperationJournalState.IntentPersisted)
            : null;
    }

    public OperationId OperationId { get; }

    public long ExpectedRevision { get; }

    public OperationJournalState NextState { get; }

    public OperationSourceHealth SourceHealth { get; }

    public StableFileIdentity? Identity { get; }

    public OperationManualRecoveryEvidence? ManualRecoveryEvidence { get; }

    internal bool HasExplicitManualRecoveryEvidence { get; }

    private static StableFileIdentity SnapshotIdentity(
        StableFileIdentity identity) =>
        new(
            identity.VolumeId,
            identity.FileId,
            identity.Length,
            identity.LastWriteTimeUtc,
            identity.KeyedFingerprint);

    internal static OperationManualRecoveryEvidence CreateUnspecifiedEvidence(
        OperationJournalState observedState) =>
        new(
            observedState,
            RecoveryPathObservation.InaccessibleOrUnknown,
            RecoveryPathObservation.InaccessibleOrUnknown,
            OperationManualRecoveryReason.UnspecifiedRecoveryBoundary,
            OperationManualRecoveryAction.InspectBothPathsWithoutMutation);
}

public sealed class OperationJournalEntry : IEquatable<OperationJournalEntry>
{
    internal OperationJournalEntry(
        FileOperationIntent intent,
        OperationJournalState state,
        long revision,
        OperationSourceHealth sourceHealth,
        StableFileIdentity? identity,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc)
        : this(
            intent,
            state,
            revision,
            sourceHealth,
            identity,
            createdAtUtc,
            updatedAtUtc,
            recoveryRecipe: null)
    {
    }

    internal OperationJournalEntry(
        FileOperationIntent intent,
        OperationJournalState state,
        long revision,
        OperationSourceHealth sourceHealth,
        StableFileIdentity? identity,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc,
        OperationRecoveryRecipe? recoveryRecipe)
        : this(
            intent,
            state,
            revision,
            sourceHealth,
            identity,
            createdAtUtc,
            updatedAtUtc,
            recoveryRecipe,
            manualRecoveryEvidence: null)
    {
    }

    internal OperationJournalEntry(
        FileOperationIntent intent,
        OperationJournalState state,
        long revision,
        OperationSourceHealth sourceHealth,
        StableFileIdentity? identity,
        DateTimeOffset createdAtUtc,
        DateTimeOffset updatedAtUtc,
        OperationRecoveryRecipe? recoveryRecipe,
        OperationManualRecoveryEvidence? manualRecoveryEvidence)
    {
        Intent = intent;
        State = state;
        Revision = revision;
        SourceHealth = sourceHealth;
        Identity = identity is null
            ? null
            : new StableFileIdentity(
                identity.VolumeId,
                identity.FileId,
                identity.Length,
                identity.LastWriteTimeUtc,
                identity.KeyedFingerprint);
        CreatedAtUtc = createdAtUtc;
        UpdatedAtUtc = updatedAtUtc;
        RecoveryRecipe = recoveryRecipe;
        ManualRecoveryEvidence = manualRecoveryEvidence;
    }

    public FileOperationIntent Intent { get; }

    public OperationId OperationId => Intent.OperationId;

    public SensitiveObjectRef Owner => Intent.Owner;

    public FileOperationKind Kind => Intent.Kind;

    public OperationJournalState State { get; }

    public long Revision { get; }

    public OperationSourceHealth SourceHealth { get; }

    public StableFileIdentity? Identity { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public DateTimeOffset UpdatedAtUtc { get; }

    public OperationRecoveryRecipe? RecoveryRecipe { get; }

    public OperationManualRecoveryEvidence? ManualRecoveryEvidence { get; }

    public bool Equals(OperationJournalEntry? other) =>
        other is not null
        && SqliteOperationJournalStore.IntentsEqual(Intent, other.Intent)
        && State == other.State
        && Revision == other.Revision
        && SourceHealth == other.SourceHealth
        && IdentitiesEqual(Identity, other.Identity)
        && RecipesEqual(RecoveryRecipe, other.RecoveryRecipe)
        && ManualRecoveryEvidence == other.ManualRecoveryEvidence
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

    private static bool IdentitiesEqual(
        StableFileIdentity? left,
        StableFileIdentity? right) =>
        ReferenceEquals(left, right)
        || left is not null
        && left.FixedTimeEquals(right);

    private static bool RecipesEqual(
        OperationRecoveryRecipe? left,
        OperationRecoveryRecipe? right) =>
        ReferenceEquals(left, right)
        || left is not null
        && left.ExactEquals(right);
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
        CancellationToken cancellationToken) =>
        await PersistIntentCoreAsync(
            intent,
            recoveryRecipe: null,
            requireExactRecipe: false,
            cancellationToken).ConfigureAwait(false);

    public async Task<PersistOperationIntentResult> PersistIntentAsync(
        FileOperationIntent intent,
        OperationRecoveryRecipe recoveryRecipe,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recoveryRecipe);
        return await PersistIntentCoreAsync(
            intent,
            recoveryRecipe,
            requireExactRecipe: true,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<PersistOperationIntentResult> PersistIntentCoreAsync(
        FileOperationIntent intent,
        OperationRecoveryRecipe? recoveryRecipe,
        bool requireExactRecipe,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(intent);
        if (recoveryRecipe is not null
            && (recoveryRecipe.AppendEvents.OperationId != intent.OperationId
                || recoveryRecipe.AppendEvents.StreamId != intent.StreamId
                || recoveryRecipe.AppendEvents.ExpectedVersion
                    != intent.ExpectedStreamVersion))
        {
            throw new ArgumentException(
                "The recovery recipe must match the operation intent.",
                nameof(recoveryRecipe));
        }

        var isUndo = intent.Kind is
            FileOperationKind.UndoSameVolumeMove
            or FileOperationKind.UndoCrossVolumeMove;
        if (isUndo != (recoveryRecipe?.ExpectedSourceIdentity is not null))
        {
            throw new ArgumentException(
                "Undo recovery requires an expected source identity and ordinary recovery forbids it.",
                nameof(recoveryRecipe));
        }

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
                    && (!requireExactRecipe
                        || recoveryRecipe!.ExactEquals(
                            existingEntry.RecoveryRecipe))
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
                        revision: 1,
                        identity: null,
                        recoveryRecipe: recoveryRecipe,
                        manualRecoveryEvidence: null);
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
                        identity: null,
                        now,
                        now,
                        recoveryRecipe);
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
                if (command.NextState == OperationJournalState.IdentityLocked
                    && !IdentitiesEqual(current.Identity, command.Identity))
                {
                    throw new OperationJournalRecoveryRequiredException();
                }
                if (command.NextState == OperationJournalState.ManualRecovery
                    && command.HasExplicitManualRecoveryEvidence
                    && current.ManualRecoveryEvidence
                        != command.ManualRecoveryEvidence)
                {
                    throw new OperationJournalRecoveryRequiredException();
                }

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
            var nextIdentity =
                command.NextState == OperationJournalState.IdentityLocked
                    ? command.Identity
                    : current.Identity;
            var nextManualRecoveryEvidence =
                command.NextState == OperationJournalState.ManualRecovery
                    ? command.HasExplicitManualRecoveryEvidence
                        ? command.ManualRecoveryEvidence
                        : TransitionOperationCommand
                            .CreateUnspecifiedEvidence(current.State)
                    : current.ManualRecoveryEvidence;
            RequireCanonicalIdentity(
                command.NextState,
                nextRevision,
                nextIdentity);
            RequireCanonicalManualRecoveryEvidence(
                command.NextState,
                nextManualRecoveryEvidence);
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
                        nextIdentity,
                        current.RecoveryRecipe,
                        nextManualRecoveryEvidence,
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
                nextIdentity,
                row.CreatedAtUtc,
                updatedAtUtc,
                current.RecoveryRecipe,
                nextManualRecoveryEvidence);
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
        && left.OriginalOperationId == right.OriginalOperationId
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
                    current.Identity,
                    current.RecoveryRecipe,
                    current.ManualRecoveryEvidence,
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
            current.Identity,
            current.CreatedAtUtc,
            updatedAtUtc,
            current.RecoveryRecipe,
            current.ManualRecoveryEvidence);
    }

    private EncryptedOperationJournalPayload Protect(
        FileOperationIntent intent,
        DataKeyId keyId,
        ReadOnlySpan<byte> dataKey,
        OperationJournalState state,
        long revision,
        StableFileIdentity? identity,
        OperationRecoveryRecipe? recoveryRecipe,
        OperationManualRecoveryEvidence? manualRecoveryEvidence,
        ReadOnlySpan<byte> commitFingerprint = default)
    {
        RequireCanonicalIdentity(state, revision, identity);
        RequireCanonicalManualRecoveryEvidence(
            state,
            manualRecoveryEvidence);
        var plaintext = SerializeIntent(
            intent,
            identity,
            recoveryRecipe,
            manualRecoveryEvidence,
            commitFingerprint);
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
                    RequireCanonicalIdentity(
                        row.State,
                        row.Revision,
                        payload.Identity);
                    RequireCanonicalManualRecoveryEvidence(
                        row.State,
                        payload.ManualRecoveryEvidence);
                    return ValueTask.FromResult(
                        new DecryptedOperationJournalPayload(
                            new OperationJournalEntry(
                                intent,
                                row.State,
                                row.Revision,
                                row.SourceHealth,
                                payload.Identity,
                                row.CreatedAtUtc,
                                row.UpdatedAtUtc,
                                payload.RecoveryRecipe,
                                payload.ManualRecoveryEvidence),
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

    private static void RequireCanonicalIdentity(
        OperationJournalState state,
        long revision,
        StableFileIdentity? identity)
    {
        if (state == OperationJournalState.IntentPersisted)
        {
            if (identity is not null)
                throw new OperationJournalRecoveryRequiredException();
            return;
        }

        if (state == OperationJournalState.ManualRecovery)
        {
            if (revision < 2
                || (revision == 2) != (identity is null))
            {
                throw new OperationJournalRecoveryRequiredException();
            }
            return;
        }
        if (identity is null)
            throw new OperationJournalRecoveryRequiredException();
    }

    private static void RequireCanonicalManualRecoveryEvidence(
        OperationJournalState state,
        OperationManualRecoveryEvidence? evidence)
    {
        if ((state == OperationJournalState.ManualRecovery)
            != (evidence is not null))
        {
            throw new OperationJournalRecoveryRequiredException();
        }
    }

    private static bool IdentitiesEqual(
        StableFileIdentity? left,
        StableFileIdentity? right) =>
        ReferenceEquals(left, right)
        || left is not null
        && left.FixedTimeEquals(right);

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
        StableFileIdentity? identity,
        OperationRecoveryRecipe? recoveryRecipe,
        OperationManualRecoveryEvidence? manualRecoveryEvidence,
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
            if (intent.OriginalOperationId is not null)
            {
                writer.WriteString(
                    "originalOperationId",
                    intent.OriginalOperationId.Value.Value);
            }
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
            if (recoveryRecipe is not null)
            {
                WriteRecoveryRecipe(writer, recoveryRecipe);
            }

            if (identity is not null)
            {
                writer.WriteStartObject("identity");
                writer.WriteBase64String(
                    "volumeId",
                    identity.VolumeId);
                writer.WriteBase64String(
                    "fileId",
                    identity.FileId);
                writer.WriteNumber("length", identity.Length);
                writer.WriteString(
                    "lastWriteTimeUtc",
                    FormatTimestamp(identity.LastWriteTimeUtc));
                writer.WriteBase64String(
                    "keyedFingerprint",
                    identity.KeyedFingerprint);
                writer.WriteEndObject();
            }

            if (manualRecoveryEvidence is not null)
            {
                writer.WriteStartObject("manualRecoveryEvidence");
                writer.WriteNumber(
                    "observedState",
                    (int)manualRecoveryEvidence.ObservedState);
                writer.WriteNumber(
                    "sourceObservation",
                    (int)manualRecoveryEvidence.SourceObservation);
                writer.WriteNumber(
                    "destinationObservation",
                    (int)manualRecoveryEvidence.DestinationObservation);
                writer.WriteNumber(
                    "reason",
                    (int)manualRecoveryEvidence.Reason);
                writer.WriteNumber(
                    "recommendedAction",
                    (int)manualRecoveryEvidence.RecommendedAction);
                writer.WriteEndObject();
            }

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

    private static void WriteRecoveryRecipe(
        Utf8JsonWriter writer,
        OperationRecoveryRecipe recipe)
    {
        writer.WriteStartObject("recoveryRecipe");
        writer.WriteString("dataKeyId", recipe.DataKeyId.Value);
        if (recipe.ExpectedSourceIdentity is not null)
        {
            WriteStableIdentity(
                writer,
                "expectedSourceIdentity",
                recipe.ExpectedSourceIdentity);
        }
        writer.WriteStartObject("appendEvents");
        writer.WriteString("streamId", recipe.AppendEvents.StreamId.Value);
        writer.WriteNumber(
            "expectedVersion",
            recipe.AppendEvents.ExpectedVersion.Value);
        writer.WriteString(
            "operationId",
            recipe.AppendEvents.OperationId.Value);
        writer.WriteStartArray("events");
        foreach (var eventToAppend in recipe.AppendEvents.Events)
        {
            writer.WriteStartObject();
            writer.WriteString("eventId", eventToAppend.EventId.Value);
            writer.WriteString("eventType", eventToAppend.EventType);
            writer.WriteNumber("schemaVersion", eventToAppend.SchemaVersion);
            writer.WriteBase64String("payload", eventToAppend.Payload.Span);
            switch (eventToAppend.Protection)
            {
                case PayloadProtection.DurableStructural:
                    writer.WriteNumber("protectionKind", 0);
                    break;
                case PayloadProtection.Shreddable shreddable:
                    writer.WriteNumber("protectionKind", 1);
                    writer.WriteNumber(
                        "protectionOwnerKind",
                        (int)shreddable.Owner.Kind);
                    writer.WriteString(
                        "protectionOwnerId",
                        shreddable.Owner.Id.Value);
                    break;
                default:
                    throw new OperationJournalRecoveryRequiredException();
            }

            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteStartArray("sideEffects");
        foreach (var sideEffect in recipe.SideEffects)
        {
            writer.WriteStartObject();
            writer.WriteString("code", sideEffect.Code);
            writer.WriteBase64String("data", sideEffect.Data.Span);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        if (recipe.Usage is not null)
        {
            writer.WriteStartObject("usage");
            writer.WriteString("code", recipe.Usage.Code);
            writer.WriteNumber("units", recipe.Usage.Units);
            writer.WriteEndObject();
        }

        writer.WriteEndObject();
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

            RequireCanonicalObject(
                root,
                "schemaVersion",
                "operationId",
                "ownerKind",
                "ownerId",
                "operationKind",
                root.TryGetProperty("originalOperationId", out _)
                    ? "originalOperationId"
                    : null,
                "sourcePath",
                "destinationPath",
                "sourceRoot",
                "destinationRoot",
                "streamId",
                "expectedStreamVersion",
                "approvedProposal",
                root.TryGetProperty("recoveryRecipe", out _)
                    ? "recoveryRecipe"
                    : null,
                root.TryGetProperty("identity", out _)
                    ? "identity"
                    : null,
                root.TryGetProperty("manualRecoveryEvidence", out _)
                    ? "manualRecoveryEvidence"
                    : null,
                root.TryGetProperty("commitFingerprint", out _)
                    ? "commitFingerprint"
                    : null);

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
                root.GetProperty("approvedProposal").GetBytesFromBase64(),
                root.TryGetProperty(
                    "originalOperationId",
                    out var originalOperationIdElement)
                    ? new OperationId(originalOperationIdElement.GetGuid())
                    : null);
            OperationRecoveryRecipe? recoveryRecipe = null;
            if (root.TryGetProperty(
                    "recoveryRecipe",
                    out var recoveryRecipeElement))
            {
                try
                {
                    if (root.EnumerateObject().Count(
                            property => property.NameEquals(
                                "recoveryRecipe")) != 1)
                    {
                        throw new OperationJournalRecoveryRequiredException();
                    }

                    recoveryRecipe = DeserializeRecoveryRecipe(
                        recoveryRecipeElement);
                    if (recoveryRecipe.AppendEvents.OperationId
                            != intent.OperationId
                        || recoveryRecipe.AppendEvents.StreamId
                            != intent.StreamId
                        || recoveryRecipe.AppendEvents.ExpectedVersion
                            != intent.ExpectedStreamVersion
                        || IsUndo(intent.Kind)
                            != (recoveryRecipe.ExpectedSourceIdentity
                                is not null))
                    {
                        throw new OperationJournalRecoveryRequiredException();
                    }
                }
                catch (OperationJournalRecoveryRequiredException)
                {
                    recoveryRecipe = null;
                }
                catch (Exception exception) when (
                    exception is ArgumentException
                        or FormatException
                        or InvalidOperationException
                        or KeyNotFoundException
                        or OverflowException)
                {
                    recoveryRecipe = null;
                }
            }

            byte[]? commitFingerprint = null;
            if (root.TryGetProperty("commitFingerprint", out var fingerprintElement))
            {
                commitFingerprint = fingerprintElement.GetBytesFromBase64();
                if (commitFingerprint.Length != SHA256.HashSizeInBytes)
                {
                    throw new OperationJournalRecoveryRequiredException();
                }
            }

            StableFileIdentity? identity = null;
            if (root.TryGetProperty("identity", out var identityElement))
            {
                if (identityElement.ValueKind != JsonValueKind.Object)
                    throw new OperationJournalRecoveryRequiredException();
                identity = DeserializeStableIdentity(identityElement);
            }

            OperationManualRecoveryEvidence? manualRecoveryEvidence = null;
            if (root.TryGetProperty(
                    "manualRecoveryEvidence",
                    out var manualRecoveryElement))
            {
                RequireCanonicalObject(
                    manualRecoveryElement,
                    "observedState",
                    "sourceObservation",
                    "destinationObservation",
                    "reason",
                    "recommendedAction");

                manualRecoveryEvidence = new OperationManualRecoveryEvidence(
                    (OperationJournalState)manualRecoveryElement
                        .GetProperty("observedState")
                        .GetInt32(),
                    (RecoveryPathObservation)manualRecoveryElement
                        .GetProperty("sourceObservation")
                        .GetInt32(),
                    (RecoveryPathObservation)manualRecoveryElement
                        .GetProperty("destinationObservation")
                        .GetInt32(),
                    (OperationManualRecoveryReason)manualRecoveryElement
                        .GetProperty("reason")
                        .GetInt32(),
                    (OperationManualRecoveryAction)manualRecoveryElement
                        .GetProperty("recommendedAction")
                        .GetInt32());
            }

            return new DeserializedOperationJournalPayload(
                intent,
                identity,
                recoveryRecipe,
                manualRecoveryEvidence,
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

    private static OperationRecoveryRecipe DeserializeRecoveryRecipe(
        JsonElement element)
    {
        RequireCanonicalObject(
            element,
            "dataKeyId",
            element.TryGetProperty("expectedSourceIdentity", out _)
                ? "expectedSourceIdentity"
                : null,
            "appendEvents",
            "sideEffects",
            element.TryGetProperty("usage", out _)
                ? "usage"
                : null);

        var appendElement = element.GetProperty("appendEvents");
        RequireCanonicalObject(
            appendElement,
            "streamId",
            "expectedVersion",
            "operationId",
            "events");
        var eventsElement = appendElement.GetProperty("events");
        if (eventsElement.ValueKind != JsonValueKind.Array)
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        var events = new List<EventToAppend>();
        foreach (var eventElement in eventsElement.EnumerateArray())
        {
            var protectionKind = eventElement
                .GetProperty("protectionKind")
                .GetInt32();
            RequireCanonicalObject(
                eventElement,
                "eventId",
                "eventType",
                "schemaVersion",
                "payload",
                "protectionKind",
                protectionKind == 1 ? "protectionOwnerKind" : null,
                protectionKind == 1 ? "protectionOwnerId" : null);
            PayloadProtection protection = protectionKind switch
            {
                0 => new PayloadProtection.DurableStructural(),
                1 => new PayloadProtection.Shreddable(
                    new SensitiveObjectRef(
                        (SensitiveObjectKind)eventElement
                            .GetProperty("protectionOwnerKind")
                            .GetInt32(),
                        new SensitiveObjectId(eventElement
                            .GetProperty("protectionOwnerId")
                            .GetGuid()))),
                _ => throw new OperationJournalRecoveryRequiredException(),
            };
            events.Add(new EventToAppend(
                new EventId(eventElement.GetProperty("eventId").GetGuid()),
                eventElement.GetProperty("eventType").GetString()
                    ?? throw new OperationJournalRecoveryRequiredException(),
                eventElement.GetProperty("schemaVersion").GetInt32(),
                eventElement.GetProperty("payload").GetBytesFromBase64(),
                protection));
        }

        var sideEffectsElement = element.GetProperty("sideEffects");
        if (sideEffectsElement.ValueKind != JsonValueKind.Array)
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        var sideEffects = sideEffectsElement
            .EnumerateArray()
            .Select(sideEffect =>
            {
                RequireCanonicalObject(sideEffect, "code", "data");
                return new FileOperationSideEffect(
                    sideEffect.GetProperty("code").GetString()
                        ?? throw new OperationJournalRecoveryRequiredException(),
                    sideEffect.GetProperty("data").GetBytesFromBase64());
            })
            .ToArray();
        FileOperationUsage? usage = null;
        if (element.TryGetProperty("usage", out var usageElement))
        {
            RequireCanonicalObject(usageElement, "code", "units");

            usage = new FileOperationUsage(
                usageElement.GetProperty("code").GetString()
                    ?? throw new OperationJournalRecoveryRequiredException(),
                usageElement.GetProperty("units").GetInt64());
        }

        StableFileIdentity? expectedSourceIdentity = null;
        if (element.TryGetProperty(
                "expectedSourceIdentity",
                out var expectedSourceIdentityElement))
        {
            expectedSourceIdentity = DeserializeStableIdentity(
                expectedSourceIdentityElement);
        }

        return new OperationRecoveryRecipe(
            new DataKeyId(element.GetProperty("dataKeyId").GetGuid()),
            new AppendEventsCommand(
                new StreamId(appendElement.GetProperty("streamId").GetGuid()),
                new StreamVersion(
                    appendElement.GetProperty("expectedVersion").GetInt64()),
                new OperationId(
                    appendElement.GetProperty("operationId").GetGuid()),
                events),
            sideEffects,
            usage,
            expectedSourceIdentity);
    }

    private static void WriteStableIdentity(
        Utf8JsonWriter writer,
        string propertyName,
        StableFileIdentity identity)
    {
        writer.WriteStartObject(propertyName);
        writer.WriteBase64String("volumeId", identity.VolumeId);
        writer.WriteBase64String("fileId", identity.FileId);
        writer.WriteNumber("length", identity.Length);
        writer.WriteString(
            "lastWriteTimeUtc",
            FormatTimestamp(identity.LastWriteTimeUtc));
        writer.WriteBase64String(
            "keyedFingerprint",
            identity.KeyedFingerprint);
        writer.WriteEndObject();
    }

    private static StableFileIdentity DeserializeStableIdentity(
        JsonElement element)
    {
        RequireCanonicalObject(
            element,
            "volumeId",
            "fileId",
            "length",
            "lastWriteTimeUtc",
            "keyedFingerprint");
        return new StableFileIdentity(
            element.GetProperty("volumeId").GetBytesFromBase64(),
            element.GetProperty("fileId").GetBytesFromBase64(),
            element.GetProperty("length").GetInt64(),
            ParseTimestamp(
                element.GetProperty("lastWriteTimeUtc").GetString()
                ?? throw new OperationJournalRecoveryRequiredException()),
            element.GetProperty("keyedFingerprint").GetBytesFromBase64());
    }

    private static bool IsUndo(FileOperationKind kind) =>
        kind is
            FileOperationKind.UndoSameVolumeMove
            or FileOperationKind.UndoCrossVolumeMove;

    private static void RequireCanonicalObject(
        JsonElement element,
        params string?[] expectedPropertyNames)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        var expected = expectedPropertyNames
            .Where(name => name is not null)
            .ToArray();
        var properties = element.EnumerateObject().ToArray();
        if (properties.Length != expected.Length)
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        for (var index = 0; index < expected.Length; index++)
        {
            if (!string.Equals(
                    properties[index].Name,
                    expected[index],
                    StringComparison.Ordinal))
            {
                throw new OperationJournalRecoveryRequiredException();
            }
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
        StableFileIdentity? Identity,
        OperationRecoveryRecipe? RecoveryRecipe,
        OperationManualRecoveryEvidence? ManualRecoveryEvidence,
        byte[]? CommitFingerprint);
}
