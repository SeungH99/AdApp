using System.ComponentModel;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Core.Transactions;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public enum FileOperationFailure
{
    UnsupportedOperation = 0,
    IntentConflict = 1,
    JournalConflict = 2,
    DestinationExists = 3,
    DifferentVolume = 4,
    PathRejected = 5,
    SourceChanged = 6,
    AccessDenied = 7,
    SharingViolation = 8,
    NativeFailure = 9,
    IdentityMismatch = 10,
    CommitConflict = 11,
    CommitStorageBusy = 12,
    UnexpectedJournalState = 13,
    SideEffectDeliveryPending = 14,
}

public sealed record FileOperationExecutionRequest
{
    public FileOperationExecutionRequest(
        FileOperationIntent intent,
        DataKeyId dataKeyId,
        AppendEventsCommand appendEvents,
        IEnumerable<FileOperationSideEffect> sideEffects,
        FileOperationUsage? usage,
        StableFileIdentity? expectedSourceIdentity = null)
    {
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(appendEvents);
        ArgumentNullException.ThrowIfNull(sideEffects);
        if (dataKeyId.Value == Guid.Empty)
            throw new ArgumentException(
                "A data-key ID is required.",
                nameof(dataKeyId));
        if (appendEvents.OperationId != intent.OperationId
            || appendEvents.StreamId != intent.StreamId
            || appendEvents.ExpectedVersion != intent.ExpectedStreamVersion)
        {
            throw new ArgumentException(
                "The event append must match the file operation intent.",
                nameof(appendEvents));
        }
        var isUndo = intent.Kind is
            FileOperationKind.UndoSameVolumeMove
            or FileOperationKind.UndoCrossVolumeMove;
        if (isUndo != (expectedSourceIdentity is not null))
        {
            throw new ArgumentException(
                "Undo execution requires an expected source identity and ordinary execution forbids it.",
                nameof(expectedSourceIdentity));
        }

        var snapshot = sideEffects.ToArray();
        if (snapshot.Any(sideEffect => sideEffect is null))
            throw new ArgumentException(
                "Side effects cannot contain null entries.",
                nameof(sideEffects));

        Intent = intent;
        DataKeyId = dataKeyId;
        AppendEvents = appendEvents;
        SideEffects = Array.AsReadOnly(snapshot);
        Usage = usage;
        RecoveryRecipe = new OperationRecoveryRecipe(
            dataKeyId,
            appendEvents,
            snapshot,
            usage,
            expectedSourceIdentity);
    }

    public FileOperationIntent Intent { get; }

    public DataKeyId DataKeyId { get; }

    public AppendEventsCommand AppendEvents { get; }

    public IReadOnlyList<FileOperationSideEffect> SideEffects { get; }

    public FileOperationUsage? Usage { get; }

    public OperationRecoveryRecipe RecoveryRecipe { get; }
}

public abstract record FileOperationExecutionResult
{
    private protected FileOperationExecutionResult()
    {
    }
}

public sealed record FileOperationSucceeded(
    CommitFileOperationResult CommitResult,
    StableFileIdentity Identity)
    : FileOperationExecutionResult;

public sealed record FileOperationNotApplied(
    FileOperationFailure Failure,
    OperationJournalState? DurableState)
    : FileOperationExecutionResult;

public sealed record FileOperationRecoveryRequired(
    FileOperationFailure Failure,
    OperationJournalState DurableState)
    : FileOperationExecutionResult;

public sealed record FileOperationUnexpectedFailure
    : FileOperationExecutionResult;

public interface IFileOperationExecutor
{
    OperationRecoveryReadiness Readiness { get; }

    Task<FileOperationExecutionResult> ExecuteAsync(
        FileOperationExecutionRequest request,
        CancellationToken cancellationToken);
}

public sealed class FileOperationCoordinator :
    IFileOperationExecutor,
    IOperationRecoveryExecutor
{
    private readonly IOperationJournalStore _journal;
    private readonly FileMutationGate _mutationGate;
    private readonly VaultFileFingerprintService _fingerprints;
    private readonly SameVolumeFileTransaction _sameVolume;
    private readonly CrossVolumeFileTransaction _crossVolume;
    private readonly IOperationCommitStore _commitStore;
    private readonly IOperationSideEffectDispatcher?
        _sideEffectDispatcher;
    private readonly IFileOperationFaultInjector _faults;
    private readonly OperationRecoveryCoordinator _liveRecovery;
    private readonly OperationRecoveryReadiness _readiness;

    public FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        IOperationCommitStore commitStore,
        OperationRecoveryReadiness readiness)
        : this(
            journal,
            mutationGate,
            fingerprints,
            sameVolume,
            new CrossVolumeFileTransaction(),
            commitStore,
            sideEffectDispatcher: null,
            NoOpFileOperationFaultInjector.Instance,
            readiness)
    {
    }

    public FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        IOperationCommitStore commitStore,
        IOperationSideEffectDispatcher sideEffectDispatcher,
        OperationRecoveryReadiness readiness)
        : this(
            journal,
            mutationGate,
            fingerprints,
            sameVolume,
            new CrossVolumeFileTransaction(),
            commitStore,
            sideEffectDispatcher,
            NoOpFileOperationFaultInjector.Instance,
            readiness)
    {
    }

    internal FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        IOperationCommitStore commitStore,
        IFileOperationFaultInjector faultInjector,
        OperationRecoveryReadiness readiness)
        : this(
            journal,
            mutationGate,
            fingerprints,
            sameVolume,
            new CrossVolumeFileTransaction(),
            commitStore,
            sideEffectDispatcher: null,
            faultInjector,
            readiness)
    {
    }

    internal FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        IOperationCommitStore commitStore,
        IOperationSideEffectDispatcher sideEffectDispatcher,
        IFileOperationFaultInjector faultInjector,
        OperationRecoveryReadiness readiness)
        : this(
            journal,
            mutationGate,
            fingerprints,
            sameVolume,
            new CrossVolumeFileTransaction(),
            commitStore,
            sideEffectDispatcher,
            faultInjector,
            readiness)
    {
    }

    internal FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        CrossVolumeFileTransaction crossVolume,
        IOperationCommitStore commitStore,
        IFileOperationFaultInjector faultInjector,
        OperationRecoveryReadiness readiness)
        : this(
            journal,
            mutationGate,
            fingerprints,
            sameVolume,
            crossVolume,
            commitStore,
            sideEffectDispatcher: null,
            faultInjector,
            readiness)
    {
    }

    internal FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        CrossVolumeFileTransaction crossVolume,
        IOperationCommitStore commitStore,
        IOperationSideEffectDispatcher? sideEffectDispatcher,
        IFileOperationFaultInjector faultInjector,
        OperationRecoveryReadiness readiness)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(mutationGate);
        ArgumentNullException.ThrowIfNull(fingerprints);
        ArgumentNullException.ThrowIfNull(sameVolume);
        ArgumentNullException.ThrowIfNull(crossVolume);
        ArgumentNullException.ThrowIfNull(commitStore);
        ArgumentNullException.ThrowIfNull(faultInjector);
        ArgumentNullException.ThrowIfNull(readiness);
        _journal = journal;
        _mutationGate = mutationGate;
        _fingerprints = fingerprints;
        _sameVolume = sameVolume;
        _crossVolume = crossVolume;
        _commitStore = commitStore;
        _sideEffectDispatcher = sideEffectDispatcher;
        _faults = faultInjector;
        _readiness = readiness;
        _liveRecovery = new OperationRecoveryCoordinator(
            journal,
            mutationGate,
            new HandleSafeOperationRecoveryObserver(fingerprints),
            this,
            readiness);
    }

    public OperationRecoveryReadiness Readiness => _readiness;

    public async Task<FileOperationExecutionResult> ExecuteAsync(
        FileOperationExecutionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _readiness.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        if (request.Intent.Kind is not (
                FileOperationKind.SameVolumeMove
                or FileOperationKind.UndoSameVolumeMove
                or FileOperationKind.CrossVolumeMove
                or FileOperationKind.UndoCrossVolumeMove))
        {
            return new FileOperationNotApplied(
                FileOperationFailure.UnsupportedOperation,
                DurableState: null);
        }

        var persisted = await _journal
            .PersistIntentAsync(
                request.Intent,
                request.RecoveryRecipe,
                cancellationToken)
            .ConfigureAwait(false);
        _faults.ThrowIfRequested(
            FileOperationFaultPoint.AfterIntentPersist);
        if (persisted.Status == PersistOperationIntentStatus.Conflict)
        {
            return new FileOperationNotApplied(
                FileOperationFailure.IntentConflict,
                DurableState: null);
        }

        var current = persisted.Entry;
        if (current is null)
        {
            return new FileOperationNotApplied(
                FileOperationFailure.JournalConflict,
                DurableState: null);
        }

        await using var writer = await _mutationGate
            .AcquireAsync(CancellationToken.None)
            .ConfigureAwait(false);
        var durableState = current.State;
        try
        {
            current = await _journal
                .GetAsync(
                    request.Intent.OperationId,
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (current is null
                || !SqliteOperationJournalStore.IntentsEqual(
                    current.Intent,
                    request.Intent)
                || !request.RecoveryRecipe.ExactEquals(
                    current.RecoveryRecipe))
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.JournalConflict,
                    durableState);
            }

            durableState = current.State;
            if (current.State == OperationJournalState.Completed)
            {
                return await FinalizeCommitWithinGateAsync(
                        current,
                        request.RecoveryRecipe,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (IsCrossVolume(current.Kind)
                && current.State
                    == OperationJournalState.IntentPersisted)
            {
                var crossIdentityProvider =
                    new NtfsFileIdentityProvider(
                    new ApprovedRootPathGuard(
                        request.Intent.SourceRoot));
                var crossSource =
                    crossIdentityProvider.OpenVerifiedSource(
                    request.Intent.SourcePath);
                await using var crossObservation =
                    new OperationRecoveryObservationScope(
                        RecoveryPathObservation.Exact,
                        RecoveryPathObservation.Missing,
                        crossSource);
                return await ResumeCrossVolumeWithinGateAsync(
                        current,
                        request.RecoveryRecipe,
                        crossObservation,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (current.Kind is
                    FileOperationKind.UndoSameVolumeMove
                    or FileOperationKind.CrossVolumeMove
                    or FileOperationKind.UndoCrossVolumeMove)
            {
                return await _liveRecovery.RecoverWithinGateAsync(
                        current,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (current.State is
                OperationJournalState.FileApplied
                or OperationJournalState.EventAndProjectionCommitted
                or OperationJournalState.SideEffectsPending)
            {
                return await _liveRecovery.RecoverWithinGateAsync(
                        current,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (current.State != OperationJournalState.IntentPersisted)
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.UnexpectedJournalState,
                    current.State);
            }

            var identityProvider = new NtfsFileIdentityProvider(
                new ApprovedRootPathGuard(request.Intent.SourceRoot));
            var source = identityProvider.OpenVerifiedSource(
                request.Intent.SourcePath);
            await using var observation =
                new OperationRecoveryObservationScope(
                    RecoveryPathObservation.Exact,
                    RecoveryPathObservation.Missing,
                    source);
            return await ResumeRenameWithinGateAsync(
                    current,
                    request.RecoveryRecipe,
                    observation,
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (StableSourceBoundaryException exception)
        {
            if (exception.Failure
                    == StableSourceBoundaryFailure.MultipleHardLinks
                && current is not null)
            {
                return await _liveRecovery.RecoverWithinGateAsync(
                        current,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }

            durableState = await ReloadDurableStateAsync(
                    request.Intent.OperationId,
                    durableState)
                .ConfigureAwait(false);
            return CreateFileSystemFailureResult(
                MapSourceFailure(exception),
                durableState);
        }
        catch (FileSystemBoundaryException exception)
        {
            durableState = await ReloadDurableStateAsync(
                    request.Intent.OperationId,
                    durableState)
                .ConfigureAwait(false);
            return CreateFileSystemFailureResult(
                MapBoundaryFailure(exception),
                durableState);
        }
        catch (OperationJournalRecoveryRequiredException)
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                durableState);
        }
        catch (UnauthorizedAccessException)
        {
            durableState = await ReloadDurableStateAsync(
                    request.Intent.OperationId,
                    durableState)
                .ConfigureAwait(false);
            return CreateFileSystemFailureResult(
                FileOperationFailure.AccessDenied,
                durableState);
        }
        catch (IOException exception)
        {
            durableState = await ReloadDurableStateAsync(
                    request.Intent.OperationId,
                    durableState)
                .ConfigureAwait(false);
            return CreateFileSystemFailureResult(
                MapBoundaryFailure(exception),
                durableState);
        }
    }

    async Task<FileOperationExecutionResult>
        IOperationRecoveryExecutor.ResumeRenameWithinGateAsync(
            OperationJournalEntry entry,
            OperationRecoveryRecipe recipe,
            OperationRecoveryObservationScope observation,
            CancellationToken cancellationToken) =>
        await ResumeRenameWithinGateAsync(
            entry,
            recipe,
            observation,
            cancellationToken).ConfigureAwait(false);

    internal async Task<FileOperationExecutionResult> ResumeRenameWithinGateAsync(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        OperationRecoveryObservationScope observation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(recipe);
        ArgumentNullException.ThrowIfNull(observation);
        cancellationToken.ThrowIfCancellationRequested();
        if (!RecipeMatches(entry, recipe)
            || observation.Source != RecoveryPathObservation.Exact
            || observation.ExactSource is null
            || entry.State is not (
                OperationJournalState.IntentPersisted
                or OperationJournalState.IdentityLocked
                or OperationJournalState.Renaming))
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                entry.State);
        }

        var current = entry;
        var lockedIdentity = current.Identity;
        if (current.State == OperationJournalState.IntentPersisted)
        {
            lockedIdentity = await _fingerprints.CaptureAsync(
                    current.Owner,
                    recipe.DataKeyId,
                    observation.ExactSource,
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (recipe.ExpectedSourceIdentity is { } expectedIdentity
                && !IdentitiesEqual(expectedIdentity, lockedIdentity))
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.IdentityMismatch,
                    current.State);
            }
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterSourceIdentityCapture);
            current = await TransitionAsync(
                    current,
                    OperationJournalState.IdentityLocked,
                    lockedIdentity)
                .ConfigureAwait(false)
                ?? throw new OperationJournalRecoveryRequiredException();
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterIdentityLocked);
        }

        if (lockedIdentity is null)
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                current.State);
        }

        if (current.State == OperationJournalState.IdentityLocked)
        {
            current = await TransitionAsync(
                    current,
                    OperationJournalState.Renaming)
                .ConfigureAwait(false)
                ?? throw new OperationJournalRecoveryRequiredException();
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterRenaming);
        }

        var renamed = await _sameVolume.RenameNoReplaceAsync(
                observation.ExactSource,
                lockedIdentity,
                current.Intent,
                _faults,
                CancellationToken.None)
            .ConfigureAwait(false);
        if (renamed is SameVolumeFileNotApplied notApplied)
        {
            return new FileOperationNotApplied(
                MapFailure(notApplied.Failure),
                OperationJournalState.Renaming);
        }

        if (renamed is SameVolumeFileVerificationRequired verification)
        {
            return new FileOperationRecoveryRequired(
                MapFailure(verification.Failure),
                OperationJournalState.Renaming);
        }

        var verifiedIdentity = await _fingerprints.CaptureAsync(
                current.Owner,
                recipe.DataKeyId,
                observation.ExactSource,
                CancellationToken.None)
            .ConfigureAwait(false);
        if (!IdentitiesEqual(lockedIdentity, verifiedIdentity))
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.IdentityMismatch,
                OperationJournalState.Renaming);
        }

        current = await TransitionAsync(
                current,
                OperationJournalState.FileApplied)
            .ConfigureAwait(false)
            ?? throw new OperationJournalRecoveryRequiredException();
        _faults.ThrowIfRequested(
            FileOperationFaultPoint.AfterFileApplied);
        return await CommitExactAsync(
                current,
                recipe,
                verifiedIdentity,
                OperationJournalState.FileApplied,
                sourceAbsenceGuard: null,
                observation.ExactSource.RequireSingleLink)
            .ConfigureAwait(false);
    }

    async Task<FileOperationExecutionResult>
        IOperationRecoveryExecutor.ResumeCrossVolumeWithinGateAsync(
            OperationJournalEntry entry,
            OperationRecoveryRecipe recipe,
            OperationRecoveryObservationScope observation,
            CancellationToken cancellationToken) =>
        await ResumeCrossVolumeWithinGateAsync(
            entry,
            recipe,
            observation,
            cancellationToken).ConfigureAwait(false);

    internal async Task<FileOperationExecutionResult>
        ResumeCrossVolumeWithinGateAsync(
            OperationJournalEntry entry,
            OperationRecoveryRecipe recipe,
            OperationRecoveryObservationScope observation,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(recipe);
        ArgumentNullException.ThrowIfNull(observation);
        cancellationToken.ThrowIfCancellationRequested();
        if (!RecipeMatches(entry, recipe)
            || entry.Kind is not (
                FileOperationKind.CrossVolumeMove
                or FileOperationKind.UndoCrossVolumeMove)
            || observation.Source != RecoveryPathObservation.Exact
            || observation.ExactSource is null
            || entry.State is not (
                OperationJournalState.IntentPersisted
                or OperationJournalState.IdentityLocked
                or OperationJournalState.Copying
                or OperationJournalState.Copied
                or OperationJournalState.Verified))
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                entry.State);
        }

        var current = entry;
        var lockedIdentity = current.Identity;
        if (current.State == OperationJournalState.IntentPersisted)
        {
            lockedIdentity = await _fingerprints.CaptureAsync(
                    current.Owner,
                    recipe.DataKeyId,
                    observation.ExactSource,
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (recipe.ExpectedSourceIdentity is { } expectedIdentity
                && !IdentitiesEqual(expectedIdentity, lockedIdentity))
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.IdentityMismatch,
                    current.State);
            }

            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterSourceIdentityCapture);
            current = await TransitionAsync(
                    current,
                    OperationJournalState.IdentityLocked,
                    lockedIdentity)
                .ConfigureAwait(false)
                ?? throw new OperationJournalRecoveryRequiredException();
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterIdentityLocked);
        }

        if (lockedIdentity is null)
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                current.State);
        }

        CrossVolumeFileSession? session = null;
        try
        {
            if (current.State == OperationJournalState.IdentityLocked)
            {
                current = await TransitionAsync(
                        current,
                        OperationJournalState.Copying)
                    .ConfigureAwait(false)
                    ?? throw new OperationJournalRecoveryRequiredException();
                _faults.ThrowIfRequested(
                    FileOperationFaultPoint.AfterCrossVolumeCopying);
            }

            if (current.State == OperationJournalState.Copying)
            {
                if (observation.Destination
                    != RecoveryPathObservation.Missing)
                {
                    return new FileOperationRecoveryRequired(
                        FileOperationFailure.DestinationExists,
                        current.State);
                }

                session = await _crossVolume.CreateNewAsync(
                        observation.ExactSource,
                        lockedIdentity,
                        current.Intent,
                        _faults,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                await session.CopyFlushAndMetadataAsync(
                        CancellationToken.None)
                    .ConfigureAwait(false);
                current = await TransitionAsync(
                        current,
                        OperationJournalState.Copied)
                    .ConfigureAwait(false)
                    ?? throw new OperationJournalRecoveryRequiredException();
                _faults.ThrowIfRequested(
                    FileOperationFaultPoint.AfterCrossVolumeCopied);
            }

            if (current.State == OperationJournalState.Copied)
            {
                if (session is null)
                {
                    if (observation.Destination
                        == RecoveryPathObservation.Missing)
                    {
                        session = await _crossVolume.CreateNewAsync(
                                observation.ExactSource,
                                lockedIdentity,
                                current.Intent,
                                _faults,
                                CancellationToken.None)
                            .ConfigureAwait(false);
                        await session.CopyFlushAndMetadataAsync(
                                CancellationToken.None)
                            .ConfigureAwait(false);
                    }
                    else if (observation is
                        {
                            Destination: RecoveryPathObservation.Exact,
                            ExactDestination: not null,
                        })
                    {
                        session = await _crossVolume.OpenExistingAsync(
                                observation.ExactSource,
                                observation.ExactDestination,
                                lockedIdentity,
                                current.Intent,
                                _faults,
                                CancellationToken.None)
                            .ConfigureAwait(false);
                    }
                    else
                    {
                        return new FileOperationRecoveryRequired(
                            FileOperationFailure.DestinationExists,
                            current.State);
                    }
                }

                var appliedIdentity =
                    await session.VerifyDestinationAsync(
                            (source, token) => _fingerprints.CaptureAsync(
                                current.Owner,
                                recipe.DataKeyId,
                                source,
                                token),
                            CancellationToken.None)
                        .ConfigureAwait(false);
                current = await TransitionAsync(
                        current,
                        OperationJournalState.Verified,
                        appliedIdentity: appliedIdentity)
                    .ConfigureAwait(false)
                    ?? throw new OperationJournalRecoveryRequiredException();
                _faults.ThrowIfRequested(
                    FileOperationFaultPoint.AfterCrossVolumeVerified);
            }

            if (current.State != OperationJournalState.Verified
                || current.AppliedIdentity is null)
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.JournalConflict,
                    current.State);
            }

            if (session is null)
            {
                if (observation is not
                    {
                        Destination: RecoveryPathObservation.Exact,
                        ExactDestination: not null,
                    })
                {
                    return new FileOperationRecoveryRequired(
                        FileOperationFailure.IdentityMismatch,
                        current.State);
                }

                session = await _crossVolume.OpenExistingAsync(
                        observation.ExactSource,
                        observation.ExactDestination,
                        lockedIdentity,
                        current.Intent,
                        _faults,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }

            current = await TransitionAsync(
                    current,
                    OperationJournalState.DeletingSource)
                .ConfigureAwait(false)
                ?? throw new OperationJournalRecoveryRequiredException();
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterCrossVolumeDeletingSource);
            await session.RevalidateAndDeleteSourceAsync(
                    lockedIdentity,
                    (source, token) => _fingerprints.CaptureAsync(
                        current.Owner,
                        recipe.DataKeyId,
                        source,
                        token),
                    CancellationToken.None)
                .ConfigureAwait(false);
            var verifiedAppliedIdentity = current.AppliedIdentity
                ?? throw new OperationJournalRecoveryRequiredException();
            current = await TransitionAsync(
                    current,
                    OperationJournalState.FileApplied)
                .ConfigureAwait(false)
                ?? throw new OperationJournalRecoveryRequiredException();
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterFileApplied);
            return await CommitExactAsync(
                    current,
                    recipe,
                    verifiedAppliedIdentity,
                    current.State,
                    sourceAbsenceGuard: null,
                    session.RequireSingleLinkDestination)
                .ConfigureAwait(false);
        }
        catch (CrossVolumeFileTransactionException exception)
        {
            return await HandleCrossVolumeFailureAsync(
                    current,
                    session,
                    exception)
                .ConfigureAwait(false);
        }
        catch
        {
            if (session is not null
                && current.State < OperationJournalState.Verified)
            {
                var cleanup =
                    await session.CleanupIncompleteDestinationAsync()
                        .ConfigureAwait(false);
                if (cleanup
                    != CrossVolumeCleanupResult
                        .DeletedCreatedDestination)
                {
                    await EnterCrossVolumeManualRecoveryAsync(
                            current,
                            RecoveryPathObservation.Exact,
                            RecoveryPathObservation
                                .InaccessibleOrUnknown)
                        .ConfigureAwait(false);
                    return new FileOperationRecoveryRequired(
                        FileOperationFailure.NativeFailure,
                        OperationJournalState.ManualRecovery);
                }
            }

            throw;
        }
        finally
        {
            if (session is not null)
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    async Task<FileOperationExecutionResult>
        IOperationRecoveryExecutor.FinalizeCommitWithinGateAsync(
            OperationJournalEntry entry,
            OperationRecoveryRecipe recipe,
            OperationRecoveryObservationScope observation,
            CancellationToken cancellationToken) =>
        await FinalizeCommitWithinGateCoreAsync(
            entry,
            recipe,
            observation,
            cancellationToken).ConfigureAwait(false);

    internal async Task<FileOperationExecutionResult> FinalizeCommitWithinGateAsync(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        CancellationToken cancellationToken) =>
        await FinalizeCommitWithinGateCoreAsync(
                entry,
                recipe,
                observation: null,
                cancellationToken)
            .ConfigureAwait(false);

    private async Task<FileOperationExecutionResult>
        FinalizeCommitWithinGateCoreAsync(
            OperationJournalEntry entry,
            OperationRecoveryRecipe recipe,
            OperationRecoveryObservationScope? observation,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(recipe);
        cancellationToken.ThrowIfCancellationRequested();
        if (!RecipeMatches(entry, recipe)
            || entry.Identity is null
            || IsCrossVolume(entry.Kind)
                && entry.AppliedIdentity is null
            || observation is not null
                && (observation.Source
                        != RecoveryPathObservation.Missing
                    || observation.SourceAbsenceGuard is null
                    || observation.Destination
                        != RecoveryPathObservation.Exact
                    || observation.ExactDestination is null))
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                entry.State);
        }

        var identity = AppliedIdentity(entry)
            ?? throw new OperationJournalRecoveryRequiredException();
        var current = entry;
        if (observation is not null
            && !observation.SourceAbsenceGuard!
                .IsStillSafelyAbsent())
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.IdentityMismatch,
                current.State);
        }

        if (current.State is
                OperationJournalState.Renaming
                or OperationJournalState.DeletingSource)
        {
            current = await TransitionAsync(
                    current,
                    OperationJournalState.FileApplied)
                .ConfigureAwait(false)
                ?? throw new OperationJournalRecoveryRequiredException();
        }

        if (current.State is not (
                OperationJournalState.FileApplied
                or OperationJournalState.EventAndProjectionCommitted
                or OperationJournalState.SideEffectsPending
                or OperationJournalState.Completed))
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.UnexpectedJournalState,
                current.State);
        }

        return await CommitExactAsync(
                current,
                recipe,
                identity,
                current.State,
                observation?.SourceAbsenceGuard,
                observation?.ExactDestination is { } exactDestination
                    ? exactDestination.RequireSingleLink
                    : null)
            .ConfigureAwait(false);
    }

    private async Task<FileOperationExecutionResult> CommitExactAsync(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        StableFileIdentity identity,
        OperationJournalState durableState,
        ISourceAbsenceGuard? sourceAbsenceGuard,
        Action? destinationBoundaryGuard)
    {
        destinationBoundaryGuard?.Invoke();
        if (sourceAbsenceGuard is not null)
        {
            _faults.ThrowIfRequested(
                FileOperationFaultPoint
                    .BeforeFinalizeSourceAbsenceRevalidation);
            if (!sourceAbsenceGuard.IsStillSafelyAbsent())
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.IdentityMismatch,
                    durableState);
            }
        }

        var commit = new CommitFileOperationCommand(
            entry.OperationId,
            expectedJournalRevision: FileAppliedRevision(entry.Kind),
            recipe.AppendEvents,
            recipe.SideEffects,
            recipe.Usage);
        var committed = await _commitStore
            .CommitAppliedAsync(commit, CancellationToken.None)
            .ConfigureAwait(false);
        if (committed is not (OperationCommitted or AlreadyCommitted))
        {
            return committed switch
            {
                OperationCommitConflict =>
                new FileOperationRecoveryRequired(
                    FileOperationFailure.CommitConflict,
                    durableState),
                OperationCommitStorageBusy =>
                new FileOperationRecoveryRequired(
                    FileOperationFailure.CommitStorageBusy,
                    durableState),
                _ => new FileOperationRecoveryRequired(
                    FileOperationFailure.NativeFailure,
                    durableState),
            };
        }

        var current = await _journal.GetAsync(
                entry.OperationId,
                CancellationToken.None)
            .ConfigureAwait(false);
        if (current is null
            || !RecipeMatches(current, recipe)
            || current.Identity is null
            || IsCrossVolume(current.Kind)
                && current.AppliedIdentity is null)
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                durableState);
        }

        if (current.State == OperationJournalState.EventAndProjectionCommitted)
        {
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterEventAndProjectionCommitted);
            current = await TransitionAsync(
                    current,
                    OperationJournalState.SideEffectsPending)
                .ConfigureAwait(false);
            if (current?.State
                == OperationJournalState.SideEffectsPending)
            {
                _faults.ThrowIfRequested(
                    FileOperationFaultPoint.AfterSideEffectsPending);
            }
        }

        if (current?.State == OperationJournalState.SideEffectsPending)
        {
            if (recipe.SideEffects.Count > 0)
            {
                if (_sideEffectDispatcher is null)
                {
                    return new FileOperationRecoveryRequired(
                        FileOperationFailure.SideEffectDeliveryPending,
                        current.State);
                }

                var delivery =
                    await _sideEffectDispatcher.DispatchPendingAsync(
                            current.OperationId,
                            recipe.SideEffects,
                            CancellationToken.None)
                        .ConfigureAwait(false);
                if (delivery
                    != OperationSideEffectDispatchStatus.Delivered)
                {
                    return new FileOperationRecoveryRequired(
                        FileOperationFailure.SideEffectDeliveryPending,
                        current.State);
                }
            }

            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterSideEffectsDelivered);
            destinationBoundaryGuard?.Invoke();
            if (sourceAbsenceGuard is not null
                && !sourceAbsenceGuard.IsStillSafelyAbsent())
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.IdentityMismatch,
                    current.State);
            }

            current = await TransitionAsync(
                    current,
                    OperationJournalState.Completed)
                .ConfigureAwait(false);
        }

        return current?.State == OperationJournalState.Completed
            ? new FileOperationSucceeded(committed, identity)
            : new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                current?.State ?? durableState);
    }

    private static bool RecipeMatches(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe) =>
        recipe.ExactEquals(entry.RecoveryRecipe)
        && recipe.AppendEvents.OperationId == entry.OperationId
        && recipe.AppendEvents.StreamId == entry.Intent.StreamId
        && recipe.AppendEvents.ExpectedVersion
            == entry.Intent.ExpectedStreamVersion;

    private async Task<OperationJournalEntry?> TransitionAsync(
        OperationJournalEntry current,
        OperationJournalState next,
        StableFileIdentity? identity = null,
        StableFileIdentity? appliedIdentity = null)
    {
        var result = await _journal
            .TransitionAsync(
                new TransitionOperationCommand(
                    current.OperationId,
                    current.Revision,
                    next,
                    OperationSourceHealth.Healthy,
                    identity: identity,
                    appliedIdentity: appliedIdentity),
                CancellationToken.None)
            .ConfigureAwait(false);
        return result.Status is (
                TransitionOperationStatus.Transitioned
                or TransitionOperationStatus.AlreadyApplied)
            && result.Entry?.State == next
                ? result.Entry
                : null;
    }

    private static bool IdentitiesEqual(
        StableFileIdentity left,
        StableFileIdentity right) =>
        left.FixedTimeEquals(right);

    private async Task<FileOperationExecutionResult>
        HandleCrossVolumeFailureAsync(
            OperationJournalEntry current,
            CrossVolumeFileSession? session,
            CrossVolumeFileTransactionException exception)
    {
        if (current.State < OperationJournalState.Verified)
        {
            var cleanup = session is null
                ? exception.PostCreateCleanupResult
                : await session.CleanupIncompleteDestinationAsync()
                    .ConfigureAwait(false);
            if (cleanup == CrossVolumeCleanupResult.Uncertain
                || (session is not null
                    && cleanup
                        != CrossVolumeCleanupResult
                            .DeletedCreatedDestination))
            {
                await EnterCrossVolumeManualRecoveryAsync(
                        current,
                        RecoveryPathObservation.Exact,
                        RecoveryPathObservation
                            .InaccessibleOrUnknown)
                    .ConfigureAwait(false);
                return new FileOperationRecoveryRequired(
                    MapFailure(exception.Failure),
                    OperationJournalState.ManualRecovery);
            }

            return new FileOperationNotApplied(
                MapFailure(exception.Failure),
                current.State);
        }

        await EnterCrossVolumeManualRecoveryAsync(
                current,
                RecoveryPathObservation.Exact,
                RecoveryPathObservation.Exact)
            .ConfigureAwait(false);
        return new FileOperationRecoveryRequired(
            MapFailure(exception.Failure),
            OperationJournalState.ManualRecovery);
    }

    private async Task EnterCrossVolumeManualRecoveryAsync(
        OperationJournalEntry current,
        RecoveryPathObservation source,
        RecoveryPathObservation destination)
    {
        var transition = await _journal.TransitionAsync(
                new TransitionOperationCommand(
                    current.OperationId,
                    current.Revision,
                    OperationJournalState.ManualRecovery,
                    OperationSourceHealth.ManualRecovery,
                    manualRecoveryEvidence:
                        new OperationManualRecoveryEvidence(
                            current.State,
                            source,
                            destination,
                            OperationManualRecoveryReason
                                .AmbiguousPathObservations,
                            OperationManualRecoveryAction
                                .InspectBothPathsWithoutMutation)),
                CancellationToken.None)
            .ConfigureAwait(false);
        if (transition.Status is not (
                TransitionOperationStatus.Transitioned
                or TransitionOperationStatus.AlreadyApplied)
            || transition.Entry?.State
                != OperationJournalState.ManualRecovery)
        {
            throw new OperationJournalRecoveryRequiredException();
        }
    }

    private static StableFileIdentity? AppliedIdentity(
        OperationJournalEntry entry) =>
        IsCrossVolume(entry.Kind)
            ? entry.AppliedIdentity
            : entry.Identity;

    private static bool IsCrossVolume(FileOperationKind kind) =>
        kind is
            FileOperationKind.CrossVolumeMove
            or FileOperationKind.UndoCrossVolumeMove;

    private static long FileAppliedRevision(FileOperationKind kind) =>
        IsCrossVolume(kind) ? 7 : 4;

    private static FileOperationFailure MapFailure(
        SameVolumeFileFailure failure) =>
        failure switch
        {
            SameVolumeFileFailure.DestinationExists =>
                FileOperationFailure.DestinationExists,
            SameVolumeFileFailure.DifferentVolume =>
                FileOperationFailure.DifferentVolume,
            SameVolumeFileFailure.PathRejected =>
                FileOperationFailure.PathRejected,
            SameVolumeFileFailure.SourceChanged =>
                FileOperationFailure.SourceChanged,
            SameVolumeFileFailure.AccessDenied =>
                FileOperationFailure.AccessDenied,
            SameVolumeFileFailure.SharingViolation =>
                FileOperationFailure.SharingViolation,
            _ => FileOperationFailure.NativeFailure,
        };

    private static FileOperationFailure MapFailure(
        CrossVolumeFileFailure failure) =>
        failure switch
        {
            CrossVolumeFileFailure.DestinationExists =>
                FileOperationFailure.DestinationExists,
            CrossVolumeFileFailure.SameVolume =>
                FileOperationFailure.DifferentVolume,
            CrossVolumeFileFailure.PathRejected =>
                FileOperationFailure.PathRejected,
            CrossVolumeFileFailure.SourceIdentityChanged =>
                FileOperationFailure.SourceChanged,
            CrossVolumeFileFailure.LengthMismatch
                or CrossVolumeFileFailure.FingerprintMismatch =>
                FileOperationFailure.IdentityMismatch,
            _ => FileOperationFailure.NativeFailure,
        };

    private static FileOperationFailure MapBoundaryFailure(
        Exception exception)
    {
        for (Exception? current = exception;
             current is not null;
             current = current.InnerException)
        {
            if (current is not Win32Exception native)
                continue;
            return native.NativeErrorCode switch
            {
                5 => FileOperationFailure.AccessDenied,
                32 or 33 => FileOperationFailure.SharingViolation,
                _ => FileOperationFailure.NativeFailure,
            };
        }

        return FileOperationFailure.PathRejected;
    }

    private static FileOperationFailure MapSourceFailure(
        StableSourceBoundaryException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        for (Exception? current = exception.InnerException;
             current is not null;
             current = current.InnerException)
        {
            if (current is not Win32Exception native)
                continue;
            return native.NativeErrorCode switch
            {
                5 => FileOperationFailure.AccessDenied,
                32 or 33 => FileOperationFailure.SharingViolation,
                50 when exception.Failure
                    == StableSourceBoundaryFailure.UnsupportedVolume =>
                    FileOperationFailure.PathRejected,
                _ => FileOperationFailure.NativeFailure,
            };
        }

        return FileOperationFailure.PathRejected;
    }

    private static FileOperationExecutionResult CreateFileSystemFailureResult(
        FileOperationFailure failure,
        OperationJournalState durableState) =>
        durableState is OperationJournalState.Renaming
            or OperationJournalState.Verified
            or OperationJournalState.DeletingSource
            or OperationJournalState.FileApplied
            or OperationJournalState.EventAndProjectionCommitted
            or OperationJournalState.SideEffectsPending
            or OperationJournalState.ManualRecovery
            ? new FileOperationRecoveryRequired(failure, durableState)
            : new FileOperationNotApplied(failure, durableState);

    private async Task<OperationJournalState> ReloadDurableStateAsync(
        OperationId operationId,
        OperationJournalState fallback)
    {
        try
        {
            return (await _journal.GetAsync(
                        operationId,
                        CancellationToken.None)
                    .ConfigureAwait(false))
                ?.State
                ?? fallback;
        }
        catch
        {
            return fallback;
        }
    }
}
