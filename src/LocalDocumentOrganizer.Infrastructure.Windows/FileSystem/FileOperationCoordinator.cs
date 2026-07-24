using System.ComponentModel;
using System.Security.Cryptography;
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
}

public sealed record FileOperationExecutionRequest
{
    public FileOperationExecutionRequest(
        FileOperationIntent intent,
        DataKeyId dataKeyId,
        AppendEventsCommand appendEvents,
        IEnumerable<FileOperationSideEffect> sideEffects,
        FileOperationUsage? usage)
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
            usage);
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
    private readonly IOperationCommitStore _commitStore;
    private readonly IFileOperationFaultInjector _faults;

    public FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        IOperationCommitStore commitStore)
        : this(
            journal,
            mutationGate,
            fingerprints,
            sameVolume,
            commitStore,
            NoOpFileOperationFaultInjector.Instance)
    {
    }

    internal FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        IOperationCommitStore commitStore,
        IFileOperationFaultInjector faultInjector)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(mutationGate);
        ArgumentNullException.ThrowIfNull(fingerprints);
        ArgumentNullException.ThrowIfNull(sameVolume);
        ArgumentNullException.ThrowIfNull(commitStore);
        ArgumentNullException.ThrowIfNull(faultInjector);
        _journal = journal;
        _mutationGate = mutationGate;
        _fingerprints = fingerprints;
        _sameVolume = sameVolume;
        _commitStore = commitStore;
        _faults = faultInjector;
    }

    public async Task<FileOperationExecutionResult> ExecuteAsync(
        FileOperationExecutionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Intent.Kind != FileOperationKind.SameVolumeMove)
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
            if (current.State is
                OperationJournalState.FileApplied
                or OperationJournalState.EventAndProjectionCommitted
                or OperationJournalState.SideEffectsPending
                or OperationJournalState.Completed)
            {
                return await FinalizeCommitWithinGateAsync(
                        current,
                        request.RecoveryRecipe,
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
                OperationJournalState.FileApplied)
            .ConfigureAwait(false);
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
            || observation is not null
                && (observation.Destination
                        != RecoveryPathObservation.Exact
                    || observation.ExactDestination is null))
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                entry.State);
        }

        var identity = entry.Identity
            ?? throw new OperationJournalRecoveryRequiredException();
        var current = entry;
        if (current.State == OperationJournalState.Renaming)
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
                current.State)
            .ConfigureAwait(false);
    }

    private async Task<FileOperationExecutionResult> CommitExactAsync(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        StableFileIdentity identity,
        OperationJournalState durableState)
    {
        var commit = new CommitFileOperationCommand(
            entry.OperationId,
            expectedJournalRevision: 4,
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
            || current.Identity is null)
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
        StableFileIdentity? identity = null)
    {
        var result = await _journal
            .TransitionAsync(
                new TransitionOperationCommand(
                    current.OperationId,
                    current.Revision,
                    next,
                    OperationSourceHealth.Healthy,
                    identity),
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
        left.Length == right.Length
        && left.LastWriteTimeUtc == right.LastWriteTimeUtc
        && CryptographicOperations.FixedTimeEquals(
            left.VolumeId,
            right.VolumeId)
        && CryptographicOperations.FixedTimeEquals(
            left.FileId,
            right.FileId)
        && CryptographicOperations.FixedTimeEquals(
            left.KeyedFingerprint,
            right.KeyedFingerprint);

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
            or OperationJournalState.FileApplied
            or OperationJournalState.EventAndProjectionCommitted
            or OperationJournalState.SideEffectsPending
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
