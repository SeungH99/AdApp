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
    }

    public FileOperationIntent Intent { get; }

    public DataKeyId DataKeyId { get; }

    public AppendEventsCommand AppendEvents { get; }

    public IReadOnlyList<FileOperationSideEffect> SideEffects { get; }

    public FileOperationUsage? Usage { get; }
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

public sealed class FileOperationCoordinator : IFileOperationExecutor
{
    private readonly IOperationJournalStore _journal;
    private readonly FileMutationGate _mutationGate;
    private readonly VaultFileFingerprintService _fingerprints;
    private readonly SameVolumeFileTransaction _sameVolume;
    private readonly IOperationCommitStore _commitStore;

    public FileOperationCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        VaultFileFingerprintService fingerprints,
        SameVolumeFileTransaction sameVolume,
        IOperationCommitStore commitStore)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(mutationGate);
        ArgumentNullException.ThrowIfNull(fingerprints);
        ArgumentNullException.ThrowIfNull(sameVolume);
        ArgumentNullException.ThrowIfNull(commitStore);
        _journal = journal;
        _mutationGate = mutationGate;
        _fingerprints = fingerprints;
        _sameVolume = sameVolume;
        _commitStore = commitStore;
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
            .PersistIntentAsync(request.Intent, cancellationToken)
            .ConfigureAwait(false);
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

        if (current.State != OperationJournalState.IntentPersisted)
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.UnexpectedJournalState,
                current.State);
        }

        await using var writer = await _mutationGate
            .AcquireAsync(CancellationToken.None)
            .ConfigureAwait(false);
        var durableState = current.State;
        try
        {
            var guard = new ApprovedRootPathGuard(request.Intent.SourceRoot);
            var identityProvider = new NtfsFileIdentityProvider(guard);
            await using var source = identityProvider.OpenVerifiedSource(
                request.Intent.SourcePath);
            var lockedIdentity = await _fingerprints
                .CaptureAsync(
                    request.Intent.Owner,
                    request.DataKeyId,
                    source,
                    CancellationToken.None)
                .ConfigureAwait(false);

            current = await TransitionAsync(
                    current,
                    OperationJournalState.IdentityLocked,
                    lockedIdentity)
                .ConfigureAwait(false);
            if (current is null)
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.JournalConflict,
                    OperationJournalState.IntentPersisted);
            }
            durableState = current.State;

            current = await TransitionAsync(
                    current,
                    OperationJournalState.Renaming)
                .ConfigureAwait(false);
            if (current is null)
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.JournalConflict,
                    OperationJournalState.IdentityLocked);
            }
            durableState = current.State;

            var renamed = await _sameVolume
                .RenameNoReplaceAsync(
                    source,
                    lockedIdentity,
                    request.Intent,
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

            var verifiedIdentity = await _fingerprints
                .CaptureAsync(
                    request.Intent.Owner,
                    request.DataKeyId,
                    source,
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
                .ConfigureAwait(false);
            if (current is null)
            {
                return new FileOperationRecoveryRequired(
                    FileOperationFailure.JournalConflict,
                    OperationJournalState.Renaming);
            }
            durableState = current.State;

            var commit = new CommitFileOperationCommand(
                request.Intent.OperationId,
                current.Revision,
                request.AppendEvents,
                request.SideEffects,
                request.Usage);
            var committed = await _commitStore
                .CommitAppliedAsync(commit, CancellationToken.None)
                .ConfigureAwait(false);
            return committed switch
            {
                OperationCommitted or AlreadyCommitted =>
                    new FileOperationSucceeded(
                        committed,
                        verifiedIdentity),
                OperationCommitConflict =>
                    new FileOperationRecoveryRequired(
                        FileOperationFailure.CommitConflict,
                        OperationJournalState.FileApplied),
                OperationCommitStorageBusy =>
                    new FileOperationRecoveryRequired(
                        FileOperationFailure.CommitStorageBusy,
                        OperationJournalState.FileApplied),
                _ => new FileOperationRecoveryRequired(
                    FileOperationFailure.NativeFailure,
                    OperationJournalState.FileApplied),
            };
        }
        catch (StableSourceBoundaryException)
        {
            return CreateFileSystemFailureResult(
                FileOperationFailure.PathRejected,
                durableState);
        }
        catch (FileSystemBoundaryException exception)
        {
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
            return CreateFileSystemFailureResult(
                FileOperationFailure.AccessDenied,
                durableState);
        }
        catch (IOException exception)
        {
            return CreateFileSystemFailureResult(
                MapBoundaryFailure(exception),
                durableState);
        }
    }

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

        return FileOperationFailure.NativeFailure;
    }

    private static FileOperationExecutionResult CreateFileSystemFailureResult(
        FileOperationFailure failure,
        OperationJournalState durableState) =>
        durableState is OperationJournalState.Renaming
            or OperationJournalState.FileApplied
            ? new FileOperationRecoveryRequired(failure, durableState)
            : new FileOperationNotApplied(failure, durableState);
}
