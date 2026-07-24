using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Transactions;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;

[assembly: InternalsVisibleTo("LocalDocumentOrganizer.Transactions.Tests")]

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

internal enum FileOperationFaultPoint
{
    AfterIntentPersist,
    AfterSourceIdentityCapture,
    AfterIdentityLocked,
    AfterRenaming,
    AfterNativeRename,
    AfterDestinationIdentityVerification,
    AfterFileApplied,
    AfterEventAndProjectionCommitted,
    AfterSideEffectsPending,
}

internal interface IFileOperationFaultInjector
{
    void ThrowIfRequested(FileOperationFaultPoint point);
}

internal sealed class NoOpFileOperationFaultInjector
    : IFileOperationFaultInjector
{
    internal static NoOpFileOperationFaultInjector Instance { get; } = new();

    private NoOpFileOperationFaultInjector()
    {
    }

    public void ThrowIfRequested(FileOperationFaultPoint point)
    {
    }
}

public interface IOperationRecoveryStartupPrerequisites
{
    Task AuthenticateAndUnlockKeyRingAsync(
        CancellationToken cancellationToken);

    Task ValidateExactSchemaAsync(CancellationToken cancellationToken);
}

public sealed record OperationRecoveryStartupResult(
    int RecoveredCount,
    int ManualRecoveryCount);

internal interface IOperationRecoveryObserver
{
    Task<OperationRecoveryObservationScope> ObserveAsync(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        CancellationToken cancellationToken);
}

internal interface IOperationRecoveryExecutor
{
    Task<FileOperationExecutionResult> ResumeRenameWithinGateAsync(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        OperationRecoveryObservationScope observation,
        CancellationToken cancellationToken);

    Task<FileOperationExecutionResult> FinalizeCommitWithinGateAsync(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        OperationRecoveryObservationScope observation,
        CancellationToken cancellationToken);
}

internal sealed class OperationRecoveryObservationScope : IAsyncDisposable
{
    internal OperationRecoveryObservationScope(
        RecoveryPathObservation source,
        RecoveryPathObservation destination,
        VerifiedStableSource? exactSource,
        VerifiedStableSource? exactDestination = null)
    {
        Source = source;
        Destination = destination;
        ExactSource = exactSource;
        ExactDestination = exactDestination;
    }

    internal RecoveryPathObservation Source { get; }

    internal RecoveryPathObservation Destination { get; }

    internal VerifiedStableSource? ExactSource { get; }

    internal VerifiedStableSource? ExactDestination { get; }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (ExactSource is not null)
            {
                await ExactSource.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            if (ExactDestination is not null)
            {
                await ExactDestination.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}

public sealed class OperationRecoveryCoordinator
{
    private readonly IOperationJournalStore _journal;
    private readonly FileMutationGate _mutationGate;
    private readonly IOperationRecoveryObserver _observer;
    private readonly IOperationRecoveryExecutor _executor;

    public OperationRecoveryCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        FileOperationCoordinator executor,
        VaultFileFingerprintService fingerprints)
        : this(
            journal,
            mutationGate,
            new HandleSafeOperationRecoveryObserver(fingerprints),
            executor)
    {
    }

    internal OperationRecoveryCoordinator(
        IOperationJournalStore journal,
        FileMutationGate mutationGate,
        IOperationRecoveryObserver observer,
        IOperationRecoveryExecutor executor)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(mutationGate);
        ArgumentNullException.ThrowIfNull(observer);
        ArgumentNullException.ThrowIfNull(executor);
        _journal = journal;
        _mutationGate = mutationGate;
        _observer = observer;
        _executor = executor;
    }

    public async Task<OperationRecoveryStartupResult> RecoverStartupAsync(
        IOperationRecoveryStartupPrerequisites prerequisites,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(prerequisites);
        await prerequisites.AuthenticateAndUnlockKeyRingAsync(cancellationToken)
            .ConfigureAwait(false);
        await prerequisites.ValidateExactSchemaAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var startupGate = await _mutationGate
            .AcquireAsync(cancellationToken)
            .ConfigureAwait(false);
        var entries = await _journal
            .GetNonTerminalAsync(CancellationToken.None)
            .ConfigureAwait(false);
        var recoveredCount = 0;
        var manualRecoveryCount = 0;
        foreach (var entry in entries
                     .OrderBy(candidate => candidate.CreatedAtUtc)
                     .ThenBy(candidate => candidate.OperationId.Value))
        {
            var recovered = await RecoverWithinGateAsync(
                    entry,
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (recovered)
            {
                recoveredCount++;
            }
            else
            {
                manualRecoveryCount++;
            }
        }

        return new OperationRecoveryStartupResult(
            recoveredCount,
            manualRecoveryCount);
    }

    private async Task<bool> RecoverWithinGateAsync(
        OperationJournalEntry entry,
        CancellationToken cancellationToken)
    {
        if (entry.RecoveryRecipe is null)
        {
            await EnterManualRecoveryAsync(
                    entry,
                    RecoveryPathObservation.InaccessibleOrUnknown,
                    RecoveryPathObservation.InaccessibleOrUnknown,
                    OperationManualRecoveryReason.MissingRecoveryRecipe,
                    OperationManualRecoveryAction
                        .RestoreAuthenticatedRecipeOrEscalate,
                    cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        if (entry.Kind != FileOperationKind.SameVolumeMove)
        {
            await EnterManualRecoveryAsync(
                    entry,
                    RecoveryPathObservation.InaccessibleOrUnknown,
                    RecoveryPathObservation.InaccessibleOrUnknown,
                    OperationManualRecoveryReason.JournalStateMismatch,
                    OperationManualRecoveryAction
                        .InspectBothPathsWithoutMutation,
                    cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        await using var observation = await _observer
            .ObserveAsync(entry, entry.RecoveryRecipe, cancellationToken)
            .ConfigureAwait(false);
        var decision = OperationJournalStateMachine.DecideSameVolumeRecovery(
            observation.Source,
            observation.Destination);
        FileOperationExecutionResult? result = null;
        if (decision == OperationRecoveryDecision.ResumeRename
            && entry.State is
                OperationJournalState.IntentPersisted
                or OperationJournalState.IdentityLocked
                or OperationJournalState.Renaming)
        {
            result = await _executor.ResumeRenameWithinGateAsync(
                    entry,
                    entry.RecoveryRecipe,
                    observation,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        else if (decision == OperationRecoveryDecision.FinalizeDatabaseCommit
            && entry.State is
                OperationJournalState.Renaming
                or OperationJournalState.FileApplied
                or OperationJournalState.EventAndProjectionCommitted
                or OperationJournalState.SideEffectsPending)
        {
            result = await _executor.FinalizeCommitWithinGateAsync(
                    entry,
                    entry.RecoveryRecipe,
                    observation,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (result is FileOperationSucceeded)
        {
            return true;
        }

        var reason = result is FileOperationRecoveryRequired
            {
                Failure: FileOperationFailure.CommitConflict,
            }
            ? OperationManualRecoveryReason.ExactCommitConflict
            : decision == OperationRecoveryDecision.ManualRecovery
                ? OperationManualRecoveryReason.AmbiguousPathObservations
                : OperationManualRecoveryReason.JournalStateMismatch;
        var action = reason == OperationManualRecoveryReason.ExactCommitConflict
            ? OperationManualRecoveryAction.InspectAtomicCommitContributions
            : OperationManualRecoveryAction.InspectBothPathsWithoutMutation;
        await EnterManualRecoveryAsync(
                entry,
                observation.Source,
                observation.Destination,
                reason,
                action,
                cancellationToken)
            .ConfigureAwait(false);
        return false;
    }

    private async Task EnterManualRecoveryAsync(
        OperationJournalEntry entry,
        RecoveryPathObservation source,
        RecoveryPathObservation destination,
        OperationManualRecoveryReason reason,
        OperationManualRecoveryAction action,
        CancellationToken cancellationToken)
    {
        var transition = await _journal.TransitionAsync(
                new TransitionOperationCommand(
                    entry.OperationId,
                    entry.Revision,
                    OperationJournalState.ManualRecovery,
                    OperationSourceHealth.ManualRecovery,
                    manualRecoveryEvidence:
                        new OperationManualRecoveryEvidence(
                            entry.State,
                            source,
                            destination,
                            reason,
                            action)),
                cancellationToken)
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
}

internal sealed class HandleSafeOperationRecoveryObserver
    : IOperationRecoveryObserver
{
    private readonly VaultFileFingerprintService _fingerprints;

    internal HandleSafeOperationRecoveryObserver(
        VaultFileFingerprintService fingerprints)
    {
        ArgumentNullException.ThrowIfNull(fingerprints);
        _fingerprints = fingerprints;
    }

    public async Task<OperationRecoveryObservationScope> ObserveAsync(
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        CancellationToken cancellationToken)
    {
        var source = await ObservePathAsync(
                entry.Intent.SourceRoot,
                entry.Intent.SourcePath,
                entry,
                recipe,
                retainExact: true,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var destination = await ObservePathAsync(
                    entry.Intent.DestinationRoot,
                    entry.Intent.DestinationPath,
                    entry,
                    recipe,
                    retainExact: true,
                    cancellationToken)
                .ConfigureAwait(false);

            return new OperationRecoveryObservationScope(
                source.Observation,
                destination.Observation,
                source.Source,
                destination.Source);
        }
        catch
        {
            if (source.Source is not null)
            {
                await source.Source.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    private async Task<PathObservation> ObservePathAsync(
        string root,
        string path,
        OperationJournalEntry entry,
        OperationRecoveryRecipe recipe,
        bool retainExact,
        CancellationToken cancellationToken)
    {
        VerifiedStableSource? source = null;
        try
        {
            source = new NtfsFileIdentityProvider(
                    new ApprovedRootPathGuard(root))
                .OpenVerifiedSource(path);
            if (entry.Identity is null)
            {
                if (retainExact)
                {
                    return new PathObservation(
                        RecoveryPathObservation.Exact,
                        source);
                }

                await source.DisposeAsync().ConfigureAwait(false);
                return new PathObservation(
                    RecoveryPathObservation.Mismatch,
                    Source: null);
            }

            var actual = await _fingerprints.CaptureAsync(
                    entry.Owner,
                    recipe.DataKeyId,
                    source,
                    cancellationToken)
                .ConfigureAwait(false);
            var observation = IdentitiesEqual(entry.Identity, actual)
                ? RecoveryPathObservation.Exact
                : RecoveryPathObservation.Mismatch;
            if (retainExact
                && observation == RecoveryPathObservation.Exact)
            {
                return new PathObservation(observation, source);
            }

            await source.DisposeAsync().ConfigureAwait(false);
            return new PathObservation(observation, Source: null);
        }
        catch (OperationCanceledException)
        {
            if (source is not null)
            {
                await source.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or StableSourceBoundaryException
                or UnauthorizedAccessException
                or IOException)
        {
            if (source is not null)
            {
                await source.DisposeAsync().ConfigureAwait(false);
            }

            return new PathObservation(
                IsMissing(exception)
                    ? RecoveryPathObservation.Missing
                    : RecoveryPathObservation.InaccessibleOrUnknown,
                Source: null);
        }
    }

    private static bool IsMissing(Exception exception)
    {
        for (Exception? current = exception;
             current is not null;
             current = current.InnerException)
        {
            if (current is Win32Exception { NativeErrorCode: 2 or 3 })
            {
                return true;
            }

            if (current is FileNotFoundException
                or DirectoryNotFoundException)
            {
                return true;
            }
        }

        return false;
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

    private sealed record PathObservation(
        RecoveryPathObservation Observation,
        VerifiedStableSource? Source);
}
