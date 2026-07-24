using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Transactions;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;
using Microsoft.Win32.SafeHandles;

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
    BeforeFinalizeSourceAbsenceRevalidation,
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

internal interface ISourceAbsenceGuard : IAsyncDisposable
{
    bool IsStillSafelyAbsent();
}

internal sealed class OperationRecoveryObservationScope : IAsyncDisposable
{
    internal OperationRecoveryObservationScope(
        RecoveryPathObservation source,
        RecoveryPathObservation destination,
        VerifiedStableSource? exactSource,
        VerifiedStableSource? exactDestination = null,
        ISourceAbsenceGuard? sourceAbsenceGuard = null)
    {
        Source = source;
        Destination = destination;
        ExactSource = exactSource;
        ExactDestination = exactDestination;
        SourceAbsenceGuard = sourceAbsenceGuard;
    }

    internal RecoveryPathObservation Source { get; }

    internal RecoveryPathObservation Destination { get; }

    internal VerifiedStableSource? ExactSource { get; }

    internal VerifiedStableSource? ExactDestination { get; }

    internal ISourceAbsenceGuard? SourceAbsenceGuard { get; }

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
            try
            {
                if (ExactDestination is not null)
                {
                    await ExactDestination
                        .DisposeAsync()
                        .ConfigureAwait(false);
                }
            }
            finally
            {
                if (SourceAbsenceGuard is not null)
                {
                    await SourceAbsenceGuard
                        .DisposeAsync()
                        .ConfigureAwait(false);
                }
            }
        }
    }
}

internal sealed class NativeSourceAbsenceGuard : ISourceAbsenceGuard
{
    private const int BufferLength = 64 * 1024;
    private const int MaximumUnrelatedChangeBatches = 64;
    private readonly string _canonicalSource;
    private readonly string _sourceFileName;
    private readonly PinnedDirectoryPathScope _pinnedAncestors;
    private readonly SafeFileHandle _parent;
    private readonly SafeWaitHandle _event;
    private IntPtr _buffer;
    private IntPtr _overlapped;
    private bool _disposed;

    private NativeSourceAbsenceGuard(
        string canonicalSource,
        PinnedDirectoryPathScope pinnedAncestors,
        SafeFileHandle parent,
        SafeWaitHandle changeEvent,
        IntPtr buffer,
        IntPtr overlapped)
    {
        _canonicalSource = canonicalSource;
        _sourceFileName = Path.GetFileName(canonicalSource);
        _pinnedAncestors = pinnedAncestors;
        _parent = parent;
        _event = changeEvent;
        _buffer = buffer;
        _overlapped = overlapped;
    }

    internal static NativeSourceAbsenceGuard Create(
        string approvedRoot,
        string sourcePath)
    {
        var rootGuard = new ApprovedRootPathGuard(approvedRoot);
        var canonicalSource =
            rootGuard.CanonicalizeContainedPath(sourcePath);
        var parentPath = Path.GetDirectoryName(canonicalSource);
        if (string.IsNullOrEmpty(parentPath))
        {
            throw new FileSystemBoundaryException(
                "The source parent path is invalid.");
        }

        PinnedDirectoryPathScope? pinnedAncestors = null;
        SafeFileHandle? parent = null;
        SafeWaitHandle? changeEvent = null;
        var buffer = IntPtr.Zero;
        var overlapped = IntPtr.Zero;
        var observationStarted = false;
        try
        {
            pinnedAncestors =
                rootGuard.OpenPinnedDirectoryPath(parentPath);
            parent = WindowsFileSystemNative.OpenDirectoryChangeHandle(
                parentPath);
            var volume = WindowsFileSystemNative.GetStableVolumeSnapshot(
                parent);
            _ = StableVolumeValidator.Validate(
                volume.IsLocal,
                volume.HasVolumeInformation,
                volume.FileSystemName,
                volume.FileId.VolumeSerialNumber);
            var parentIdentity =
                WindowsFileSystemNative.GetFileIdInfo(parent);
            if (!ParentIdentitiesEqual(
                    pinnedAncestors.FinalIdentity,
                    parentIdentity))
            {
                throw new FileSystemBoundaryException(
                    "The watched source parent did not match its retained path component.");
            }

            changeEvent =
                WindowsFileSystemNative.CreateDirectoryChangeEvent();
            buffer = Marshal.AllocHGlobal(BufferLength);
            overlapped = Marshal.AllocHGlobal(
                Marshal.SizeOf<NativeOverlappedData>());
            StartDirectoryChangeObservation(
                parent,
                changeEvent,
                buffer,
                overlapped);
            observationStarted = true;
            return new NativeSourceAbsenceGuard(
                canonicalSource,
                pinnedAncestors,
                parent,
                changeEvent,
                buffer,
                overlapped);
        }
        catch
        {
            if (observationStarted
                && parent is not null)
            {
                WindowsFileSystemNative.CancelDirectoryChangeObservation(
                    parent,
                    overlapped);
            }

            if (overlapped != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(overlapped);
            }

            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }

            try
            {
                changeEvent?.Dispose();
            }
            finally
            {
                try
                {
                    parent?.Dispose();
                }
                finally
                {
                    pinnedAncestors?.Dispose();
                }
            }

            throw;
        }
    }

    public bool IsStillSafelyAbsent()
    {
        if (_disposed)
        {
            return false;
        }

        try
        {
            if (!HasNoSourceNameChanges())
            {
                return false;
            }

            var currentParent =
                WindowsFileSystemNative.GetFileIdInfo(_parent);
            if (!ParentIdentitiesEqual(
                    _pinnedAncestors.FinalIdentity,
                    currentParent)
                || WindowsFileSystemNative.TryGetPathComponentInfo(
                        _canonicalSource,
                        out _)
                    != WindowsFileSystemNative
                        .PathComponentOpenOutcome.Missing)
            {
                return false;
            }

            return HasNoSourceNameChanges();
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or UnauthorizedAccessException
                or IOException)
        {
            return false;
        }
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed)
            return ValueTask.CompletedTask;
        _disposed = true;
        try
        {
            WindowsFileSystemNative.CancelDirectoryChangeObservation(
                _parent,
                _overlapped);
        }
        finally
        {
            Marshal.FreeHGlobal(_overlapped);
            Marshal.FreeHGlobal(_buffer);
            _overlapped = IntPtr.Zero;
            _buffer = IntPtr.Zero;
            try
            {
                _event.Dispose();
            }
            finally
            {
                try
                {
                    _parent.Dispose();
                }
                finally
                {
                    _pinnedAncestors.Dispose();
                }
            }
        }

        return ValueTask.CompletedTask;
    }

    private bool HasNoSourceNameChanges()
    {
        for (var batch = 0;
             batch < MaximumUnrelatedChangeBatches;
             batch++)
        {
            var status =
                WindowsFileSystemNative.GetDirectoryChangeObservationStatus(
                    _parent,
                    _buffer,
                    BufferLength,
                    _overlapped,
                    _sourceFileName,
                    out _,
                    wait: false);
            switch (status)
            {
                case WindowsFileSystemNative
                    .DirectoryChangeObservationStatus.Pending:
                    return true;
                case WindowsFileSystemNative
                    .DirectoryChangeObservationStatus.Unrelated:
                    StartDirectoryChangeObservation(
                        _parent,
                        _event,
                        _buffer,
                        _overlapped);
                    break;
                case WindowsFileSystemNative
                    .DirectoryChangeObservationStatus.Changed:
                case WindowsFileSystemNative
                    .DirectoryChangeObservationStatus.Unreliable:
                default:
                    return false;
            }
        }

        return false;
    }

    private static void StartDirectoryChangeObservation(
        SafeFileHandle parent,
        SafeWaitHandle changeEvent,
        IntPtr buffer,
        IntPtr overlapped)
    {
        Marshal.StructureToPtr(
            new NativeOverlappedData
            {
                EventHandle = changeEvent.DangerousGetHandle(),
            },
            overlapped,
            fDeleteOld: false);
        WindowsFileSystemNative.BeginDirectoryChangeObservation(
            parent,
            changeEvent,
            buffer,
            BufferLength,
            overlapped);
    }

    private static bool ParentIdentitiesEqual(
        WindowsFileSystemNative.FILE_ID_INFO left,
        WindowsFileSystemNative.FILE_ID_INFO right) =>
        left.VolumeSerialNumber == right.VolumeSerialNumber
        && left.FileId.LowPart == right.FileId.LowPart
        && left.FileId.HighPart == right.FileId.HighPart;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOverlappedData
    {
        internal IntPtr Internal;
        internal IntPtr InternalHigh;
        internal uint Offset;
        internal uint OffsetHigh;
        internal IntPtr EventHandle;
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
            var recovery = await RecoverWithinGateAsync(
                    entry,
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (recovery is FileOperationSucceeded)
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

    internal async Task<FileOperationExecutionResult> RecoverWithinGateAsync(
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
            return new FileOperationRecoveryRequired(
                FileOperationFailure.JournalConflict,
                OperationJournalState.ManualRecovery);
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
            return new FileOperationRecoveryRequired(
                FileOperationFailure.UnexpectedJournalState,
                OperationJournalState.ManualRecovery);
        }

        await using var observation = await _observer
            .ObserveAsync(entry, entry.RecoveryRecipe, cancellationToken)
            .ConfigureAwait(false);
        var decision = OperationJournalStateMachine.DecideSameVolumeRecovery(
            observation.Source,
            observation.Destination);
        FileOperationExecutionResult? result = null;
        Exception? recoverableFailure = null;
        try
        {
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
            else if (decision
                    == OperationRecoveryDecision.FinalizeDatabaseCommit
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
        }
        catch (Exception exception) when (
            exception is not OperationCanceledException)
        {
            recoverableFailure = exception;
        }

        if (result is FileOperationSucceeded)
        {
            return result;
        }

        var latest = await ReloadExactAsync(entry, cancellationToken)
            .ConfigureAwait(false);
        if (latest.State == OperationJournalState.Completed)
        {
            if (latest.Identity is null)
            {
                throw new OperationJournalRecoveryRequiredException();
            }

            return new FileOperationSucceeded(
                new AlreadyCommitted(
                    latest.Intent.ExpectedStreamVersion.Next()),
                latest.Identity);
        }

        if (latest.State == OperationJournalState.ManualRecovery)
        {
            return new FileOperationRecoveryRequired(
                FileOperationFailure.UnexpectedJournalState,
                latest.State);
        }

        var reason = recoverableFailure is not null
            ? OperationManualRecoveryReason.ObservationFailed
            : result is FileOperationRecoveryRequired
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
                latest,
                observation.Source,
                observation.Destination,
                reason,
                action,
                cancellationToken)
            .ConfigureAwait(false);
        return new FileOperationRecoveryRequired(
            result is FileOperationRecoveryRequired recoveryRequired
                ? recoveryRequired.Failure
                : FileOperationFailure.UnexpectedJournalState,
            OperationJournalState.ManualRecovery);
    }

    private async Task<OperationJournalEntry> ReloadExactAsync(
        OperationJournalEntry original,
        CancellationToken cancellationToken)
    {
        var latest = await _journal.GetAsync(
                original.OperationId,
                cancellationToken)
            .ConfigureAwait(false);
        if (latest is null
            || !SqliteOperationJournalStore.IntentsEqual(
                original.Intent,
                latest.Intent)
            || original.RecoveryRecipe is null
            || !original.RecoveryRecipe.ExactEquals(
                latest.RecoveryRecipe))
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        return latest;
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
        NativeSourceAbsenceGuard? sourceAbsenceGuard = null;
        PathObservation? source = null;
        try
        {
            try
            {
                sourceAbsenceGuard = NativeSourceAbsenceGuard.Create(
                    entry.Intent.SourceRoot,
                    entry.Intent.SourcePath);
            }
            catch (Exception exception) when (
                exception is FileSystemBoundaryException
                    or StableSourceBoundaryException
                    or UnauthorizedAccessException
                    or IOException)
            {
            }

            source = await ObservePathAsync(
                    entry.Intent.SourceRoot,
                    entry.Intent.SourcePath,
                    entry,
                    recipe,
                    retainExact: true,
                    cancellationToken)
                .ConfigureAwait(false);
            if (source.Observation != RecoveryPathObservation.Missing)
            {
                if (sourceAbsenceGuard is not null)
                {
                    await sourceAbsenceGuard
                        .DisposeAsync()
                        .ConfigureAwait(false);
                    sourceAbsenceGuard = null;
                }
            }
            else if (sourceAbsenceGuard is null
                || !sourceAbsenceGuard.IsStillSafelyAbsent())
            {
                source = source with
                {
                    Observation =
                        RecoveryPathObservation.InaccessibleOrUnknown,
                };
            }

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
                destination.Source,
                sourceAbsenceGuard);
        }
        catch
        {
            try
            {
                if (source?.Source is not null)
                {
                    await source.Source.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                if (sourceAbsenceGuard is not null)
                {
                    await sourceAbsenceGuard
                        .DisposeAsync()
                        .ConfigureAwait(false);
                }
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
