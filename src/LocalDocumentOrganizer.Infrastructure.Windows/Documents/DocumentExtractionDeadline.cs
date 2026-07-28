using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Documents;

internal interface IDocumentExtractionDeadlineFactory
{
    IDocumentExtractionDeadline Start(
        CancellationToken callerCancellation);
}

internal interface IDocumentExtractionDeadline : IDisposable
{
    CancellationToken Token { get; }

    TimeSpan Remaining { get; }

    DocumentWorkerDeadlineStamp Capture();

    void ThrowIfCancellationRequested();
}

internal sealed class MonotonicDocumentExtractionDeadlineFactory
    : IDocumentExtractionDeadlineFactory
{
    private readonly TimeSpan _budget;
    private readonly TimeProvider _timeProvider;
    private readonly DedicatedMonotonicDeadlineScheduler _scheduler;

    internal MonotonicDocumentExtractionDeadlineFactory(
        TimeSpan budget,
        TimeProvider timeProvider,
        DedicatedMonotonicDeadlineScheduler? scheduler = null)
    {
        if (budget <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(budget));
        }

        _budget = budget;
        _timeProvider = timeProvider
            ?? throw new ArgumentNullException(nameof(timeProvider));
        _scheduler = scheduler
            ?? DedicatedMonotonicDeadlineScheduler.Shared;
    }

    public IDocumentExtractionDeadline Start(
        CancellationToken callerCancellation) =>
        new MonotonicDocumentExtractionDeadline(
            _budget,
            _timeProvider,
            _scheduler,
            callerCancellation);
}

internal sealed class MonotonicDocumentExtractionDeadline
    : IDocumentExtractionDeadline
{
    private readonly CancellationTokenSource _timeout;
    private readonly CancellationTokenSource _linked;
    private readonly DocumentWorkerDeadlineStamp _deadline;
    private readonly IDedicatedDeadlineRegistration _registration;

    internal MonotonicDocumentExtractionDeadline(
        TimeSpan budget,
        TimeProvider timeProvider,
        DedicatedMonotonicDeadlineScheduler scheduler,
        CancellationToken callerCancellation)
    {
        _timeout = new CancellationTokenSource();
        _linked = CancellationTokenSource.CreateLinkedTokenSource(
            callerCancellation,
            _timeout.Token);
        _deadline = DocumentWorkerDeadlineStamp.FromNow(
            budget,
            _linked.Token,
            timeProvider);
        _registration = scheduler.Schedule(
            _deadline,
            _ =>
            {
                try
                {
                    _timeout.Cancel();
                }
                catch (ObjectDisposedException)
                {
                }
            });
    }

    public CancellationToken Token => _linked.Token;

    public TimeSpan Remaining => _deadline.Remaining;

    public DocumentWorkerDeadlineStamp Capture() => _deadline;

    public void ThrowIfCancellationRequested()
    {
        Token.ThrowIfCancellationRequested();
        if (Remaining > TimeSpan.Zero)
        {
            return;
        }

        _timeout.Cancel();
        Token.ThrowIfCancellationRequested();
    }

    public void Dispose()
    {
        _registration.Dispose();
        _linked.Dispose();
        _timeout.Dispose();
    }
}

internal interface IDocumentSourceHasher
{
    Task<byte[]> ComputeSha256Async(
        SafeFileHandle source,
        long length,
        CancellationToken cancellationToken);
}

internal interface IDocumentWorkerSessionLauncher
{
    Task<IDocumentWorkerSession> LaunchAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        SafeFileHandle source,
        DocumentWorkerDeadlineStamp deadline);
}

internal interface IDocumentWorkerSession
{
    string WorkerPackageIdentity { get; }
    Stream StandardInput { get; }

    Stream StandardOutput { get; }

    ulong InheritedSourceHandle { get; }

    uint ExitCode { get; }

    void Abort();

    bool WasProcessMemoryLimitReached();

    Task WaitForExitAsync(CancellationToken cancellationToken);

    ValueTask CleanupAsync(Exception? primaryException);
}

internal enum DocumentWorkerCleanupFailureKind
{
    Abort,
    LaunchProfileCleanup,
    SessionCleanup,
    BackgroundCleanup,
    LateLaunch,
}

internal interface IDocumentWorkerCleanupDiagnostics
{
    void Report(DocumentWorkerCleanupFailureKind failureKind);
}

internal sealed class NullDocumentWorkerCleanupDiagnostics
    : IDocumentWorkerCleanupDiagnostics
{
    internal static NullDocumentWorkerCleanupDiagnostics Instance { get; } =
        new();

    private NullDocumentWorkerCleanupDiagnostics()
    {
    }

    public void Report(DocumentWorkerCleanupFailureKind failureKind)
    {
    }
}

internal static class DocumentWorkerCleanupDiagnostics
{
    internal static void ReportSafely(
        IDocumentWorkerCleanupDiagnostics diagnostics,
        DocumentWorkerCleanupFailureKind failureKind)
    {
        try
        {
            diagnostics.Report(failureKind);
        }
        catch (Exception)
        {
            // Diagnostics must never replace the extraction result.
        }
    }
}

internal sealed class AppContainerDocumentWorkerSessionLauncher
    : IDocumentWorkerSessionLauncher
{
    private readonly IWorkerLaunchFaultInjector _faultInjector;
    private readonly IDocumentWorkerCleanupDiagnostics _cleanupDiagnostics;
    private readonly DocumentWorkerExecutionLanes _executionLanes;

    internal AppContainerDocumentWorkerSessionLauncher(
        IWorkerLaunchFaultInjector faultInjector,
        IDocumentWorkerCleanupDiagnostics cleanupDiagnostics,
        DocumentWorkerExecutionLanes? executionLanes = null)
    {
        _faultInjector = faultInjector;
        _cleanupDiagnostics = cleanupDiagnostics;
        _executionLanes = executionLanes
            ?? DocumentWorkerExecutionLanes.Shared;
    }

    public Task<IDocumentWorkerSession> LaunchAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        SafeFileHandle source,
        DocumentWorkerDeadlineStamp deadline) =>
        _executionLanes.LaunchAsync<IDocumentWorkerSession>(
            deadline,
            source,
            (nativeSource, cleanup) =>
                Launch(
                    executablePath,
                    arguments,
                    nativeSource,
                    cleanup,
                    deadline));

    private IDocumentWorkerSession Launch(
        string executablePath,
        IReadOnlyList<string> arguments,
        SafeFileHandle source,
        DocumentWorkerCleanupReservation cleanup,
        DocumentWorkerDeadlineStamp deadline)
    {
        deadline.ThrowIfExpired();
        var profile = AppContainerProfile.OpenOrCreate();
        try
        {
            deadline.ThrowIfExpired();
            var launcher = new AppContainerProcessLauncher(
                profile,
                _faultInjector);
            var worker = launcher.Start(
                executablePath,
                arguments,
                source,
                deadline);
            return new AppContainerDocumentWorkerSession(
                worker,
                profile,
                _cleanupDiagnostics,
                cleanup);
        }
        catch
        {
            try
            {
                profile.Dispose();
            }
            catch (Exception cleanupException) when (
                cleanupException is AppContainerLaunchException
                    or IOException
                    or ObjectDisposedException
                    or UnauthorizedAccessException)
            {
                DocumentWorkerCleanupDiagnostics.ReportSafely(
                    _cleanupDiagnostics,
                    DocumentWorkerCleanupFailureKind.LaunchProfileCleanup);
            }

            throw;
        }
    }
}

internal sealed class AppContainerDocumentWorkerSession
    : IDocumentWorkerSession
{
    private readonly object _cleanupLock = new();
    private readonly LaunchedAppContainerProcess _worker;
    private readonly AppContainerProfile _profile;
    private readonly IDocumentWorkerCleanupDiagnostics _cleanupDiagnostics;
    private readonly DocumentWorkerCleanupReservation _cleanupReservation;
    private Task? _cleanup;

    internal AppContainerDocumentWorkerSession(
        LaunchedAppContainerProcess worker,
        AppContainerProfile profile,
        IDocumentWorkerCleanupDiagnostics cleanupDiagnostics,
        DocumentWorkerCleanupReservation cleanupReservation)
    {
        _worker = worker;
        _profile = profile;
        _cleanupDiagnostics = cleanupDiagnostics;
        _cleanupReservation = cleanupReservation;
    }

    public Stream StandardInput => _worker.StandardInput;

    public Stream StandardOutput => _worker.StandardOutput;

    public ulong InheritedSourceHandle => _worker.InheritedSourceHandle;

    public string WorkerPackageIdentity => _worker.WorkerPackageIdentity;

    public uint ExitCode => _worker.ExitCode;

    public void Abort() => _worker.Kill();

    public bool WasProcessMemoryLimitReached() =>
        _worker.WasProcessMemoryLimitReached();

    public Task WaitForExitAsync(CancellationToken cancellationToken) =>
        _worker.WaitForExitAsync(cancellationToken);

    public ValueTask CleanupAsync(Exception? primaryException)
    {
        lock (_cleanupLock)
        {
            _cleanup ??= _cleanupReservation.ExecuteAsync(
                    () => CleanupCore(primaryException))
                .AsTask();
            return new ValueTask(_cleanup);
        }
    }

    private void CleanupCore(Exception? primaryException)
    {
        var cleanupFailed = false;
        var workerTerminationUnconfirmed = false;
        try
        {
            _worker.Dispose();
        }
        catch (Exception exception) when (
            exception is AppContainerLaunchException
                or IOException
                or ObjectDisposedException
                or UnauthorizedAccessException)
        {
            cleanupFailed = true;
            workerTerminationUnconfirmed = true;
        }

        if (workerTerminationUnconfirmed)
        {
            try
            {
                _profile.ReleaseWithoutProfileDeletion();
            }
            catch (Exception exception) when (
                exception is IOException
                    or ObjectDisposedException
                    or UnauthorizedAccessException)
            {
                cleanupFailed = true;
            }
        }
        else
        {
            try
            {
                _profile.Dispose();
            }
            catch (Exception exception) when (
                exception is AppContainerLaunchException
                    or IOException
                    or ObjectDisposedException
                    or UnauthorizedAccessException)
            {
                cleanupFailed = true;
            }
        }

        if (!cleanupFailed)
        {
            return;
        }

        if (primaryException is not null)
        {
            DocumentWorkerCleanupDiagnostics.ReportSafely(
                _cleanupDiagnostics,
                DocumentWorkerCleanupFailureKind.SessionCleanup);
            return;
        }

        throw new AppContainerLaunchException(
            "The isolated worker cleanup did not complete.");
    }
}

internal sealed class DocumentWorkerSessionLease
{
    private readonly IDocumentWorkerSession _session;
    private readonly IDocumentWorkerCleanupDiagnostics _cleanupDiagnostics;
    private int _abortStarted;

    internal DocumentWorkerSessionLease(
        IDocumentWorkerSession session,
        IDocumentWorkerCleanupDiagnostics cleanupDiagnostics)
    {
        _session = session;
        _cleanupDiagnostics = cleanupDiagnostics;
    }

    internal IDocumentWorkerSession Session => _session;

    internal void Abort()
    {
        if (Interlocked.Exchange(ref _abortStarted, 1) == 0)
        {
            try
            {
                _session.Abort();
            }
            catch (Exception)
            {
                DocumentWorkerCleanupDiagnostics.ReportSafely(
                    _cleanupDiagnostics,
                    DocumentWorkerCleanupFailureKind.Abort);
            }
        }
    }

    internal ValueTask CleanupAsync(Exception? primaryException) =>
        _session.CleanupAsync(primaryException);
}
