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

    void ThrowIfCancellationRequested();
}

internal sealed class MonotonicDocumentExtractionDeadlineFactory
    : IDocumentExtractionDeadlineFactory
{
    private readonly TimeSpan _budget;
    private readonly TimeProvider _timeProvider;

    internal MonotonicDocumentExtractionDeadlineFactory(
        TimeSpan budget,
        TimeProvider timeProvider)
    {
        if (budget <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(budget));
        }

        _budget = budget;
        _timeProvider = timeProvider
            ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public IDocumentExtractionDeadline Start(
        CancellationToken callerCancellation) =>
        new MonotonicDocumentExtractionDeadline(
            _budget,
            _timeProvider,
            callerCancellation);
}

internal sealed class MonotonicDocumentExtractionDeadline
    : IDocumentExtractionDeadline
{
    private readonly TimeSpan _budget;
    private readonly TimeProvider _timeProvider;
    private readonly long _startedAt;
    private readonly CancellationTokenSource _timeout;
    private readonly CancellationTokenSource _linked;

    internal MonotonicDocumentExtractionDeadline(
        TimeSpan budget,
        TimeProvider timeProvider,
        CancellationToken callerCancellation)
    {
        _budget = budget;
        _timeProvider = timeProvider;
        _startedAt = timeProvider.GetTimestamp();
        _timeout = new CancellationTokenSource(budget, timeProvider);
        _linked = CancellationTokenSource.CreateLinkedTokenSource(
            callerCancellation,
            _timeout.Token);
    }

    public CancellationToken Token => _linked.Token;

    public TimeSpan Remaining
    {
        get
        {
            var elapsed = _timeProvider.GetElapsedTime(
                _startedAt,
                _timeProvider.GetTimestamp());
            var remaining = _budget - elapsed;
            return remaining > TimeSpan.Zero
                ? remaining
                : TimeSpan.Zero;
        }
    }

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
        TimeSpan remainingBudget);
}

internal interface IDocumentWorkerSession
{
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

    internal AppContainerDocumentWorkerSessionLauncher(
        IWorkerLaunchFaultInjector faultInjector,
        IDocumentWorkerCleanupDiagnostics cleanupDiagnostics)
    {
        _faultInjector = faultInjector;
        _cleanupDiagnostics = cleanupDiagnostics;
    }

    public Task<IDocumentWorkerSession> LaunchAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        SafeFileHandle source,
        TimeSpan remainingBudget) =>
        Task.Run<IDocumentWorkerSession>(
            () => Launch(executablePath, arguments, source));

    private IDocumentWorkerSession Launch(
        string executablePath,
        IReadOnlyList<string> arguments,
        SafeFileHandle source)
    {
        var profile = AppContainerProfile.OpenOrCreate();
        try
        {
            var launcher = new AppContainerProcessLauncher(
                profile,
                _faultInjector);
            var worker = launcher.Start(
                executablePath,
                arguments,
                source);
            return new AppContainerDocumentWorkerSession(
                worker,
                profile,
                _cleanupDiagnostics);
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
    private Task? _cleanup;

    internal AppContainerDocumentWorkerSession(
        LaunchedAppContainerProcess worker,
        AppContainerProfile profile,
        IDocumentWorkerCleanupDiagnostics cleanupDiagnostics)
    {
        _worker = worker;
        _profile = profile;
        _cleanupDiagnostics = cleanupDiagnostics;
    }

    public Stream StandardInput => _worker.StandardInput;

    public Stream StandardOutput => _worker.StandardOutput;

    public ulong InheritedSourceHandle => _worker.InheritedSourceHandle;

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
            _cleanup ??= CleanupCoreAsync(primaryException);
            return new ValueTask(_cleanup);
        }
    }

    private async Task CleanupCoreAsync(Exception? primaryException)
    {
        var cleanupFailed = false;
        var workerTerminationUnconfirmed = false;
        try
        {
            await _worker.DisposeAsync().ConfigureAwait(false);
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
