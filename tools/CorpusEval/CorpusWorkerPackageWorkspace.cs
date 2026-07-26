using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

namespace LocalDocumentOrganizer.CorpusEval;

public sealed class CorpusWorkerPackageWorkspace :
    IDisposable,
    IAsyncDisposable
{
    private const string WorkspaceDirectoryPrefix = "workspace-";
    private CorpusWorkerPackageLease? _packageLease;
    private CorpusProtectedRootSet? _protectedRoots;
    private readonly CorpusWorkerPackageDeadlineFactory _deadlineFactory;
    private readonly string _workspaceParent;
    private string? _workspaceRoot;
    private int _disposed;

    private CorpusWorkerPackageWorkspace(
        CorpusWorkerPackageLease packageLease,
        CorpusProtectedRootSet protectedRoots,
        string workspaceParent,
        string workspaceRoot,
        CorpusWorkerPackageDeadlineFactory deadlineFactory)
    {
        _packageLease = packageLease;
        _protectedRoots = protectedRoots;
        _workspaceParent = workspaceParent;
        _workspaceRoot = workspaceRoot;
        _deadlineFactory = deadlineFactory;
        StagedExecutablePath = packageLease.StagedExecutablePath;
        Identity = packageLease.Identity;
    }

    public string StagedExecutablePath { get; }

    public CorpusWorkerPackageIdentity Identity { get; }

    public static async Task<CorpusWorkerPackageWorkspace> OpenAsync(
        string packageRoot,
        string workerExecutablePath,
        string expectedPackageSha256,
        string corpusRoot,
        CancellationToken cancellationToken) =>
        await OpenAsync(
                packageRoot,
                workerExecutablePath,
                expectedPackageSha256,
                corpusRoot,
                cancellationToken,
                TimeSpan.FromMilliseconds(
                    DocumentExtractionLimits.ExtractionTimeoutMilliseconds),
                TimeProvider.System,
                beforePackageOperation: null)
            .ConfigureAwait(false);

    internal static async Task<CorpusWorkerPackageWorkspace> OpenAsync(
        string packageRoot,
        string workerExecutablePath,
        string expectedPackageSha256,
        string corpusRoot,
        CancellationToken cancellationToken,
        TimeSpan operationTimeout,
        TimeProvider timeProvider,
        Func<CancellationToken, Task>? beforePackageOperation)
    {
        if (!Path.IsPathFullyQualified(packageRoot)
            || !Path.IsPathFullyQualified(workerExecutablePath)
            || !Path.IsPathFullyQualified(corpusRoot)
            || !CorpusWorkerPackageManifest.IsSha256(
                expectedPackageSha256)
            || !string.Equals(
                expectedPackageSha256,
                expectedPackageSha256.ToLowerInvariant(),
                StringComparison.Ordinal))
        {
            throw new CorpusWorkerAttestationException();
        }

        var deadlineFactory = new CorpusWorkerPackageDeadlineFactory(
            operationTimeout,
            timeProvider);
        using var deadline = deadlineFactory.Start(cancellationToken);
        try
        {
            deadline.ThrowIfCancellationRequested();
            return await OpenWithinDeadlineAsync(
                    packageRoot,
                    workerExecutablePath,
                    expectedPackageSha256,
                    corpusRoot,
                    deadline,
                    deadlineFactory,
                    beforePackageOperation)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new CorpusWorkerAttestationException();
        }
    }

    private static async Task<CorpusWorkerPackageWorkspace>
        OpenWithinDeadlineAsync(
        string packageRoot,
        string workerExecutablePath,
        string expectedPackageSha256,
        string corpusRoot,
        CorpusWorkerPackageDeadline deadline,
        CorpusWorkerPackageDeadlineFactory deadlineFactory,
        Func<CancellationToken, Task>? beforePackageOperation)
    {
        CorpusWorkerPackageLease? packageLease = null;
        CorpusProtectedRootSet? protectedRoots = null;
        string? workspaceParent = null;
        string? workspaceRoot = null;
        try
        {
            deadline.ThrowIfCancellationRequested();
            workspaceParent = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(
                    Path.Combine(
                        Path.GetTempPath(),
                        "LocalDocumentOrganizer",
                        "CorpusWorkbench",
                        "package-workspaces")));
            Directory.CreateDirectory(workspaceParent);
            _ = new ApprovedRootPathGuard(workspaceParent);
            deadline.ThrowIfCancellationRequested();
            workspaceRoot = Path.Combine(
                workspaceParent,
                WorkspaceDirectoryPrefix
                    + Guid.NewGuid().ToString("N"));
            CorpusWorkerPackageLease.CreatePrivateDirectory(
                workspaceRoot);
            var stageParent = Path.Combine(workspaceRoot, "stage");
            CorpusWorkerPackageLease.CreatePrivateDirectory(stageParent);
            deadline.ThrowIfCancellationRequested();
            if (beforePackageOperation is not null)
            {
                await beforePackageOperation(deadline.Token)
                    .ConfigureAwait(false);
            }

            deadline.ThrowIfCancellationRequested();
            var outputRoot = Path.Combine(workspaceRoot, "output");
            protectedRoots = CorpusProtectedRootSet.Create(
                packageRoot,
                corpusRoot,
                outputRoot);
            deadline.ThrowIfCancellationRequested();
            protectedRoots.Revalidate();
            packageLease = await CorpusWorkerPackageLease.CreateAsync(
                    packageRoot,
                    workerExecutablePath,
                    expectedPackageSha256,
                    protectedRoots,
                    stageParent,
                    deadline.Token)
                .ConfigureAwait(false);
            deadline.ThrowIfCancellationRequested();
            protectedRoots.Revalidate();
            var workspace = new CorpusWorkerPackageWorkspace(
                packageLease,
                protectedRoots,
                workspaceParent,
                workspaceRoot,
                deadlineFactory);
            packageLease = null;
            protectedRoots = null;
            workspaceParent = null;
            workspaceRoot = null;
            return workspace;
        }
        catch (CorpusWorkerAttestationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or NotSupportedException
                or System.Security.SecurityException
                or StableSourceBoundaryException
                or FileSystemBoundaryException)
        {
            throw new CorpusWorkerAttestationException();
        }
        finally
        {
            if (packageLease is not null)
            {
                await packageLease.DisposeAsync().ConfigureAwait(false);
            }

            protectedRoots?.Dispose();
            if (workspaceParent is not null
                && workspaceRoot is not null)
            {
                DeleteWorkspaceBounded(
                    workspaceParent,
                    workspaceRoot);
            }
        }
    }

    public async Task VerifyAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        using var deadline = _deadlineFactory.Start(cancellationToken);
        try
        {
            deadline.ThrowIfCancellationRequested();
            var roots = _protectedRoots
                ?? throw new ObjectDisposedException(
                    nameof(CorpusWorkerPackageWorkspace));
            var lease = _packageLease
                ?? throw new ObjectDisposedException(
                    nameof(CorpusWorkerPackageWorkspace));
            roots.Revalidate();
            deadline.ThrowIfCancellationRequested();
            await lease.VerifyAsync(deadline.Token).ConfigureAwait(false);
            deadline.ThrowIfCancellationRequested();
            roots.Revalidate();
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new CorpusWorkerAttestationException();
        }
    }

    public void Dispose() =>
        DisposeAsync().AsTask().GetAwaiter().GetResult();

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        var packageLease = Interlocked.Exchange(
            ref _packageLease,
            null);
        var protectedRoots = Interlocked.Exchange(
            ref _protectedRoots,
            null);
        var workspaceRoot = Interlocked.Exchange(
            ref _workspaceRoot,
            null);
        try
        {
            if (packageLease is not null)
            {
                await packageLease.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            protectedRoots?.Dispose();
            if (workspaceRoot is not null)
            {
                DeleteWorkspaceBounded(
                    _workspaceParent,
                    workspaceRoot);
            }
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);

    private static void DeleteWorkspaceBounded(
        string workspaceParent,
        string workspaceRoot)
    {
        var parent = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(workspaceParent));
        var workspace = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(workspaceRoot));
        var relative = Path.GetRelativePath(parent, workspace);
        if (!relative.StartsWith(
                WorkspaceDirectoryPrefix,
                StringComparison.Ordinal)
            || relative.Contains(Path.DirectorySeparatorChar)
            || relative.Contains(Path.AltDirectorySeparatorChar)
            || !Directory.Exists(workspace))
        {
            return;
        }

        var attributes = File.GetAttributes(workspace);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(workspace);
            return;
        }

        foreach (var child in Directory.EnumerateFileSystemEntries(
                     workspace,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            var childAttributes = File.GetAttributes(child);
            if ((childAttributes & FileAttributes.ReparsePoint) != 0)
            {
                if ((childAttributes & FileAttributes.Directory) != 0)
                {
                    Directory.Delete(child);
                }
                else
                {
                    File.Delete(child);
                }

                continue;
            }

            if ((childAttributes & FileAttributes.Directory) == 0
                || Directory.EnumerateFileSystemEntries(child).Any())
            {
                throw new CorpusWorkerAttestationException();
            }

            Directory.Delete(child);
        }

        Directory.Delete(workspace);
    }
}

internal sealed class CorpusWorkerPackageDeadlineFactory
{
    private readonly TimeSpan _budget;
    private readonly TimeProvider _timeProvider;

    internal CorpusWorkerPackageDeadlineFactory(
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

    internal CorpusWorkerPackageDeadline Start(
        CancellationToken callerCancellation) =>
        new(_budget, _timeProvider, callerCancellation);
}

internal sealed class CorpusWorkerPackageDeadline : IDisposable
{
    private readonly TimeSpan _budget;
    private readonly long _startedAt;
    private readonly TimeProvider _timeProvider;
    private readonly CancellationTokenSource _timeout;
    private readonly CancellationTokenSource _linked;

    internal CorpusWorkerPackageDeadline(
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

    internal CancellationToken Token => _linked.Token;

    internal void ThrowIfCancellationRequested()
    {
        Token.ThrowIfCancellationRequested();
        if (_timeProvider.GetElapsedTime(_startedAt) < _budget)
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
