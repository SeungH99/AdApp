using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

namespace LocalDocumentOrganizer.CorpusEval;

public sealed class CorpusWorkerPackageWorkspace :
    IDisposable,
    IAsyncDisposable
{
    private const string WorkspaceDirectoryPrefix = "workspace-";
    private CorpusWorkerPackageLease? _packageLease;
    private CorpusProtectedRootSet? _protectedRoots;
    private string? _workspaceRoot;
    private int _disposed;

    private CorpusWorkerPackageWorkspace(
        CorpusWorkerPackageLease packageLease,
        CorpusProtectedRootSet protectedRoots,
        string workspaceRoot)
    {
        _packageLease = packageLease;
        _protectedRoots = protectedRoots;
        _workspaceRoot = workspaceRoot;
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
        CancellationToken cancellationToken)
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

        cancellationToken.ThrowIfCancellationRequested();
        CorpusWorkerPackageLease? packageLease = null;
        CorpusProtectedRootSet? protectedRoots = null;
        string? workspaceRoot = null;
        try
        {
            var parent = Path.Combine(
                Path.GetTempPath(),
                "LocalDocumentOrganizer",
                "CorpusWorkbench",
                "package-workspaces");
            Directory.CreateDirectory(parent);
            _ = new ApprovedRootPathGuard(parent);
            workspaceRoot = Path.Combine(
                parent,
                WorkspaceDirectoryPrefix
                    + Guid.NewGuid().ToString("N"));
            CorpusWorkerPackageLease.CreatePrivateDirectory(
                workspaceRoot);
            var stageParent = Path.Combine(workspaceRoot, "stage");
            CorpusWorkerPackageLease.CreatePrivateDirectory(stageParent);
            var outputRoot = Path.Combine(workspaceRoot, "output");
            protectedRoots = CorpusProtectedRootSet.Create(
                packageRoot,
                corpusRoot,
                outputRoot);
            protectedRoots.Revalidate();
            packageLease = await CorpusWorkerPackageLease.CreateAsync(
                    packageRoot,
                    workerExecutablePath,
                    expectedPackageSha256,
                    protectedRoots,
                    stageParent,
                    cancellationToken)
                .ConfigureAwait(false);
            protectedRoots.Revalidate();
            var workspace = new CorpusWorkerPackageWorkspace(
                packageLease,
                protectedRoots,
                workspaceRoot);
            packageLease = null;
            protectedRoots = null;
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
            if (workspaceRoot is not null)
            {
                DeleteWorkspaceBounded(workspaceRoot);
            }
        }
    }

    public async Task VerifyAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var roots = _protectedRoots
            ?? throw new ObjectDisposedException(
                nameof(CorpusWorkerPackageWorkspace));
        var lease = _packageLease
            ?? throw new ObjectDisposedException(
                nameof(CorpusWorkerPackageWorkspace));
        roots.Revalidate();
        await lease.VerifyAsync(cancellationToken).ConfigureAwait(false);
        roots.Revalidate();
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
                DeleteWorkspaceBounded(workspaceRoot);
            }
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposed) != 0,
            this);

    private static void DeleteWorkspaceBounded(string workspaceRoot)
    {
        var parent = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(
                Path.Combine(
                    Path.GetTempPath(),
                    "LocalDocumentOrganizer",
                    "CorpusWorkbench",
                    "package-workspaces")));
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
