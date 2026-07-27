using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using LocalDocumentOrganizer.Infrastructure.Windows.Documents;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

namespace LocalDocumentOrganizer.CorpusEval;

public sealed record CorpusWorkerPackageIdentity(
    string ManifestId,
    string ManifestVersion,
    string Sha256,
    string ExecutableRelativePath,
    string ExecutableSha256)
{
    public const string CanonicalManifestId =
        "ordinal-relative-path-length-sha256-lf";
    public const string CanonicalManifestVersion = "1";

    public static CorpusWorkerPackageIdentity Synthetic { get; } =
        new(
            "synthetic-corpus-observation",
            "1",
            CorpusHashing.Sha256(
                "synthetic-corpus-observation|1\n"),
            "synthetic-observation",
            CorpusHashing.Sha256(
                "synthetic-corpus-observation|executable\n"));

    internal static CorpusWorkerPackageIdentity Canonical(
        string sha256,
        string executableRelativePath,
        string executableSha256) =>
        new(
            CanonicalManifestId,
            CanonicalManifestVersion,
            sha256,
            executableRelativePath,
            executableSha256);
}

public sealed record CorpusWorkerPackageEntry(
    string RelativePath,
    long Length,
    string Sha256);

public static class CorpusWorkerPackageManifest
{
    public static CorpusWorkerPackageIdentity ComputeIdentity(
        IReadOnlyList<CorpusWorkerPackageEntry> entries,
        string executableRelativePath)
    {
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Count == 0
            || !IsSafeRelativePath(executableRelativePath))
        {
            throw new CorpusWorkerAttestationException();
        }

        var exact = new HashSet<string>(StringComparer.Ordinal);
        var caseFolded = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);
        var lines = new List<string>(entries.Count);
        CorpusWorkerPackageEntry? executable = null;
        foreach (var entry in entries)
        {
            if (!IsSafeRelativePath(entry.RelativePath)
                || entry.Length < 0
                || !IsSha256(entry.Sha256)
                || !exact.Add(entry.RelativePath)
                || !caseFolded.Add(entry.RelativePath))
            {
                throw new CorpusWorkerAttestationException();
            }

            lines.Add(
                $"{entry.RelativePath}|{entry.Length}"
                + $"|{entry.Sha256.ToLowerInvariant()}");
            if (string.Equals(
                    entry.RelativePath,
                    executableRelativePath,
                    StringComparison.Ordinal))
            {
                executable = entry;
            }
        }

        if (executable is null)
        {
            throw new CorpusWorkerAttestationException();
        }

        lines.Sort(StringComparer.Ordinal);
        var bytes = Encoding.UTF8.GetBytes(
            string.Join('\n', lines) + "\n");
        return CorpusWorkerPackageIdentity.Canonical(
            CorpusHashing.Sha256(bytes),
            executableRelativePath,
            executable.Sha256.ToLowerInvariant());
    }

    public static bool IsCanonicalExecutionIdentity(
        CorpusWorkerPackageIdentity identity) =>
        identity is not null
        && string.Equals(
            identity.ManifestId,
            CorpusWorkerPackageIdentity.CanonicalManifestId,
            StringComparison.Ordinal)
        && string.Equals(
            identity.ManifestVersion,
            CorpusWorkerPackageIdentity.CanonicalManifestVersion,
            StringComparison.Ordinal)
        && IsLowerSha256(identity.Sha256)
        && IsSafeRelativePath(identity.ExecutableRelativePath)
        && IsLowerSha256(identity.ExecutableSha256);

    private static bool IsSafeRelativePath(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !Path.IsPathFullyQualified(value)
        && !value.Contains('\\')
        && !value.Contains('|')
        && !value.Contains('\r')
        && !value.Contains('\n')
        && value.Split('/').All(
            static segment => IsSafeSegment(segment));

    private static bool IsSafeSegment(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value is not "." and not ".."
        && !value.EndsWith(' ')
        && !value.EndsWith('.')
        && value.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    internal static bool IsSha256(string value) =>
        value is not null
        && value.Length == 64
        && value.All(Uri.IsHexDigit);

    private static bool IsLowerSha256(string value) =>
        value is not null
        && value.Length == 64
        && value.All(
            static character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');
}

public sealed class CorpusWorkerPackageSnapshot
    : IAsyncDisposable
{
    private readonly IReadOnlyList<PinnedPackageEntry> _pinnedEntries;

    private CorpusWorkerPackageSnapshot(
        string root,
        string executableRelativePath,
        IReadOnlyList<PinnedPackageEntry> pinnedEntries,
        CorpusWorkerPackageIdentity identity)
    {
        Root = root;
        ExecutableRelativePath = executableRelativePath;
        _pinnedEntries = pinnedEntries;
        Entries = pinnedEntries
            .Select(static item => item.Entry)
            .ToArray();
        Identity = identity;
    }

    internal string Root { get; }

    internal string ExecutableRelativePath { get; }

    public IReadOnlyList<CorpusWorkerPackageEntry> Entries { get; }

    public CorpusWorkerPackageIdentity Identity { get; }

    public static async Task<CorpusWorkerPackageSnapshot> CaptureAsync(
        string packageRoot,
        string workerExecutablePath,
        CancellationToken cancellationToken)
    {
        var pinned = new List<PinnedPackageEntry>();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var root = RequireRegularRoot(packageRoot);
            var executable = RequireContainedFile(
                root,
                workerExecutablePath);
            var guard = new ApprovedRootPathGuard(root);
            var paths = EnumerateRegularFiles(
                root,
                cancellationToken);
            var exact = new HashSet<string>(StringComparer.Ordinal);
            var caseFolded = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
            string? executableRelativePath = null;
            foreach (var path in paths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relativePath = NormalizeRelativePath(root, path);
                if (!exact.Add(relativePath)
                    || !caseFolded.Add(relativePath))
                {
                    throw new CorpusWorkerAttestationException();
                }

                var source =
                    guard.OpenVerifiedSourceFromApprovedRoot(path);
                try
                {
                    var hash = await source.ComputeSha256Async(
                            cancellationToken)
                        .ConfigureAwait(false);
                    var sha256 = Convert.ToHexString(hash)
                        .ToLowerInvariant();
                    CryptographicOperations.ZeroMemory(hash);
                    pinned.Add(
                        new PinnedPackageEntry(
                            new CorpusWorkerPackageEntry(
                                relativePath,
                                source.Length,
                                sha256),
                            source));
                    source = null!;
                }
                finally
                {
                    if (source is not null)
                    {
                        await source.DisposeAsync().ConfigureAwait(false);
                    }
                }

                if (string.Equals(
                        path,
                        executable,
                        StringComparison.OrdinalIgnoreCase))
                {
                    executableRelativePath = relativePath;
                }
            }

            if (executableRelativePath is null)
            {
                throw new CorpusWorkerAttestationException();
            }

            var ordered = pinned
                .OrderBy(
                    static item => item.Entry.RelativePath,
                    StringComparer.Ordinal)
                .ToArray();
            RequireSameMemberSet(
                ordered.Select(static item => item.Entry.RelativePath),
                EnumerateRegularFiles(root, cancellationToken)
                    .Select(path => NormalizeRelativePath(root, path)));
            var identity = CorpusWorkerPackageManifest.ComputeIdentity(
                ordered.Select(static item => item.Entry).ToArray(),
                executableRelativePath);
            return new CorpusWorkerPackageSnapshot(
                root,
                executableRelativePath,
                ordered,
                identity);
        }
        catch (CorpusWorkerAttestationException)
        {
            await DisposePinnedAsync(pinned).ConfigureAwait(false);
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
            await DisposePinnedAsync(pinned).ConfigureAwait(false);
            throw new CorpusWorkerAttestationException();
        }
    }

    public ValueTask DisposeAsync() =>
        new(DisposePinnedAsync(_pinnedEntries));

    internal async Task CopyToAsync(
        string destinationRoot,
        CancellationToken cancellationToken)
    {
        foreach (var pinned in _pinnedEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var destinationPath = Path.Combine(
                destinationRoot,
                pinned.Entry.RelativePath.Replace(
                    '/',
                    Path.DirectorySeparatorChar));
            Directory.CreateDirectory(
                Path.GetDirectoryName(destinationPath)
                ?? throw new CorpusWorkerAttestationException());
            await using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                81_920,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await pinned.Source.CopyToAsync(
                    output,
                    cancellationToken)
                .ConfigureAwait(false);
            await output.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
            output.Flush(flushToDisk: true);
        }
    }

    internal async Task VerifyCurrentAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            RequireSameMemberSet(
                Entries.Select(static item => item.RelativePath),
                EnumerateRegularFiles(Root, cancellationToken)
                    .Select(path => NormalizeRelativePath(Root, path)));
            foreach (var pinned in _pinnedEntries)
            {
                var hash = await pinned.Source.ComputeSha256Async(
                        cancellationToken)
                    .ConfigureAwait(false);
                var actual = Convert.ToHexString(hash).ToLowerInvariant();
                CryptographicOperations.ZeroMemory(hash);
                if (pinned.Source.Length != pinned.Entry.Length
                    || !CorpusHashing.FixedTimeEquals(
                        pinned.Entry.Sha256,
                        actual))
                {
                    throw new CorpusWorkerAttestationException();
                }
            }
        }
        catch (CorpusWorkerAttestationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or StableSourceBoundaryException
                or FileSystemBoundaryException)
        {
            throw new CorpusWorkerAttestationException();
        }
    }

    private static string RequireRegularRoot(string packageRoot)
    {
        if (!Path.IsPathFullyQualified(packageRoot))
        {
            throw new CorpusWorkerAttestationException();
        }

        var root = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(packageRoot));
        var attributes = File.GetAttributes(root);
        if ((attributes & FileAttributes.Directory) == 0
            || (attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new CorpusWorkerAttestationException();
        }

        return root;
    }

    private static string RequireContainedFile(
        string root,
        string candidatePath)
    {
        if (!Path.IsPathFullyQualified(candidatePath))
        {
            throw new CorpusWorkerAttestationException();
        }

        var candidate = Path.GetFullPath(candidatePath);
        var prefix = Path.EndsInDirectorySeparator(root)
            ? root
            : root + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(
                prefix,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new CorpusWorkerAttestationException();
        }

        return candidate;
    }

    private static IReadOnlyList<string> EnumerateRegularFiles(
        string root,
        CancellationToken cancellationToken)
    {
        var files = new List<string>();
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = pending.Pop();
            foreach (var path in Directory.EnumerateFileSystemEntries(
                         directory,
                         "*",
                         SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new CorpusWorkerAttestationException();
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    pending.Push(path);
                }
                else
                {
                    files.Add(Path.GetFullPath(path));
                }
            }
        }

        return files;
    }

    private static string NormalizeRelativePath(
        string root,
        string path)
    {
        var relative = Path.GetRelativePath(root, path)
            .Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(relative)
            || relative == "."
            || relative.StartsWith("../", StringComparison.Ordinal)
            || Path.IsPathFullyQualified(relative)
            || relative.Split('/').Any(
                static segment =>
                    string.IsNullOrEmpty(segment)
                    || segment is "." or ".."))
        {
            throw new CorpusWorkerAttestationException();
        }

        return relative;
    }

    private static void RequireSameMemberSet(
        IEnumerable<string> expected,
        IEnumerable<string> actual)
    {
        var expectedArray = expected
            .Order(StringComparer.Ordinal)
            .ToArray();
        var actualArray = actual
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!expectedArray.SequenceEqual(
                actualArray,
                StringComparer.Ordinal))
        {
            throw new CorpusWorkerAttestationException();
        }
    }

    private static async Task DisposePinnedAsync(
        IEnumerable<PinnedPackageEntry> entries)
    {
        foreach (var entry in entries.Reverse())
        {
            await entry.Source.DisposeAsync().ConfigureAwait(false);
        }
    }

    private sealed record PinnedPackageEntry(
        CorpusWorkerPackageEntry Entry,
        VerifiedStableSource Source);
}

public sealed class CorpusWorkerPackageLease
    : IAsyncDisposable
{
    private const string StageDirectoryPrefix = "run-";
    private readonly CorpusWorkerPackageSnapshot _stagedSnapshot;
    private bool _disposed;

    private CorpusWorkerPackageLease(
        string stageParent,
        string stageRoot,
        CorpusWorkerPackageSnapshot stagedSnapshot)
    {
        StageParent = stageParent;
        StageRoot = stageRoot;
        _stagedSnapshot = stagedSnapshot;
        Identity = stagedSnapshot.Identity;
        StagedExecutablePath = Path.Combine(
            stageRoot,
            stagedSnapshot.ExecutableRelativePath.Replace(
                '/',
                Path.DirectorySeparatorChar));
    }

    private string StageParent { get; }

    public string StageRoot { get; }

    public string StagedExecutablePath { get; }

    public CorpusWorkerPackageIdentity Identity { get; }

    public static async Task<CorpusWorkerPackageLease> CreateAsync(
        string packageRoot,
        string workerExecutablePath,
        string expectedPackageSha256,
        CorpusProtectedRootSet protectedRoots,
        CancellationToken cancellationToken) =>
        await CreateAsync(
                packageRoot,
                workerExecutablePath,
                expectedPackageSha256,
                protectedRoots,
                Path.Combine(
                    Path.GetTempPath(),
                    "LocalDocumentOrganizer",
                    "CorpusEval",
                    "worker-stage"),
                cancellationToken)
            .ConfigureAwait(false);

    internal static async Task<CorpusWorkerPackageLease> CreateAsync(
        string packageRoot,
        string workerExecutablePath,
        string expectedPackageSha256,
        CorpusProtectedRootSet protectedRoots,
        string stageParent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(protectedRoots);
        if (!CorpusWorkerPackageManifest.IsSha256(
                expectedPackageSha256)
            || !Path.IsPathFullyQualified(stageParent))
        {
            throw new CorpusWorkerAttestationException();
        }

        CorpusWorkerPackageSnapshot? source = null;
        CorpusWorkerPackageSnapshot? staged = null;
        string? stageRoot = null;
        stageParent = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(stageParent));
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            protectedRoots.Revalidate();
            var fullPackageRoot = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(packageRoot));
            source = await CorpusWorkerPackageSnapshot.CaptureAsync(
                    fullPackageRoot,
                    workerExecutablePath,
                    cancellationToken)
                .ConfigureAwait(false);
            var expected = expectedPackageSha256.ToLowerInvariant();
            if (!CorpusHashing.FixedTimeEquals(
                    expected,
                    source.Identity.Sha256))
            {
                throw new CorpusWorkerAttestationException();
            }

            Directory.CreateDirectory(stageParent);
            _ = new ApprovedRootPathGuard(stageParent);
            cancellationToken.ThrowIfCancellationRequested();
            stageRoot = Path.Combine(
                stageParent,
                StageDirectoryPrefix + Guid.NewGuid().ToString("N"));
            CreatePrivateDirectory(stageRoot);
            protectedRoots.RequireDisjointExisting(stageRoot);
            await source.CopyToAsync(stageRoot, cancellationToken)
                .ConfigureAwait(false);
            foreach (var entry in source.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var path = Path.Combine(
                    stageRoot,
                    entry.RelativePath.Replace(
                        '/',
                        Path.DirectorySeparatorChar));
                File.SetAttributes(
                    path,
                    File.GetAttributes(path) | FileAttributes.ReadOnly);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var stagedExecutable = Path.Combine(
                stageRoot,
                source.ExecutableRelativePath.Replace(
                    '/',
                    Path.DirectorySeparatorChar));
            staged = await CorpusWorkerPackageSnapshot.CaptureAsync(
                    stageRoot,
                    stagedExecutable,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!CorpusHashing.FixedTimeEquals(
                    expected,
                    staged.Identity.Sha256)
                || !source.Entries.SequenceEqual(staged.Entries))
            {
                throw new CorpusWorkerAttestationException();
            }

            cancellationToken.ThrowIfCancellationRequested();
            SealStageDirectory(stageRoot);
            cancellationToken.ThrowIfCancellationRequested();
            await source.DisposeAsync().ConfigureAwait(false);
            source = null;
            var lease = new CorpusWorkerPackageLease(
                stageParent,
                stageRoot,
                staged);
            staged = null;
            stageRoot = null;
            return lease;
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
            if (source is not null)
            {
                await source.DisposeAsync().ConfigureAwait(false);
            }

            if (staged is not null)
            {
                await staged.DisposeAsync().ConfigureAwait(false);
            }

            if (stageRoot is not null)
            {
                DeleteStageBounded(stageParent, stageRoot);
            }
        }
    }

    public Task VerifyAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return VerifyCoreAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _stagedSnapshot.DisposeAsync().ConfigureAwait(false);
        DeleteStageBounded(StageParent, StageRoot);
    }

    private async Task VerifyCoreAsync(
        CancellationToken cancellationToken)
    {
        await _stagedSnapshot.VerifyCurrentAsync(cancellationToken)
            .ConfigureAwait(false);
        var current = CorpusWorkerPackageManifest.ComputeIdentity(
            _stagedSnapshot.Entries,
            _stagedSnapshot.ExecutableRelativePath);
        if (!string.Equals(
                Identity.ManifestId,
                current.ManifestId,
                StringComparison.Ordinal)
            || !string.Equals(
                Identity.ManifestVersion,
                current.ManifestVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                Identity.ExecutableRelativePath,
                current.ExecutableRelativePath,
                StringComparison.Ordinal)
            || !CorpusHashing.FixedTimeEquals(
                Identity.Sha256,
                current.Sha256)
            || !CorpusHashing.FixedTimeEquals(
                Identity.ExecutableSha256,
                current.ExecutableSha256))
        {
            throw new CorpusWorkerAttestationException();
        }
    }

    internal static void CreatePrivateDirectory(string stageRoot)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User
            ?? throw new CorpusWorkerAttestationException();
        Directory.CreateDirectory(stageRoot);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(
            new FileSystemAccessRule(
                user,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        new DirectoryInfo(stageRoot).SetAccessControl(security);
    }

    private static void SealStageDirectory(string stageRoot)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User
            ?? throw new CorpusWorkerAttestationException();
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        AddReadAndExecuteRule(security, user);
        AddReadAndExecuteRule(
            security,
            new SecurityIdentifier(AppContainerProfile.DeriveSid()));
        new DirectoryInfo(stageRoot).SetAccessControl(security);
    }

    private static void AddReadAndExecuteRule(
        DirectorySecurity security,
        IdentityReference identity)
    {
        security.AddAccessRule(
            new FileSystemAccessRule(
                identity,
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
    }

    private static void DeleteStageBounded(
        string stageParent,
        string stageRoot)
    {
        var fullParent = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(stageParent));
        var fullStage = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(stageRoot));
        var relative = Path.GetRelativePath(fullParent, fullStage);
        if (!relative.StartsWith(
                StageDirectoryPrefix,
                StringComparison.Ordinal)
            || relative.Contains(Path.DirectorySeparatorChar)
            || relative.Contains(Path.AltDirectorySeparatorChar)
            || !Directory.Exists(fullStage))
        {
            return;
        }

        var attributes = File.GetAttributes(fullStage);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(fullStage);
            return;
        }

        RestoreStageForCleanup(fullStage);
        DeleteTreeWithoutFollowingReparsePoints(fullStage);
    }

    private static void RestoreStageForCleanup(string stageRoot)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User
            ?? throw new CorpusWorkerAttestationException();
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.AddAccessRule(
            new FileSystemAccessRule(
                user,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                    | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        new DirectoryInfo(stageRoot).SetAccessControl(security);
    }

    private static void DeleteTreeWithoutFollowingReparsePoints(
        string directory)
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(
                     directory,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Directory.Delete(path);
                }
                else
                {
                    File.SetAttributes(
                        path,
                        attributes & ~FileAttributes.ReadOnly);
                    File.Delete(path);
                }
            }
            else if ((attributes & FileAttributes.Directory) != 0)
            {
                DeleteTreeWithoutFollowingReparsePoints(path);
            }
            else
            {
                File.SetAttributes(
                    path,
                    attributes & ~FileAttributes.ReadOnly);
                File.Delete(path);
            }
        }

        Directory.Delete(directory);
    }
}
