using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public sealed class ApprovedRootPathGuard
{
    private readonly string _approvedPrefix;

    public ApprovedRootPathGuard(string approvedRoot)
    {
        ApprovedRoot = Canonicalize(approvedRoot, nameof(approvedRoot));
        var inspection = InspectExistingComponents(ApprovedRoot);
        if (!inspection.TargetExists
            || (inspection.TargetAttributes
                & WindowsFileSystemNative.FileAttributeDirectory) == 0)
        {
            throw new FileSystemBoundaryException(
                "The approved root must be an existing regular directory.");
        }

        _approvedPrefix = Path.EndsInDirectorySeparator(ApprovedRoot)
            ? ApprovedRoot
            : ApprovedRoot + Path.DirectorySeparatorChar;
    }

    public string ApprovedRoot { get; }

    internal string CanonicalizeContainedPath(string candidatePath) =>
        RequireContainedCanonicalPath(candidatePath);

    internal PinnedDirectoryPathScope OpenPinnedDirectoryPath(
        string candidateDirectory)
    {
        var canonical = RequireContainedCanonicalPath(candidateDirectory);
        var components = EnumerateComponents(
                canonical,
                ApprovedRoot)
            .ToArray();
        var pinned = new List<SafeFileHandle>(components.Length);
        ulong? pinnedVolumeId = null;
        try
        {
            foreach (var component in components)
            {
                var outcome = WindowsFileSystemNative
                    .OpenPinnedDirectoryPathComponent(
                        component,
                        out var handle);
                if (outcome
                        == WindowsFileSystemNative
                            .PathComponentOpenOutcome.Missing
                    || handle is null)
                {
                    throw new FileSystemBoundaryException(
                        "An approved directory-path component is unavailable.");
                }

                try
                {
                    var information =
                        WindowsFileSystemNative.GetAttributeTagInfo(handle);
                    if ((information.FileAttributes
                            & WindowsFileSystemNative
                                .FileAttributeReparsePoint) != 0
                        || (information.FileAttributes
                            & WindowsFileSystemNative
                                .FileAttributeDirectory) == 0)
                    {
                        throw new FileSystemBoundaryException(
                            "An approved path component is not a regular directory.");
                    }

                    var volume =
                        WindowsFileSystemNative.GetStableVolumeSnapshot(
                            handle);
                    var volumeId = StableVolumeValidator.Validate(
                        volume.IsLocal,
                        volume.HasVolumeInformation,
                        volume.FileSystemName,
                        volume.FileId.VolumeSerialNumber);
                    if (pinnedVolumeId is not null
                        && pinnedVolumeId.Value != volumeId)
                    {
                        throw new FileSystemBoundaryException(
                            "Approved directory-path components crossed volumes.");
                    }

                    pinnedVolumeId = volumeId;
                    pinned.Add(handle);
                }
                catch
                {
                    handle.Dispose();
                    throw;
                }
            }

            var finalIdentity = WindowsFileSystemNative.GetFileIdInfo(
                pinned[^1]);
            return new PinnedDirectoryPathScope(
                canonical,
                finalIdentity,
                pinned);
        }
        catch
        {
            PinnedDirectoryPathScope.DisposeHandles(pinned);
            throw;
        }
    }

    public VerifiedStableSource OpenVerifiedSource(string candidatePath)
    {
        var canonical = RequireContainedCanonicalPath(candidatePath);
        var components = EnumerateComponents(
                canonical,
                Path.GetPathRoot(canonical)
                    ?? throw new FileSystemBoundaryException("The path root is invalid."))
            .ToArray();
        var pinnedAncestors = new List<SafeFileHandle>(Math.Max(0, components.Length - 1));
        try
        {
            for (var index = 0; index < components.Length - 1; index++)
            {
                var outcome = WindowsFileSystemNative.OpenPinnedPathComponent(
                    components[index],
                    out var handle);
                if (outcome == WindowsFileSystemNative.PathComponentOpenOutcome.Missing)
                {
                    throw new FileSystemBoundaryException(
                        "An approved source-path component is unavailable.");
                }

                var pinned = handle
                    ?? throw new FileSystemBoundaryException(
                        "An approved source-path handle is unavailable.");
                try
                {
                    var information = WindowsFileSystemNative.GetAttributeTagInfo(pinned);
                    if ((information.FileAttributes
                            & WindowsFileSystemNative.FileAttributeReparsePoint) != 0)
                    {
                        throw new FileSystemBoundaryException(
                            "A reparse-point path component is not approved.");
                    }

                    if ((information.FileAttributes
                            & WindowsFileSystemNative.FileAttributeDirectory) == 0)
                    {
                        throw new FileSystemBoundaryException(
                            "A non-directory path component is not approved.");
                    }

                    pinnedAncestors.Add(pinned);
                }
                catch
                {
                    pinned.Dispose();
                    throw;
                }
            }

            var sourceHandle =
                WindowsFileSystemNative.OpenVerifiedSourceHandle(canonical);
            return VerifiedStableSource.Create(sourceHandle);
        }
        finally
        {
            for (var index = pinnedAncestors.Count - 1; index >= 0; index--)
                pinnedAncestors[index].Dispose();
        }
    }

    private string RequireContainedCanonicalPath(string candidatePath)
    {
        var canonical = Canonicalize(candidatePath, nameof(candidatePath));
        if (!string.Equals(canonical, ApprovedRoot, StringComparison.OrdinalIgnoreCase)
            && !canonical.StartsWith(_approvedPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new FileSystemBoundaryException(
                "The candidate path is outside the approved root.");
        }

        return canonical;
    }

    private static ComponentInspection InspectExistingComponents(string canonicalPath)
    {
        var root = Path.GetPathRoot(canonicalPath);
        if (string.IsNullOrEmpty(root))
            throw new FileSystemBoundaryException("The path root is invalid.");

        var targetExists = true;
        uint targetAttributes = 0;
        foreach (var component in EnumerateComponents(canonicalPath, root))
        {
            if (!targetExists) continue;
            var outcome = WindowsFileSystemNative.TryGetPathComponentInfo(
                component,
                out var information);
            if (outcome == WindowsFileSystemNative.PathComponentOpenOutcome.Missing)
            {
                targetExists = false;
                continue;
            }

            if ((information.FileAttributes
                    & WindowsFileSystemNative.FileAttributeReparsePoint) != 0)
            {
                throw new FileSystemBoundaryException(
                    "A reparse-point path component is not approved.");
            }

            var isTarget = string.Equals(
                component,
                canonicalPath,
                StringComparison.OrdinalIgnoreCase);
            if (!isTarget
                && (information.FileAttributes
                    & WindowsFileSystemNative.FileAttributeDirectory) == 0)
            {
                throw new FileSystemBoundaryException(
                    "A non-directory path component is not approved.");
            }

            if (isTarget) targetAttributes = information.FileAttributes;
        }

        return new ComponentInspection(targetExists, targetAttributes);
    }

    private static IEnumerable<string> EnumerateComponents(
        string canonicalPath,
        string root)
    {
        var current = root;
        yield return current;
        var relative = canonicalPath[root.Length..];
        foreach (var component in relative.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            yield return current;
        }
    }

    private static string Canonicalize(string path, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path, parameterName);
        if (!Path.IsPathFullyQualified(path))
            throw new ArgumentException("An absolute Windows path is required.", parameterName);

        string canonical;
        try
        {
            canonical = RemoveExtendedPrefix(Path.GetFullPath(path));
        }
        catch (Exception exception) when (exception is ArgumentException
            or NotSupportedException
            or PathTooLongException)
        {
            throw new ArgumentException("The Windows path is invalid.", parameterName);
        }

        var root = Path.GetPathRoot(canonical);
        if (string.IsNullOrEmpty(root))
            throw new ArgumentException("The Windows path root is invalid.", parameterName);
        foreach (var component in canonical[root.Length..].Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            if (component.Contains(':', StringComparison.Ordinal))
                throw new ArgumentException(
                    "Alternate data stream paths are not approved.",
                    parameterName);
        }

        return string.Equals(canonical, root, StringComparison.OrdinalIgnoreCase)
            ? root
            : Path.TrimEndingDirectorySeparator(canonical);
    }

    private static string RemoveExtendedPrefix(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string extendedPrefix = @"\\?\";
        if (path.StartsWith(uncPrefix, StringComparison.OrdinalIgnoreCase))
            return @"\\" + path[uncPrefix.Length..];
        return path.StartsWith(extendedPrefix, StringComparison.Ordinal)
            ? path[extendedPrefix.Length..]
            : path;
    }

    private readonly record struct ComponentInspection(
        bool TargetExists,
        uint TargetAttributes);
}

internal sealed class PinnedDirectoryPathScope : IDisposable
{
    private readonly List<SafeFileHandle> _handles;

    internal PinnedDirectoryPathScope(
        string canonicalPath,
        WindowsFileSystemNative.FILE_ID_INFO finalIdentity,
        List<SafeFileHandle> handles)
    {
        CanonicalPath = canonicalPath;
        FinalIdentity = finalIdentity;
        _handles = handles;
    }

    internal string CanonicalPath { get; }

    internal WindowsFileSystemNative.FILE_ID_INFO FinalIdentity { get; }

    public void Dispose() => DisposeHandles(_handles);

    internal static void DisposeHandles(List<SafeFileHandle> handles)
    {
        for (var index = handles.Count - 1; index >= 0; index--)
        {
            handles[index].Dispose();
        }

        handles.Clear();
    }
}
