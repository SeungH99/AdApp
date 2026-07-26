using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.CorpusEval;

public sealed class CorpusProtectedRootSet
    : IDisposable
{
    private CorpusProtectedDirectoryLease? _package;
    private CorpusProtectedDirectoryLease? _corpus;
    private CorpusProtectedDirectoryLease? _output;

    private CorpusProtectedRootSet(
        CorpusProtectedDirectoryLease package,
        CorpusProtectedDirectoryLease corpus,
        CorpusProtectedDirectoryLease output)
    {
        _package = package;
        _corpus = corpus;
        _output = output;
    }

    public static CorpusProtectedRootSet Create(
        string packageRoot,
        string corpusRoot,
        string outputRoot)
    {
        CorpusProtectedDirectoryLease? corpus = null;
        try
        {
            corpus = CorpusProtectedDirectoryLease.OpenExisting(
                corpusRoot);
            var roots = Create(packageRoot, corpus, outputRoot);
            corpus = null;
            return roots;
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
                or System.Security.SecurityException)
        {
            throw new CorpusWorkerAttestationException();
        }
        finally
        {
            corpus?.Dispose();
        }
    }

    internal static CorpusProtectedRootSet Create(
        string packageRoot,
        CorpusProtectedDirectoryLease corpus,
        string outputRoot)
    {
        ArgumentNullException.ThrowIfNull(corpus);
        CorpusProtectedDirectoryLease? package = null;
        CorpusProtectedDirectoryLease? output = null;
        try
        {
            package = CorpusProtectedDirectoryLease.OpenExisting(
                packageRoot);
            RequireDisjoint(package, corpus);
            output = CorpusProtectedDirectoryLease.CreateOutput(
                outputRoot,
                [package, corpus]);
            RequireDisjoint(package, output);
            RequireDisjoint(corpus, output);
            var roots = new CorpusProtectedRootSet(
                package,
                corpus,
                output);
            package = null;
            output = null;
            return roots;
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
                or System.Security.SecurityException)
        {
            throw new CorpusWorkerAttestationException();
        }
        finally
        {
            package?.Dispose();
            output?.Dispose();
        }
    }

    internal void RequireDisjointExisting(string candidateRoot)
    {
        ObjectDisposedException.ThrowIf(
            _package is null || _corpus is null || _output is null,
            this);
        using var candidate =
            CorpusProtectedDirectoryLease.OpenExisting(candidateRoot);
        RequireDisjoint(_package, candidate);
        RequireDisjoint(_corpus, candidate);
        RequireDisjoint(_output, candidate);
    }

    public void Revalidate()
    {
        ObjectDisposedException.ThrowIf(
            _package is null || _corpus is null || _output is null,
            this);
        _package.Revalidate();
        _corpus.Revalidate();
        _output.Revalidate();
        RequireDisjoint(_package, _corpus);
        RequireDisjoint(_package, _output);
        RequireDisjoint(_corpus, _output);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _output, null)?.Dispose();
        Interlocked.Exchange(ref _corpus, null)?.Dispose();
        Interlocked.Exchange(ref _package, null)?.Dispose();
    }

    private static void RequireDisjoint(
        CorpusProtectedDirectoryLease left,
        CorpusProtectedDirectoryLease right)
    {
        if (left.Identity == right.Identity
            || ContainsPhysical(
                left.PhysicalPath,
                right.PhysicalPath)
            || ContainsPhysical(
                right.PhysicalPath,
                left.PhysicalPath))
        {
            throw new CorpusWorkerAttestationException();
        }
    }

    private static bool ContainsPhysical(
        string root,
        string candidate)
    {
        if (string.Equals(
                root,
                candidate,
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var prefix = Path.EndsInDirectorySeparator(root)
            ? root
            : root + Path.DirectorySeparatorChar;
        return candidate.StartsWith(
            prefix,
            StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed class CorpusProtectedDirectoryLease
    : IDisposable
{
    private PinnedDirectoryComponent? _root;

    private CorpusProtectedDirectoryLease(
        string logicalPath,
        PinnedDirectoryComponent root)
    {
        LogicalPath = logicalPath;
        _root = root;
        PhysicalPath = root.PhysicalPath;
        Identity = root.Identity;
    }

    internal string LogicalPath { get; }

    internal string PhysicalPath { get; }

    internal CorpusDirectoryIdentity Identity { get; }

    internal static CorpusProtectedDirectoryLease OpenExisting(
        string path)
    {
        var logicalPath = Canonicalize(path);
        var observed = ValidateExistingPath(logicalPath);
        PinnedDirectoryComponent? root = null;
        try
        {
            root = OpenComponent(logicalPath, pinRoot: true)
                ?? throw new CorpusWorkerAttestationException();
            RequireSameDirectory(observed, root);
            RequireSameDirectory(
                ValidateExistingPath(logicalPath),
                root);
            var lease = new CorpusProtectedDirectoryLease(
                logicalPath,
                root);
            root = null;
            return lease;
        }
        finally
        {
            observed.Handle.Dispose();
            root?.Handle.Dispose();
        }
    }

    internal static CorpusProtectedDirectoryLease CreateOutput(
        string path,
        IReadOnlyList<CorpusProtectedDirectoryLease> protectedRoots)
    {
        var logicalPath = Canonicalize(path);
        var logicalComponents = EnumerateComponents(logicalPath)
            .ToArray();
        var firstMissing = logicalComponents.Length;
        PinnedDirectoryComponent? observedAncestor = null;
        try
        {
            for (var index = 0;
                 index < logicalComponents.Length;
                 index++)
            {
                var observed = OpenComponent(
                    logicalComponents[index],
                    pinRoot: false);
                if (observed is null)
                {
                    firstMissing = index;
                    break;
                }

                observedAncestor?.Handle.Dispose();
                observedAncestor = observed;
            }
        }
        catch
        {
            observedAncestor?.Handle.Dispose();
            throw;
        }

        if (observedAncestor is null)
        {
            throw new CorpusWorkerAttestationException();
        }

        if (firstMissing == logicalComponents.Length)
        {
            observedAncestor.Handle.Dispose();
            return OpenExisting(logicalPath);
        }

        var creationPins = new List<PinnedDirectoryComponent>();
        PinnedDirectoryComponent? root = null;
        try
        {
            var ancestorPath = logicalComponents[firstMissing - 1];
            var ancestor = OpenComponent(ancestorPath, pinRoot: true)
                ?? throw new CorpusWorkerAttestationException();
            creationPins.Add(ancestor);
            RequireSameDirectory(observedAncestor, ancestor);
            observedAncestor.Handle.Dispose();
            observedAncestor = null;
            RequireSameDirectory(
                ValidateExistingPath(ancestorPath),
                ancestor);

            var predictedPhysical = ancestor.PhysicalPath;
            for (var index = firstMissing;
                 index < logicalComponents.Length;
                 index++)
            {
                var name = Path.GetFileName(logicalComponents[index]);
                if (!IsSafeNewDirectoryName(name))
                {
                    throw new CorpusWorkerAttestationException();
                }

                predictedPhysical = Path.Combine(
                    predictedPhysical,
                    name);
            }

            foreach (var protectedRoot in protectedRoots)
            {
                RequirePredictedDisjoint(
                    protectedRoot,
                    predictedPhysical);
            }

            for (var index = firstMissing;
                 index < logicalComponents.Length;
                 index++)
            {
                Directory.CreateDirectory(logicalComponents[index]);
                var created = OpenComponent(
                        logicalComponents[index],
                        pinRoot: true)
                    ?? throw new CorpusWorkerAttestationException();
                creationPins.Add(created);
            }

            root = creationPins[^1];
            if (!string.Equals(
                    root.PhysicalPath,
                    predictedPhysical,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new CorpusWorkerAttestationException();
            }

            RequireSameDirectory(
                ValidateExistingPath(logicalPath),
                root);
            foreach (var protectedRoot in protectedRoots)
            {
                RequirePredictedDisjoint(
                    protectedRoot,
                    root.PhysicalPath);
            }

            creationPins.RemoveAt(creationPins.Count - 1);
            var lease = new CorpusProtectedDirectoryLease(
                logicalPath,
                root);
            root = null;
            return lease;
        }
        finally
        {
            observedAncestor?.Handle.Dispose();
            root?.Handle.Dispose();
            DisposeComponents(creationPins);
        }
    }

    internal void Revalidate()
    {
        var root = _root
            ?? throw new ObjectDisposedException(
                nameof(CorpusProtectedDirectoryLease));
        RequireSameDirectory(
            ValidatePinnedComponent(root),
            root);
        RequireSameDirectory(
            ValidateExistingPath(LogicalPath),
            root);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _root, null)?.Handle.Dispose();
    }

    private static PinnedDirectoryComponent ValidateExistingPath(
        string logicalPath)
    {
        PinnedDirectoryComponent? final = null;
        try
        {
            foreach (var component in EnumerateComponents(logicalPath))
            {
                var observed = OpenComponent(
                        component,
                        pinRoot: false)
                    ?? throw new CorpusWorkerAttestationException();
                final?.Handle.Dispose();
                final = observed;
            }

            return final
                ?? throw new CorpusWorkerAttestationException();
        }
        catch
        {
            final?.Handle.Dispose();
            throw;
        }
    }

    private static PinnedDirectoryComponent? OpenComponent(
        string logicalPath,
        bool pinRoot)
    {
        var handle = CorpusProtectedRootNative.OpenDirectoryNoFollow(
            logicalPath,
            pinRoot);
        if (handle is null)
        {
            return null;
        }

        try
        {
            return ValidatePinnedComponent(handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static PinnedDirectoryComponent ValidatePinnedComponent(
        SafeFileHandle handle)
    {
        var attributes =
            CorpusProtectedRootNative.GetAttributes(handle);
        if ((attributes
                & (FileAttributes.Directory
                    | FileAttributes.ReparsePoint))
            != FileAttributes.Directory)
        {
            throw new CorpusWorkerAttestationException();
        }

        return new PinnedDirectoryComponent(
            handle,
            CorpusProtectedRootNative.GetFinalPath(handle),
            CorpusProtectedRootNative.GetIdentity(handle));
    }

    private static PinnedDirectoryComponent ValidatePinnedComponent(
        PinnedDirectoryComponent component)
    {
        var observed = ValidatePinnedComponent(component.Handle);
        return observed;
    }

    private static void RequireSameDirectory(
        PinnedDirectoryComponent observed,
        PinnedDirectoryComponent pinned)
    {
        try
        {
            if (observed.Identity != pinned.Identity
                || !string.Equals(
                    observed.PhysicalPath,
                    pinned.PhysicalPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new CorpusWorkerAttestationException();
            }
        }
        finally
        {
            if (!ReferenceEquals(observed.Handle, pinned.Handle))
            {
                observed.Handle.Dispose();
            }
        }
    }

    private static string Canonicalize(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var withoutPrefix = RemoveExtendedPrefix(path);
        if (!Path.IsPathFullyQualified(withoutPrefix))
        {
            throw new CorpusWorkerAttestationException();
        }

        string canonical;
        try
        {
            canonical = RemoveExtendedPrefix(
                Path.GetFullPath(withoutPrefix));
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or NotSupportedException
                or PathTooLongException)
        {
            throw new CorpusWorkerAttestationException();
        }

        var root = Path.GetPathRoot(canonical);
        if (string.IsNullOrEmpty(root))
        {
            throw new CorpusWorkerAttestationException();
        }

        var relative = canonical[root.Length..];
        if (relative.Split(
                [
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar,
                ],
                StringSplitOptions.RemoveEmptyEntries)
            .Any(
                static component =>
                    component.Contains(':')
                    || !IsSafeNewDirectoryName(component)))
        {
            throw new CorpusWorkerAttestationException();
        }

        canonical = string.Equals(
                canonical,
                root,
                StringComparison.OrdinalIgnoreCase)
            ? root
            : Path.TrimEndingDirectorySeparator(canonical);
        if (string.Equals(
                canonical,
                root,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new CorpusWorkerAttestationException();
        }

        return canonical;
    }

    private static IEnumerable<string> EnumerateComponents(
        string canonicalPath)
    {
        var root = Path.GetPathRoot(canonicalPath)
            ?? throw new CorpusWorkerAttestationException();
        var current = root;
        foreach (var component in canonicalPath[root.Length..].Split(
                     [
                         Path.DirectorySeparatorChar,
                         Path.AltDirectorySeparatorChar,
                     ],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            yield return current;
        }
    }

    private static bool IsSafeNewDirectoryName(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value is not "." and not ".."
        && !value.EndsWith(' ')
        && !value.EndsWith('.')
        && value.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    private static string RemoveExtendedPrefix(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string extendedPrefix = @"\\?\";
        if (path.StartsWith(
                uncPrefix,
                StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[uncPrefix.Length..];
        }

        return path.StartsWith(
                extendedPrefix,
                StringComparison.Ordinal)
            ? path[extendedPrefix.Length..]
            : path;
    }

    private static void RequirePredictedDisjoint(
        CorpusProtectedDirectoryLease root,
        string predictedPhysical)
    {
        if (string.Equals(
                root.PhysicalPath,
                predictedPhysical,
                StringComparison.OrdinalIgnoreCase)
            || IsAncestor(root.PhysicalPath, predictedPhysical)
            || IsAncestor(predictedPhysical, root.PhysicalPath))
        {
            throw new CorpusWorkerAttestationException();
        }
    }

    private static bool IsAncestor(string root, string candidate)
    {
        var prefix = Path.EndsInDirectorySeparator(root)
            ? root
            : root + Path.DirectorySeparatorChar;
        return candidate.StartsWith(
            prefix,
            StringComparison.OrdinalIgnoreCase);
    }

    private static void DisposeComponents(
        IEnumerable<PinnedDirectoryComponent> components)
    {
        foreach (var component in components.Reverse())
        {
            component.Handle.Dispose();
        }
    }

    private sealed record PinnedDirectoryComponent(
        SafeFileHandle Handle,
        string PhysicalPath,
        CorpusDirectoryIdentity Identity);
}

internal readonly record struct CorpusDirectoryIdentity(
    ulong VolumeSerialNumber,
    ulong FileIdLow,
    ulong FileIdHigh);

internal static class CorpusProtectedRootNative
{
    private const uint FileListDirectory = 0x00000001;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    internal static SafeFileHandle? OpenDirectoryNoFollow(
        string path,
        bool pinRoot)
    {
        var handle = CreateFile(
            ToExtendedPath(path),
            FileListDirectory | FileReadAttributes,
            pinRoot
                ? FileShareRead | FileShareWrite
                : FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        if (error is ErrorFileNotFound or ErrorPathNotFound)
        {
            return null;
        }

        throw Boundary(error);
    }

    internal static FileAttributes GetAttributes(
        SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileAttributeTagInfo,
                out FileAttributeTagInfo information,
                checked((uint)Marshal.SizeOf<FileAttributeTagInfo>())))
        {
            throw Boundary(Marshal.GetLastPInvokeError());
        }

        return (FileAttributes)information.FileAttributes;
    }

    internal static CorpusDirectoryIdentity GetIdentity(
        SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileIdInfo,
                out FileIdInfo information,
                checked((uint)Marshal.SizeOf<FileIdInfo>())))
        {
            throw Boundary(Marshal.GetLastPInvokeError());
        }

        return new CorpusDirectoryIdentity(
            information.VolumeSerialNumber,
            information.FileId.LowPart,
            information.FileId.HighPart);
    }

    internal static string GetFinalPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(512);
        var length = GetFinalPathNameByHandle(
            handle,
            buffer,
            checked((uint)buffer.Capacity),
            flags: 0);
        if (length == 0)
        {
            throw Boundary(Marshal.GetLastPInvokeError());
        }

        if (length >= buffer.Capacity)
        {
            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandle(
                handle,
                buffer,
                checked((uint)buffer.Capacity),
                flags: 0);
            if (length == 0 || length >= buffer.Capacity)
            {
                throw Boundary(Marshal.GetLastPInvokeError());
            }
        }

        var path = RemoveExtendedPrefix(buffer.ToString());
        var root = Path.GetPathRoot(path)
            ?? throw new CorpusWorkerAttestationException();
        return string.Equals(
                path,
                root,
                StringComparison.OrdinalIgnoreCase)
            ? root
            : Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(path));
    }

    private static string ToExtendedPath(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            return path;
        }

        return path.StartsWith(@"\\", StringComparison.Ordinal)
            ? @"\\?\UNC\" + path[2..]
            : @"\\?\" + path;
    }

    private static string RemoveExtendedPrefix(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string extendedPrefix = @"\\?\";
        if (path.StartsWith(
                uncPrefix,
                StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[uncPrefix.Length..];
        }

        return path.StartsWith(
                extendedPrefix,
                StringComparison.Ordinal)
            ? path[extendedPrefix.Length..]
            : path;
    }

    private static CorpusWorkerAttestationException Boundary(int _) =>
        new();

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass informationClass,
        out FileAttributeTagInfo information,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass informationClass,
        out FileIdInfo information,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFinalPathNameByHandleW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    private enum FileInfoByHandleClass
    {
        FileAttributeTagInfo = 9,
        FileIdInfo = 18,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        internal uint FileAttributes;
        internal uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId128
    {
        internal ulong LowPart;
        internal ulong HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        internal ulong VolumeSerialNumber;
        internal FileId128 FileId;
    }
}
