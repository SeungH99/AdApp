using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.Core.Transactions;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public enum SameVolumeFileFailure
{
    DestinationExists = 0,
    DifferentVolume = 1,
    PathRejected = 2,
    SourceChanged = 3,
    AccessDenied = 4,
    SharingViolation = 5,
    NativeFailure = 6,
    IdentityChanged = 7,
    DestinationEntryMissing = 8,
    DestinationIdentityMismatch = 9,
}

public abstract record SameVolumeFileTransactionResult
{
    private protected SameVolumeFileTransactionResult()
    {
    }
}

public sealed record SameVolumeFileApplied(StableFileIdentity Identity)
    : SameVolumeFileTransactionResult;

public sealed record SameVolumeFileNotApplied(SameVolumeFileFailure Failure)
    : SameVolumeFileTransactionResult;

public sealed record SameVolumeFileVerificationRequired(
    SameVolumeFileFailure Failure)
    : SameVolumeFileTransactionResult;

public sealed class SameVolumeFileTransaction
{
    private const int ErrorAccessDenied = 5;
    private const int ErrorNotSameDevice = 17;
    private const int ErrorSharingViolation = 32;
    private const int ErrorLockViolation = 33;
    private const int ErrorFileExists = 80;
    private const int ErrorAlreadyExists = 183;
    private const uint FileListDirectory = 0x00000001;

    public Task<SameVolumeFileTransactionResult> RenameNoReplaceAsync(
        VerifiedStableSource source,
        StableFileIdentity originalIdentity,
        FileOperationIntent intent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(originalIdentity);
        ArgumentNullException.ThrowIfNull(intent);
        cancellationToken.ThrowIfCancellationRequested();
        if (intent.Kind is not (
                FileOperationKind.SameVolumeMove
                or FileOperationKind.UndoSameVolumeMove))
        {
            throw new ArgumentException(
                "A same-volume operation intent is required.",
                nameof(intent));
        }

        SameVolumeFileTransactionResult result;
        try
        {
            result = RenameNoReplace(source, originalIdentity, intent);
        }
        catch (FileSystemBoundaryException exception)
        {
            result = new SameVolumeFileNotApplied(MapFailure(exception));
        }
        catch (StableSourceBoundaryException)
        {
            result = new SameVolumeFileNotApplied(
                SameVolumeFileFailure.PathRejected);
        }
        catch (UnauthorizedAccessException)
        {
            result = new SameVolumeFileNotApplied(
                SameVolumeFileFailure.AccessDenied);
        }
        catch (IOException exception)
        {
            result = new SameVolumeFileNotApplied(MapFailure(exception));
        }

        return Task.FromResult(result);
    }

    private static SameVolumeFileTransactionResult RenameNoReplace(
        VerifiedStableSource source,
        StableFileIdentity originalIdentity,
        FileOperationIntent intent)
    {
        var canonicalSource = Canonicalize(intent.SourcePath);
        if (!PathMatchesHandle(source.Handle, canonicalSource)
            || !IdentityMatchesHandle(source.Handle, originalIdentity))
        {
            return new SameVolumeFileNotApplied(
                SameVolumeFileFailure.SourceChanged);
        }

        using var destination = DestinationMutationScope.Open(
            intent.DestinationRoot,
            intent.DestinationPath);
        if (destination.Failure is { } destinationFailure)
            return new SameVolumeFileNotApplied(destinationFailure);
        if (!VolumeMatches(
                originalIdentity.VolumeId,
                destination.ParentVolumeId))
        {
            return new SameVolumeFileNotApplied(
                SameVolumeFileFailure.DifferentVolume);
        }

        var renameFailure = RenameHandleNoReplace(
            source.Handle,
            destination.CanonicalPath);
        if (renameFailure is { } failure)
            return new SameVolumeFileNotApplied(failure);

        try
        {
            if (!IdentityMatchesHandle(source.Handle, originalIdentity))
            {
                return new SameVolumeFileVerificationRequired(
                    SameVolumeFileFailure.IdentityChanged);
            }
            var destinationVerification =
                destination.VerifyDestination(originalIdentity);
            if (destinationVerification != DestinationVerification.Matched)
            {
                return new SameVolumeFileVerificationRequired(
                    destinationVerification
                        == DestinationVerification.IdentityMismatch
                            ? SameVolumeFileFailure.DestinationIdentityMismatch
                            : SameVolumeFileFailure.DestinationEntryMissing);
            }
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or UnauthorizedAccessException
                or IOException)
        {
            return new SameVolumeFileVerificationRequired(
                MapFailure(exception));
        }

        return new SameVolumeFileApplied(originalIdentity);
    }

    private static SameVolumeFileFailure? RenameHandleNoReplace(
        SafeFileHandle source,
        string destination)
    {
        var fileName = destination.ToCharArray();
        var fileNameBytes = checked((uint)(fileName.Length * sizeof(char)));
        var headerSize = checked((int)Marshal.OffsetOf<
            WindowsFileSystemNative.FILE_RENAME_INFO_EX>(
            nameof(WindowsFileSystemNative.FILE_RENAME_INFO_EX.FileName)));
        var bufferSize = checked(
            Marshal.SizeOf<WindowsFileSystemNative.FILE_RENAME_INFO_EX>()
            + (int)fileNameBytes);
        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            for (var index = 0; index < bufferSize; index++)
                Marshal.WriteByte(buffer, index, 0);
            Marshal.WriteInt32(buffer, 0, 0);
            Marshal.WriteIntPtr(
                buffer,
                IntPtr.Size == 8 ? 8 : 4,
                IntPtr.Zero);
            Marshal.WriteInt32(
                buffer,
                IntPtr.Size == 8 ? 16 : 8,
                checked((int)fileNameBytes));
            Marshal.Copy(
                fileName,
                0,
                IntPtr.Add(buffer, headerSize),
                fileName.Length);
            if (WindowsFileSystemNative.SetFileInformationByHandle(
                    source,
                    WindowsFileSystemNative.FileInfoByHandleClass.FileRenameInfoEx,
                    buffer,
                    checked((uint)bufferSize)))
            {
                return null;
            }

            return MapNativeError(Marshal.GetLastPInvokeError());
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool IdentityMatchesHandle(
        SafeFileHandle handle,
        StableFileIdentity expected)
    {
        var actual = WindowsFileSystemNative.GetFileIdInfo(handle);
        Span<byte> volume = stackalloc byte[sizeof(ulong)];
        Span<byte> file = stackalloc byte[2 * sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(
            volume,
            actual.VolumeSerialNumber);
        BinaryPrimitives.WriteUInt64LittleEndian(
            file[..sizeof(ulong)],
            actual.FileId.LowPart);
        BinaryPrimitives.WriteUInt64LittleEndian(
            file[sizeof(ulong)..],
            actual.FileId.HighPart);
        return CryptographicOperations.FixedTimeEquals(
                volume,
                expected.VolumeId)
            && CryptographicOperations.FixedTimeEquals(
                file,
                expected.FileId);
    }

    private static bool VolumeMatches(
        byte[] expectedVolume,
        ulong actualVolume)
    {
        Span<byte> actual = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(actual, actualVolume);
        return CryptographicOperations.FixedTimeEquals(
            expectedVolume,
            actual);
    }

    private static bool PathMatchesHandle(
        SafeFileHandle handle,
        string expectedPath)
    {
        var buffer = new StringBuilder(512);
        var length = GetFinalPathNameByHandle(
            handle,
            buffer,
            checked((uint)buffer.Capacity),
            0);
        if (length == 0)
            throw CreateBoundaryException(Marshal.GetLastPInvokeError());
        if (length >= buffer.Capacity)
        {
            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandle(
                handle,
                buffer,
                checked((uint)buffer.Capacity),
                0);
            if (length == 0 || length >= buffer.Capacity)
                throw CreateBoundaryException(Marshal.GetLastPInvokeError());
        }

        var actual = Canonicalize(RemoveExtendedPrefix(buffer.ToString()));
        return string.Equals(
            actual,
            expectedPath,
            StringComparison.OrdinalIgnoreCase);
    }

    private static DestinationVerification DestinationMatchesIdentity(
        SafeFileHandle parent,
        string destinationPath,
        StableFileIdentity expected)
    {
        const int bufferSize = 64 * 1024;
        const int fileIdOffset = 72;
        const int fileNameOffset = 88;
        const int errorNoMoreFiles = 18;
        var expectedName = Path.GetFileName(destinationPath);
        var expectedFileId = expected.FileId;
        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            while (true)
            {
                if (!GetFileInformationByHandleEx(
                        parent,
                        WindowsFileSystemNative.FileInfoByHandleClass
                            .FileIdExtdDirectoryInfo,
                        buffer,
                        bufferSize))
                {
                    var error = Marshal.GetLastPInvokeError();
                    if (error == errorNoMoreFiles)
                        return DestinationVerification.Missing;
                    throw CreateBoundaryException(error);
                }

                var offset = 0;
                while (true)
                {
                    var entry = IntPtr.Add(buffer, offset);
                    var fileNameLength = Marshal.ReadInt32(entry, 60);
                    if (fileNameLength < 0
                        || (fileNameLength & 1) != 0
                        || fileNameLength > bufferSize - fileNameOffset - offset)
                    {
                        throw new FileSystemBoundaryException(
                            "A directory identity record was invalid.");
                    }

                    var fileName = Marshal.PtrToStringUni(
                        IntPtr.Add(entry, fileNameOffset),
                        fileNameLength / sizeof(char));
                    if (string.Equals(
                            fileName,
                            expectedName,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        Span<byte> actualFileId =
                            stackalloc byte[2 * sizeof(ulong)];
                        BinaryPrimitives.WriteUInt64LittleEndian(
                            actualFileId[..sizeof(ulong)],
                            unchecked((ulong)Marshal.ReadInt64(
                                entry,
                                fileIdOffset)));
                        BinaryPrimitives.WriteUInt64LittleEndian(
                            actualFileId[sizeof(ulong)..],
                            unchecked((ulong)Marshal.ReadInt64(
                                entry,
                                fileIdOffset + sizeof(ulong))));
                        return CryptographicOperations.FixedTimeEquals(
                                actualFileId,
                                expectedFileId)
                            ? DestinationVerification.Matched
                            : DestinationVerification.IdentityMismatch;
                    }

                    var next = Marshal.ReadInt32(entry, 0);
                    if (next == 0)
                        break;
                    if (next < fileNameOffset
                        || offset > bufferSize - next)
                    {
                        throw new FileSystemBoundaryException(
                            "A directory identity record was invalid.");
                    }

                    offset += next;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private enum DestinationVerification
    {
        Matched,
        Missing,
        IdentityMismatch,
    }

    private static string Canonicalize(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
            throw new FileSystemBoundaryException(
                "An absolute Windows path is required.");
        var canonical = RemoveExtendedPrefix(Path.GetFullPath(path));
        var root = Path.GetPathRoot(canonical);
        if (string.IsNullOrEmpty(root))
            throw new FileSystemBoundaryException(
                "The Windows path root is invalid.");
        foreach (var component in canonical[root.Length..].Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            if (component.Contains(':', StringComparison.Ordinal))
            {
                throw new FileSystemBoundaryException(
                    "Alternate data stream paths are not approved.");
            }
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

    private static SameVolumeFileFailure MapFailure(Exception exception)
    {
        for (Exception? current = exception;
             current is not null;
             current = current.InnerException)
        {
            if (current is Win32Exception native)
                return MapNativeError(native.NativeErrorCode);
        }

        return SameVolumeFileFailure.NativeFailure;
    }

    private static SameVolumeFileFailure MapNativeError(int error) =>
        error switch
        {
            ErrorFileExists or ErrorAlreadyExists =>
                SameVolumeFileFailure.DestinationExists,
            ErrorNotSameDevice =>
                SameVolumeFileFailure.DifferentVolume,
            ErrorAccessDenied =>
                SameVolumeFileFailure.AccessDenied,
            ErrorSharingViolation or ErrorLockViolation =>
                SameVolumeFileFailure.SharingViolation,
            _ => SameVolumeFileFailure.NativeFailure,
        };

    private static FileSystemBoundaryException CreateBoundaryException(
        int error) =>
        new(
            "A native file-system boundary operation failed.",
            new Win32Exception(error));

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

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        WindowsFileSystemNative.FileInfoByHandleClass informationClass,
        IntPtr fileInformation,
        int bufferSize);

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

    private sealed class DestinationMutationScope : IDisposable
    {
        private readonly List<SafeFileHandle> _pinned;

        private DestinationMutationScope(
            string canonicalPath,
            string parentPath,
            ulong parentVolumeId,
            SameVolumeFileFailure? failure,
            List<SafeFileHandle> pinned)
        {
            CanonicalPath = canonicalPath;
            ParentPath = parentPath;
            ParentVolumeId = parentVolumeId;
            Failure = failure;
            _pinned = pinned;
        }

        internal string CanonicalPath { get; }

        internal ulong ParentVolumeId { get; }

        private string ParentPath { get; }

        internal DestinationVerification VerifyDestination(
            StableFileIdentity identity)
        {
            for (var attempt = 0; attempt < 16; attempt++)
            {
                using var parent = OpenDirectoryEnumerator(ParentPath);
                var result = DestinationMatchesIdentity(
                    parent,
                    CanonicalPath,
                    identity);
                if (result != DestinationVerification.Missing)
                    return result;
                Thread.Yield();
            }

            return DestinationVerification.Missing;
        }

        internal SameVolumeFileFailure? Failure { get; }

        internal static DestinationMutationScope Open(
            string approvedRoot,
            string destinationPath)
        {
            var guard = new ApprovedRootPathGuard(approvedRoot);
            var canonicalRoot = guard.ApprovedRoot;
            var canonicalDestination = Canonicalize(destinationPath);
            var prefix = Path.EndsInDirectorySeparator(canonicalRoot)
                ? canonicalRoot
                : canonicalRoot + Path.DirectorySeparatorChar;
            if (string.Equals(
                    canonicalDestination,
                    canonicalRoot,
                    StringComparison.OrdinalIgnoreCase)
                || !canonicalDestination.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase))
            {
                return Failed(
                    canonicalDestination,
                    SameVolumeFileFailure.PathRejected);
            }

            var parent = Path.GetDirectoryName(canonicalDestination);
            if (string.IsNullOrEmpty(parent))
            {
                return Failed(
                    canonicalDestination,
                    SameVolumeFileFailure.PathRejected);
            }

            var pinned = new List<SafeFileHandle>();
            try
            {
                var root = Path.GetPathRoot(parent);
                if (string.IsNullOrEmpty(root))
                {
                    return Failed(
                        canonicalDestination,
                        SameVolumeFileFailure.PathRejected,
                        pinned);
                }

                foreach (var component in EnumerateComponents(parent, root))
                {
                    var outcome =
                        WindowsFileSystemNative.OpenPinnedPathComponent(
                            component,
                            out var handle);
                    if (outcome
                            == WindowsFileSystemNative.PathComponentOpenOutcome.Missing
                        || handle is null)
                    {
                        return Failed(
                            canonicalDestination,
                            SameVolumeFileFailure.PathRejected,
                            pinned);
                    }

                    var information =
                        WindowsFileSystemNative.GetAttributeTagInfo(handle);
                    if ((information.FileAttributes
                            & WindowsFileSystemNative.FileAttributeReparsePoint) != 0
                        || (information.FileAttributes
                            & WindowsFileSystemNative.FileAttributeDirectory) == 0)
                    {
                        handle.Dispose();
                        return Failed(
                            canonicalDestination,
                            SameVolumeFileFailure.PathRejected,
                            pinned);
                    }

                    pinned.Add(handle);
                }

                var destinationOutcome =
                    WindowsFileSystemNative.TryGetPathComponentInfo(
                        canonicalDestination,
                        out var destinationInformation);
                if (destinationOutcome
                    == WindowsFileSystemNative.PathComponentOpenOutcome.Opened)
                {
                    var failure =
                        (destinationInformation.FileAttributes
                            & WindowsFileSystemNative.FileAttributeReparsePoint) != 0
                            ? SameVolumeFileFailure.PathRejected
                            : SameVolumeFileFailure.DestinationExists;
                    return Failed(canonicalDestination, failure, pinned);
                }

                var parentVolume =
                    WindowsFileSystemNative.GetStableVolumeSnapshot(
                        pinned[^1]);
                var parentVolumeId = StableVolumeValidator.Validate(
                    parentVolume.IsLocal,
                    parentVolume.HasVolumeInformation,
                    parentVolume.FileSystemName,
                    parentVolume.FileId.VolumeSerialNumber);
                return new DestinationMutationScope(
                    canonicalDestination,
                    parent,
                    parentVolumeId,
                    failure: null,
                    pinned);
            }
            catch
            {
                DisposePinned(pinned);
                throw;
            }
        }

        private static DestinationMutationScope Failed(
            string canonicalDestination,
            SameVolumeFileFailure failure,
            List<SafeFileHandle>? pinned = null)
        {
            if (pinned is not null)
                DisposePinned(pinned);
            return new DestinationMutationScope(
                canonicalDestination,
                parentPath: string.Empty,
                parentVolumeId: 0,
                failure,
                []);
        }

        private static SafeFileHandle OpenDirectoryEnumerator(
            string canonicalParent)
        {
            var handle = CreateFile(
                WindowsFileSystemNative.ToExtendedPath(canonicalParent),
                FileListDirectory,
                WindowsFileSystemNative.FileShareRead
                    | WindowsFileSystemNative.FileShareWrite,
                IntPtr.Zero,
                WindowsFileSystemNative.OpenExisting,
                WindowsFileSystemNative.FileFlagBackupSemantics
                    | WindowsFileSystemNative.FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                throw CreateBoundaryException(error);
            }

            try
            {
                var information =
                    WindowsFileSystemNative.GetAttributeTagInfo(handle);
                if ((information.FileAttributes
                        & WindowsFileSystemNative.FileAttributeReparsePoint) != 0
                    || (information.FileAttributes
                        & WindowsFileSystemNative.FileAttributeDirectory) == 0)
                {
                    throw new FileSystemBoundaryException(
                        "The destination parent is not an approved directory.");
                }

                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
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

        private static void DisposePinned(List<SafeFileHandle> pinned)
        {
            for (var index = pinned.Count - 1; index >= 0; index--)
                pinned[index].Dispose();
            pinned.Clear();
        }

        public void Dispose() => DisposePinned(_pinned);
    }
}
