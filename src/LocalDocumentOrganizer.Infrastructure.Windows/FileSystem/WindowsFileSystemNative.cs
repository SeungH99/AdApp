using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

internal static class WindowsFileSystemNative
{
    internal const uint GenericRead = 0x80000000;
    internal const uint Delete = 0x00010000;
    internal const uint FileShareRead = 0x00000001;
    internal const uint FileShareWrite = 0x00000002;
    internal const uint FileShareDelete = 0x00000004;
    internal const uint OpenExisting = 3;
    internal const uint FileFlagBackupSemantics = 0x02000000;
    internal const uint FileFlagSequentialScan = 0x08000000;
    internal const uint FileFlagOverlapped = 0x40000000;
    internal const uint FileFlagOpenReparsePoint = 0x00200000;
    internal const uint FileAttributeDirectory = 0x00000010;
    internal const uint FileAttributeReparsePoint = 0x00000400;
    internal const uint FileListDirectory = 0x00000001;

    internal const uint FILE_RENAME_REPLACE_IF_EXISTS = 0x00000001;
    internal const uint FILE_RENAME_POSIX_SEMANTICS = 0x00000002;
    internal const uint FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE = 0x00000004;
    internal const uint FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE = 0x00000008;

    internal const uint FILE_DISPOSITION_DELETE = 0x00000001;
    internal const uint FILE_DISPOSITION_POSIX_SEMANTICS = 0x00000002;
    internal const uint FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK = 0x00000004;
    internal const uint FILE_DISPOSITION_ON_CLOSE = 0x00000008;
    internal const uint FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE = 0x00000010;

    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorAccessDenied = 5;
    private const int ErrorInvalidFunction = 1;
    private const int ErrorNotSupported = 50;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorIoIncomplete = 996;
    private const uint InvalidFileAttributes = uint.MaxValue;

    internal static SafeFileHandle OpenVerifiedSourceHandle(string canonicalPath)
    {
        RequireWindows();
        var handle = CreateFile(
            ToExtendedPath(canonicalPath),
            GenericRead | Delete,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan | FileFlagOverlapped,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw CreateNativeException(error);
        }

        try
        {
            var information = GetAttributeTagInfo(handle);
            if ((information.FileAttributes
                    & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0)
            {
                throw new FileSystemBoundaryException(
                    "The source entry is not an approved regular file.");
            }

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static SafeFileHandle OpenIdentityProbeHandle(
        string canonicalPath)
    {
        RequireWindows();
        var handle = CreateFile(
            ToExtendedPath(canonicalPath),
            GenericRead,
            FileShareRead | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint
                | FileFlagSequentialScan
                | FileFlagOverlapped,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw CreateNativeException(error);
        }

        try
        {
            var information = GetAttributeTagInfo(handle);
            if ((information.FileAttributes
                    & (FileAttributeDirectory
                        | FileAttributeReparsePoint)) != 0)
            {
                throw new FileSystemBoundaryException(
                    "The identity-probe entry is not an approved regular file.");
            }

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static PathComponentOpenOutcome TryGetPathComponentInfo(
        string canonicalPath,
        out FILE_ATTRIBUTE_TAG_INFO information)
    {
        RequireWindows();
        var opened = CreateFile(
            ToExtendedPath(canonicalPath),
            desiredAccess: 0,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!opened.IsInvalid)
        {
            using (opened)
            {
                information = GetAttributeTagInfo(opened);
            }

            return PathComponentOpenOutcome.Opened;
        }

        var error = Marshal.GetLastPInvokeError();
        opened.Dispose();
        if (error is ErrorFileNotFound or ErrorPathNotFound)
        {
            information = default;
            return PathComponentOpenOutcome.Missing;
        }

        if (error == ErrorAccessDenied)
        {
            var attributes = GetFileAttributes(ToExtendedPath(canonicalPath));
            if (attributes != InvalidFileAttributes)
            {
                information = new FILE_ATTRIBUTE_TAG_INFO
                {
                    FileAttributes = attributes,
                    ReparseTag = 0,
                };
                return PathComponentOpenOutcome.Opened;
            }

            error = Marshal.GetLastPInvokeError();
            if (error is ErrorFileNotFound or ErrorPathNotFound)
            {
                information = default;
                return PathComponentOpenOutcome.Missing;
            }
        }

        information = default;
        throw CreateNativeException(error);
    }

    internal static PathComponentOpenOutcome OpenPinnedPathComponent(
        string canonicalPath,
        out SafeFileHandle? handle) =>
        OpenPinnedPathComponent(
            canonicalPath,
            desiredAccess: 0,
            out handle);

    internal static PathComponentOpenOutcome OpenPinnedDirectoryPathComponent(
        string canonicalPath,
        out SafeFileHandle? handle) =>
        OpenPinnedPathComponent(
            canonicalPath,
            FileListDirectory,
            out handle);

    private static PathComponentOpenOutcome OpenPinnedPathComponent(
        string canonicalPath,
        uint desiredAccess,
        out SafeFileHandle? handle)
    {
        RequireWindows();
        var opened = CreateFile(
            ToExtendedPath(canonicalPath),
            desiredAccess,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (!opened.IsInvalid)
        {
            handle = opened;
            return PathComponentOpenOutcome.Opened;
        }

        var error = Marshal.GetLastPInvokeError();
        opened.Dispose();
        handle = null;
        if (error is ErrorFileNotFound or ErrorPathNotFound)
            return PathComponentOpenOutcome.Missing;
        throw CreateNativeException(error);
    }

    internal static SafeFileHandle OpenDirectoryChangeHandle(
        string canonicalPath)
    {
        RequireWindows();
        var opened = CreateFile(
            ToExtendedPath(canonicalPath),
            FileListDirectory,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics
                | FileFlagOpenReparsePoint
                | FileFlagOverlapped,
            IntPtr.Zero);
        if (opened.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            opened.Dispose();
            throw CreateNativeException(error);
        }

        try
        {
            var information = GetAttributeTagInfo(opened);
            if ((information.FileAttributes
                    & FileAttributeReparsePoint) != 0
                || (information.FileAttributes
                    & FileAttributeDirectory) == 0)
            {
                throw new FileSystemBoundaryException(
                    "The source parent is not an approved directory.");
            }

            return opened;
        }
        catch
        {
            opened.Dispose();
            throw;
        }
    }

    internal static SafeWaitHandle CreateDirectoryChangeEvent()
    {
        var handle = CreateEvent(
            IntPtr.Zero,
            manualReset: true,
            initialState: false,
            name: null);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw CreateNativeException(error);
        }

        return handle;
    }

    internal static void BeginDirectoryChangeObservation(
        SafeFileHandle directory,
        SafeWaitHandle changeEvent,
        IntPtr buffer,
        uint bufferLength,
        IntPtr overlapped)
    {
        RequireUsableHandle(directory);
        ArgumentNullException.ThrowIfNull(changeEvent);
        if (changeEvent.IsInvalid
            || changeEvent.IsClosed)
        {
            throw new ArgumentException(
                "A live change event is required.",
                nameof(changeEvent));
        }

        if (!ResetEvent(changeEvent))
        {
            throw CreateNativeException(Marshal.GetLastPInvokeError());
        }

        if (!ReadDirectoryChanges(
                directory,
                buffer,
                bufferLength,
                watchSubtree: false,
                notifyFilter: 0x00000001 | 0x00000002,
                IntPtr.Zero,
                overlapped,
                IntPtr.Zero))
        {
            throw CreateNativeException(Marshal.GetLastPInvokeError());
        }
    }

    internal static DirectoryChangeObservationStatus
        GetDirectoryChangeObservationStatus(
            SafeFileHandle directory,
            IntPtr buffer,
            uint bufferLength,
            IntPtr overlapped,
            string watchedFileName,
            out uint bytesTransferred,
            bool wait)
    {
        RequireUsableHandle(directory);
        ArgumentException.ThrowIfNullOrEmpty(watchedFileName);
        if (GetOverlappedResult(
                directory,
                overlapped,
                out bytesTransferred,
                wait))
        {
            return ClassifyDirectoryChanges(
                buffer,
                bufferLength,
                bytesTransferred,
                watchedFileName);
        }

        var error = Marshal.GetLastPInvokeError();
        bytesTransferred = 0;
        return !wait && error == ErrorIoIncomplete
            ? DirectoryChangeObservationStatus.Pending
            : DirectoryChangeObservationStatus.Unreliable;
    }

    internal static DirectoryChangeObservationStatus ClassifyDirectoryChanges(
        IntPtr buffer,
        uint bufferLength,
        uint bytesTransferred,
        string watchedFileName)
    {
        ArgumentException.ThrowIfNullOrEmpty(watchedFileName);
        if (buffer == IntPtr.Zero
            || bytesTransferred == 0
            || bytesTransferred > bufferLength
            || bytesTransferred > int.MaxValue)
        {
            return DirectoryChangeObservationStatus.Unreliable;
        }

        const int headerLength = sizeof(uint) * 3;
        var available = checked((int)bytesTransferred);
        var offset = 0;
        var watchedNameChanged = false;
        while (true)
        {
            if (available - offset < headerLength)
            {
                return DirectoryChangeObservationStatus.Unreliable;
            }

            var record = IntPtr.Add(buffer, offset);
            var nextOffset = unchecked((uint)Marshal.ReadInt32(record));
            var action = unchecked(
                (uint)Marshal.ReadInt32(record, sizeof(uint)));
            var fileNameLength = unchecked(
                (uint)Marshal.ReadInt32(record, sizeof(uint) * 2));
            if (action is < 1 or > 5
                || fileNameLength == 0
                || (fileNameLength & 1) != 0
                || fileNameLength > int.MaxValue
                || fileNameLength
                    > checked((uint)(available - offset - headerLength)))
            {
                return DirectoryChangeObservationStatus.Unreliable;
            }

            var fileName = Marshal.PtrToStringUni(
                IntPtr.Add(record, headerLength),
                checked((int)fileNameLength / sizeof(char)));
            if (fileName is null)
            {
                return DirectoryChangeObservationStatus.Unreliable;
            }

            watchedNameChanged |= string.Equals(
                fileName,
                watchedFileName,
                StringComparison.OrdinalIgnoreCase);
            if (nextOffset == 0)
            {
                return watchedNameChanged
                    ? DirectoryChangeObservationStatus.Changed
                    : DirectoryChangeObservationStatus.Unrelated;
            }

            var minimumRecordLength =
                checked(headerLength + (int)fileNameLength);
            if ((nextOffset & 3) != 0
                || nextOffset < minimumRecordLength
                || nextOffset > checked((uint)(available - offset)))
            {
                return DirectoryChangeObservationStatus.Unreliable;
            }

            offset = checked(offset + (int)nextOffset);
        }
    }

    internal static void CancelDirectoryChangeObservation(
        SafeFileHandle directory,
        IntPtr overlapped)
    {
        if (directory.IsInvalid || directory.IsClosed)
            return;
        _ = CancelIoEx(directory, overlapped);
        _ = GetOverlappedResult(
            directory,
            overlapped,
            out _,
            wait: true);
    }

    internal static FILE_ATTRIBUTE_TAG_INFO GetAttributeTagInfo(SafeFileHandle handle)
    {
        RequireUsableHandle(handle);
        if (!GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileAttributeTagInfo,
                out FILE_ATTRIBUTE_TAG_INFO information,
                checked((uint)Marshal.SizeOf<FILE_ATTRIBUTE_TAG_INFO>())))
        {
            throw CreateNativeException(Marshal.GetLastPInvokeError());
        }

        return information;
    }

    internal static FILE_ID_INFO GetFileIdInfo(SafeFileHandle handle)
    {
        RequireUsableHandle(handle);
        if (!GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileIdInfo,
                out FILE_ID_INFO information,
                checked((uint)Marshal.SizeOf<FILE_ID_INFO>())))
        {
            throw CreateNativeException(Marshal.GetLastPInvokeError());
        }

        return information;
    }

    internal static StableSourceSnapshot GetStableSourceSnapshot(
        SafeFileHandle handle)
    {
        RequireUsableHandle(handle);
        var volume = GetStableVolumeSnapshot(handle);
        if (!volume.IsLocal)
        {
            return new StableSourceSnapshot(
                IsLocal: false,
                HasVolumeInformation: false,
                string.Empty,
                default,
                Length: 0,
                DateTimeOffset.UnixEpoch);
        }

        if (!volume.HasVolumeInformation)
        {
            return new StableSourceSnapshot(
                volume.IsLocal,
                HasVolumeInformation: false,
                string.Empty,
                default,
                Length: 0,
                DateTimeOffset.UnixEpoch);
        }

        var standard = GetStandardInfo(handle);
        if (standard.EndOfFile < 0)
        {
            throw new FileSystemBoundaryException(
                "The source handle reported an invalid file length.");
        }

        var basic = GetBasicInfo(handle);
        DateTimeOffset lastWriteTimeUtc;
        try
        {
            lastWriteTimeUtc = DateTimeOffset
                .FromFileTime(basic.LastWriteTime)
                .ToUniversalTime();
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new FileSystemBoundaryException(
                "The source handle reported an invalid last-write time.",
                exception);
        }

        return new StableSourceSnapshot(
            volume.IsLocal,
            HasVolumeInformation: true,
            volume.FileSystemName,
            volume.FileId,
            standard.EndOfFile,
            lastWriteTimeUtc);
    }

    internal static StableVolumeSnapshot GetStableVolumeSnapshot(
        SafeFileHandle handle)
    {
        RequireUsableHandle(handle);
        var isLocal = IsLocalFileHandle(handle);
        if (!isLocal)
        {
            return new StableVolumeSnapshot(
                IsLocal: false,
                HasVolumeInformation: false,
                string.Empty,
                default);
        }

        var fileSystemName = GetVolumeFileSystemName(handle);
        return fileSystemName is null
            ? new StableVolumeSnapshot(
                isLocal,
                HasVolumeInformation: false,
                string.Empty,
                default)
            : new StableVolumeSnapshot(
                isLocal,
                HasVolumeInformation: true,
                fileSystemName,
                GetFileIdInfo(handle));
    }

    private static bool IsLocalFileHandle(SafeFileHandle handle)
    {
        if (GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileRemoteProtocolInfo,
                out FILE_REMOTE_PROTOCOL_INFO information,
                checked((uint)Marshal.SizeOf<FILE_REMOTE_PROTOCOL_INFO>())))
        {
            return information.Protocol == 0;
        }

        var error = Marshal.GetLastPInvokeError();
        if (error == ErrorInvalidParameter)
            return true;
        if (IsApprovedUnsupportedError(
                StableSourceNativeBoundary.RemoteProtocolInformation,
                error))
        {
            throw new StableSourceBoundaryException(
                StableSourceBoundaryFailure.UnsupportedVolume,
                new Win32Exception(error));
        }

        throw CreateNativeException(error);
    }

    private static string? GetVolumeFileSystemName(SafeFileHandle handle)
    {
        var fileSystemName = new StringBuilder(32);
        if (GetVolumeInformationByHandle(
                handle,
                volumeNameBuffer: null,
                volumeNameSize: 0,
                out _,
                out _,
                out _,
                fileSystemName,
                checked((uint)fileSystemName.Capacity)))
        {
            return fileSystemName.ToString();
        }

        var error = Marshal.GetLastPInvokeError();
        if (IsApprovedUnsupportedError(
                StableSourceNativeBoundary.VolumeInformation,
                error))
        {
            return null;
        }

        throw CreateNativeException(error);
    }

    internal static bool IsApprovedUnsupportedError(
        StableSourceNativeBoundary boundary,
        int error) =>
        boundary switch
        {
            StableSourceNativeBoundary.RemoteProtocolInformation =>
                error == ErrorNotSupported,
            StableSourceNativeBoundary.VolumeInformation =>
                error is ErrorInvalidFunction or ErrorNotSupported,
            _ => false,
        };

    private static FILE_STANDARD_INFO GetStandardInfo(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileStandardInfo,
                out FILE_STANDARD_INFO information,
                checked((uint)Marshal.SizeOf<FILE_STANDARD_INFO>())))
        {
            throw CreateNativeException(Marshal.GetLastPInvokeError());
        }

        return information;
    }

    internal static FILE_BASIC_INFO GetBasicInfo(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileBasicInfo,
                out FILE_BASIC_INFO information,
                checked((uint)Marshal.SizeOf<FILE_BASIC_INFO>())))
        {
            throw CreateNativeException(Marshal.GetLastPInvokeError());
        }

        return information;
    }

    internal static void FlushFileData(SafeFileHandle handle)
    {
        RequireUsableHandle(handle);
        if (!FlushFileBuffers(handle))
        {
            throw CreateNativeException(Marshal.GetLastPInvokeError());
        }
    }

    internal static string ToExtendedPath(string canonicalPath)
    {
        if (canonicalPath.StartsWith(@"\\?\", StringComparison.Ordinal))
            return canonicalPath;
        if (canonicalPath.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + canonicalPath[2..];
        return @"\\?\" + canonicalPath;
    }

    private static void RequireUsableHandle(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid || handle.IsClosed)
            throw new ArgumentException("A live file handle is required.", nameof(handle));
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("NTFS file operations require Windows.");
    }

    private static Exception CreateNativeException(int error) =>
        new FileSystemBoundaryException(
            "A native file-system boundary operation failed.",
            new Win32Exception(error));

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
        EntryPoint = "FlushFileBuffers",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle file);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateEventW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeWaitHandle CreateEvent(
        IntPtr eventAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool manualReset,
        [MarshalAs(UnmanagedType.Bool)] bool initialState,
        string? name);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "ResetEvent",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ResetEvent(SafeWaitHandle eventHandle);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "ReadDirectoryChangesW",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadDirectoryChanges(
        SafeFileHandle directory,
        IntPtr buffer,
        uint bufferLength,
        [MarshalAs(UnmanagedType.Bool)] bool watchSubtree,
        uint notifyFilter,
        IntPtr bytesReturned,
        IntPtr overlapped,
        IntPtr completionRoutine);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetOverlappedResult",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetOverlappedResult(
        SafeFileHandle file,
        IntPtr overlapped,
        out uint bytesTransferred,
        [MarshalAs(UnmanagedType.Bool)] bool wait);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CancelIoEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelIoEx(
        SafeFileHandle file,
        IntPtr overlapped);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileAttributesW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFileAttributes(string fileName);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        out FILE_ID_INFO fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        out FILE_ATTRIBUTE_TAG_INFO fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        out FILE_STANDARD_INFO fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        out FILE_BASIC_INFO fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetFileInformationByHandleEx",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        out FILE_REMOTE_PROTOCOL_INFO fileInformation,
        uint bufferSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetVolumeInformationByHandleW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandle(
        SafeFileHandle file,
        StringBuilder? volumeNameBuffer,
        uint volumeNameSize,
        out uint volumeSerialNumber,
        out uint maximumComponentLength,
        out uint fileSystemFlags,
        StringBuilder fileSystemNameBuffer,
        uint fileSystemNameSize);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "SetFileInformationByHandle",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        IntPtr fileInformation,
        uint bufferSize);

    internal enum PathComponentOpenOutcome
    {
        Opened,
        Missing,
    }

    internal enum DirectoryChangeObservationStatus
    {
        Pending,
        Unrelated,
        Changed,
        Unreliable,
    }

    internal enum StableSourceNativeBoundary
    {
        RemoteProtocolInformation,
        VolumeInformation,
    }

    internal enum FileInfoByHandleClass
    {
        FileBasicInfo = 0,
        FileStandardInfo = 1,
        FileNameInfo = 2,
        FileRenameInfo = 3,
        FileDispositionInfo = 4,
        FileAllocationInfo = 5,
        FileEndOfFileInfo = 6,
        FileStreamInfo = 7,
        FileCompressionInfo = 8,
        FileAttributeTagInfo = 9,
        FileIdBothDirectoryInfo = 10,
        FileIdBothDirectoryRestartInfo = 11,
        FileIoPriorityHintInfo = 12,
        FileRemoteProtocolInfo = 13,
        FileFullDirectoryInfo = 14,
        FileFullDirectoryRestartInfo = 15,
        FileStorageInfo = 16,
        FileAlignmentInfo = 17,
        FileIdInfo = 18,
        FileIdExtdDirectoryInfo = 19,
        FileIdExtdDirectoryRestartInfo = 20,
        FileDispositionInfoEx = 21,
        FileRenameInfoEx = 22,
        FileCaseSensitiveInfo = 23,
        FileNormalizedNameInfo = 24,
        MaximumFileInfoByHandleClass = 25,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_ID_128
    {
        internal ulong LowPart;
        internal ulong HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_ID_INFO
    {
        internal ulong VolumeSerialNumber;
        internal FILE_ID_128 FileId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_ATTRIBUTE_TAG_INFO
    {
        internal uint FileAttributes;
        internal uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_STANDARD_INFO
    {
        internal long AllocationSize;
        internal long EndOfFile;
        internal uint NumberOfLinks;

        [MarshalAs(UnmanagedType.U1)]
        internal bool DeletePending;

        [MarshalAs(UnmanagedType.U1)]
        internal bool Directory;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_BASIC_INFO
    {
        internal long CreationTime;
        internal long LastAccessTime;
        internal long LastWriteTime;
        internal long ChangeTime;
        internal uint FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential, Size = 116)]
    internal struct FILE_REMOTE_PROTOCOL_INFO
    {
        internal ushort StructureVersion;
        internal ushort StructureSize;
        internal uint Protocol;
    }

    internal readonly record struct StableSourceSnapshot(
        bool IsLocal,
        bool HasVolumeInformation,
        string FileSystemName,
        FILE_ID_INFO FileId,
        long Length,
        DateTimeOffset LastWriteTimeUtc);

    internal readonly record struct StableVolumeSnapshot(
        bool IsLocal,
        bool HasVolumeInformation,
        string FileSystemName,
        FILE_ID_INFO FileId);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FILE_RENAME_INFO_EX
    {
        internal uint Flags;
        internal IntPtr RootDirectory;
        internal uint FileNameLength;
        internal char FileName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_DISPOSITION_INFO_EX
    {
        internal uint Flags;
    }
}

public sealed class FileSystemBoundaryException : IOException
{
    internal FileSystemBoundaryException(string message)
        : base(message)
    {
    }

    internal FileSystemBoundaryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
