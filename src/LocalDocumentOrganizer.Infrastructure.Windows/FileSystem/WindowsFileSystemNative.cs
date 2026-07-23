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
    private const int ErrorInvalidParameter = 87;
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
        out SafeFileHandle? handle)
    {
        RequireWindows();
        var opened = CreateFile(
            ToExtendedPath(canonicalPath),
            desiredAccess: 0,
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
        var isLocal = IsLocalFileHandle(handle);
        if (!isLocal)
        {
            return new StableSourceSnapshot(
                IsLocal: false,
                HasVolumeInformation: false,
                string.Empty,
                default,
                Length: 0,
                DateTimeOffset.UnixEpoch);
        }

        var fileSystemName = new StringBuilder(32);
        if (!GetVolumeInformationByHandle(
                handle,
                volumeNameBuffer: null,
                volumeNameSize: 0,
                out _,
                out _,
                out _,
                fileSystemName,
                checked((uint)fileSystemName.Capacity)))
        {
            return new StableSourceSnapshot(
                isLocal,
                HasVolumeInformation: false,
                string.Empty,
                default,
                Length: 0,
                DateTimeOffset.UnixEpoch);
        }

        var fileId = GetFileIdInfo(handle);
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
            isLocal,
            HasVolumeInformation: true,
            fileSystemName.ToString(),
            fileId,
            standard.EndOfFile,
            lastWriteTimeUtc);
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
        throw new StableSourceBoundaryException(
            StableSourceBoundaryFailure.UnsupportedVolume,
            new Win32Exception(error));
    }

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

    private static FILE_BASIC_INFO GetBasicInfo(SafeFileHandle handle)
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
