using System.Runtime.InteropServices;
using System.Text;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class WindowsVaultPathGuard
{
    private const int MaximumPathBuffer = 32_768;
    private const uint InvalidFileAttributes = uint.MaxValue;
    private const uint OpenExisting = 3;
    private const uint ShareReadWriteDelete = 1 | 2 | 4;
    private const uint BackupSemantics = 0x02000000;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    internal static string NormalizeLocalDrivePath(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)
                || path.StartsWith("\\\\", StringComparison.Ordinal))
            {
                throw new VaultRecoveryRequiredException();
            }

            var fullPath = Path.GetFullPath(path);
            var root = Path.GetPathRoot(fullPath);
            if (root is null
                || root.Length != 3
                || !char.IsAsciiLetter(root[0])
                || root[1] != ':'
                || root[2] != Path.DirectorySeparatorChar
                || fullPath.AsSpan(2).Contains(':'))
            {
                throw new VaultRecoveryRequiredException();
            }

            foreach (var component in fullPath[3..].Split(Path.DirectorySeparatorChar))
            {
                if (component.EndsWith(' ')
                    || component.EndsWith('.')
                    || ContainsDosShortAliasPattern(component)
                    || IsReservedDosDeviceComponent(component))
                    throw new VaultRecoveryRequiredException();
            }

            RequireReadyLocalDrive(root);
            return fullPath;
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException
            or IOException
            or InvalidOperationException
            or NotSupportedException
            or PathTooLongException
            or UnauthorizedAccessException
            or System.Security.SecurityException)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    internal static void RequireSafeForOpen(string path)
    {
        try
        {
            var fullPath = NormalizeLocalDrivePath(path);
            RequireNoReparseOrShortAliases(fullPath);
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException
            or IOException
            or InvalidOperationException
            or NotSupportedException
            or PathTooLongException
            or UnauthorizedAccessException
            or System.Security.SecurityException)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    internal static void RequireSafeVaultSet(
        string databasePath,
        string keyRingPath,
        string lockPath)
    {
        RequireSafeDatabaseSet(databasePath);
        RequireSafeForOpen(keyRingPath);

        // A live maintenance lock is intentionally opened with FileShare.None, so
        // its link count and final path are verified on the handle after acquisition.
        RequireSafeEntryShape(lockPath);
    }

    internal static void RequireSafeDatabaseSet(string databasePath)
    {
        RequireSafeForOpen(databasePath);
        RequireSafeForOpen(databasePath + "-journal");
        RequireSafeForOpen(databasePath + "-wal");
        RequireSafeForOpen(databasePath + "-shm");
    }

    internal static void RequireSafeEntryShape(string path)
    {
        try
        {
            var fullPath = NormalizeLocalDrivePath(path);
            RequireNoReparseOrShortAliases(fullPath, requireCanonicalSingleLink: false);
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException
            or IOException
            or InvalidOperationException
            or NotSupportedException
            or PathTooLongException
            or UnauthorizedAccessException
            or System.Security.SecurityException)
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    internal static void RequireOpenedCanonicalSingleLinkFile(
        string path,
        SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        var fullPath = NormalizeLocalDrivePath(path);
        RequireCanonicalSingleLinkFile(fullPath, handle);
    }

    internal static bool EntryExists(string path)
    {
        var fullPath = NormalizeLocalDrivePath(path);
        return TryGetEntryAttributes(fullPath, out _);
    }

    private static void RequireReadyLocalDrive(string root)
    {
        var drive = new DriveInfo(root);
        if (!drive.IsReady
            || drive.DriveType is DriveType.Unknown
                or DriveType.NoRootDirectory
                or DriveType.Network
                or DriveType.CDRom)
        {
            throw new VaultRecoveryRequiredException();
        }

        var target = new StringBuilder(512);
        if (QueryDosDevice(root[..2], target, target.Capacity) == 0
            || target.ToString().StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static void RequireNoReparseOrShortAliases(
        string fullPath,
        bool requireCanonicalSingleLink = true)
    {
        for (var current = fullPath; current.Length >= 3; current = Path.GetDirectoryName(current)!)
        {
            if (!TryGetEntryAttributes(current, out var attributes)) continue;

            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new VaultRecoveryRequiredException();

            if (string.Equals(current, fullPath, StringComparison.OrdinalIgnoreCase))
            {
                if ((attributes & FileAttributes.Directory) != 0)
                    throw new VaultRecoveryRequiredException();
                if (requireCanonicalSingleLink)
                    RequireCanonicalSingleLinkFile(current);
            }
            else if ((attributes & FileAttributes.Directory) == 0)
            {
                throw new VaultRecoveryRequiredException();
            }

            if (current.Length == 3) break;
        }
    }

    private static bool ContainsDosShortAliasPattern(string component)
    {
        for (var index = 0; index + 1 < component.Length; index++)
        {
            if (component[index] == '~' && char.IsAsciiDigit(component[index + 1]))
                return true;
        }

        return false;
    }

    private static bool IsReservedDosDeviceComponent(string component)
    {
        var trimmed = component.Trim();
        var separator = trimmed.IndexOf('.');
        var stem = (separator < 0 ? trimmed : trimmed[..separator]).TrimEnd(' ', '.');
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("CONIN$", StringComparison.OrdinalIgnoreCase)
            || stem.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (stem.Length != 4
            || !(stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase)
                || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        return stem[3] is >= '1' and <= '9' or '\u00B9' or '\u00B2' or '\u00B3';
    }

    private static bool TryGetEntryAttributes(string path, out FileAttributes attributes)
    {
        var rawAttributes = GetFileAttributes(path);
        if (rawAttributes != InvalidFileAttributes)
        {
            attributes = (FileAttributes)rawAttributes;
            return true;
        }

        var error = Marshal.GetLastPInvokeError();
        if (error is ErrorFileNotFound or ErrorPathNotFound)
        {
            attributes = default;
            return false;
        }

        throw new VaultRecoveryRequiredException();
    }

    private static void RequireCanonicalSingleLinkFile(string path)
    {
        using var handle = CreateFile(
            path,
            desiredAccess: 0,
            ShareReadWriteDelete,
            IntPtr.Zero,
            OpenExisting,
            BackupSemantics,
            IntPtr.Zero);
        RequireCanonicalSingleLinkFile(path, handle);
    }

    private static void RequireCanonicalSingleLinkFile(
        string path,
        SafeFileHandle handle)
    {
        if (handle.IsInvalid
            || handle.IsClosed
            || !GetFileInformationByHandle(handle, out var information)
            || ((FileAttributes)information.FileAttributes & FileAttributes.Directory) != 0
            || ((FileAttributes)information.FileAttributes & FileAttributes.ReparsePoint) != 0
            || information.NumberOfLinks != 1
            || !string.Equals(path, GetFinalPath(handle), StringComparison.OrdinalIgnoreCase))
        {
            throw new VaultRecoveryRequiredException();
        }
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(MaximumPathBuffer);
        var length = GetFinalPathNameByHandle(handle, buffer, buffer.Capacity, fileNameFlags: 0);
        if (length == 0 || length >= buffer.Capacity)
            throw new VaultRecoveryRequiredException();
        const string extendedPrefix = "\\\\?\\";
        var result = buffer.ToString();
        if (!result.StartsWith(extendedPrefix, StringComparison.Ordinal))
            throw new VaultRecoveryRequiredException();
        return result[extendedPrefix.Length..];
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(
        string deviceName,
        StringBuilder targetPath,
        int maximumLength);

    [DllImport("kernel32.dll", EntryPoint = "GetFileAttributesW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileAttributes(string fileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        int filePathLength,
        uint fileNameFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}
