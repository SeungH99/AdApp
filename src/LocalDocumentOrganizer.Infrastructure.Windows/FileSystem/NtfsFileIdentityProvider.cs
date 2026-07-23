using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public readonly record struct NtfsFileIdentity(
    ulong VolumeSerialNumber,
    UInt128 FileId);

public sealed class NtfsFileIdentityProvider
{
    private readonly ApprovedRootPathGuard _pathGuard;

    public NtfsFileIdentityProvider(ApprovedRootPathGuard pathGuard)
    {
        ArgumentNullException.ThrowIfNull(pathGuard);
        _pathGuard = pathGuard;
    }

    public SafeFileHandle OpenSourceReadHandle(string path)
        => _pathGuard.OpenSourceReadHandle(path);

    public NtfsFileIdentity GetIdentity(string path)
    {
        using var handle = OpenSourceReadHandle(path);
        return GetIdentity(handle);
    }

    public NtfsFileIdentity GetIdentity(SafeFileHandle sourceHandle)
    {
        var information = WindowsFileSystemNative.GetFileIdInfo(sourceHandle);
        var fileId = ((UInt128)information.FileId.HighPart << 64)
            | information.FileId.LowPart;
        return new NtfsFileIdentity(information.VolumeSerialNumber, fileId);
    }
}
