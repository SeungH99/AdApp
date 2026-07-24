using System.Buffers.Binary;
using LocalDocumentOrganizer.Core.Transactions;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public enum StableSourceBoundaryFailure
{
    RemoteVolume,
    UnsupportedVolume,
    NonNtfsVolume,
    MissingVolumeId,
    MissingFileId,
    MultipleHardLinks,
}

public sealed class StableSourceBoundaryException : IOException
{
    internal StableSourceBoundaryException(StableSourceBoundaryFailure failure)
        : base(CreateMessage(failure))
    {
        Failure = failure;
    }

    internal StableSourceBoundaryException(
        StableSourceBoundaryFailure failure,
        Exception innerException)
        : base(CreateMessage(failure), innerException)
    {
        Failure = failure;
    }

    public StableSourceBoundaryFailure Failure { get; }

    private static string CreateMessage(StableSourceBoundaryFailure failure) =>
        failure switch
        {
            StableSourceBoundaryFailure.RemoteVolume =>
                "The source handle is not on a supported local volume.",
            StableSourceBoundaryFailure.UnsupportedVolume =>
                "The source handle does not support stable volume information.",
            StableSourceBoundaryFailure.NonNtfsVolume =>
                "The source handle is not on an NTFS volume.",
            StableSourceBoundaryFailure.MissingVolumeId =>
                "The source handle has no supported volume identifier.",
            StableSourceBoundaryFailure.MissingFileId =>
                "The source handle has no supported file identifier.",
            StableSourceBoundaryFailure.MultipleHardLinks =>
                "The file handle does not identify an exclusive single-link file.",
            _ => "The source handle is outside the stable-source boundary.",
        };
}

public sealed class VerifiedStableSource : IDisposable, IAsyncDisposable
{
    private readonly byte[] _volumeId;
    private readonly byte[] _fileId;
    private readonly List<SafeFileHandle> _pinnedAncestors;
    private SafeFileHandle? _handle;

    private VerifiedStableSource(
        SafeFileHandle handle,
        byte[] volumeId,
        byte[] fileId,
        long length,
        DateTimeOffset lastWriteTimeUtc,
        List<SafeFileHandle> pinnedAncestors)
    {
        _handle = handle;
        _volumeId = volumeId;
        _fileId = fileId;
        _pinnedAncestors = pinnedAncestors;
        Length = length;
        LastWriteTimeUtc = lastWriteTimeUtc;
    }

    internal SafeFileHandle Handle =>
        _handle is { IsClosed: false, IsInvalid: false } handle
            ? handle
            : throw new ObjectDisposedException(nameof(VerifiedStableSource));

    internal long Length { get; }

    internal DateTimeOffset LastWriteTimeUtc { get; }

    internal static VerifiedStableSource Create(SafeFileHandle handle)
        => Create(handle, []);

    internal static VerifiedStableSource Create(
        SafeFileHandle handle,
        List<SafeFileHandle> pinnedAncestors)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(pinnedAncestors);
        try
        {
            var snapshot = WindowsFileSystemNative.GetStableSourceSnapshot(handle);
            RequireSingleLink(snapshot.NumberOfLinks);
            var identifiers = StableSourceValidator.Validate(
                snapshot.IsLocal,
                snapshot.HasVolumeInformation,
                snapshot.FileSystemName,
                snapshot.FileId.VolumeSerialNumber,
                snapshot.FileId.FileId.LowPart,
                snapshot.FileId.FileId.HighPart);
            var volumeId = new byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(
                volumeId,
                identifiers.VolumeId);
            var fileId = new byte[2 * sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(
                fileId.AsSpan(0, sizeof(ulong)),
                identifiers.FileIdLow);
            BinaryPrimitives.WriteUInt64LittleEndian(
                fileId.AsSpan(sizeof(ulong), sizeof(ulong)),
                identifiers.FileIdHigh);
            return new VerifiedStableSource(
                handle,
                volumeId,
                fileId,
                snapshot.Length,
                snapshot.LastWriteTimeUtc,
                pinnedAncestors);
        }
        catch
        {
            handle.Dispose();
            PinnedDirectoryPathScope.DisposeHandles(
                pinnedAncestors);
            throw;
        }
    }

    internal void RequireSingleLink()
    {
        _ = Handle;
        RequireSingleLink(
            WindowsFileSystemNative.GetLinkCount(Handle));
    }

    internal void AttachPinnedAncestors(
        List<SafeFileHandle> pinnedAncestors)
    {
        ArgumentNullException.ThrowIfNull(pinnedAncestors);
        _ = Handle;
        _pinnedAncestors.AddRange(pinnedAncestors);
        pinnedAncestors.Clear();
    }

    internal StableFileIdentity CreateIdentity(byte[] keyedFingerprint)
    {
        _ = Handle;
        return new StableFileIdentity(
            _volumeId,
            _fileId,
            Length,
            LastWriteTimeUtc,
            keyedFingerprint);
    }

    public void Dispose()
    {
        var handle = Interlocked.Exchange(ref _handle, null);
        try
        {
            handle?.Dispose();
        }
        finally
        {
            PinnedDirectoryPathScope.DisposeHandles(
                _pinnedAncestors);
        }
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private static void RequireSingleLink(uint numberOfLinks)
    {
        if (numberOfLinks != 1)
        {
            throw new StableSourceBoundaryException(
                StableSourceBoundaryFailure.MultipleHardLinks);
        }
    }
}

internal static class StableSourceValidator
{
    internal static ValidatedStableSourceIdentifiers Validate(
        bool isLocal,
        bool hasVolumeInformation,
        string fileSystemName,
        ulong volumeId,
        ulong fileIdLow,
        ulong fileIdHigh)
    {
        var validatedVolumeId = StableVolumeValidator.Validate(
            isLocal,
            hasVolumeInformation,
            fileSystemName,
            volumeId);

        if (fileIdLow == 0 && fileIdHigh == 0)
        {
            throw new StableSourceBoundaryException(
                StableSourceBoundaryFailure.MissingFileId);
        }

        return new ValidatedStableSourceIdentifiers(
            validatedVolumeId,
            fileIdLow,
            fileIdHigh);
    }
}

internal static class StableVolumeValidator
{
    internal static ulong Validate(
        bool isLocal,
        bool hasVolumeInformation,
        string fileSystemName,
        ulong volumeId)
    {
        if (!isLocal)
        {
            throw new StableSourceBoundaryException(
                StableSourceBoundaryFailure.RemoteVolume);
        }

        if (!hasVolumeInformation)
        {
            throw new StableSourceBoundaryException(
                StableSourceBoundaryFailure.UnsupportedVolume);
        }

        if (!string.Equals(
                fileSystemName,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new StableSourceBoundaryException(
                StableSourceBoundaryFailure.NonNtfsVolume);
        }

        if (volumeId == 0)
        {
            throw new StableSourceBoundaryException(
                StableSourceBoundaryFailure.MissingVolumeId);
        }

        return volumeId;
    }
}

internal readonly record struct ValidatedStableSourceIdentifiers(
    ulong VolumeId,
    ulong FileIdLow,
    ulong FileIdHigh);

public sealed class NtfsFileIdentityProvider
{
    private readonly ApprovedRootPathGuard _pathGuard;

    public NtfsFileIdentityProvider(ApprovedRootPathGuard pathGuard)
    {
        ArgumentNullException.ThrowIfNull(pathGuard);
        _pathGuard = pathGuard;
    }

    public VerifiedStableSource OpenVerifiedSource(string path)
        => _pathGuard.OpenVerifiedSource(path);
}
