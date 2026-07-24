using System.Buffers;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Transactions;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public enum CrossVolumeFileFailure
{
    DestinationExists = 0,
    SameVolume = 1,
    PathRejected = 2,
    CopyFailed = 3,
    FlushFailed = 4,
    MetadataFailed = 5,
    LengthMismatch = 6,
    FingerprintMismatch = 7,
    SourceIdentityChanged = 8,
    DeleteFailed = 9,
    UnsupportedHandleDeletion = 10,
}

public enum CrossVolumeCleanupResult
{
    DeletedCreatedDestination = 0,
    NoCreatedDestination = 1,
    Uncertain = 2,
}

public sealed class CrossVolumeFileTransactionException : IOException
{
    internal CrossVolumeFileTransactionException(
        CrossVolumeFileFailure failure)
        : base(CreateMessage(failure))
    {
        Failure = failure;
    }

    internal CrossVolumeFileTransactionException(
        CrossVolumeFileFailure failure,
        Exception innerException)
        : base(CreateMessage(failure), innerException)
    {
        Failure = failure;
    }

    internal CrossVolumeFileTransactionException(
        CrossVolumeFileFailure failure,
        CrossVolumeCleanupResult postCreateCleanupResult,
        Exception innerException)
        : base(CreateMessage(failure), innerException)
    {
        if (postCreateCleanupResult
            == CrossVolumeCleanupResult.NoCreatedDestination)
        {
            throw new ArgumentException(
                "A post-create failure requires a definite or uncertain cleanup result.",
                nameof(postCreateCleanupResult));
        }

        Failure = failure;
        PostCreateCleanupResult = postCreateCleanupResult;
    }

    public CrossVolumeFileFailure Failure { get; }

    public CrossVolumeCleanupResult PostCreateCleanupResult { get; } =
        CrossVolumeCleanupResult.NoCreatedDestination;

    private static string CreateMessage(CrossVolumeFileFailure failure) =>
        $"The cross-volume file transaction failed at '{failure}'.";
}

internal interface ICrossVolumeFileSystemAdapter
{
    ValueTask<ICrossVolumeFileSystemSession> CreateNewAsync(
        VerifiedStableSource source,
        StableFileIdentity sourceIdentity,
        FileOperationIntent intent,
        CancellationToken cancellationToken);

    ValueTask<ICrossVolumeFileSystemSession> OpenExistingAsync(
        VerifiedStableSource source,
        VerifiedStableSource destination,
        StableFileIdentity sourceIdentity,
        FileOperationIntent intent,
        CancellationToken cancellationToken);
}

internal interface ICrossVolumeFileSystemSession : IAsyncDisposable
{
    bool CreatedDestination { get; }

    Task CopyAsync(int bufferSize, CancellationToken cancellationToken);

    void Flush();

    void CopyMetadata();

    Task<StableFileIdentity> CaptureDestinationIdentityAsync(
        Func<VerifiedStableSource, CancellationToken,
            Task<StableFileIdentity>> capture,
        CancellationToken cancellationToken);

    Task<bool> RevalidateSourceIdentityAsync(
        StableFileIdentity expectedIdentity,
        Func<VerifiedStableSource, CancellationToken,
            Task<StableFileIdentity>> capture,
        CancellationToken cancellationToken);

    void DeleteSourceByHandle();

    CrossVolumeCleanupResult CleanupDestinationByHandle();
}

public sealed class CrossVolumeFileTransaction
{
    internal const int CopyBufferSize = 64 * 1024;
    private readonly ICrossVolumeFileSystemAdapter _adapter;

    public CrossVolumeFileTransaction()
        : this(new NativeCrossVolumeFileSystemAdapter())
    {
    }

    internal CrossVolumeFileTransaction(
        ICrossVolumeFileSystemAdapter adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        _adapter = adapter;
    }

    internal async ValueTask<CrossVolumeFileSession> CreateNewAsync(
        VerifiedStableSource source,
        StableFileIdentity sourceIdentity,
        FileOperationIntent intent,
        IFileOperationFaultInjector faults,
        CancellationToken cancellationToken)
    {
        ValidateArguments(source, sourceIdentity, intent, faults);
        try
        {
            var session = await _adapter.CreateNewAsync(
                    source,
                    sourceIdentity,
                    intent,
                    cancellationToken)
                .ConfigureAwait(false);
            return new CrossVolumeFileSession(
                session,
                sourceIdentity,
                faults);
        }
        catch (IOException exception)
            when (exception is not CrossVolumeFileTransactionException)
        {
            throw MapCreateFailure(exception);
        }
    }

    internal async ValueTask<CrossVolumeFileSession> OpenExistingAsync(
        VerifiedStableSource source,
        VerifiedStableSource destination,
        StableFileIdentity sourceIdentity,
        FileOperationIntent intent,
        IFileOperationFaultInjector faults,
        CancellationToken cancellationToken)
    {
        ValidateArguments(source, sourceIdentity, intent, faults);
        ArgumentNullException.ThrowIfNull(destination);
        var session = await _adapter.OpenExistingAsync(
                source,
                destination,
                sourceIdentity,
                intent,
                cancellationToken)
            .ConfigureAwait(false);
        return new CrossVolumeFileSession(
            session,
            sourceIdentity,
            faults);
    }

    private static void ValidateArguments(
        VerifiedStableSource source,
        StableFileIdentity sourceIdentity,
        FileOperationIntent intent,
        IFileOperationFaultInjector faults)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(sourceIdentity);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(faults);
        if (intent.Kind is not (
                FileOperationKind.CrossVolumeMove
                or FileOperationKind.UndoCrossVolumeMove))
        {
            throw new ArgumentException(
                "A cross-volume operation intent is required.",
                nameof(intent));
        }
    }

    private static CrossVolumeFileTransactionException MapCreateFailure(
        IOException exception)
    {
        for (Exception? current = exception;
             current is not null;
             current = current.InnerException)
        {
            if (current is Win32Exception
                {
                    NativeErrorCode: 80 or 183,
                })
            {
                return new CrossVolumeFileTransactionException(
                    CrossVolumeFileFailure.DestinationExists,
                    exception);
            }
        }

        if ((exception.HResult & 0xffff) is 80 or 183)
        {
            return new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.DestinationExists,
                exception);
        }

        return new CrossVolumeFileTransactionException(
            CrossVolumeFileFailure.PathRejected,
            exception);
    }
}

internal sealed class CrossVolumeFileSession : IAsyncDisposable
{
    private readonly ICrossVolumeFileSystemSession _session;
    private readonly StableFileIdentity _sourceIdentity;
    private readonly IFileOperationFaultInjector _faults;

    internal CrossVolumeFileSession(
        ICrossVolumeFileSystemSession session,
        StableFileIdentity sourceIdentity,
        IFileOperationFaultInjector faults)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(sourceIdentity);
        ArgumentNullException.ThrowIfNull(faults);
        _session = session;
        _sourceIdentity = sourceIdentity;
        _faults = faults;
    }

    internal bool CreatedDestination => _session.CreatedDestination;

    internal async Task CopyFlushAndMetadataAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            await _session.CopyAsync(
                    CrossVolumeFileTransaction.CopyBufferSize,
                    cancellationToken)
                .ConfigureAwait(false);
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterCrossVolumeCopy);
        }
        catch (Exception exception) when (
            exception is not OperationCanceledException
            && exception is not CrossVolumeFileTransactionException)
        {
            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.CopyFailed,
                exception);
        }

        try
        {
            _session.Flush();
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterCrossVolumeFlush);
        }
        catch (Exception exception) when (
            exception is not CrossVolumeFileTransactionException)
        {
            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.FlushFailed,
                exception);
        }

        try
        {
            _session.CopyMetadata();
            _faults.ThrowIfRequested(
                FileOperationFaultPoint.AfterCrossVolumeMetadata);
        }
        catch (Exception exception) when (
            exception is not CrossVolumeFileTransactionException)
        {
            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.MetadataFailed,
                exception);
        }
    }

    internal async Task<StableFileIdentity> VerifyDestinationAsync(
        Func<VerifiedStableSource, CancellationToken,
            Task<StableFileIdentity>> capture,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(capture);
        _faults.ThrowIfRequested(
            FileOperationFaultPoint.BeforeCrossVolumeFingerprint);
        var destination = await _session
            .CaptureDestinationIdentityAsync(capture, cancellationToken)
            .ConfigureAwait(false);
        _faults.ThrowIfRequested(
            FileOperationFaultPoint.AfterCrossVolumeFingerprint);
        if (destination.Length != _sourceIdentity.Length)
        {
            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.LengthMismatch);
        }

        var sourceFingerprint = _sourceIdentity.KeyedFingerprint;
        var destinationFingerprint = destination.KeyedFingerprint;
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    sourceFingerprint,
                    destinationFingerprint))
            {
                throw new CrossVolumeFileTransactionException(
                    CrossVolumeFileFailure.FingerprintMismatch);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sourceFingerprint);
            CryptographicOperations.ZeroMemory(destinationFingerprint);
        }

        return destination;
    }

    internal async Task RevalidateAndDeleteSourceAsync(
        StableFileIdentity expectedIdentity,
        Func<VerifiedStableSource, CancellationToken,
            Task<StableFileIdentity>> capture,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        ArgumentNullException.ThrowIfNull(capture);
        _faults.ThrowIfRequested(
            FileOperationFaultPoint.BeforeCrossVolumeSourceRevalidation);
        if (!await _session.RevalidateSourceIdentityAsync(
                expectedIdentity,
                capture,
                cancellationToken).ConfigureAwait(false))
        {
            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.SourceIdentityChanged);
        }

        _faults.ThrowIfRequested(
            FileOperationFaultPoint.AfterCrossVolumeSourceRevalidation);
        _faults.ThrowIfRequested(
            FileOperationFaultPoint.BeforeCrossVolumeSourceDeletion);
        try
        {
            _session.DeleteSourceByHandle();
        }
        catch (CrossVolumeFileTransactionException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.DeleteFailed,
                exception);
        }

        _faults.ThrowIfRequested(
            FileOperationFaultPoint.AfterCrossVolumeSourceDeletion);
    }

    internal ValueTask<CrossVolumeCleanupResult>
        CleanupIncompleteDestinationAsync() =>
        ValueTask.FromResult(_session.CleanupDestinationByHandle());

    public ValueTask DisposeAsync() => _session.DisposeAsync();
}

internal sealed class NativeCrossVolumeFileSystemAdapter
    : ICrossVolumeFileSystemAdapter
{
    public ValueTask<ICrossVolumeFileSystemSession> CreateNewAsync(
        VerifiedStableSource source,
        StableFileIdentity sourceIdentity,
        FileOperationIntent intent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var boundaries = NativeCrossVolumeBoundaries.Open(
            sourceIdentity,
            intent);
        SafeFileHandle? destinationHandle = null;
        try
        {
            destinationHandle = WindowsFileSystemNative
                .OpenNewCrossVolumeDestinationHandle(
                    boundaries.DestinationPath);
            RequireRegularFile(destinationHandle);
            var destinationVolume = ValidatedVolume(destinationHandle);
            if (destinationVolume == boundaries.SourceVolumeId)
            {
                throw new CrossVolumeFileTransactionException(
                    CrossVolumeFileFailure.SameVolume);
            }

            var session = new NativeCrossVolumeFileSystemSession(
                source,
                existingDestination: null,
                destinationHandle,
                sourceIdentity,
                boundaries,
                createdDestination: true);
            destinationHandle = null;
            return ValueTask.FromResult<ICrossVolumeFileSystemSession>(
                session);
        }
        catch (Exception exception)
        {
            if (destinationHandle is null)
            {
                boundaries.Dispose();
                throw;
            }

            try
            {
                throw NativeCrossVolumeHandleDeletion
                    .CleanupCreatedDestinationAfterAdmissionFailure(
                        destinationHandle,
                        exception);
            }
            finally
            {
                boundaries.Dispose();
            }
        }
    }

    public ValueTask<ICrossVolumeFileSystemSession> OpenExistingAsync(
        VerifiedStableSource source,
        VerifiedStableSource destination,
        StableFileIdentity sourceIdentity,
        FileOperationIntent intent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var boundaries = NativeCrossVolumeBoundaries.Open(
            sourceIdentity,
            intent);
        try
        {
            var destinationVolume = ValidatedVolume(destination.Handle);
            if (destinationVolume == boundaries.SourceVolumeId)
            {
                throw new CrossVolumeFileTransactionException(
                    CrossVolumeFileFailure.SameVolume);
            }

            return ValueTask.FromResult<ICrossVolumeFileSystemSession>(
                new NativeCrossVolumeFileSystemSession(
                    source,
                    destination,
                    destinationHandle: null,
                    sourceIdentity,
                    boundaries,
                    createdDestination: false));
        }
        catch
        {
            boundaries.Dispose();
            throw;
        }
    }

    private static ulong ValidatedVolume(SafeFileHandle handle)
    {
        var snapshot = WindowsFileSystemNative
            .GetStableVolumeSnapshot(handle);
        return StableVolumeValidator.Validate(
            snapshot.IsLocal,
            snapshot.HasVolumeInformation,
            snapshot.FileSystemName,
            snapshot.FileId.VolumeSerialNumber);
    }

    private static void RequireRegularFile(SafeFileHandle handle)
    {
        var information = WindowsFileSystemNative.GetAttributeTagInfo(handle);
        if ((information.FileAttributes
                & (WindowsFileSystemNative.FileAttributeDirectory
                    | WindowsFileSystemNative.FileAttributeReparsePoint)) != 0)
        {
            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.PathRejected);
        }
    }
}

internal sealed class NativeCrossVolumeFileSystemSession
    : ICrossVolumeFileSystemSession
{
    private const uint FileAttributeReadOnly = 0x00000001;
    private const uint FileAttributeHidden = 0x00000002;
    private const uint FileAttributeSystem = 0x00000004;
    private const uint FileAttributeArchive = 0x00000020;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileAttributeNotContentIndexed = 0x00002000;

    private readonly VerifiedStableSource _source;
    private readonly StableFileIdentity _sourceIdentity;
    private readonly NativeCrossVolumeBoundaries _boundaries;
    private readonly bool _createdDestination;
    private SafeFileHandle? _destinationHandle;
    private VerifiedStableSource? _destination;

    internal NativeCrossVolumeFileSystemSession(
        VerifiedStableSource source,
        VerifiedStableSource? existingDestination,
        SafeFileHandle? destinationHandle,
        StableFileIdentity sourceIdentity,
        NativeCrossVolumeBoundaries boundaries,
        bool createdDestination)
    {
        _source = source;
        _destination = existingDestination;
        _destinationHandle = destinationHandle;
        _sourceIdentity = sourceIdentity;
        _boundaries = boundaries;
        _createdDestination = createdDestination;
    }

    public bool CreatedDestination => _createdDestination;

    public async Task CopyAsync(
        int bufferSize,
        CancellationToken cancellationToken)
    {
        if (!_createdDestination
            || _destinationHandle is null)
        {
            throw new InvalidOperationException(
                "Only a newly created destination can be copied.");
        }

        byte[]? buffer = null;
        try
        {
            buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
            long offset = 0;
            while (offset < _sourceIdentity.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requested = checked((int)Math.Min(
                    bufferSize,
                    _sourceIdentity.Length - offset));
                var read = await RandomAccess.ReadAsync(
                        _source.Handle,
                        buffer.AsMemory(0, requested),
                        offset,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read <= 0)
                {
                    throw new EndOfStreamException(
                        "The source ended before the locked length.");
                }

                await RandomAccess.WriteAsync(
                        _destinationHandle,
                        buffer.AsMemory(0, read),
                        offset,
                        cancellationToken)
                    .ConfigureAwait(false);
                offset = checked(offset + read);
            }
        }
        finally
        {
            if (buffer is not null)
            {
                CryptographicOperations.ZeroMemory(buffer);
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    public void Flush()
    {
        WindowsFileSystemNative.FlushFileData(DestinationHandle);
    }

    public void CopyMetadata()
    {
        var source = WindowsFileSystemNative.GetBasicInfo(_source.Handle);
        var safeAttributes = source.FileAttributes
            & (FileAttributeReadOnly
                | FileAttributeHidden
                | FileAttributeSystem
                | FileAttributeArchive
                | FileAttributeNormal
                | FileAttributeNotContentIndexed);
        if (safeAttributes == 0)
        {
            safeAttributes = FileAttributeNormal;
        }

        var destination = new WindowsFileSystemNative.FILE_BASIC_INFO
        {
            CreationTime = source.CreationTime,
            LastAccessTime = source.LastAccessTime,
            LastWriteTime = source.LastWriteTime,
            ChangeTime = 0,
            FileAttributes = safeAttributes,
        };
        var size = checked(
            (uint)Marshal.SizeOf<WindowsFileSystemNative.FILE_BASIC_INFO>());
        var buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            Marshal.StructureToPtr(destination, buffer, fDeleteOld: false);
            if (!WindowsFileSystemNative.SetFileInformationByHandle(
                    DestinationHandle,
                    WindowsFileSystemNative.FileInfoByHandleClass.FileBasicInfo,
                    buffer,
                    size))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            WindowsFileSystemNative.FlushFileData(DestinationHandle);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public async Task<StableFileIdentity> CaptureDestinationIdentityAsync(
        Func<VerifiedStableSource, CancellationToken,
            Task<StableFileIdentity>> capture,
        CancellationToken cancellationToken)
    {
        if (_destination is null)
        {
            var handle = Interlocked.Exchange(
                    ref _destinationHandle,
                    null)
                ?? throw new ObjectDisposedException(
                    nameof(NativeCrossVolumeFileSystemSession));
            _destination = VerifiedStableSource.Create(handle);
        }

        return await capture(_destination, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<bool> RevalidateSourceIdentityAsync(
        StableFileIdentity expectedIdentity,
        Func<VerifiedStableSource, CancellationToken,
            Task<StableFileIdentity>> capture,
        CancellationToken cancellationToken)
    {
        var handle = WindowsFileSystemNative
            .OpenIdentityProbeHandle(
                _boundaries.SourcePath);
        await using var probe = VerifiedStableSource.Create(handle);
        var actual = await capture(probe, cancellationToken)
            .ConfigureAwait(false);
        return expectedIdentity.FixedTimeEquals(actual);
    }

    public void DeleteSourceByHandle()
    {
        NativeCrossVolumeHandleDeletion.SetDeleteDisposition(
            _source.Handle);
    }

    public CrossVolumeCleanupResult CleanupDestinationByHandle()
    {
        if (!_createdDestination)
        {
            return CrossVolumeCleanupResult.NoCreatedDestination;
        }

        try
        {
            NativeCrossVolumeHandleDeletion.SetDeleteDisposition(
                DestinationHandle);
            return CrossVolumeCleanupResult.DeletedCreatedDestination;
        }
        catch
        {
            return CrossVolumeCleanupResult.Uncertain;
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_createdDestination)
            {
                if (_destination is not null)
                {
                    await _destination.DisposeAsync().ConfigureAwait(false);
                }
                else
                {
                    _destinationHandle?.Dispose();
                }
            }
        }
        finally
        {
            _destinationHandle = null;
            _boundaries.Dispose();
        }
    }

    private SafeFileHandle DestinationHandle =>
        _destination?.Handle
        ?? _destinationHandle
        ?? throw new ObjectDisposedException(
            nameof(NativeCrossVolumeFileSystemSession));

}

internal static class NativeCrossVolumeHandleDeletion
{
    private const int ErrorInvalidFunction = 1;
    private const int ErrorNotSupported = 50;
    private const int ErrorInvalidParameter = 87;

    internal static CrossVolumeFileTransactionException
        CleanupCreatedDestinationAfterAdmissionFailure(
            SafeFileHandle handle,
            Exception admissionFailure)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(admissionFailure);
        var cleanup =
            CrossVolumeCleanupResult.DeletedCreatedDestination;
        Exception? cleanupFailure = null;
        try
        {
            SetDeleteDisposition(handle);
        }
        catch (Exception exception)
        {
            cleanup = CrossVolumeCleanupResult.Uncertain;
            cleanupFailure = exception;
        }
        finally
        {
            handle.Dispose();
        }

        var failure =
            admissionFailure is CrossVolumeFileTransactionException
                crossVolumeFailure
                ? crossVolumeFailure.Failure
                : CrossVolumeFileFailure.PathRejected;
        return new CrossVolumeFileTransactionException(
            failure,
            cleanup,
            cleanupFailure is null
                ? admissionFailure
                : new AggregateException(
                    admissionFailure,
                    cleanupFailure));
    }

    internal static void SetDeleteDisposition(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        var information =
            new WindowsFileSystemNative.FILE_DISPOSITION_INFO_EX
            {
                Flags =
                    WindowsFileSystemNative.FILE_DISPOSITION_DELETE
                    | WindowsFileSystemNative.FILE_DISPOSITION_ON_CLOSE
                    | WindowsFileSystemNative
                        .FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
            };
        var size = checked(
            (uint)Marshal.SizeOf<
                WindowsFileSystemNative.FILE_DISPOSITION_INFO_EX>());
        var buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            Marshal.StructureToPtr(information, buffer, fDeleteOld: false);
            if (WindowsFileSystemNative.SetFileInformationByHandle(
                    handle,
                    WindowsFileSystemNative.FileInfoByHandleClass
                        .FileDispositionInfoEx,
                    buffer,
                    size))
            {
                return;
            }

            var error = Marshal.GetLastPInvokeError();
            if (error is
                ErrorInvalidFunction
                or ErrorNotSupported
                or ErrorInvalidParameter)
            {
                SetLegacyDeleteDisposition(handle);
                return;
            }

            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.DeleteFailed,
                new Win32Exception(error));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void SetLegacyDeleteDisposition(
        SafeFileHandle handle)
    {
        var information =
            new WindowsFileSystemNative.FILE_DISPOSITION_INFO
            {
                DeleteFile = true,
            };
        var size = checked(
            (uint)Marshal.SizeOf<
                WindowsFileSystemNative.FILE_DISPOSITION_INFO>());
        var buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            Marshal.StructureToPtr(
                information,
                buffer,
                fDeleteOld: false);
            if (WindowsFileSystemNative.SetFileInformationByHandle(
                    handle,
                    WindowsFileSystemNative.FileInfoByHandleClass
                        .FileDispositionInfo,
                    buffer,
                    size))
            {
                return;
            }

            var error = Marshal.GetLastPInvokeError();
            throw error is
                    ErrorInvalidFunction
                    or ErrorNotSupported
                    or ErrorInvalidParameter
                ? new CrossVolumeFileTransactionException(
                    CrossVolumeFileFailure.UnsupportedHandleDeletion,
                    new Win32Exception(error))
                : new CrossVolumeFileTransactionException(
                    CrossVolumeFileFailure.DeleteFailed,
                    new Win32Exception(error));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}

internal sealed class NativeCrossVolumeBoundaries : IDisposable
{
    private readonly PinnedDirectoryPathScope _sourceParent;
    private readonly PinnedDirectoryPathScope _destinationParent;

    private NativeCrossVolumeBoundaries(
        string sourcePath,
        string destinationPath,
        ulong sourceVolumeId,
        PinnedDirectoryPathScope sourceParent,
        PinnedDirectoryPathScope destinationParent)
    {
        SourcePath = sourcePath;
        DestinationPath = destinationPath;
        SourceVolumeId = sourceVolumeId;
        _sourceParent = sourceParent;
        _destinationParent = destinationParent;
    }

    internal string SourcePath { get; }

    internal string DestinationPath { get; }

    internal ulong SourceVolumeId { get; }

    internal static NativeCrossVolumeBoundaries Open(
        StableFileIdentity sourceIdentity,
        FileOperationIntent intent)
    {
        var sourceVolume = sourceIdentity.VolumeId;
        if (sourceVolume.Length != sizeof(ulong))
        {
            throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.PathRejected);
        }

        var sourceVolumeId =
            BinaryPrimitives.ReadUInt64LittleEndian(sourceVolume);
        var sourceGuard = new ApprovedRootPathGuard(intent.SourceRoot);
        var destinationGuard =
            new ApprovedRootPathGuard(intent.DestinationRoot);
        var sourcePath = sourceGuard.CanonicalizeContainedPath(
            intent.SourcePath);
        var destinationPath =
            destinationGuard.CanonicalizeContainedPath(
                intent.DestinationPath);
        var sourceParentPath = Path.GetDirectoryName(sourcePath)
            ?? throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.PathRejected);
        var destinationParentPath =
            Path.GetDirectoryName(destinationPath)
            ?? throw new CrossVolumeFileTransactionException(
                CrossVolumeFileFailure.PathRejected);
        var sourceParent =
            sourceGuard.OpenPinnedDirectoryPath(sourceParentPath);
        PinnedDirectoryPathScope? destinationParent = null;
        try
        {
            destinationParent =
                destinationGuard.OpenPinnedDirectoryPath(
                    destinationParentPath);
            var destinationVolumeId =
                destinationParent.FinalIdentity.VolumeSerialNumber;
            if (sourceParent.FinalIdentity.VolumeSerialNumber
                    != sourceVolumeId)
            {
                throw new CrossVolumeFileTransactionException(
                    CrossVolumeFileFailure.SourceIdentityChanged);
            }

            if (destinationVolumeId == sourceVolumeId)
            {
                throw new CrossVolumeFileTransactionException(
                    CrossVolumeFileFailure.SameVolume);
            }

            return new NativeCrossVolumeBoundaries(
                sourcePath,
                destinationPath,
                sourceVolumeId,
                sourceParent,
                destinationParent);
        }
        catch
        {
            destinationParent?.Dispose();
            sourceParent.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        _destinationParent.Dispose();
        _sourceParent.Dispose();
    }
}
