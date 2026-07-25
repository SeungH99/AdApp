using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Documents;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Source;

public sealed class InheritedSourceDocument : IAsyncDisposable, IDisposable
{
    private InheritedSourceDocument(
        FileStream content,
        DocumentSourceDescriptor descriptor,
        ImmutableArray<byte> verifiedSha256)
    {
        Content = content;
        ContainerKind = descriptor.ContainerKind;
        DeclaredMimeType = descriptor.DeclaredMimeType;
        VerifiedLength = descriptor.DeclaredLength;
        VerifiedSha256 = verifiedSha256;
    }

    public Stream Content { get; }

    public DocumentContainerKind ContainerKind { get; }

    public string DeclaredMimeType { get; }

    public long VerifiedLength { get; }

    public ImmutableArray<byte> VerifiedSha256 { get; }

    public static async Task<InheritedSourceDocument> OpenAndVerifyAsync(
        DocumentSourceDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        SafeFileHandle? duplicatedHandle = null;
        FileStream? content = null;
        try
        {
            duplicatedHandle = Duplicate(descriptor.InheritedHandle);
            EnsureRegularDiskFile(duplicatedHandle);
            content = new FileStream(
                duplicatedHandle,
                FileAccess.Read,
                bufferSize: 4096,
                isAsync: false);
            duplicatedHandle = null;

            if (!content.CanRead || !content.CanSeek || content.CanWrite)
            {
                throw new SourceDocumentException(
                    DocumentExtractionFailureCode.InvalidSourceHandle);
            }

            if (descriptor.DeclaredLength < 0
                || content.Length != descriptor.DeclaredLength)
            {
                throw new SourceDocumentException(
                    DocumentExtractionFailureCode.InvalidSourceLength);
            }

            if (descriptor.Sha256.IsDefaultOrEmpty || descriptor.Sha256.Length != 32)
            {
                throw new SourceDocumentException(
                    DocumentExtractionFailureCode.InvalidSourceFingerprint);
            }

            content.Position = 0;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[81920];
            try
            {
                var remaining = descriptor.DeclaredLength;
                while (remaining > 0)
                {
                    var count = (int)Math.Min(buffer.Length, remaining);
                    var read = await content.ReadAsync(
                            buffer.AsMemory(0, count),
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0)
                    {
                        throw new SourceDocumentException(
                            DocumentExtractionFailureCode.InvalidSourceLength);
                    }

                    hash.AppendData(buffer, 0, read);
                    remaining -= read;
                }

                var actualHash = hash.GetHashAndReset();
                if (!CryptographicOperations.FixedTimeEquals(
                        actualHash,
                        descriptor.Sha256.AsSpan()))
                {
                    throw new SourceDocumentException(
                        DocumentExtractionFailureCode.InvalidSourceFingerprint);
                }

                content.Position = 0;
                return new InheritedSourceDocument(
                    content,
                    descriptor,
                    ImmutableArray.Create(actualHash));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }
        catch (SourceDocumentException)
        {
            content?.Dispose();
            throw;
        }
        catch (OperationCanceledException)
        {
            content?.Dispose();
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or NotSupportedException)
        {
            content?.Dispose();
            throw new SourceDocumentException(
                DocumentExtractionFailureCode.InvalidSourceHandle,
                exception);
        }
        finally
        {
            duplicatedHandle?.Dispose();
        }
    }

    public void Dispose() => Content.Dispose();

    public ValueTask DisposeAsync() => Content.DisposeAsync();

    private static SafeFileHandle Duplicate(ulong inheritedHandle)
    {
        if (inheritedHandle == 0)
        {
            throw new SourceDocumentException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }

        var currentProcess = NativeMethods.GetCurrentProcess();
        if (!NativeMethods.DuplicateHandle(
                currentProcess,
                new IntPtr(unchecked((long)inheritedHandle)),
                currentProcess,
                out var duplicate,
                0,
                false,
                NativeMethods.DuplicateSameAccess))
        {
            throw new SourceDocumentException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }

        return duplicate;
    }

    private static void EnsureRegularDiskFile(SafeFileHandle handle)
    {
        if (NativeMethods.GetFileType(handle) != NativeMethods.FileTypeDisk
            || !NativeMethods.GetFileInformationByHandle(handle, out var information)
            || (information.FileAttributes & NativeMethods.FileAttributeDirectory) != 0)
        {
            throw new SourceDocumentException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }
    }

    private static class NativeMethods
    {
        public const uint DuplicateSameAccess = 0x00000002;
        public const uint FileTypeDisk = 0x0001;
        public const uint FileAttributeDirectory = 0x00000010;

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(
            IntPtr sourceProcessHandle,
            IntPtr sourceHandle,
            IntPtr targetProcessHandle,
            out SafeFileHandle targetHandle,
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint options);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetFileType(SafeFileHandle handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out ByHandleFileInformation fileInformation);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}

public sealed class SourceDocumentException : Exception
{
    public SourceDocumentException(
        DocumentExtractionFailureCode failureCode,
        Exception? innerException = null)
        : base("The inherited source document is invalid.", innerException)
    {
        FailureCode = failureCode;
    }

    public DocumentExtractionFailureCode FailureCode { get; }
}
