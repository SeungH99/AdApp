using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Core.Transactions;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public sealed class VaultFileFingerprintService
{
    private readonly VaultKeyRingStore _keyRing;

    public VaultFileFingerprintService(VaultKeyRingStore keyRing)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        _keyRing = keyRing;
    }

    public async Task<StableFileIdentity> CaptureAsync(
        SensitiveObjectRef owner,
        DataKeyId expectedKeyId,
        VerifiedStableSource source,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        return await _keyRing.UseFileFingerprintSubkeyAsync(
            owner,
            expectedKeyId,
            async (subkey, token) =>
            {
                await using var content = new StableSourceReadStream(
                    source.Handle,
                    source.Length);
                byte[]? fingerprint = null;
                try
                {
                    fingerprint = await KeyedContentFingerprint
                        .ComputeAsync(subkey, content, token)
                        .ConfigureAwait(false);
                    return source.CreateIdentity(fingerprint);
                }
                finally
                {
                    if (fingerprint is not null)
                        CryptographicOperations.ZeroMemory(fingerprint);
                }
            },
            cancellationToken).ConfigureAwait(false);
    }

    private sealed class StableSourceReadStream : Stream
    {
        private readonly SafeFileHandle _handle;
        private readonly long _length;
        private long _position;

        internal StableSourceReadStream(SafeFileHandle handle, long length)
        {
            _handle = handle;
            _length = length;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => _length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var count = RandomAccess.Read(_handle, buffer, _position);
            _position = checked(_position + count);
            return count;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var count = await RandomAccess
                .ReadAsync(_handle, buffer, _position, cancellationToken)
                .ConfigureAwait(false);
            _position = checked(_position + count);
            return count;
        }

        public override void Flush() => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
