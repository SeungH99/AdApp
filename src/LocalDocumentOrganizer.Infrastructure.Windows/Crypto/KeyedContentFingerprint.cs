using System.Buffers;
using System.Security.Cryptography;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public static class KeyedContentFingerprint
{
    private const int BufferSize = 64 * 1024;

    public static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> content)
    {
        ValidateKeyLength(key.Length);

        return HMACSHA256.HashData(key, content);
    }

    public static async Task<byte[]> ComputeAsync(
        ReadOnlyMemory<byte> key,
        Stream content,
        CancellationToken cancellationToken)
    {
        ValidateKeyLength(key.Length);
        ArgumentNullException.ThrowIfNull(content);
        if (!content.CanRead)
            throw new ArgumentException("The fingerprint content stream must be readable.", nameof(content));

        cancellationToken.ThrowIfCancellationRequested();
        byte[]? keyCopy = null;
        byte[]? buffer = null;
        try
        {
            keyCopy = key.ToArray();
            buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, keyCopy);
            while (true)
            {
                var read = await content
                    .ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0) break;
                hmac.AppendData(buffer.AsSpan(0, read));
            }

            cancellationToken.ThrowIfCancellationRequested();
            return hmac.GetHashAndReset();
        }
        finally
        {
            if (buffer is not null)
            {
                CryptographicOperations.ZeroMemory(buffer);
                ArrayPool<byte>.Shared.Return(buffer);
            }

            if (keyCopy is not null) CryptographicOperations.ZeroMemory(keyCopy);
        }
    }

    private static void ValidateKeyLength(int length)
    {
        if (length != AesGcmRecordProtector.DataKeySize)
            throw new ArgumentException("The fingerprint key length is invalid.", "key");
    }
}
