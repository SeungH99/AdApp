using System.Security.Cryptography;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public static class KeyedContentFingerprint
{
    public static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> content)
    {
        if (key.Length != AesGcmRecordProtector.DataKeySize)
        {
            throw new ArgumentException("The fingerprint key length is invalid.", nameof(key));
        }

        return HMACSHA256.HashData(key, content);
    }
}
