using System.Security.Cryptography;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public sealed class AesGcmRecordProtector : IAuthenticatedRecordProtector
{
    internal const int DataKeySize = 32;
    internal const int NonceSize = 12;
    internal const int TagSize = 16;

    private readonly Action<ReadOnlyMemory<byte>>? _authenticationFailureZeroedObserver;

    public AesGcmRecordProtector()
        : this(null)
    {
    }

    internal AesGcmRecordProtector(
        Action<ReadOnlyMemory<byte>>? authenticationFailureZeroedObserver)
    {
        _authenticationFailureZeroedObserver = authenticationFailureZeroedObserver;
    }

    public EncryptedRecordEnvelope Protect(
        ReadOnlySpan<byte> dataKey,
        ReadOnlySpan<byte> plaintext,
        EventEncryptionContext context)
    {
        ValidateDataKey(dataKey);
        ArgumentNullException.ThrowIfNull(context);

        var additionalData = EventAdditionalData.Create(context);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(dataKey, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, additionalData);

        return new EncryptedRecordEnvelope(
            context.EnvelopeVersion,
            context.KeyId,
            nonce,
            ciphertext,
            tag);
    }

    public byte[] Unprotect(
        ReadOnlySpan<byte> dataKey,
        EncryptedRecordEnvelope envelope,
        EventEncryptionContext context)
    {
        ValidateDataKey(dataKey);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(context);

        if (envelope.KeyId != context.KeyId)
        {
            throw new ArgumentException(
                "The envelope data key ID does not match the encryption context.",
                nameof(envelope));
        }

        var additionalData = EventAdditionalData.Create(context);
        var nonce = envelope.Nonce.ToArray();
        var ciphertext = envelope.Ciphertext.ToArray();
        var tag = envelope.Tag.ToArray();
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(dataKey, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, additionalData);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            _authenticationFailureZeroedObserver?.Invoke(plaintext);
            throw new PayloadAuthenticationException(context.KeyId, context.EventId);
        }
    }

    private static void ValidateDataKey(ReadOnlySpan<byte> dataKey)
    {
        if (dataKey.Length != DataKeySize)
        {
            throw new ArgumentException("The data key length is invalid.", nameof(dataKey));
        }
    }
}
