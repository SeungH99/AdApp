using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Core.Transactions;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public sealed record OperationJournalEncryptionContext
{
    public OperationJournalEncryptionContext(
        int envelopeVersion,
        DataKeyId keyId,
        SensitiveObjectRef owner,
        OperationId operationId,
        FileOperationKind operationKind,
        OperationJournalState state,
        long revision,
        int payloadSchemaVersion)
    {
        if (envelopeVersion != EncryptedOperationJournalPayload.CurrentVersion)
        {
            throw new ArgumentOutOfRangeException(
                nameof(envelopeVersion),
                "The operation Journal encryption envelope version is not supported.");
        }

        if (keyId.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid data key ID is required.", nameof(keyId));
        }

        if (!Enum.IsDefined(owner.Kind) || owner.Id.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A valid sensitive object owner is required.",
                nameof(owner));
        }

        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "A valid operation ID is required.",
                nameof(operationId));
        }

        if (!Enum.IsDefined(operationKind))
        {
            throw new ArgumentOutOfRangeException(
                nameof(operationKind),
                "The file operation kind is not defined.");
        }

        if (!Enum.IsDefined(state))
        {
            throw new ArgumentOutOfRangeException(
                nameof(state),
                "The operation Journal state is not defined.");
        }

        if (revision <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(revision),
                revision,
                "The operation Journal revision must be positive.");
        }

        if (payloadSchemaVersion <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payloadSchemaVersion),
                payloadSchemaVersion,
                "The operation Journal payload schema version must be positive.");
        }

        EnvelopeVersion = envelopeVersion;
        KeyId = keyId;
        Owner = owner;
        OperationId = operationId;
        OperationKind = operationKind;
        State = state;
        Revision = revision;
        PayloadSchemaVersion = payloadSchemaVersion;
    }

    public int EnvelopeVersion { get; }

    public DataKeyId KeyId { get; }

    public SensitiveObjectRef Owner { get; }

    public OperationId OperationId { get; }

    public FileOperationKind OperationKind { get; }

    public OperationJournalState State { get; }

    public long Revision { get; }

    public int PayloadSchemaVersion { get; }
}

public sealed record EncryptedOperationJournalPayload
{
    internal const int CurrentVersion = 1;
    internal const int NonceSize = 12;
    internal const int TagSize = 16;

    private readonly byte[] _nonce;
    private readonly byte[] _ciphertext;
    private readonly byte[] _tag;

    public EncryptedOperationJournalPayload(
        int envelopeVersion,
        DataKeyId keyId,
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> ciphertext,
        ReadOnlyMemory<byte> tag)
    {
        if (envelopeVersion != CurrentVersion)
        {
            throw new ArgumentOutOfRangeException(
                nameof(envelopeVersion),
                "The operation Journal encryption envelope version is not supported.");
        }

        if (keyId.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid data key ID is required.", nameof(keyId));
        }

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException("The nonce length is invalid.", nameof(nonce));
        }

        if (ciphertext.Length == 0)
        {
            throw new ArgumentException(
                "The encrypted operation Journal payload cannot be empty.",
                nameof(ciphertext));
        }

        if (tag.Length != TagSize)
        {
            throw new ArgumentException(
                "The authentication tag length is invalid.",
                nameof(tag));
        }

        EnvelopeVersion = envelopeVersion;
        KeyId = keyId;
        _nonce = nonce.ToArray();
        _ciphertext = ciphertext.ToArray();
        _tag = tag.ToArray();
    }

    public int EnvelopeVersion { get; }

    public DataKeyId KeyId { get; }

    public ReadOnlyMemory<byte> Nonce => _nonce.ToArray();

    public ReadOnlyMemory<byte> Ciphertext => _ciphertext.ToArray();

    public ReadOnlyMemory<byte> Tag => _tag.ToArray();
}

public sealed class OperationJournalPayloadAuthenticationException : CryptographicException
{
    internal OperationJournalPayloadAuthenticationException()
        : base("Encrypted operation Journal payload authentication failed.")
    {
    }

    internal OperationJournalPayloadAuthenticationException(Exception innerException)
        : base("Encrypted operation Journal payload authentication failed.", innerException)
    {
    }
}

public sealed class SqliteOperationJournalPayloadProtector
{
    private const int DataKeySize = 32;
    private readonly Action<ReadOnlyMemory<byte>>? _authenticationFailureZeroedObserver;

    public SqliteOperationJournalPayloadProtector()
        : this(null)
    {
    }

    internal SqliteOperationJournalPayloadProtector(
        Action<ReadOnlyMemory<byte>>? authenticationFailureZeroedObserver)
    {
        _authenticationFailureZeroedObserver = authenticationFailureZeroedObserver;
    }

    public EncryptedOperationJournalPayload Protect(
        ReadOnlySpan<byte> dataKey,
        ReadOnlySpan<byte> plaintext,
        OperationJournalEncryptionContext context)
    {
        ValidateDataKey(dataKey);
        ArgumentNullException.ThrowIfNull(context);
        if (plaintext.IsEmpty)
        {
            throw new ArgumentException(
                "The operation Journal payload cannot be empty.",
                nameof(plaintext));
        }

        var additionalData = OperationJournalAdditionalData.Create(context);
        var nonce = RandomNumberGenerator.GetBytes(
            EncryptedOperationJournalPayload.NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[EncryptedOperationJournalPayload.TagSize];
        try
        {
            using var aes = new AesGcm(
                dataKey,
                EncryptedOperationJournalPayload.TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, additionalData);
            return new EncryptedOperationJournalPayload(
                context.EnvelopeVersion,
                context.KeyId,
                nonce,
                ciphertext,
                tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(additionalData);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public byte[] Unprotect(
        ReadOnlySpan<byte> dataKey,
        EncryptedOperationJournalPayload envelope,
        OperationJournalEncryptionContext context)
    {
        ValidateDataKey(dataKey);
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(context);

        if (envelope.EnvelopeVersion != context.EnvelopeVersion
            || envelope.KeyId != context.KeyId)
        {
            throw new OperationJournalPayloadAuthenticationException();
        }

        var additionalData = OperationJournalAdditionalData.Create(context);
        var nonce = envelope.Nonce.ToArray();
        var ciphertext = envelope.Ciphertext.ToArray();
        var tag = envelope.Tag.ToArray();
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(
                dataKey,
                EncryptedOperationJournalPayload.TagSize);
            try
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext, additionalData);
                return plaintext;
            }
            catch (AuthenticationTagMismatchException exception)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                _authenticationFailureZeroedObserver?.Invoke(plaintext);
                throw new OperationJournalPayloadAuthenticationException(exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(additionalData);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
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
