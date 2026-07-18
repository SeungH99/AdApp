using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public sealed record EventEncryptionContext
{
    public EventEncryptionContext(
        int envelopeVersion,
        DataKeyId keyId,
        SensitiveObjectRef owner,
        StreamId streamId,
        StreamVersion streamVersion,
        EventId eventId,
        string eventType,
        int schemaVersion,
        OperationId operationId)
    {
        if (envelopeVersion != 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(envelopeVersion),
                "The encryption envelope version is not supported.");
        }

        if (keyId.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid data key ID is required.", nameof(keyId));
        }

        if (!Enum.IsDefined(owner.Kind))
        {
            throw new ArgumentOutOfRangeException(
                nameof(owner),
                "The sensitive object kind is not defined.");
        }

        if (owner.Id.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid sensitive object owner is required.", nameof(owner));
        }

        ArgumentNullException.ThrowIfNull(streamId);
        if (streamId.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid stream ID is required.", nameof(streamId));
        }

        if (streamVersion.Value < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(streamVersion),
                "An encrypted event requires a persisted stream version.");
        }

        ArgumentNullException.ThrowIfNull(eventId);
        if (eventId.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid event ID is required.", nameof(eventId));
        }

        if (string.IsNullOrWhiteSpace(eventType))
        {
            throw new ArgumentException("A stable logical event type is required.", nameof(eventType));
        }

        try
        {
            _ = Encoding.UTF8.GetByteCount(eventType);
        }
        catch (ArgumentException)
        {
            throw new ArgumentException(
                "The encoded event type is too large.",
                nameof(eventType));
        }

        if (schemaVersion < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(schemaVersion),
                "Schema versions start at 1.");
        }

        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid operation ID is required.", nameof(operationId));
        }

        EnvelopeVersion = envelopeVersion;
        KeyId = keyId;
        Owner = owner;
        StreamId = streamId;
        StreamVersion = streamVersion;
        EventId = eventId;
        EventType = eventType;
        SchemaVersion = schemaVersion;
        OperationId = operationId;
    }

    public int EnvelopeVersion { get; }

    public DataKeyId KeyId { get; }

    public SensitiveObjectRef Owner { get; }

    public StreamId StreamId { get; }

    public StreamVersion StreamVersion { get; }

    public EventId EventId { get; }

    public string EventType { get; }

    public int SchemaVersion { get; }

    public OperationId OperationId { get; }
}

public sealed record EncryptedRecordEnvelope
{
    private readonly byte[] _nonce;
    private readonly byte[] _ciphertext;
    private readonly byte[] _tag;

    public EncryptedRecordEnvelope(
        int envelopeVersion,
        DataKeyId keyId,
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> ciphertext,
        ReadOnlyMemory<byte> tag)
    {
        if (envelopeVersion != 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(envelopeVersion),
                "The encryption envelope version is not supported.");
        }

        if (keyId.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid data key ID is required.", nameof(keyId));
        }

        if (nonce.Length != AesGcmRecordProtector.NonceSize)
        {
            throw new ArgumentException("The nonce length is invalid.", nameof(nonce));
        }

        if (tag.Length != AesGcmRecordProtector.TagSize)
        {
            throw new ArgumentException("The authentication tag length is invalid.", nameof(tag));
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

public interface IAuthenticatedRecordProtector
{
    EncryptedRecordEnvelope Protect(
        ReadOnlySpan<byte> dataKey,
        ReadOnlySpan<byte> plaintext,
        EventEncryptionContext context);

    byte[] Unprotect(
        ReadOnlySpan<byte> dataKey,
        EncryptedRecordEnvelope envelope,
        EventEncryptionContext context);
}

public sealed class PayloadAuthenticationException : CryptographicException
{
    internal PayloadAuthenticationException(DataKeyId keyId, EventId eventId)
        : base("Encrypted payload authentication failed.")
    {
        KeyId = keyId;
        EventId = eventId;
    }

    public DataKeyId KeyId { get; }

    public EventId EventId { get; }
}
