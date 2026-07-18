using System.Security.Cryptography;
using System.Runtime.InteropServices;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

internal sealed class SqliteEventPayloadProtectionProvider
{
    private readonly VaultKeyRingStore _keyRing;
    private readonly IAuthenticatedRecordProtector _protector;

    public SqliteEventPayloadProtectionProvider(
        VaultKeyRingStore keyRing,
        IAuthenticatedRecordProtector? protector = null)
    {
        _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
        _protector = protector ?? new AesGcmRecordProtector();
    }

    public VaultKeyRingStore KeyRing => _keyRing;

    public Task<VaultKeyRing> ValidateKeyRingAsync(CancellationToken cancellationToken) =>
        _keyRing.OpenAsync(cancellationToken);

    public async Task<ProtectedEventPayload> ProtectAsync(
        EventToAppend eventToAppend,
        StreamId streamId,
        StreamVersion streamVersion,
        OperationId operationId,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(eventToAppend);
        ArgumentNullException.ThrowIfNull(streamId);
        ArgumentNullException.ThrowIfNull(lease);

        if (eventToAppend.Protection is PayloadProtection.DurableStructural)
        {
            return ProtectedEventPayload.Structural(eventToAppend.Payload);
        }

        var owner = ((PayloadProtection.Shreddable)eventToAppend.Protection).Owner;
        return await _keyRing.GetOrCreateDataKeyAsync(
            owner,
            lease,
            async (keyId, key, token) =>
            {
                var plaintext = eventToAppend.Payload;
                try
                {
                    var context = new EventEncryptionContext(
                        1, keyId, owner, streamId, streamVersion, eventToAppend.EventId,
                        eventToAppend.EventType, eventToAppend.SchemaVersion, operationId);
                    var envelope = _protector.Protect(key.Span, plaintext.Span, context);
                    return await ValueTask.FromResult(ProtectedEventPayload.Shreddable(owner, envelope));
                }
                finally
                {
                    ZeroTemporary(plaintext);
                }
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<EventForReplay> UnprotectAsync(
        PersistedProtectedEvent persisted,
        CancellationToken cancellationToken)
    {
        if (persisted.Kind == PersistedProtectionKind.Structural)
        {
            return new DecryptedEvent(persisted.Metadata, persisted.Ciphertext);
        }

        var owner = persisted.Owner ?? throw new VaultRecoveryRequiredException();
        var keyId = persisted.Metadata.DataKeyId ?? throw new VaultRecoveryRequiredException();
        VaultKeyRing keyRing;
        try
        {
            keyRing = await _keyRing.OpenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }

        if (keyRing.DestroyedReceipts.Any(receipt => receipt.Owner == owner && receipt.KeyId == keyId))
        {
            return new ShreddedEvent(persisted.Metadata, owner);
        }

        if (!keyRing.ActiveKeys.Any(active => active.Owner == owner && active.KeyId == keyId))
        {
            throw new VaultRecoveryRequiredException();
        }

        try
        {
            return await _keyRing.OpenDataKeyAsync(
                owner,
                async (resolvedId, key, token) =>
                {
                    if (resolvedId != keyId) throw new VaultRecoveryRequiredException();
                    var envelope = new EncryptedRecordEnvelope(
                        persisted.Metadata.EncryptionEnvelopeVersion,
                        keyId,
                        persisted.Nonce!,
                        persisted.Ciphertext,
                        persisted.Tag!);
                    var context = new EventEncryptionContext(
                        persisted.Metadata.EncryptionEnvelopeVersion,
                        keyId,
                        owner,
                        persisted.Metadata.StreamId,
                        persisted.Metadata.StreamVersion,
                        persisted.Metadata.EventId,
                        persisted.Metadata.EventType,
                        persisted.Metadata.SchemaVersion,
                        persisted.Metadata.OperationId);
                    var plaintext = _protector.Unprotect(key.Span, envelope, context);
                    try
                    {
                        return await ValueTask.FromResult<EventForReplay>(
                            new DecryptedEvent(persisted.Metadata, plaintext));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is VaultKeyRingException or PayloadAuthenticationException or CryptographicException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    private static void ZeroTemporary(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
            throw new VaultRecoveryRequiredException();
        CryptographicOperations.ZeroMemory(segment.Array.AsSpan(segment.Offset, segment.Count));
    }
}

internal enum PersistedProtectionKind { Structural = 0, Shreddable = 1 }

internal sealed record ProtectedEventPayload(
    PersistedProtectionKind Kind,
    SensitiveObjectRef? Owner,
    DataKeyId? KeyId,
    int EnvelopeVersion,
    byte[]? Nonce,
    byte[] Ciphertext,
    byte[]? Tag)
{
    public static ProtectedEventPayload Structural(ReadOnlyMemory<byte> contentFreePayload) =>
        new(PersistedProtectionKind.Structural, null, null, 0, null, contentFreePayload.ToArray(), null);

    public static ProtectedEventPayload Shreddable(
        SensitiveObjectRef owner,
        EncryptedRecordEnvelope envelope) =>
        new(PersistedProtectionKind.Shreddable, owner, envelope.KeyId, envelope.EnvelopeVersion,
            envelope.Nonce.ToArray(), envelope.Ciphertext.ToArray(), envelope.Tag.ToArray());
}

internal sealed record PersistedProtectedEvent(
    EventMetadata Metadata,
    PersistedProtectionKind Kind,
    SensitiveObjectRef? Owner,
    byte[]? Nonce,
    byte[] Ciphertext,
    byte[]? Tag);

public sealed class VaultRecoveryRequiredException : InvalidOperationException
{
    public VaultRecoveryRequiredException() : base("Vault recovery is required.") { }
    internal VaultRecoveryRequiredException(Exception innerException)
        : base("Vault recovery is required.", innerException) { }
}

public sealed class LegacyPlaintextVaultRecoveryRequiredException : InvalidOperationException
{
    public LegacyPlaintextVaultRecoveryRequiredException()
        : base("Legacy plaintext Vault recovery is required.") { }
}
