using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;

[assembly: InternalsVisibleTo("LocalDocumentOrganizer.Storage.Tests")]

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

internal sealed class SqliteEventPayloadProtectionProvider
{
    private readonly VaultKeyRingStore _keyRing;
    private readonly IAuthenticatedRecordProtector _protector;
    private readonly Action<ReadOnlyMemory<byte>>? _zeroedPlaintextObserver;

    public SqliteEventPayloadProtectionProvider(
        VaultKeyRingStore keyRing,
        IAuthenticatedRecordProtector? protector = null,
        Action<ReadOnlyMemory<byte>>? zeroedPlaintextObserver = null)
    {
        _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
        _protector = protector ?? new AesGcmRecordProtector();
        _zeroedPlaintextObserver = zeroedPlaintextObserver;
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
        => await UnprotectCoreAsync(persisted, lease: null, cancellationToken).ConfigureAwait(false);

    public async Task<EventForReplay> UnprotectAsync(
        PersistedProtectedEvent persisted,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
        => await UnprotectCoreAsync(persisted, lease, cancellationToken).ConfigureAwait(false);

    private async Task<EventForReplay> UnprotectCoreAsync(
        PersistedProtectedEvent persisted,
        VaultMaintenanceLease? lease,
        CancellationToken cancellationToken)
    {
        if (persisted.Kind == PersistedProtectionKind.Structural)
        {
            return new DecryptedEvent(persisted.Metadata, persisted.Ciphertext);
        }

        var owner = persisted.Owner ?? throw new VaultRecoveryRequiredException();
        var keyId = persisted.Metadata.DataKeyId ?? throw new VaultRecoveryRequiredException();
        try
        {
            async ValueTask<EventForReplay> DecryptAsync(
                DataKeyId resolvedId,
                ReadOnlyMemory<byte> key,
                CancellationToken token)
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
                    _zeroedPlaintextObserver?.Invoke(plaintext);
                }
            }

            EventForReplay Destroyed() => new ShreddedEvent(persisted.Metadata, owner);
            return lease is null
                ? await _keyRing.ResolveDataKeyAsync(
                    owner, keyId, Destroyed, DecryptAsync, cancellationToken).ConfigureAwait(false)
                : await _keyRing.ResolveDataKeyAsync(
                    owner, keyId, lease, Destroyed, DecryptAsync, cancellationToken).ConfigureAwait(false);
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

    private void ZeroTemporary(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
            throw new VaultRecoveryRequiredException();
        CryptographicOperations.ZeroMemory(segment.Array.AsSpan(segment.Offset, segment.Count));
        _zeroedPlaintextObserver?.Invoke(value);
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
