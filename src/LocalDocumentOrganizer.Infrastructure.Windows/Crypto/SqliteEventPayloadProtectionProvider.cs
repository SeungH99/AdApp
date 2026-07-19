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

    public async Task<VaultKeyRingStore.VaultKeyRingSession> OpenWriteSessionAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _keyRing.OpenWriteSessionAsync(lease, cancellationToken).ConfigureAwait(false);
        }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    internal SqliteEventPayloadReadSession CreateReadSession(VaultMaintenanceLease lease) =>
        new(this, lease);

    internal async Task<VaultKeyRingStore.VaultKeyRingSession> OpenReadKeySessionAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _keyRing.OpenReadSessionAsync(lease, cancellationToken).ConfigureAwait(false);
        }
        catch (VaultKeyRingException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

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

    public async Task<ProtectedEventPayload> ProtectAsync(
        EventToAppend eventToAppend,
        StreamId streamId,
        StreamVersion streamVersion,
        OperationId operationId,
        VaultKeyRingStore.VaultKeyRingSession session,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(eventToAppend);
        ArgumentNullException.ThrowIfNull(streamId);
        ArgumentNullException.ThrowIfNull(session);

        if (eventToAppend.Protection is PayloadProtection.DurableStructural)
            return ProtectedEventPayload.Structural(eventToAppend.Payload);

        var owner = ((PayloadProtection.Shreddable)eventToAppend.Protection).Owner;
        try
        {
            return await session.GetOrCreateDataKeyAsync(
                owner,
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
        catch (VaultRecoveryRequiredException) { throw; }
        catch (Exception exception) when (exception is VaultKeyRingException or CryptographicException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    public async Task<EventForReplay> UnprotectAsync(
        PersistedProtectedEvent persisted,
        CancellationToken cancellationToken)
        => await UnprotectCoreAsync(persisted, lease: null, session: null, cancellationToken).ConfigureAwait(false);

    public async Task<EventForReplay> UnprotectAsync(
        PersistedProtectedEvent persisted,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
        => await UnprotectCoreAsync(persisted, lease, session: null, cancellationToken).ConfigureAwait(false);

    public async Task<EventForReplay> UnprotectAsync(
        PersistedProtectedEvent persisted,
        VaultKeyRingStore.VaultKeyRingSession session,
        CancellationToken cancellationToken)
        => await UnprotectCoreAsync(persisted, lease: null, session, cancellationToken).ConfigureAwait(false);

    private async Task<EventForReplay> UnprotectCoreAsync(
        PersistedProtectedEvent persisted,
        VaultMaintenanceLease? lease,
        VaultKeyRingStore.VaultKeyRingSession? session,
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
            if (session is not null)
                return await session.ResolveDataKeyAsync(
                    owner, keyId, Destroyed, DecryptAsync, cancellationToken).ConfigureAwait(false);
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

internal sealed class SqliteEventPayloadReadSession : IAsyncDisposable
{
    private readonly SqliteEventPayloadProtectionProvider _provider;
    private readonly VaultMaintenanceLease _lease;
    private VaultKeyRingStore.VaultKeyRingSession? _keys;
    private int _disposeStarted;

    internal SqliteEventPayloadReadSession(
        SqliteEventPayloadProtectionProvider provider,
        VaultMaintenanceLease lease)
    {
        _provider = provider;
        _lease = lease;
    }

    public async Task<EventForReplay> UnprotectAsync(
        PersistedProtectedEvent persisted,
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposeStarted) != 0)
            throw new ObjectDisposedException(nameof(SqliteEventPayloadReadSession));
        if (persisted.Kind == PersistedProtectionKind.Structural)
            return await _provider.UnprotectAsync(persisted, cancellationToken).ConfigureAwait(false);
        _keys ??= await _provider.OpenReadKeySessionAsync(_lease, cancellationToken).ConfigureAwait(false);
        return await _provider.UnprotectAsync(persisted, _keys, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0) return;
        if (_keys is not null) await _keys.DisposeAsync().ConfigureAwait(false);
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
