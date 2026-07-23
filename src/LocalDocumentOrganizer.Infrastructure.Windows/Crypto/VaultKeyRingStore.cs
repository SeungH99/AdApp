using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;

[assembly: InternalsVisibleTo("LocalDocumentOrganizer.Security.Tests")]

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public sealed class VaultKeyRingStore
{
    private static readonly byte[] CurrentMagic = "LDOVKEY2"u8.ToArray();
    private static readonly byte[] LegacyMagic = "LDOVKEY1"u8.ToArray();
    private const int LegacyFormatVersion = 1;
    private const int KeyWrappingFormatVersion = 1;
    private static readonly byte[] AuthenticationDomain =
        "LocalDocumentOrganizer/VaultKeyRing/Authentication/v1"u8.ToArray();
    private static readonly byte[] WrappingDomain =
        "LocalDocumentOrganizer/VaultKeyRing/DekWrapping/v1"u8.ToArray();
    private static readonly byte[] IdentityDomain =
        "LocalDocumentOrganizer/VaultKeyRing/Identity/v1"u8.ToArray();
    private static readonly byte[] ProjectionValueEncryptionKeyDomain =
        "LocalDocumentOrganizer/ProjectionValue/EncryptionKey/v1"u8.ToArray();

    private const int AuthenticationTagSize = 32;
    private const int NonceSize = 12;
    private const int AesTagSize = 16;
    private const int MaximumFileSize = 16 * 1024 * 1024;
    private const int MaximumProtectedRootSize = 64 * 1024;
    private const int MaximumRecords = 100_000;

    private readonly string _path;
    private readonly IVaultKeyProtector _protector;
    private readonly IVaultKeyRingFaultInjector _faults;
    private readonly Action<SensitiveObjectRef, ReadOnlyMemory<byte>>? _sessionKeyObserver;

    public VaultKeyRingStore(string path)
        : this(path, new DpapiCurrentUserVaultKeyProtector())
    {
    }

    public VaultKeyRingStore(string path, IVaultKeyProtector protector)
        : this(path, protector, NoVaultKeyRingFaultInjector.Instance)
    {
    }

    internal VaultKeyRingStore(
        string path,
        IVaultKeyProtector protector,
        IVaultKeyRingFaultInjector faults)
        : this(path, protector, faults, sessionKeyObserver: null)
    {
    }

    internal VaultKeyRingStore(
        string path,
        IVaultKeyProtector protector,
        IVaultKeyRingFaultInjector faults,
        Action<SensitiveObjectRef, ReadOnlyMemory<byte>>? sessionKeyObserver)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(faults);
        MaintenanceGate = new VaultMaintenanceGate(path);
        _path = MaintenanceGate.KeyRingPath;
        _protector = protector;
        _faults = faults;
        _sessionKeyObserver = sessionKeyObserver;
    }

    public VaultMaintenanceGate MaintenanceGate { get; }

    public async Task<VaultKeyRing> CreateAsync(CancellationToken cancellationToken)
    {
        await using var lease = await MaintenanceGate.AcquireMutationAsync(cancellationToken).ConfigureAwait(false);
        return await CreateAsync(lease, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<VaultKeyRing> CreateAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        await using var operation = await MaintenanceGate
            .EnterOperationAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        WindowsVaultPathGuard.RequireSafeEntryShape(_path);
        var directory = Path.GetDirectoryName(_path)
            ?? throw new ArgumentException("The keyring path has no parent directory.", nameof(_path));
        Directory.CreateDirectory(directory);
        WindowsVaultPathGuard.RequireSafeForOpen(_path);
        CleanupOrphans(requireCanonical: true);
        if (WindowsVaultPathGuard.EntryExists(_path))
        {
            throw new VaultKeyRingPersistenceException("The Vault keyring already exists.");
        }

        var root = RandomNumberGenerator.GetBytes(VaultKeyRing.RootSize);
        byte[]? protectedRoot = null;
        try
        {
            protectedRoot = _protector.Protect(root);
            if (protectedRoot.Length is 0 or > MaximumProtectedRootSize)
            {
                throw new VaultKeyProtectionException("The protected Vault root length is invalid.");
            }

            using var state = new KeyRingState(
                VaultKeyRing.FormatVersion,
                1,
                protectedRoot,
                root,
                [],
                []);
            var image = Serialize(state);
            await PublishAsync(image, oldImage: null, cancellationToken).ConfigureAwait(false);
            return state.ToMetadata();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(root);
            if (protectedRoot is not null)
            {
                CryptographicOperations.ZeroMemory(protectedRoot);
            }
        }
    }

    public async Task<VaultKeyRing> OpenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var image = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
        using var state = Deserialize(image);
        return state.ToMetadata();
    }

    internal async Task EnsureCurrentFormatAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        await using var operation = await MaintenanceGate
            .EnterOperationAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        CleanupOrphans(requireCanonical: true);
        var oldImage = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
        using var state = Deserialize(oldImage);
        if (state.SourceFormatVersion == VaultKeyRing.FormatVersion)
        {
            return;
        }

        if (state.SourceFormatVersion != LegacyFormatVersion || state.Destroyed.Count != 0)
        {
            throw new VaultKeyRingRecoveryRequiredException();
        }

        state.Revision = NextRevision(state.Revision);
        await PublishAsync(Serialize(state), oldImage, cancellationToken).ConfigureAwait(false);
    }

    internal async Task RequireCanonicalIdentityAsync(
        VaultKeyRingIdentity expectedIdentity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        byte[]? image = null;
        try
        {
            image = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
            using var state = Deserialize(image);
            if (!CreateIdentity(state.Root).FixedTimeEquals(expectedIdentity))
                throw new VaultKeyRingRecoveryRequiredException();
        }
        finally
        {
            if (image is not null) CryptographicOperations.ZeroMemory(image);
        }
    }

    internal Task<VaultKeyRingSession> OpenReadSessionAsync(
        VaultMaintenanceLease lease,
        VaultKeyRingIdentity expectedIdentity,
        CancellationToken cancellationToken) =>
        OpenSessionAsync(lease, expectedIdentity, writable: false, cancellationToken);

    internal Task<VaultKeyRingSession> OpenWriteSessionAsync(
        VaultMaintenanceLease lease,
        VaultKeyRingIdentity expectedIdentity,
        CancellationToken cancellationToken) =>
        OpenSessionAsync(lease, expectedIdentity, writable: true, cancellationToken);

    private async Task<VaultKeyRingSession> OpenSessionAsync(
        VaultMaintenanceLease lease,
        VaultKeyRingIdentity expectedIdentity,
        bool writable,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        if (writable)
        {
            MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        }
        else
        {
            MaintenanceGate.Validate(
                lease,
                VaultLeaseMode.Read,
                VaultLeaseMode.Mutation,
                VaultLeaseMode.Rebuild);
        }
        var operation = await MaintenanceGate
            .EnterOperationAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        byte[]? image = null;
        KeyRingState? state = null;
        try
        {
            image = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
            state = Deserialize(image);
            var actualIdentity = CreateIdentity(state.Root);
            if (!actualIdentity.FixedTimeEquals(expectedIdentity))
                throw new VaultKeyRingRecoveryRequiredException();
            if (writable) CleanupOrphans(requireCanonical: true);
            var session = new VaultKeyRingSession(
                this,
                lease,
                operation,
                state,
                writable,
                image,
                _sessionKeyObserver);
            state = null;
            image = null;
            return session;
        }
        catch
        {
            state?.Dispose();
            if (image is not null) CryptographicOperations.ZeroMemory(image);
            await operation.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<TResult> GetOrCreateDataKeyAsync<TResult>(
        SensitiveObjectRef owner,
        Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken)
    {
        await using var lease = await MaintenanceGate.AcquireMutationAsync(cancellationToken).ConfigureAwait(false);
        return await GetOrCreateDataKeyAsync(owner, lease, callback, cancellationToken).ConfigureAwait(false);
    }

    public async Task<TResult> GetOrCreateDataKeyAsync<TResult>(
        SensitiveObjectRef owner,
        VaultMaintenanceLease lease,
        Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken)
    {
        ValidateOwner(owner);
        ArgumentNullException.ThrowIfNull(callback);
        MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        await using var operation = await MaintenanceGate
            .EnterOperationAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        CleanupOrphans(requireCanonical: true);
        var oldImage = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
        using var state = Deserialize(oldImage);
        ThrowIfDestroyed(state, owner);

        var entry = state.Active.SingleOrDefault(candidate => candidate.Owner == owner);
        if (entry is not null)
        {
            return await UseKeyAsync(state, entry, callback, cancellationToken).ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var dataKey = RandomNumberGenerator.GetBytes(VaultKeyRing.DataKeySize);
        try
        {
            var keyId = new DataKeyId(Guid.NewGuid());
            var nextEntry = Wrap(owner, keyId, dataKey, state.Root);
            state.Active.Add(nextEntry);
            state.Revision = NextRevision(state.Revision);
            var nextImage = Serialize(state);
            await PublishAsync(nextImage, oldImage, cancellationToken).ConfigureAwait(false);
            return await callback(keyId, dataKey, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    public async Task<TResult> OpenDataKeyAsync<TResult>(
        SensitiveObjectRef owner,
        Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken)
    {
        ValidateOwner(owner);
        ArgumentNullException.ThrowIfNull(callback);
        await using var lease = await MaintenanceGate
            .AcquireReadAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var operation = await MaintenanceGate
            .EnterOperationAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        CleanupOrphans(requireCanonical: true);
        var image = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
        using var state = Deserialize(image);
        ThrowIfDestroyed(state, owner);
        var entry = state.Active.SingleOrDefault(candidate => candidate.Owner == owner)
            ?? throw new VaultDataKeyNotFoundException();
        return await UseKeyAsync(state, entry, callback, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<TResult> ResolveDataKeyAsync<TResult>(
        SensitiveObjectRef owner,
        DataKeyId expectedKeyId,
        Func<TResult> destroyedCallback,
        Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> activeCallback,
        CancellationToken cancellationToken)
    {
        await using var lease = await MaintenanceGate.AcquireReadAsync(cancellationToken).ConfigureAwait(false);
        return await ResolveDataKeyAsync(
            owner, expectedKeyId, lease, destroyedCallback, activeCallback, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<TResult> ResolveDataKeyAsync<TResult>(
        SensitiveObjectRef owner,
        DataKeyId expectedKeyId,
        VaultMaintenanceLease lease,
        Func<TResult> destroyedCallback,
        Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> activeCallback,
        CancellationToken cancellationToken)
    {
        ValidateOwner(owner);
        if (expectedKeyId.Value == Guid.Empty) throw new ArgumentException("A data-key ID is required.", nameof(expectedKeyId));
        ArgumentNullException.ThrowIfNull(destroyedCallback);
        ArgumentNullException.ThrowIfNull(activeCallback);
        MaintenanceGate.Validate(
            lease,
            VaultLeaseMode.Read,
            VaultLeaseMode.Mutation,
            VaultLeaseMode.Rebuild);
        await using var operation = await MaintenanceGate
            .EnterOperationAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        CleanupOrphans(requireCanonical: true);
        var image = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
        using var state = Deserialize(image);
        var destroyed = state.Destroyed.SingleOrDefault(candidate => candidate.Owner == owner);
        if (destroyed is not null)
        {
            if (destroyed.KeyId != expectedKeyId) throw new VaultReceiptConflictException();
            return destroyedCallback();
        }

        var active = state.Active.SingleOrDefault(candidate => candidate.Owner == owner)
            ?? throw new VaultDataKeyNotFoundException();
        if (active.KeyId != expectedKeyId) throw new VaultReceiptConflictException();
        return await UseKeyAsync(state, active, activeCallback, cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask<TResult> UseProjectionSubkeyAsync<TResult>(
        SensitiveObjectRef owner,
        DataKeyId expectedKeyId,
        VaultMaintenanceLease lease,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken)
    {
        ValidateOwner(owner);
        if (expectedKeyId.Value == Guid.Empty)
            throw new ArgumentException("A data-key ID is required.", nameof(expectedKeyId));
        ArgumentNullException.ThrowIfNull(callback);
        MaintenanceGate.Validate(
            lease,
            VaultLeaseMode.Read,
            VaultLeaseMode.Mutation,
            VaultLeaseMode.Rebuild);

        byte[]? subkey = null;
        try
        {
            await using (var operation = await MaintenanceGate
                .EnterOperationAsync(lease, cancellationToken)
                .ConfigureAwait(false))
            {
                CleanupOrphans(requireCanonical: true);
                var image = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
                using var state = Deserialize(image);
                if (state.Destroyed.Any(candidate => candidate.Owner == owner))
                    throw new VaultDataKeyDestroyedException();
                var active = state.Active.SingleOrDefault(candidate => candidate.Owner == owner)
                    ?? throw new VaultDataKeyNotFoundException();
                if (active.KeyId != expectedKeyId) throw new VaultReceiptConflictException();
                subkey = await UseKeyAsync(
                    state,
                    active,
                    static (_, dataKey, _) => ValueTask.FromResult(
                        HMACSHA256.HashData(
                            dataKey.Span,
                            ProjectionValueEncryptionKeyDomain)),
                    cancellationToken).ConfigureAwait(false);
            }

            return await callback(subkey, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (subkey is not null) CryptographicOperations.ZeroMemory(subkey);
        }
    }

    internal sealed class VaultKeyRingSession : IAsyncDisposable
    {
        private readonly VaultKeyRingStore _store;
        private readonly VaultMaintenanceLease _lease;
        private VaultMaintenanceOperation? _operation;
        private readonly KeyRingState _state;
        private readonly bool _writable;
        private readonly Dictionary<SensitiveObjectRef, ActiveEntry> _active;
        private readonly Dictionary<SensitiveObjectRef, VaultDestroyedKeyReceipt> _destroyed;
        private readonly Dictionary<SensitiveObjectRef, CachedDataKey> _cached = [];
        private readonly Action<SensitiveObjectRef, ReadOnlyMemory<byte>>? _keyObserver;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private byte[]? _image;
        private int _disposeStarted;

        internal VaultKeyRingSession(
            VaultKeyRingStore store,
            VaultMaintenanceLease lease,
            VaultMaintenanceOperation operation,
            object state,
            bool writable,
            byte[]? image,
            Action<SensitiveObjectRef, ReadOnlyMemory<byte>>? keyObserver)
        {
            _store = store;
            _lease = lease;
            _operation = operation;
            _state = (KeyRingState)state;
            Identity = CreateIdentity(_state.Root);
            _writable = writable;
            _image = image;
            _keyObserver = keyObserver;
            _active = _state.Active.ToDictionary(entry => entry.Owner);
            _destroyed = _state.Destroyed.ToDictionary(receipt => receipt.Owner);
        }

        internal VaultKeyRingIdentity Identity { get; }

        internal async Task RequireCanonicalImageAsync(CancellationToken cancellationToken)
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                ThrowIfAdmissionReleased();
                await _store.RequireCanonicalImageAsync(_image!, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                _gate.Release();
            }
        }

        internal async ValueTask<TResult> ResolveDataKeyAsync<TResult>(
            SensitiveObjectRef owner,
            DataKeyId expectedKeyId,
            Func<TResult> destroyedCallback,
            Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> activeCallback,
            CancellationToken cancellationToken)
        {
            ValidateOwner(owner);
            if (expectedKeyId.Value == Guid.Empty)
                throw new ArgumentException("A data-key ID is required.", nameof(expectedKeyId));
            ArgumentNullException.ThrowIfNull(destroyedCallback);
            ArgumentNullException.ThrowIfNull(activeCallback);
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                ThrowIfAdmissionReleased();
                if (_destroyed.TryGetValue(owner, out var destroyed))
                {
                    if (destroyed.KeyId != expectedKeyId) throw new VaultReceiptConflictException();
                    return destroyedCallback();
                }

                if (!_active.TryGetValue(owner, out var active))
                    throw new VaultDataKeyNotFoundException();
                if (active.KeyId != expectedKeyId) throw new VaultReceiptConflictException();
                var cached = GetOrUnwrap(active);
                return await activeCallback(cached.KeyId, cached.Key, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                _gate.Release();
            }
        }

        internal async ValueTask<TResult> UseProjectionSubkeyAsync<TResult>(
            SensitiveObjectRef owner,
            DataKeyId expectedKeyId,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
            CancellationToken cancellationToken)
        {
            ValidateOwner(owner);
            if (expectedKeyId.Value == Guid.Empty)
                throw new ArgumentException("A data-key ID is required.", nameof(expectedKeyId));
            ArgumentNullException.ThrowIfNull(callback);

            byte[]? subkey = null;
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                ThrowIfAdmissionReleased();
                if (_destroyed.ContainsKey(owner)) throw new VaultDataKeyDestroyedException();
                if (!_active.TryGetValue(owner, out var active))
                    throw new VaultDataKeyNotFoundException();
                if (active.KeyId != expectedKeyId) throw new VaultReceiptConflictException();
                var cached = GetOrUnwrap(active);
                subkey = HMACSHA256.HashData(
                    cached.Key.Span,
                    ProjectionValueEncryptionKeyDomain);

                var operation = _operation!;
                _operation = null;
                await operation.DisposeAsync().ConfigureAwait(false);
                try
                {
                    return await callback(subkey, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    try
                    {
                        _operation = await _store.MaintenanceGate
                            .EnterOperationAsync(_lease, CancellationToken.None)
                            .ConfigureAwait(false);
                        await _store.RequireCanonicalImageAsync(_image!, CancellationToken.None)
                            .ConfigureAwait(false);
                    }
                    catch
                    {
                        if (_operation is not null)
                        {
                            await _operation.DisposeAsync().ConfigureAwait(false);
                            _operation = null;
                        }

                        throw;
                    }
                }
            }
            finally
            {
                if (subkey is not null) CryptographicOperations.ZeroMemory(subkey);
                _gate.Release();
            }
        }

        internal async ValueTask<TResult> GetOrCreateDataKeyAsync<TResult>(
            SensitiveObjectRef owner,
            Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
            CancellationToken cancellationToken)
        {
            ValidateOwner(owner);
            ArgumentNullException.ThrowIfNull(callback);
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                ThrowIfAdmissionReleased();
                if (!_writable) throw new InvalidOperationException("The Vault keyring session is read-only.");
                if (_destroyed.ContainsKey(owner)) throw new VaultDataKeyDestroyedException();
                if (_active.TryGetValue(owner, out var active))
                {
                    var cached = GetOrUnwrap(active);
                    return await callback(cached.KeyId, cached.Key, cancellationToken)
                        .ConfigureAwait(false);
                }

                cancellationToken.ThrowIfCancellationRequested();
                var dataKey = RandomNumberGenerator.GetBytes(VaultKeyRing.DataKeySize);
                var keepDataKey = false;
                byte[]? nextImage = null;
                try
                {
                    await _store.RequireCanonicalImageAsync(_image!, cancellationToken)
                        .ConfigureAwait(false);
                    var keyId = new DataKeyId(Guid.NewGuid());
                    var nextEntry = Wrap(owner, keyId, dataKey, _state.Root);
                    _state.Active.Add(nextEntry);
                    _active.Add(owner, nextEntry);
                    _state.Revision = NextRevision(_state.Revision);
                    nextImage = _store.Serialize(_state);
                    await _store.PublishAsync(nextImage, _image, cancellationToken).ConfigureAwait(false);
                    if (_image is not null) CryptographicOperations.ZeroMemory(_image);
                    _image = nextImage;
                    nextImage = null;
                    var cached = new CachedDataKey(keyId, dataKey);
                    _cached.Add(owner, cached);
                    keepDataKey = true;
                    _keyObserver?.Invoke(owner, cached.Key);
                    return await callback(keyId, cached.Key, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    if (nextImage is not null) CryptographicOperations.ZeroMemory(nextImage);
                    if (!keepDataKey) CryptographicOperations.ZeroMemory(dataKey);
                }
            }
            finally
            {
                _gate.Release();
            }
        }

        private CachedDataKey GetOrUnwrap(ActiveEntry active)
        {
            if (_cached.TryGetValue(active.Owner, out var cached)) return cached;
            var plaintext = _store.UnwrapDataKey(_state, active);
            cached = new CachedDataKey(active.KeyId, plaintext);
            _cached.Add(active.Owner, cached);
            _keyObserver?.Invoke(active.Owner, cached.Key);
            return cached;
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposeStarted) != 0)
                throw new ObjectDisposedException(nameof(VaultKeyRingSession));
        }

        private void ThrowIfAdmissionReleased()
        {
            if (_operation is null) throw new VaultKeyRingRecoveryRequiredException();
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposeStarted, 1) != 0) return;
            await _gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                foreach (var cached in _cached.Values)
                    CryptographicOperations.ZeroMemory(cached.Bytes);
                _cached.Clear();
                _state.Dispose();
                if (_image is not null)
                {
                    CryptographicOperations.ZeroMemory(_image);
                    _image = null;
                }
            }
            finally
            {
                _gate.Release();
                if (_operation is not null)
                {
                    await _operation.DisposeAsync().ConfigureAwait(false);
                    _operation = null;
                }
            }
        }

        private sealed record CachedDataKey(DataKeyId KeyId, byte[] Bytes)
        {
            public ReadOnlyMemory<byte> Key => Bytes;
        }
    }

    public async Task DestroyDataKeyAsync(
        VaultDestroyedKeyReceipt receipt,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        receipt.Validate();
        MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        await using var operation = await MaintenanceGate
            .EnterOperationAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        CleanupOrphans(requireCanonical: true);
        var oldImage = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
        using var state = Deserialize(oldImage);
        var existing = state.Destroyed.SingleOrDefault(candidate => candidate.Owner == receipt.Owner);
        if (existing is not null)
        {
            if (existing == receipt)
            {
                return;
            }

            throw new VaultReceiptConflictException();
        }

        if (receipt.State != VaultDestroyedReceiptState.PendingSqlCompletion)
        {
            throw new VaultReceiptConflictException();
        }

        var active = state.Active.SingleOrDefault(candidate => candidate.Owner == receipt.Owner)
            ?? throw new VaultDataKeyNotFoundException();
        if (active.KeyId != receipt.KeyId)
        {
            throw new VaultReceiptConflictException();
        }

        state.Active.Remove(active);
        state.Destroyed.Add(receipt);
        state.Revision = NextRevision(state.Revision);
        await PublishAsync(Serialize(state), oldImage, cancellationToken).ConfigureAwait(false);
    }

    public async Task UpdateDestroyedReceiptAsync(
        VaultDestroyedKeyReceipt receipt,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        receipt.Validate();
        MaintenanceGate.Validate(lease, VaultLeaseMode.Mutation);
        await using var operation = await MaintenanceGate
            .EnterOperationAsync(lease, cancellationToken)
            .ConfigureAwait(false);
        CleanupOrphans(requireCanonical: true);
        var oldImage = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
        using var state = Deserialize(oldImage);
        var index = state.Destroyed.FindIndex(candidate => candidate.Owner == receipt.Owner);
        if (index < 0)
        {
            throw new VaultReceiptConflictException();
        }

        var existing = state.Destroyed[index];
        if (existing == receipt)
        {
            return;
        }

        if (!SameReceiptIdentity(existing, receipt)
            || existing.State != VaultDestroyedReceiptState.PendingSqlCompletion
            || receipt.State != VaultDestroyedReceiptState.Completed)
        {
            throw new VaultReceiptConflictException();
        }

        state.Destroyed[index] = receipt;
        state.Revision = NextRevision(state.Revision);
        await PublishAsync(Serialize(state), oldImage, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TResult> UseKeyAsync<TResult>(
        KeyRingState state,
        ActiveEntry entry,
        Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken)
    {
        var plaintext = UnwrapDataKey(state, entry);
        try
        {
            return await callback(entry.KeyId, plaintext, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private byte[] UnwrapDataKey(KeyRingState state, ActiveEntry entry)
    {
        var wrappingKey = DeriveKey(state.Root, WrappingDomain);
        var plaintext = new byte[VaultKeyRing.DataKeySize];
        try
        {
            using var aes = new AesGcm(wrappingKey, AesTagSize);
            aes.Decrypt(
                entry.Nonce,
                entry.WrappedKey,
                entry.Tag,
                plaintext,
                CreateWrappingAad(entry.Owner, entry.KeyId));
            return plaintext;
        }
        catch (AuthenticationTagMismatchException exception)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new VaultKeyRingAuthenticationException(exception);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }
    }

    private static ActiveEntry Wrap(
        SensitiveObjectRef owner,
        DataKeyId keyId,
        ReadOnlySpan<byte> dataKey,
        ReadOnlySpan<byte> root)
    {
        var wrappingKey = DeriveKey(root, WrappingDomain);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var wrapped = new byte[VaultKeyRing.DataKeySize];
        var tag = new byte[AesTagSize];
        try
        {
            using var aes = new AesGcm(wrappingKey, AesTagSize);
            aes.Encrypt(nonce, dataKey, wrapped, tag, CreateWrappingAad(owner, keyId));
            return new ActiveEntry(owner, keyId, nonce, wrapped, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }
    }

    private byte[] Serialize(KeyRingState state)
    {
        ValidateSerializableState(state);
        long destroyedReasonBytes = 0;
        foreach (var receipt in state.Destroyed)
        {
            destroyedReasonBytes = checked(destroyedReasonBytes + receipt.ReasonCode.Length);
        }

        var expectedImageSize = ValidateSerializationBounds(
            state.Active.Count,
            state.Destroyed.Count,
            state.ProtectedRoot.Length,
            destroyedReasonBytes);
        state.Active.Sort(ActiveEntryComparer.Instance);
        state.Destroyed.Sort(DestroyedEntryComparer.Instance);
        using var stream = new MemoryStream();
        Write(stream, CurrentMagic);
        WriteUInt32(stream, VaultKeyRing.FormatVersion);
        WriteUInt64(stream, state.Revision);
        WriteBytes(stream, state.ProtectedRoot);
        WriteUInt32(stream, checked((uint)state.Active.Count));
        foreach (var entry in state.Active)
        {
            WriteOwner(stream, entry.Owner);
            WriteGuid(stream, entry.KeyId.Value);
            Write(stream, entry.Nonce);
            WriteBytes(stream, entry.WrappedKey);
            Write(stream, entry.Tag);
        }

        WriteUInt32(stream, checked((uint)state.Destroyed.Count));
        foreach (var receipt in state.Destroyed)
        {
            WriteOwner(stream, receipt.Owner);
            WriteGuid(stream, receipt.KeyId.Value);
            WriteGuid(stream, receipt.StreamId.Value);
            WriteGuid(stream, receipt.OperationId.Value);
            WriteGuid(stream, receipt.TombstoneEventId.Value);
            WriteInt64(stream, receipt.ExpectedStreamVersion.Value);
            var reason = Encoding.ASCII.GetBytes(receipt.ReasonCode);
            WriteBytes(stream, reason);
            WriteUInt32(stream, (uint)receipt.State);
        }

        var authenticated = stream.ToArray();
        var authenticationKey = DeriveKey(state.Root, AuthenticationDomain);
        try
        {
            var tag = HMACSHA256.HashData(authenticationKey, authenticated);
            var image = new byte[checked(authenticated.Length + tag.Length)];
            authenticated.CopyTo(image, 0);
            tag.CopyTo(image, authenticated.Length);
            if (image.Length != expectedImageSize)
            {
                throw new VaultKeyRingFormatException("The serialized Vault keyring size is inconsistent.");
            }

            return image;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authenticationKey);
        }
    }

    private KeyRingState Deserialize(byte[] image)
    {
        try
        {
            return DeserializeCore(image);
        }
        catch (VaultKeyRingException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            throw new VaultKeyRingFormatException("The Vault keyring contains an invalid value.", exception);
        }
    }

    private KeyRingState DeserializeCore(byte[] image)
    {
        if (image.Length < CurrentMagic.Length + 4 + 8 + 4 + 1 + AuthenticationTagSize
            || image.Length > MaximumFileSize)
        {
            throw new VaultKeyRingFormatException("The Vault keyring size is invalid.");
        }

        var offset = 0;
        int sourceFormatVersion;
        if (image.AsSpan(0, CurrentMagic.Length).SequenceEqual(CurrentMagic))
        {
            sourceFormatVersion = VaultKeyRing.FormatVersion;
        }
        else if (image.AsSpan(0, LegacyMagic.Length).SequenceEqual(LegacyMagic))
        {
            sourceFormatVersion = LegacyFormatVersion;
        }
        else
        {
            throw new VaultKeyRingFormatException("The Vault keyring magic is invalid.");
        }

        offset += CurrentMagic.Length;
        var version = ReadUInt32(image, ref offset);
        if (version != sourceFormatVersion)
        {
            throw new VaultKeyRingFormatException("The Vault keyring version is unsupported.");
        }

        var revision = ReadUInt64(image, ref offset);
        if (revision == 0)
        {
            throw new VaultKeyRingFormatException("The Vault keyring revision is invalid.");
        }

        var protectedRoot = ReadBytes(image, ref offset, MaximumProtectedRootSize, beforeAuthentication: true);
        var root = new byte[VaultKeyRing.RootSize];
        try
        {
            _protector.Unprotect(protectedRoot, root);
            var authenticatedLength = image.Length - AuthenticationTagSize;
            var authenticationKey = DeriveKey(root, AuthenticationDomain);
            byte[] computed;
            try
            {
                computed = HMACSHA256.HashData(authenticationKey, image.AsSpan(0, authenticatedLength));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(authenticationKey);
            }

            try
            {
                if (!CryptographicOperations.FixedTimeEquals(computed, image.AsSpan(authenticatedLength)))
                {
                    throw new VaultKeyRingAuthenticationException();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(computed);
            }

            var bodyLimit = authenticatedLength;
            var activeCount = ReadCount(image, ref offset, bodyLimit);
            var active = new List<ActiveEntry>(activeCount);
            for (var index = 0; index < activeCount; index++)
            {
                var owner = ReadOwner(image, ref offset, bodyLimit);
                var keyId = new DataKeyId(ReadGuid(image, ref offset, bodyLimit));
                var nonce = ReadFixed(image, ref offset, NonceSize, bodyLimit);
                var wrapped = ReadBytes(image, ref offset, VaultKeyRing.DataKeySize, bodyLimit);
                if (wrapped.Length != VaultKeyRing.DataKeySize)
                {
                    throw new VaultKeyRingFormatException("A wrapped data key length is invalid.");
                }

                var tag = ReadFixed(image, ref offset, AesTagSize, bodyLimit);
                active.Add(new ActiveEntry(owner, keyId, nonce, wrapped, tag));
            }

            var destroyedCount = ReadCount(image, ref offset, bodyLimit);
            if (sourceFormatVersion == LegacyFormatVersion && destroyedCount != 0)
            {
                throw new VaultKeyRingRecoveryRequiredException();
            }

            var destroyed = new List<VaultDestroyedKeyReceipt>(destroyedCount);
            for (var index = 0; index < destroyedCount; index++)
            {
                var receipt = new VaultDestroyedKeyReceipt(
                    ReadOwner(image, ref offset, bodyLimit),
                    new DataKeyId(ReadGuid(image, ref offset, bodyLimit)),
                    new StreamId(ReadGuid(image, ref offset, bodyLimit)),
                    new OperationId(ReadGuid(image, ref offset, bodyLimit)),
                    new EventId(ReadGuid(image, ref offset, bodyLimit)),
                    new StreamVersion(ReadInt64(image, ref offset, bodyLimit)),
                    Encoding.ASCII.GetString(ReadBytes(image, ref offset, 32, bodyLimit)),
                    (VaultDestroyedReceiptState)ReadUInt32(image, ref offset, bodyLimit));
                receipt.Validate();
                destroyed.Add(receipt);
            }

            if (offset != bodyLimit)
            {
                throw new VaultKeyRingFormatException("The Vault keyring has trailing data.");
            }

            ValidateCanonical(active, destroyed);
            return new KeyRingState(
                sourceFormatVersion,
                revision,
                protectedRoot,
                root,
                active,
                destroyed);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(root);
            throw;
        }
    }

    private static void ValidateCanonical(
        List<ActiveEntry> active,
        List<VaultDestroyedKeyReceipt> destroyed)
    {
        if (!active.SequenceEqual(active.OrderBy(entry => entry, ActiveEntryComparer.Instance))
            || !destroyed.SequenceEqual(destroyed.OrderBy(entry => entry, DestroyedEntryComparer.Instance)))
        {
            throw new VaultKeyRingFormatException("The Vault keyring records are not canonical.");
        }

        var owners = new HashSet<SensitiveObjectRef>();
        var keyIds = new HashSet<DataKeyId>();
        foreach (var entry in active)
        {
            if (!owners.Add(entry.Owner) || !keyIds.Add(entry.KeyId))
            {
                throw new VaultKeyRingFormatException("The Vault keyring contains duplicate records.");
            }
        }

        foreach (var receipt in destroyed)
        {
            if (!owners.Add(receipt.Owner) || !keyIds.Add(receipt.KeyId))
            {
                throw new VaultKeyRingFormatException("The Vault keyring contains duplicate records.");
            }
        }
    }

    private async Task<byte[]> ReadCanonicalAsync(CancellationToken cancellationToken)
    {
        try
        {
            WindowsVaultPathGuard.RequireSafeForOpen(_path);
            var image = await ReadBoundedFileAsync(_path, cancellationToken).ConfigureAwait(false);
            WindowsVaultPathGuard.RequireSafeForOpen(_path);
            return image;
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            if (FindOrphans().Count != 0)
            {
                throw new VaultKeyRingRecoveryRequiredException(exception);
            }

            throw new VaultKeyRingNotFoundException();
        }
        catch (VaultKeyRingException)
        {
            throw;
        }
        catch (IOException exception)
        {
            throw new VaultKeyRingPersistenceException("The Vault keyring could not be read.", exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new VaultKeyRingPersistenceException("The Vault keyring could not be read.", exception);
        }
    }

    internal static Task<byte[]> ReadBoundedFileForTestAsync(
        string path,
        CancellationToken cancellationToken) =>
        ReadBoundedFileAsync(path, cancellationToken);

    private static async Task<byte[]> ReadBoundedFileAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(path, stream.SafeFileHandle);
        var length = ValidateOpenedLength(stream.Length);
        var image = new byte[length];
        var offset = 0;
        while (offset < image.Length)
        {
            var read = await stream.ReadAsync(image.AsMemory(offset), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new VaultKeyRingFormatException("The Vault keyring changed or was truncated while reading.");
            }

            offset += read;
        }

        var probe = new byte[1];
        if (await stream.ReadAsync(probe, cancellationToken).ConfigureAwait(false) != 0
            || stream.Length != length)
        {
            throw new VaultKeyRingFormatException("The Vault keyring changed or grew while reading.");
        }

        WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(path, stream.SafeFileHandle);

        return image;
    }

    private static byte[] ReadBoundedFile(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            bufferSize: 4096,
            FileOptions.SequentialScan);
        WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(path, stream.SafeFileHandle);
        var length = ValidateOpenedLength(stream.Length);
        var image = new byte[length];
        var offset = 0;
        while (offset < image.Length)
        {
            var read = stream.Read(image, offset, image.Length - offset);
            if (read == 0)
            {
                throw new VaultKeyRingFormatException("The Vault keyring changed or was truncated while reading.");
            }

            offset += read;
        }

        if (stream.ReadByte() != -1 || stream.Length != length)
        {
            throw new VaultKeyRingFormatException("The Vault keyring changed or grew while reading.");
        }

        WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(path, stream.SafeFileHandle);

        return image;
    }

    private static int ValidateOpenedLength(long length)
    {
        if (length < 0 || length > MaximumFileSize)
        {
            throw new VaultKeyRingFormatException("The Vault keyring size is invalid.");
        }

        return checked((int)length);
    }

    internal static void ValidateSerializationBoundsForTest(
        int activeCount,
        int destroyedCount,
        int protectedRootSize,
        long destroyedReasonBytes) =>
        _ = ValidateSerializationBounds(activeCount, destroyedCount, protectedRootSize, destroyedReasonBytes);

    private static int ValidateSerializationBounds(
        int activeCount,
        int destroyedCount,
        int protectedRootSize,
        long destroyedReasonBytes)
    {
        if (activeCount is < 0 or > MaximumRecords
            || destroyedCount is < 0 or > MaximumRecords)
        {
            throw new VaultKeyRingFormatException("A keyring record count is excessive.");
        }

        if (protectedRootSize is <= 0 or > MaximumProtectedRootSize
            || destroyedReasonBytes < destroyedCount
            || destroyedReasonBytes > (long)destroyedCount * 32)
        {
            throw new VaultKeyRingFormatException("A serialized keyring field length is invalid.");
        }

        long imageSize;
        try
        {
            imageSize = checked(
                64L
                + protectedRootSize
                + ((long)activeCount * 100)
                + ((long)destroyedCount * 100)
                + destroyedReasonBytes);
        }
        catch (OverflowException exception)
        {
            throw new VaultKeyRingFormatException("The serialized Vault keyring size is invalid.", exception);
        }

        if (imageSize > MaximumFileSize)
        {
            throw new VaultKeyRingFormatException("The serialized Vault keyring is excessive.");
        }

        return checked((int)imageSize);
    }

    private async Task PublishAsync(byte[] image, byte[]? oldImage, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_path)!;
        var temp = Path.Combine(directory, $"{Path.GetFileName(_path)}.tmp-{Guid.NewGuid():N}");
        try
        {
            WindowsVaultPathGuard.RequireSafeForOpen(_path);
            WindowsVaultPathGuard.RequireSafeEntryShape(temp);
            _faults.ThrowIfRequested(VaultKeyRingFaultPoint.BeforeTempCreate);
            await using (var stream = new FileStream(
                temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(
                    temp, stream.SafeFileHandle);
                await stream.WriteAsync(image, cancellationToken).ConfigureAwait(false);
                _faults.ThrowIfRequested(VaultKeyRingFaultPoint.AfterTempWrite);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
                _faults.ThrowIfRequested(VaultKeyRingFaultPoint.AfterFlushBeforePublish);
            }

            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                WindowsVaultPathGuard.RequireSafeForOpen(_path);
                if (oldImage is not null)
                    await RequireCanonicalImageAsync(oldImage, cancellationToken).ConfigureAwait(false);
                if (oldImage is null)
                {
                    File.Move(temp, _path, overwrite: false);
                }
                else
                {
                    File.Replace(temp, _path, destinationBackupFileName: null);
                }

                WindowsVaultPathGuard.RequireSafeForOpen(_path);
                _faults.ThrowIfRequested(VaultKeyRingFaultPoint.AfterPublish);
            }
            catch (VaultRecoveryRequiredException exception) when (oldImage is null)
            {
                throw new VaultKeyRingPersistenceException(
                    "The Vault keyring could not be published.", exception);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                var publicationState = ClassifyCanonical(image, oldImage);
                if (publicationState == PublicationState.New)
                {
                    return;
                }

                if (oldImage is null || publicationState == PublicationState.Old)
                {
                    throw new VaultKeyRingPersistenceException("The Vault keyring could not be published.", exception);
                }

                throw new VaultAtomicPublicationException(exception);
            }
        }
        catch (VaultKeyRingException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new VaultKeyRingPersistenceException("The Vault keyring could not be persisted.", exception);
        }
        finally
        {
            if (WindowsVaultPathGuard.EntryExists(temp))
            {
                try
                {
                    WindowsVaultPathGuard.RequireSafeForOpen(temp);
                    File.Delete(temp);
                    if (WindowsVaultPathGuard.EntryExists(temp))
                        throw new IOException("Temporary keyring cleanup was not durable.");
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    throw new VaultKeyRingRecoveryRequiredException(exception);
                }
            }
        }
    }

    private async Task RequireCanonicalImageAsync(
        byte[] expectedImage,
        CancellationToken cancellationToken)
    {
        byte[]? canonical = null;
        try
        {
            canonical = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
            if (canonical.Length != expectedImage.Length
                || !CryptographicOperations.FixedTimeEquals(canonical, expectedImage))
            {
                throw new VaultKeyRingRecoveryRequiredException();
            }
        }
        finally
        {
            if (canonical is not null) CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private PublicationState ClassifyCanonical(byte[] next, byte[]? previous)
    {
        try
        {
            WindowsVaultPathGuard.RequireSafeForOpen(_path);
            if (!WindowsVaultPathGuard.EntryExists(_path)) return PublicationState.Missing;
            var canonical = ReadBoundedFile(_path);
            using var canonicalState = Deserialize(canonical);
            using var nextState = Deserialize(next);
            if (canonicalState.Revision == nextState.Revision
                && canonical.AsSpan().SequenceEqual(next))
            {
                return PublicationState.New;
            }

            if (previous is not null)
            {
                using var previousState = Deserialize(previous);
                if (canonicalState.Revision == previousState.Revision
                    && canonical.AsSpan().SequenceEqual(previous))
                {
                    return PublicationState.Old;
                }
            }

            return PublicationState.Invalid;
        }
        catch
        {
            return PublicationState.Invalid;
        }
    }

    private void CleanupOrphans(bool requireCanonical)
    {
        var orphans = FindOrphans();
        if (orphans.Count == 0) return;
        WindowsVaultPathGuard.RequireSafeForOpen(_path);
        if (requireCanonical && !WindowsVaultPathGuard.EntryExists(_path))
        {
            throw new VaultKeyRingRecoveryRequiredException();
        }

        if (requireCanonical)
        {
            try
            {
                using var canonical = Deserialize(ReadBoundedFile(_path));
            }
            catch (Exception exception) when (exception is IOException
                or UnauthorizedAccessException
                or VaultKeyRingException)
            {
                throw new VaultKeyRingRecoveryRequiredException(exception);
            }
        }

        foreach (var orphan in orphans)
        {
            try
            {
                WindowsVaultPathGuard.RequireSafeForOpen(orphan);
                File.Delete(orphan);
                if (WindowsVaultPathGuard.EntryExists(orphan))
                    throw new IOException("Temporary keyring cleanup was not durable.");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new VaultKeyRingRecoveryRequiredException(exception);
            }
        }
    }

    private List<string> FindOrphans()
    {
        try
        {
            var directory = Path.GetDirectoryName(_path)!;
            var prefix = Path.GetFileName(_path) + ".tmp-";
            return Directory.EnumerateFiles(directory, prefix + "*")
                .Where(path =>
                {
                    var name = Path.GetFileName(path);
                    var suffix = name.AsSpan(prefix.Length);
                    return name.StartsWith(prefix, OperatingSystem.IsWindows()
                            ? StringComparison.OrdinalIgnoreCase
                            : StringComparison.Ordinal)
                        && suffix.Length == 32
                        && IsHex(suffix);
                })
                .ToList();
        }
        catch (DirectoryNotFoundException)
        {
            return [];
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or System.Security.SecurityException)
        {
            throw new VaultKeyRingRecoveryRequiredException(exception);
        }
    }

    private static bool IsHex(ReadOnlySpan<char> value)
    {
        foreach (var character in value)
        {
            if (!char.IsAsciiHexDigit(character)) return false;
        }

        return true;
    }

    private static void ValidateSerializableState(KeyRingState state)
    {
        if (state.Revision == 0 || state.Root.Length != VaultKeyRing.RootSize
            || state.ProtectedRoot.Length is <= 0 or > MaximumProtectedRootSize)
        {
            throw new VaultKeyRingFormatException("The keyring state is invalid for serialization.");
        }

        var owners = new HashSet<SensitiveObjectRef>();
        var keyIds = new HashSet<DataKeyId>();
        foreach (var entry in state.Active)
        {
            ValidateOwner(entry.Owner);
            if (entry.KeyId.Value == Guid.Empty
                || entry.Nonce.Length != NonceSize
                || entry.WrappedKey.Length != VaultKeyRing.DataKeySize
                || entry.Tag.Length != AesTagSize
                || !owners.Add(entry.Owner)
                || !keyIds.Add(entry.KeyId))
            {
                throw new VaultKeyRingFormatException("An active keyring record is invalid.");
            }
        }

        foreach (var receipt in state.Destroyed)
        {
            receipt.Validate();
            if (!owners.Add(receipt.Owner) || !keyIds.Add(receipt.KeyId))
            {
                throw new VaultKeyRingFormatException("A destroyed keyring record is invalid.");
            }
        }
    }

    private static bool SameReceiptIdentity(
        VaultDestroyedKeyReceipt left,
        VaultDestroyedKeyReceipt right) =>
        left.Owner == right.Owner && left.KeyId == right.KeyId
        && left.StreamId == right.StreamId
        && left.OperationId == right.OperationId
        && left.TombstoneEventId == right.TombstoneEventId
        && left.ExpectedStreamVersion == right.ExpectedStreamVersion
        && string.Equals(left.ReasonCode, right.ReasonCode, StringComparison.Ordinal);

    private static ulong NextRevision(ulong revision)
    {
        if (revision == ulong.MaxValue)
        {
            throw new VaultKeyRingFormatException("The Vault keyring revision cannot be incremented.");
        }

        return revision + 1;
    }

    private static void ThrowIfDestroyed(KeyRingState state, SensitiveObjectRef owner)
    {
        if (state.Destroyed.Any(receipt => receipt.Owner == owner))
        {
            throw new VaultDataKeyDestroyedException();
        }
    }

    private static void ValidateOwner(SensitiveObjectRef owner)
    {
        if (!Enum.IsDefined(owner.Kind) || owner.Id.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid sensitive object owner is required.", nameof(owner));
        }
    }

    private static byte[] DeriveKey(ReadOnlySpan<byte> root, ReadOnlySpan<byte> domain) =>
        HMACSHA256.HashData(root, domain);

    private static VaultKeyRingIdentity CreateIdentity(ReadOnlySpan<byte> root)
    {
        var value = DeriveKey(root, IdentityDomain);
        try { return new VaultKeyRingIdentity(value); }
        finally { CryptographicOperations.ZeroMemory(value); }
    }

    private static byte[] CreateWrappingAad(SensitiveObjectRef owner, DataKeyId keyId)
    {
        var aad = new byte[4 + 4 + 16 + 16];
        BinaryPrimitives.WriteUInt32BigEndian(aad, KeyWrappingFormatVersion);
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(4), (int)owner.Kind);
        owner.Id.Value.TryWriteBytes(aad.AsSpan(8, 16), bigEndian: true, out _);
        keyId.Value.TryWriteBytes(aad.AsSpan(24, 16), bigEndian: true, out _);
        return aad;
    }

    private static void WriteOwner(Stream stream, SensitiveObjectRef owner)
    {
        WriteUInt32(stream, (uint)owner.Kind);
        WriteGuid(stream, owner.Id.Value);
    }

    private static void WriteBytes(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteUInt32(stream, checked((uint)value.Length));
        Write(stream, value);
    }

    private static void Write(Stream stream, ReadOnlySpan<byte> value) => stream.Write(value);

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteUInt64(Stream stream, ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteInt64(Stream stream, long value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteGuid(Stream stream, Guid value)
    {
        Span<byte> buffer = stackalloc byte[16];
        value.TryWriteBytes(buffer, bigEndian: true, out _);
        stream.Write(buffer);
    }

    private static uint ReadUInt32(byte[] image, ref int offset, int? limit = null)
    {
        var span = ReadFixed(image, ref offset, 4, limit ?? image.Length);
        return BinaryPrimitives.ReadUInt32BigEndian(span);
    }

    private static ulong ReadUInt64(byte[] image, ref int offset)
    {
        var span = ReadFixed(image, ref offset, 8, image.Length);
        return BinaryPrimitives.ReadUInt64BigEndian(span);
    }

    private static long ReadInt64(byte[] image, ref int offset, int limit)
    {
        var span = ReadFixed(image, ref offset, 8, limit);
        return BinaryPrimitives.ReadInt64BigEndian(span);
    }

    private static Guid ReadGuid(byte[] image, ref int offset, int limit) =>
        new(ReadFixed(image, ref offset, 16, limit), bigEndian: true);

    private static SensitiveObjectRef ReadOwner(byte[] image, ref int offset, int limit)
    {
        var rawKind = ReadUInt32(image, ref offset, limit);
        if (rawKind > int.MaxValue || !Enum.IsDefined((SensitiveObjectKind)(int)rawKind))
        {
            throw new VaultKeyRingFormatException("A sensitive object kind is invalid.");
        }

        return new SensitiveObjectRef(
            (SensitiveObjectKind)(int)rawKind,
            new SensitiveObjectId(ReadGuid(image, ref offset, limit)));
    }

    private static int ReadCount(byte[] image, ref int offset, int limit)
    {
        var count = ReadUInt32(image, ref offset, limit);
        if (count > MaximumRecords) throw new VaultKeyRingFormatException("A keyring record count is excessive.");
        return (int)count;
    }

    private static byte[] ReadBytes(
        byte[] image,
        ref int offset,
        int maximum,
        int? limit = null,
        bool beforeAuthentication = false)
    {
        var effectiveLimit = limit ?? image.Length - AuthenticationTagSize;
        var length = ReadUInt32(image, ref offset, effectiveLimit);
        if (length == 0 || length > maximum)
        {
            throw new VaultKeyRingFormatException(beforeAuthentication
                ? "The protected Vault root length is invalid."
                : "A keyring field length is invalid.");
        }

        return ReadFixed(image, ref offset, (int)length, effectiveLimit);
    }

    private static byte[] ReadFixed(byte[] image, ref int offset, int length, int limit)
    {
        if (length < 0 || offset < 0 || offset > limit - length)
        {
            throw new VaultKeyRingFormatException("The Vault keyring is truncated.");
        }

        var value = image.AsSpan(offset, length).ToArray();
        offset += length;
        return value;
    }

    private enum PublicationState { Missing, Old, New, Invalid }

    private sealed class KeyRingState : IDisposable
    {
        public KeyRingState(
            int sourceFormatVersion,
            ulong revision,
            byte[] protectedRoot,
            byte[] root,
            List<ActiveEntry> active,
            List<VaultDestroyedKeyReceipt> destroyed)
        {
            SourceFormatVersion = sourceFormatVersion;
            Revision = revision;
            ProtectedRoot = protectedRoot;
            Root = root;
            Active = active;
            Destroyed = destroyed;
        }

        public int SourceFormatVersion { get; }
        public ulong Revision { get; set; }
        public byte[] ProtectedRoot { get; }
        public byte[] Root { get; }
        public List<ActiveEntry> Active { get; }
        public List<VaultDestroyedKeyReceipt> Destroyed { get; }

        public VaultKeyRing ToMetadata() => new(
            CreateIdentity(Root),
            Active.Select(entry => new VaultActiveKeyMetadata(entry.Owner, entry.KeyId)),
            Destroyed);

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Root);
            CryptographicOperations.ZeroMemory(ProtectedRoot);
            foreach (var entry in Active) entry.Dispose();
        }
    }

    private sealed class ActiveEntry : IDisposable
    {
        public ActiveEntry(
            SensitiveObjectRef owner,
            DataKeyId keyId,
            byte[] nonce,
            byte[] wrappedKey,
            byte[] tag)
        {
            Owner = owner;
            KeyId = keyId;
            Nonce = nonce;
            WrappedKey = wrappedKey;
            Tag = tag;
        }

        public SensitiveObjectRef Owner { get; }
        public DataKeyId KeyId { get; }
        public byte[] Nonce { get; }
        public byte[] WrappedKey { get; }
        public byte[] Tag { get; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(WrappedKey);
            CryptographicOperations.ZeroMemory(Nonce);
            CryptographicOperations.ZeroMemory(Tag);
        }
    }

    private sealed class ActiveEntryComparer : IComparer<ActiveEntry>
    {
        public static ActiveEntryComparer Instance { get; } = new();
        public int Compare(ActiveEntry? left, ActiveEntry? right) =>
            CompareOwner(left!.Owner, right!.Owner);
    }

    private sealed class DestroyedEntryComparer : IComparer<VaultDestroyedKeyReceipt>
    {
        public static DestroyedEntryComparer Instance { get; } = new();
        public int Compare(VaultDestroyedKeyReceipt? left, VaultDestroyedKeyReceipt? right) =>
            CompareOwner(left!.Owner, right!.Owner);
    }

    private static int CompareOwner(SensitiveObjectRef left, SensitiveObjectRef right)
    {
        var kind = left.Kind.CompareTo(right.Kind);
        if (kind != 0) return kind;
        Span<byte> leftBytes = stackalloc byte[16];
        Span<byte> rightBytes = stackalloc byte[16];
        left.Id.Value.TryWriteBytes(leftBytes, bigEndian: true, out _);
        right.Id.Value.TryWriteBytes(rightBytes, bigEndian: true, out _);
        return leftBytes.SequenceCompareTo(rightBytes);
    }
}

internal enum VaultKeyRingFaultPoint
{
    BeforeTempCreate,
    AfterTempWrite,
    AfterFlushBeforePublish,
    AfterPublish,
}

internal interface IVaultKeyRingFaultInjector
{
    void ThrowIfRequested(VaultKeyRingFaultPoint point);
}

internal sealed class NoVaultKeyRingFaultInjector : IVaultKeyRingFaultInjector
{
    public static NoVaultKeyRingFaultInjector Instance { get; } = new();
    public void ThrowIfRequested(VaultKeyRingFaultPoint point) { }
}
