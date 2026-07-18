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
    private static readonly byte[] Magic = "LDOVKEY1"u8.ToArray();
    private static readonly byte[] AuthenticationDomain =
        "LocalDocumentOrganizer/VaultKeyRing/Authentication/v1"u8.ToArray();
    private static readonly byte[] WrappingDomain =
        "LocalDocumentOrganizer/VaultKeyRing/DekWrapping/v1"u8.ToArray();

    private const int AuthenticationTagSize = 32;
    private const int NonceSize = 12;
    private const int AesTagSize = 16;
    private const int MaximumFileSize = 16 * 1024 * 1024;
    private const int MaximumProtectedRootSize = 64 * 1024;
    private const int MaximumRecords = 100_000;

    private readonly string _path;
    private readonly IVaultKeyProtector _protector;
    private readonly IVaultKeyRingFaultInjector _faults;

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
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(faults);
        MaintenanceGate = new VaultMaintenanceGate(path);
        _path = MaintenanceGate.KeyRingPath;
        _protector = protector;
        _faults = faults;
    }

    public VaultMaintenanceGate MaintenanceGate { get; }

    public async Task<VaultKeyRing> CreateAsync(CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_path)
            ?? throw new ArgumentException("The keyring path has no parent directory.", nameof(_path));
        Directory.CreateDirectory(directory);
        await using var lease = await MaintenanceGate.AcquireAsync(cancellationToken).ConfigureAwait(false);
        CleanupOrphans(requireCanonical: true);
        if (File.Exists(_path))
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

            using var state = new KeyRingState(1, protectedRoot, root, [], []);
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

    public async Task<TResult> GetOrCreateDataKeyAsync<TResult>(
        SensitiveObjectRef owner,
        Func<DataKeyId, ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken)
    {
        await using var lease = await MaintenanceGate.AcquireAsync(cancellationToken).ConfigureAwait(false);
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
        MaintenanceGate.Validate(lease);
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
        var image = await ReadCanonicalAsync(cancellationToken).ConfigureAwait(false);
        using var state = Deserialize(image);
        ThrowIfDestroyed(state, owner);
        var entry = state.Active.SingleOrDefault(candidate => candidate.Owner == owner)
            ?? throw new VaultDataKeyNotFoundException();
        return await UseKeyAsync(state, entry, callback, cancellationToken).ConfigureAwait(false);
    }

    public async Task DestroyDataKeyAsync(
        VaultDestroyedKeyReceipt receipt,
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        receipt.Validate();
        MaintenanceGate.Validate(lease);
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
        MaintenanceGate.Validate(lease);
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
        var wrappingKey = DeriveKey(state.Root, WrappingDomain);
        var plaintext = new byte[VaultKeyRing.DataKeySize];
        try
        {
            using var aes = new AesGcm(wrappingKey, AesTagSize);
            aes.Decrypt(entry.Nonce, entry.WrappedKey, entry.Tag, plaintext, CreateWrappingAad(entry.Owner, entry.KeyId));
            return await callback(entry.KeyId, plaintext, cancellationToken).ConfigureAwait(false);
        }
        catch (AuthenticationTagMismatchException exception)
        {
            throw new VaultKeyRingAuthenticationException(exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
            CryptographicOperations.ZeroMemory(plaintext);
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
        state.Active.Sort(ActiveEntryComparer.Instance);
        state.Destroyed.Sort(DestroyedEntryComparer.Instance);
        using var stream = new MemoryStream();
        Write(stream, Magic);
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
            return [.. authenticated, .. tag];
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
        if (image.Length < Magic.Length + 4 + 8 + 4 + 1 + AuthenticationTagSize
            || image.Length > MaximumFileSize)
        {
            throw new VaultKeyRingFormatException("The Vault keyring size is invalid.");
        }

        var offset = 0;
        if (!image.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new VaultKeyRingFormatException("The Vault keyring magic is invalid.");
        }

        offset += Magic.Length;
        var version = ReadUInt32(image, ref offset);
        if (version != VaultKeyRing.FormatVersion)
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
            var destroyed = new List<VaultDestroyedKeyReceipt>(destroyedCount);
            for (var index = 0; index < destroyedCount; index++)
            {
                var receipt = new VaultDestroyedKeyReceipt(
                    ReadOwner(image, ref offset, bodyLimit),
                    new DataKeyId(ReadGuid(image, ref offset, bodyLimit)),
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
            return new KeyRingState(revision, protectedRoot, root, active, destroyed);
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
            var info = new FileInfo(_path);
            if (!info.Exists)
            {
                if (FindOrphans().Count != 0)
                {
                    throw new VaultKeyRingRecoveryRequiredException();
                }

                throw new VaultKeyRingNotFoundException();
            }

            if (info.Length > MaximumFileSize)
            {
                throw new VaultKeyRingFormatException("The Vault keyring size is invalid.");
            }

            return await File.ReadAllBytesAsync(_path, cancellationToken).ConfigureAwait(false);
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

    private async Task PublishAsync(byte[] image, byte[]? oldImage, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_path)!;
        var temp = Path.Combine(directory, $"{Path.GetFileName(_path)}.tmp-{Guid.NewGuid():N}");
        try
        {
            _faults.ThrowIfRequested(VaultKeyRingFaultPoint.BeforeTempCreate);
            await using (var stream = new FileStream(
                temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(image, cancellationToken).ConfigureAwait(false);
                _faults.ThrowIfRequested(VaultKeyRingFaultPoint.AfterTempWrite);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
                _faults.ThrowIfRequested(VaultKeyRingFaultPoint.AfterFlushBeforePublish);
            }

            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (oldImage is null)
                {
                    File.Move(temp, _path, overwrite: false);
                }
                else
                {
                    File.Replace(temp, _path, destinationBackupFileName: null);
                }

                _faults.ThrowIfRequested(VaultKeyRingFaultPoint.AfterPublish);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                var publicationState = ClassifyCanonical(image, oldImage);
                if (publicationState == PublicationState.New)
                {
                    return;
                }

                if (publicationState == PublicationState.Old)
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
            if (File.Exists(temp))
            {
                try
                {
                    File.Delete(temp);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    throw new VaultKeyRingRecoveryRequiredException(exception);
                }
            }
        }
    }

    private PublicationState ClassifyCanonical(byte[] next, byte[]? previous)
    {
        try
        {
            if (!File.Exists(_path)) return PublicationState.Missing;
            var canonical = File.ReadAllBytes(_path);
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
        if (requireCanonical && !File.Exists(_path))
        {
            throw new VaultKeyRingRecoveryRequiredException();
        }

        if (requireCanonical)
        {
            try
            {
                using var canonical = Deserialize(File.ReadAllBytes(_path));
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
                File.Delete(orphan);
                if (File.Exists(orphan)) throw new IOException("Temporary keyring cleanup was not durable.");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new VaultKeyRingRecoveryRequiredException(exception);
            }
        }
    }

    private List<string> FindOrphans()
    {
        var directory = Path.GetDirectoryName(_path)!;
        if (!Directory.Exists(directory)) return [];
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

    private static bool IsHex(ReadOnlySpan<char> value)
    {
        foreach (var character in value)
        {
            if (!char.IsAsciiHexDigit(character)) return false;
        }

        return true;
    }

    private static bool SameReceiptIdentity(
        VaultDestroyedKeyReceipt left,
        VaultDestroyedKeyReceipt right) =>
        left.Owner == right.Owner && left.KeyId == right.KeyId
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

    private static byte[] CreateWrappingAad(SensitiveObjectRef owner, DataKeyId keyId)
    {
        var aad = new byte[4 + 4 + 16 + 16];
        BinaryPrimitives.WriteUInt32BigEndian(aad, VaultKeyRing.FormatVersion);
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
            ulong revision,
            byte[] protectedRoot,
            byte[] root,
            List<ActiveEntry> active,
            List<VaultDestroyedKeyReceipt> destroyed)
        {
            Revision = revision;
            ProtectedRoot = protectedRoot;
            Root = root;
            Active = active;
            Destroyed = destroyed;
        }

        public ulong Revision { get; set; }
        public byte[] ProtectedRoot { get; }
        public byte[] Root { get; }
        public List<ActiveEntry> Active { get; }
        public List<VaultDestroyedKeyReceipt> Destroyed { get; }

        public VaultKeyRing ToMetadata() => new(
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
