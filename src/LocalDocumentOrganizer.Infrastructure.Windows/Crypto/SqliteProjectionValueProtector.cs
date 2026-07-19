using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

internal class ProjectionValueRecoveryRequiredException : Exception
{
    internal ProjectionValueRecoveryRequiredException(string message)
        : base(message)
    {
    }

    internal ProjectionValueRecoveryRequiredException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal sealed class ProjectionValueFormatException : ProjectionValueRecoveryRequiredException
{
    internal ProjectionValueFormatException()
        : base("The encrypted projection value format is invalid or unsupported.")
    {
    }

    internal ProjectionValueFormatException(Exception innerException)
        : base("The encrypted projection value format is invalid or unsupported.", innerException)
    {
    }
}

internal sealed class ProjectionValueOwnerKeyException : ProjectionValueRecoveryRequiredException
{
    internal ProjectionValueOwnerKeyException()
        : base("The encrypted projection value owner or key binding is invalid.")
    {
    }

    internal ProjectionValueOwnerKeyException(Exception innerException)
        : base("The encrypted projection value owner or key binding is invalid.", innerException)
    {
    }
}

internal sealed class ProjectionValueAuthenticationException : ProjectionValueRecoveryRequiredException
{
    internal ProjectionValueAuthenticationException(Exception innerException)
        : base("The encrypted projection value could not be authenticated.", innerException)
    {
    }
}

internal sealed class ProjectionValueReentrancyException : ProjectionValueRecoveryRequiredException
{
    internal ProjectionValueReentrancyException()
        : base("A projection value operation is already active for this context.")
    {
    }
}

internal sealed class ProjectionContentFreeContractException : ProjectionValueRecoveryRequiredException
{
    internal ProjectionContentFreeContractException()
        : base("Sensitive projection values are unavailable for a content-free event.")
    {
    }
}

internal sealed class EncryptedProjectionValue
{
    internal const int CurrentVersion = 1;
    internal const int NonceSize = 12;
    internal const int TagSize = 16;

    private readonly byte[] _nonce;
    private readonly byte[] _ciphertext;
    private readonly byte[] _tag;

    internal EncryptedProjectionValue(
        int encryptionVersion,
        DataKeyId dataKeyId,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag)
    {
        if (encryptionVersion != CurrentVersion
            || dataKeyId.Value == Guid.Empty
            || nonce is null
            || ciphertext is null
            || tag is null
            || nonce.Length != NonceSize
            || tag.Length != TagSize)
        {
            throw new ProjectionValueFormatException();
        }

        EncryptionVersion = encryptionVersion;
        DataKeyId = dataKeyId;
        _nonce = nonce.ToArray();
        _ciphertext = ciphertext.ToArray();
        _tag = tag.ToArray();
    }

    public int EncryptionVersion { get; }

    public DataKeyId DataKeyId { get; }

    public ReadOnlyMemory<byte> Nonce => _nonce.ToArray();

    public ReadOnlyMemory<byte> Ciphertext => _ciphertext.ToArray();

    public ReadOnlyMemory<byte> Tag => _tag.ToArray();

    internal byte[] CopyNonce() => _nonce.ToArray();

    internal byte[] CopyCiphertext() => _ciphertext.ToArray();

    internal byte[] CopyTag() => _tag.ToArray();
}

internal static class ProjectionValueAdditionalData
{
    private const int MaximumIdentifierBytes = 256;
    private static readonly byte[] Domain =
        "LocalDocumentOrganizer/ProjectionValue/AAD/v1"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal static void ValidateIdentifier(string value) => _ = EncodeIdentifier(value);

    internal static byte[] Create(
        SqliteProjectionRegistration registration,
        string tableName,
        string fieldName,
        string logicalValueKey,
        SensitiveObjectRef owner,
        DataKeyId dataKeyId)
    {
        ArgumentNullException.ThrowIfNull(registration);
        if (registration.EncryptionVersion != EncryptedProjectionValue.CurrentVersion)
            throw new ProjectionValueFormatException();
        if (dataKeyId.Value == Guid.Empty || owner.Id.Value == Guid.Empty)
            throw new ProjectionValueOwnerKeyException();
        if (!registration.EncryptedLocations.Contains(
                new EncryptedProjectionLocation(tableName, fieldName)))
            throw new ProjectionValueFormatException();

        try
        {
            var projectionName = EncodeIdentifier(registration.Name);
            var table = EncodeIdentifier(tableName);
            var field = EncodeIdentifier(fieldName);
            var logicalKey = EncodeIdentifier(logicalValueKey);
            var length = checked(
                Domain.Length
                + 4 + 4
                + 2 + projectionName.Length
                + 2 + table.Length
                + 2 + field.Length
                + 2 + logicalKey.Length
                + 4 + 16 + 16);
            var output = new byte[length];
            var offset = 0;
            Domain.CopyTo(output, offset);
            offset += Domain.Length;
            WriteUInt32(output, ref offset, checked((uint)registration.EncryptionVersion));
            WriteUInt32(output, ref offset, checked((uint)registration.SchemaVersion));
            WriteBytes(output, ref offset, projectionName);
            WriteBytes(output, ref offset, table);
            WriteBytes(output, ref offset, field);
            WriteBytes(output, ref offset, logicalKey);
            WriteUInt32(output, ref offset, OwnerCode(owner.Kind));
            WriteGuid(output, ref offset, owner.Id.Value);
            WriteGuid(output, ref offset, dataKeyId.Value);
            if (offset != output.Length) throw new ProjectionValueFormatException();
            return output;
        }
        catch (ProjectionValueRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is EncoderFallbackException
            or OverflowException or ArgumentException)
        {
            throw new ProjectionValueFormatException(exception);
        }
    }

    private static byte[] EncodeIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ProjectionValueFormatException();
        var bytes = StrictUtf8.GetBytes(value);
        if (bytes.Length is 0 or > MaximumIdentifierBytes)
            throw new ProjectionValueFormatException();
        return bytes;
    }

    private static uint OwnerCode(SensitiveObjectKind kind) => kind switch
    {
        SensitiveObjectKind.Case => 0,
        SensitiveObjectKind.DocumentEvidence => 1,
        SensitiveObjectKind.Journal => 2,
        SensitiveObjectKind.Entitlement => 3,
        _ => throw new ProjectionValueFormatException(),
    };

    private static void WriteUInt32(byte[] destination, ref int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination.AsSpan(offset, 4), value);
        offset += 4;
    }

    private static void WriteBytes(byte[] destination, ref int offset, byte[] value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.AsSpan(offset, 2),
            checked((ushort)value.Length));
        offset += 2;
        value.CopyTo(destination, offset);
        offset += value.Length;
    }

    private static void WriteGuid(byte[] destination, ref int offset, Guid value)
    {
        if (!value.TryWriteBytes(destination.AsSpan(offset, 16), bigEndian: true, out var written)
            || written != 16)
            throw new ProjectionValueFormatException();
        offset += written;
    }
}

internal sealed class SqliteProjectionValueProtector
{
    private readonly VaultKeyRingStore _keyRing;
    private readonly VaultMaintenanceLease? _lease;
    private readonly VaultKeyRingStore.VaultKeyRingSession? _session;
    private readonly SqliteEventPayloadReadSession? _readSession;
    private readonly SqliteProjectionRegistration _registration;

    internal SqliteProjectionValueProtector(
        VaultKeyRingStore keyRing,
        VaultMaintenanceLease lease,
        SqliteProjectionRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(registration);
        _keyRing = keyRing;
        _lease = lease;
        _registration = registration;
    }

    internal SqliteProjectionValueProtector(
        VaultKeyRingStore keyRing,
        SqliteEventPayloadReadSession readSession,
        SqliteProjectionRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(readSession);
        ArgumentNullException.ThrowIfNull(registration);
        _keyRing = keyRing;
        _readSession = readSession;
        _registration = registration;
    }

    internal SqliteProjectionValueProtector(
        VaultKeyRingStore keyRing,
        VaultKeyRingStore.VaultKeyRingSession session,
        SqliteProjectionRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(registration);
        _keyRing = keyRing;
        _session = session;
        _registration = registration;
    }

    internal IProjectionApplyValues CreateApplyValues(
        SensitiveObjectRef owner,
        DataKeyId dataKeyId) => new ApplyValues(this, owner, dataKeyId);

    internal IProjectionAdministrativeValues CreateAdministrativeValues() =>
        new AdministrativeValues(this);

    private async ValueTask<EncryptedProjectionValue> ProtectAsync(
        string tableName,
        string fieldName,
        string logicalValueKey,
        SensitiveObjectRef owner,
        DataKeyId dataKeyId,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken)
    {
        var aad = ProjectionValueAdditionalData.Create(
            _registration, tableName, fieldName, logicalValueKey, owner, dataKeyId);
        try
        {
            return await UseProjectionSubkeyAsync(
                owner,
                dataKeyId,
                (subkey, token) => EncryptAsync(dataKeyId, plaintext, subkey, aad, token),
                cancellationToken).ConfigureAwait(false);
        }
        catch (ProjectionValueRecoveryRequiredException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (VaultKeyRingException exception)
        {
            throw new ProjectionValueOwnerKeyException(exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private async ValueTask<TResult> UnprotectAsync<TResult>(
        string tableName,
        string fieldName,
        string logicalValueKey,
        SensitiveObjectRef owner,
        DataKeyId dataKeyId,
        EncryptedProjectionValue encryptedValue,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(encryptedValue);
        ArgumentNullException.ThrowIfNull(callback);
        if (encryptedValue.DataKeyId != dataKeyId)
            throw new ProjectionValueOwnerKeyException();
        var aad = ProjectionValueAdditionalData.Create(
            _registration, tableName, fieldName, logicalValueKey, owner, dataKeyId);
        try
        {
            return await UseProjectionSubkeyAsync(
                owner,
                dataKeyId,
                (subkey, token) => DecryptAsync(
                    encryptedValue, subkey, aad, callback, token),
                cancellationToken).ConfigureAwait(false);
        }
        catch (ProjectionValueRecoveryRequiredException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (VaultKeyRingException exception)
        {
            throw new ProjectionValueOwnerKeyException(exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private ValueTask<TResult> UseProjectionSubkeyAsync<TResult>(
        SensitiveObjectRef owner,
        DataKeyId dataKeyId,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken) =>
        _session is not null
            ? _session.UseProjectionSubkeyAsync(
                owner, dataKeyId, callback, cancellationToken)
            : _readSession is not null
                ? _readSession.UseProjectionSubkeyAsync(
                    owner, dataKeyId, callback, cancellationToken)
            : _keyRing.UseProjectionSubkeyAsync(
                owner,
                dataKeyId,
                _lease ?? throw new InvalidOperationException("A maintenance lease is required."),
                callback,
                cancellationToken);

    private static ValueTask<EncryptedProjectionValue> EncryptAsync(
        DataKeyId dataKeyId,
        ReadOnlyMemory<byte> plaintext,
        ReadOnlyMemory<byte> subkey,
        byte[] aad,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var nonce = RandomNumberGenerator.GetBytes(EncryptedProjectionValue.NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[EncryptedProjectionValue.TagSize];
        try
        {
            using var aes = new AesGcm(subkey.Span, EncryptedProjectionValue.TagSize);
            aes.Encrypt(nonce, plaintext.Span, ciphertext, tag, aad);
            return ValueTask.FromResult(new EncryptedProjectionValue(
                EncryptedProjectionValue.CurrentVersion,
                dataKeyId,
                nonce,
                ciphertext,
                tag));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static async ValueTask<TResult> DecryptAsync<TResult>(
        EncryptedProjectionValue encryptedValue,
        ReadOnlyMemory<byte> subkey,
        byte[] aad,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var nonce = encryptedValue.CopyNonce();
        var ciphertext = encryptedValue.CopyCiphertext();
        var tag = encryptedValue.CopyTag();
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(subkey.Span, EncryptedProjectionValue.TagSize);
            try
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            }
            catch (AuthenticationTagMismatchException exception)
            {
                throw new ProjectionValueAuthenticationException(exception);
            }

            return await callback(plaintext, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private abstract class ValuesBase
    {
        protected readonly SqliteProjectionValueProtector Protector;
        private int _operationActive;

        protected ValuesBase(SqliteProjectionValueProtector protector)
        {
            Protector = protector;
        }

        protected void EnterOperation()
        {
            if (Interlocked.CompareExchange(ref _operationActive, 1, 0) != 0)
                throw new ProjectionValueReentrancyException();
        }

        protected void ExitOperation() => Volatile.Write(ref _operationActive, 0);
    }

    private sealed class ApplyValues : ValuesBase, IProjectionApplyValues
    {
        internal ApplyValues(
            SqliteProjectionValueProtector protector,
            SensitiveObjectRef owner,
            DataKeyId dataKeyId)
            : base(protector)
        {
            if (owner.Id.Value == Guid.Empty || dataKeyId.Value == Guid.Empty)
                throw new ProjectionValueOwnerKeyException();
            BoundOwner = owner;
            BoundDataKeyId = dataKeyId;
        }

        public SensitiveObjectRef BoundOwner { get; }

        public DataKeyId BoundDataKeyId { get; }

        public async ValueTask<EncryptedProjectionValue> ProtectAsync(
            string tableName,
            string fieldName,
            string logicalValueKey,
            SensitiveObjectRef owner,
            DataKeyId dataKeyId,
            ReadOnlyMemory<byte> plaintext,
            CancellationToken cancellationToken)
        {
            EnterOperation();
            try
            {
                RequireBinding(owner, dataKeyId);
                return await Protector.ProtectAsync(
                    tableName, fieldName, logicalValueKey, owner, dataKeyId,
                    plaintext, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ExitOperation();
            }
        }

        public async ValueTask<TResult> UnprotectAsync<TResult>(
            string tableName,
            string fieldName,
            string logicalValueKey,
            SensitiveObjectRef owner,
            DataKeyId dataKeyId,
            EncryptedProjectionValue encryptedValue,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
            CancellationToken cancellationToken)
        {
            EnterOperation();
            try
            {
                RequireBinding(owner, dataKeyId);
                return await Protector.UnprotectAsync(
                    tableName, fieldName, logicalValueKey, owner, dataKeyId,
                    encryptedValue, callback, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ExitOperation();
            }
        }

        private void RequireBinding(SensitiveObjectRef owner, DataKeyId dataKeyId)
        {
            if (owner != BoundOwner || dataKeyId != BoundDataKeyId)
                throw new ProjectionValueOwnerKeyException();
        }
    }

    private sealed class AdministrativeValues : ValuesBase, IProjectionAdministrativeValues
    {
        internal AdministrativeValues(SqliteProjectionValueProtector protector)
            : base(protector)
        {
        }

        public async ValueTask<TResult> UnprotectAsync<TResult>(
            string tableName,
            string fieldName,
            string logicalValueKey,
            SensitiveObjectRef owner,
            DataKeyId dataKeyId,
            EncryptedProjectionValue encryptedValue,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<TResult>> callback,
            CancellationToken cancellationToken)
        {
            EnterOperation();
            try
            {
                return await Protector.UnprotectAsync(
                    tableName, fieldName, logicalValueKey, owner, dataKeyId,
                    encryptedValue, callback, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ExitOperation();
            }
        }
    }
}
