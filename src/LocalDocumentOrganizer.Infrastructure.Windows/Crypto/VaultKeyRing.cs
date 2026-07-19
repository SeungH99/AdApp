using System.Collections.ObjectModel;
using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public sealed class VaultKeyRing
{
    public const int RootSize = 32;
    public const int DataKeySize = 32;
    public const int FormatVersion = 1;

    private readonly ReadOnlyCollection<VaultActiveKeyMetadata> _activeKeys;
    private readonly ReadOnlyCollection<VaultDestroyedKeyReceipt> _destroyedReceipts;

    internal VaultKeyRing(
        VaultKeyRingIdentity identity,
        IEnumerable<VaultActiveKeyMetadata> activeKeys,
        IEnumerable<VaultDestroyedKeyReceipt> destroyedReceipts)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _activeKeys = Array.AsReadOnly(activeKeys.ToArray());
        _destroyedReceipts = Array.AsReadOnly(destroyedReceipts.ToArray());
    }

    internal VaultKeyRingIdentity Identity { get; }

    public IReadOnlyList<VaultActiveKeyMetadata> ActiveKeys => _activeKeys;

    public IReadOnlyList<VaultDestroyedKeyReceipt> DestroyedReceipts => _destroyedReceipts;
}

internal sealed class VaultKeyRingIdentity
{
    public const int Size = 32;
    private readonly byte[] _value;

    internal VaultKeyRingIdentity(ReadOnlySpan<byte> value)
    {
        if (value.Length != Size)
            throw new ArgumentException("The Vault keyring identity length is invalid.", nameof(value));
        _value = value.ToArray();
    }

    internal byte[] Export() => _value.ToArray();

    internal bool FixedTimeEquals(ReadOnlySpan<byte> candidate) =>
        candidate.Length == Size
        && CryptographicOperations.FixedTimeEquals(_value, candidate);

    internal bool FixedTimeEquals(VaultKeyRingIdentity? candidate) =>
        candidate is not null
        && CryptographicOperations.FixedTimeEquals(_value, candidate._value);
}

public sealed record VaultActiveKeyMetadata(SensitiveObjectRef Owner, DataKeyId KeyId);

public enum VaultDestroyedReceiptState
{
    PendingSqlCompletion = 1,
    Completed = 2,
}

public sealed record VaultDestroyedKeyReceipt
{
    public VaultDestroyedKeyReceipt(
        SensitiveObjectRef owner,
        DataKeyId keyId,
        OperationId operationId,
        EventId tombstoneEventId,
        StreamVersion expectedStreamVersion,
        string reasonCode,
        VaultDestroyedReceiptState state)
    {
        Owner = owner;
        KeyId = keyId;
        OperationId = operationId;
        TombstoneEventId = tombstoneEventId;
        ExpectedStreamVersion = expectedStreamVersion;
        ReasonCode = reasonCode;
        State = state;
        Validate();
    }

    public SensitiveObjectRef Owner { get; }
    public DataKeyId KeyId { get; }
    public OperationId OperationId { get; }
    public EventId TombstoneEventId { get; }
    public StreamVersion ExpectedStreamVersion { get; }
    public string ReasonCode { get; }
    public VaultDestroyedReceiptState State { get; }

    internal void Validate()
    {
        if (!Enum.IsDefined(Owner.Kind) || Owner.Id.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid receipt owner is required.", nameof(Owner));
        }

        if (KeyId.Value == Guid.Empty || OperationId.Value == Guid.Empty
            || TombstoneEventId.Value == Guid.Empty)
        {
            throw new ArgumentException("Receipt identifiers must be non-empty.");
        }

        if (ExpectedStreamVersion.Value < StreamVersion.NoStream.Value)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ExpectedStreamVersion),
                "The expected stream version is invalid.");
        }

        if (string.IsNullOrEmpty(ReasonCode) || ReasonCode.Length > 32
            || ReasonCode.Any(character =>
                !char.IsAsciiLetterLower(character)
                && !char.IsAsciiDigit(character)
                && character != '-'))
        {
            throw new ArgumentException(
                "The reason code must be a lowercase ASCII token of at most 32 characters.",
                nameof(ReasonCode));
        }

        if (!Enum.IsDefined(State))
        {
            throw new ArgumentOutOfRangeException(nameof(State), "The receipt state is invalid.");
        }
    }
}

public abstract class VaultKeyRingException : Exception
{
    protected VaultKeyRingException(string message)
        : base(message)
    {
    }

    protected VaultKeyRingException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class VaultKeyRingFormatException : VaultKeyRingException
{
    internal VaultKeyRingFormatException(string message) : base(message) { }
    internal VaultKeyRingFormatException(string message, Exception innerException) : base(message, innerException) { }
}

public sealed class VaultKeyRingAuthenticationException : VaultKeyRingException
{
    internal VaultKeyRingAuthenticationException() : base("Vault keyring authentication failed.") { }
    internal VaultKeyRingAuthenticationException(Exception innerException)
        : base("Vault keyring authentication failed.", innerException) { }
}

public sealed class VaultKeyProtectionException : VaultKeyRingException
{
    internal VaultKeyProtectionException(string message) : base(message) { }
    internal VaultKeyProtectionException(string message, Exception innerException) : base(message, innerException) { }
}

public sealed class VaultDataKeyDestroyedException : VaultKeyRingException
{
    internal VaultDataKeyDestroyedException() : base("The requested Vault data key was destroyed.") { }
}

public sealed class VaultDataKeyNotFoundException : VaultKeyRingException
{
    internal VaultDataKeyNotFoundException() : base("The requested Vault data key does not exist.") { }
}

public sealed class VaultReceiptConflictException : VaultKeyRingException
{
    internal VaultReceiptConflictException() : base("The destroyed-key receipt conflicts with persisted metadata.") { }
}

public sealed class VaultAtomicPublicationException : VaultKeyRingException
{
    internal VaultAtomicPublicationException(Exception innerException)
        : base("The Vault keyring publication result is indeterminate.", innerException) { }
}

public sealed class VaultKeyRingNotFoundException : VaultKeyRingException
{
    internal VaultKeyRingNotFoundException() : base("The Vault keyring does not exist.") { }
}

public sealed class VaultKeyRingPersistenceException : VaultKeyRingException
{
    internal VaultKeyRingPersistenceException(string message) : base(message) { }
    internal VaultKeyRingPersistenceException(string message, Exception innerException)
        : base(message, innerException) { }
}

public sealed class VaultKeyRingRecoveryRequiredException : VaultKeyRingException
{
    internal VaultKeyRingRecoveryRequiredException()
        : base("Vault keyring recovery is required.") { }
    internal VaultKeyRingRecoveryRequiredException(Exception innerException)
        : base("Vault keyring recovery is required.", innerException) { }
}
