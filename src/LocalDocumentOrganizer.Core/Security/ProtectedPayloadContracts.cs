namespace LocalDocumentOrganizer.Core.Security;

public readonly record struct OperationId
{
    public OperationId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("An operation ID cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
}

public readonly record struct DataKeyId
{
    public DataKeyId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A data key ID cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
}

public readonly record struct SensitiveObjectId
{
    public SensitiveObjectId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A sensitive object ID cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
}

public enum SensitiveObjectKind
{
    Case,
    DocumentEvidence,
    Journal,
    Entitlement,
}

public readonly record struct SensitiveObjectRef
{
    public SensitiveObjectRef(SensitiveObjectKind kind, SensitiveObjectId id)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), "The sensitive object kind is not defined.");
        }

        if (id.Value == Guid.Empty)
        {
            throw new ArgumentException("A sensitive object ID cannot be empty.", nameof(id));
        }

        Kind = kind;
        Id = id;
    }

    public SensitiveObjectKind Kind { get; }

    public SensitiveObjectId Id { get; }
}

public abstract record PayloadProtection
{
    public sealed record DurableStructural : PayloadProtection;

    public sealed record Shreddable : PayloadProtection
    {
        public Shreddable(SensitiveObjectRef owner)
        {
            if (!Enum.IsDefined(owner.Kind) || owner.Id.Value == Guid.Empty)
            {
                throw new ArgumentException("A valid sensitive object owner is required.", nameof(owner));
            }

            Owner = owner;
        }

        public SensitiveObjectRef Owner { get; }
    }
}
