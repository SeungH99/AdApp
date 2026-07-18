using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Core.Events;

public sealed record StreamId
{
    public StreamId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A stream ID cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
}

public sealed record EventId
{
    public EventId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("An event ID cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
}

public readonly record struct StreamVersion
{
    public static StreamVersion NoStream { get; } = new(-1);

    public StreamVersion(long value)
    {
        if (value < -1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                value,
                "A stream version cannot be lower than -1.");
        }

        Value = value;
    }

    public long Value { get; }

    public StreamVersion Next() => new(checked(Value + 1));
}

public sealed record EventToAppend
{
    private readonly byte[] _payload;

    public EventToAppend(
        EventId eventId,
        string eventType,
        int schemaVersion,
        ReadOnlyMemory<byte> payload,
        PayloadProtection protection)
    {
        ArgumentNullException.ThrowIfNull(eventId);
        ArgumentNullException.ThrowIfNull(protection);
        EventContractValidation.ThrowIfInvalidEventType(eventType);
        EventContractValidation.ThrowIfInvalidSchemaVersion(schemaVersion);

        EventId = eventId;
        EventType = eventType;
        SchemaVersion = schemaVersion;
        _payload = payload.ToArray();
        Protection = protection;
    }

    public EventId EventId { get; }

    public string EventType { get; }

    public int SchemaVersion { get; }

    public ReadOnlyMemory<byte> Payload => _payload.ToArray();

    public PayloadProtection Protection { get; }
}

public sealed record StoredEvent
{
    private readonly byte[] _payload;

    public StoredEvent(
        StreamId streamId,
        StreamVersion streamVersion,
        EventId eventId,
        string eventType,
        int schemaVersion,
        ReadOnlyMemory<byte> payload,
        DateTimeOffset recordedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        ArgumentNullException.ThrowIfNull(eventId);
        EventContractValidation.ThrowIfInvalidEventType(eventType);
        EventContractValidation.ThrowIfInvalidSchemaVersion(schemaVersion);

        StreamId = streamId;
        StreamVersion = streamVersion;
        EventId = eventId;
        EventType = eventType;
        SchemaVersion = schemaVersion;
        _payload = payload.ToArray();
        RecordedAtUtc = recordedAtUtc.ToUniversalTime();
    }

    public StreamId StreamId { get; }

    public StreamVersion StreamVersion { get; }

    public EventId EventId { get; }

    public string EventType { get; }

    public int SchemaVersion { get; }

    public ReadOnlyMemory<byte> Payload => _payload.ToArray();

    public DateTimeOffset RecordedAtUtc { get; }
}

public sealed record AppendEventsCommand
{
    public AppendEventsCommand(
        StreamId streamId,
        StreamVersion expectedVersion,
        OperationId operationId,
        IEnumerable<EventToAppend> events)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        ArgumentNullException.ThrowIfNull(events);
        EventContractValidation.ThrowIfEmptyOperationId(operationId);

        var snapshot = Array.AsReadOnly(events.ToArray());
        if (snapshot.Count == 0)
        {
            throw new ArgumentException("At least one event is required.", nameof(events));
        }

        StreamId = streamId;
        ExpectedVersion = expectedVersion;
        OperationId = operationId;
        Events = snapshot;
    }

    public StreamId StreamId { get; }

    public StreamVersion ExpectedVersion { get; }

    public OperationId OperationId { get; }

    public IReadOnlyList<EventToAppend> Events { get; }
}

public abstract record AppendEventsResult
{
    private protected AppendEventsResult()
    {
    }
}

public sealed record Appended(StreamVersion NewVersion) : AppendEventsResult;

public sealed record ConcurrencyConflict(
    StreamVersion ExpectedVersion,
    StreamVersion ActualVersion) : AppendEventsResult;

public sealed record AlreadyApplied(StreamVersion ExistingVersion) : AppendEventsResult;

public sealed record OperationConflict(OperationId OperationId) : AppendEventsResult;

public sealed record OperationComparisonUnavailable(OperationId OperationId) : AppendEventsResult;

public sealed record StorageBusy : AppendEventsResult;

public interface IEventStore
{
    Task<IReadOnlyList<EventForReplay>> ReadStreamAsync(
        StreamId streamId,
        CancellationToken cancellationToken);

    Task<AppendEventsResult> AppendAsync(
        AppendEventsCommand command,
        CancellationToken cancellationToken);
}

public sealed record EventMetadata
{
    public EventMetadata(
        StreamId streamId,
        StreamVersion streamVersion,
        EventId eventId,
        string eventType,
        int schemaVersion,
        DateTimeOffset recordedAtUtc,
        OperationId operationId,
        DataKeyId? dataKeyId,
        int encryptionEnvelopeVersion)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        ArgumentNullException.ThrowIfNull(eventId);
        EventContractValidation.ThrowIfInvalidEventType(eventType);
        EventContractValidation.ThrowIfInvalidSchemaVersion(schemaVersion);
        EventContractValidation.ThrowIfEmptyOperationId(operationId);
        EventContractValidation.ThrowIfInvalidRecordedAtUtc(recordedAtUtc);
        EventContractValidation.ThrowIfInvalidProtectionEnvelope(dataKeyId, encryptionEnvelopeVersion);

        StreamId = streamId;
        StreamVersion = streamVersion;
        EventId = eventId;
        EventType = eventType;
        SchemaVersion = schemaVersion;
        RecordedAtUtc = recordedAtUtc;
        OperationId = operationId;
        DataKeyId = dataKeyId;
        EncryptionEnvelopeVersion = encryptionEnvelopeVersion;
    }

    public StreamId StreamId { get; }

    public StreamVersion StreamVersion { get; }

    public EventId EventId { get; }

    public string EventType { get; }

    public int SchemaVersion { get; }

    public DateTimeOffset RecordedAtUtc { get; }

    public OperationId OperationId { get; }

    public DataKeyId? DataKeyId { get; }

    public int EncryptionEnvelopeVersion { get; }
}

public abstract record EventForReplay
{
    protected EventForReplay(EventMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        Metadata = metadata;
    }

    public EventMetadata Metadata { get; }
}

public sealed record DecryptedEvent : EventForReplay
{
    private readonly byte[] _payload;

    public DecryptedEvent(EventMetadata metadata, ReadOnlyMemory<byte> payload)
        : base(metadata)
    {
        _payload = payload.ToArray();
    }

    public ReadOnlyMemory<byte> Payload => _payload.ToArray();
}

public sealed record ShreddedEvent : EventForReplay
{
    public ShreddedEvent(EventMetadata metadata, SensitiveObjectRef owner)
        : base(metadata)
    {
        if (metadata.DataKeyId is null || metadata.EncryptionEnvelopeVersion < 1)
        {
            throw new ArgumentException(
                "Shredded events require protected replay metadata.",
                nameof(metadata));
        }

        if (!Enum.IsDefined(owner.Kind) || owner.Id.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid sensitive object owner is required.", nameof(owner));
        }

        Owner = owner;
    }

    public SensitiveObjectRef Owner { get; }
}

internal static class EventContractValidation
{
    public static void ThrowIfInvalidEventType(string eventType)
    {
        if (string.IsNullOrWhiteSpace(eventType))
        {
            throw new ArgumentException("A stable logical event type is required.", nameof(eventType));
        }
    }

    public static void ThrowIfInvalidSchemaVersion(int schemaVersion)
    {
        if (schemaVersion < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(schemaVersion),
                schemaVersion,
                "Schema versions start at 1.");
        }
    }

    public static void ThrowIfEmptyOperationId(OperationId operationId)
    {
        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException("An operation ID cannot be empty.", nameof(operationId));
        }
    }

    public static void ThrowIfInvalidRecordedAtUtc(DateTimeOffset recordedAtUtc)
    {
        if (recordedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("The recorded timestamp must use the UTC offset.", nameof(recordedAtUtc));
        }
    }

    public static void ThrowIfInvalidProtectionEnvelope(
        DataKeyId? dataKeyId,
        int encryptionEnvelopeVersion)
    {
        if (dataKeyId is null && encryptionEnvelopeVersion != 0)
        {
            throw new ArgumentException("Structural events require the unencrypted envelope version.");
        }

        if (dataKeyId is { } keyId && keyId.Value == Guid.Empty)
        {
            throw new ArgumentException("A data key ID cannot be empty.", nameof(dataKeyId));
        }

        if (dataKeyId is not null && encryptionEnvelopeVersion < 1)
        {
            throw new ArgumentException("Protected events require an encryption envelope version.");
        }
    }
}
