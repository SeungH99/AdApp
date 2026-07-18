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
        ReadOnlyMemory<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(eventId);
        EventContractValidation.ThrowIfInvalidEventType(eventType);
        EventContractValidation.ThrowIfInvalidSchemaVersion(schemaVersion);

        EventId = eventId;
        EventType = eventType;
        SchemaVersion = schemaVersion;
        _payload = payload.ToArray();
    }

    public EventId EventId { get; }

    public string EventType { get; }

    public int SchemaVersion { get; }

    public ReadOnlyMemory<byte> Payload => _payload.ToArray();
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
        IEnumerable<EventToAppend> events)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        ArgumentNullException.ThrowIfNull(events);

        var snapshot = Array.AsReadOnly(events.ToArray());
        if (snapshot.Count == 0)
        {
            throw new ArgumentException("At least one event is required.", nameof(events));
        }

        StreamId = streamId;
        ExpectedVersion = expectedVersion;
        Events = snapshot;
    }

    public StreamId StreamId { get; }

    public StreamVersion ExpectedVersion { get; }

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

public sealed record StorageBusy : AppendEventsResult;

public interface IEventStore
{
    Task<IReadOnlyList<StoredEvent>> ReadStreamAsync(
        StreamId streamId,
        CancellationToken cancellationToken);

    Task<AppendEventsResult> AppendAsync(
        AppendEventsCommand command,
        CancellationToken cancellationToken);
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
}
