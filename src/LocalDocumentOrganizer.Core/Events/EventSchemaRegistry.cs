using LocalDocumentOrganizer.Core.Deletion;

namespace LocalDocumentOrganizer.Core.Events;

public interface IEventUpcaster
{
    string EventType { get; }

    int FromSchemaVersion { get; }

    int ToSchemaVersion { get; }

    ReadOnlyMemory<byte> Upcast(ReadOnlyMemory<byte> payload);
}

public sealed class EventSchemaRegistry
{
    private readonly IReadOnlyDictionary<string, int> _currentVersions;
    private readonly IReadOnlyDictionary<(string EventType, int FromVersion), IEventUpcaster> _steps;

    public EventSchemaRegistry(
        IReadOnlyDictionary<string, int> currentVersions,
        IEnumerable<IEventUpcaster> upcasters)
    {
        ArgumentNullException.ThrowIfNull(currentVersions);
        ArgumentNullException.ThrowIfNull(upcasters);

        var versionSnapshot = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [SensitiveObjectDeletedEventContract.EventType] =
                SensitiveObjectDeletedEventContract.SchemaVersion,
        };
        foreach (var registration in currentVersions)
        {
            EventContractValidation.ThrowIfInvalidEventType(registration.Key);
            EventContractValidation.ThrowIfInvalidSchemaVersion(registration.Value);
            if (string.Equals(
                registration.Key,
                SensitiveObjectDeletedEventContract.EventType,
                StringComparison.Ordinal))
            {
                throw new ReservedSystemEventTypeException(registration.Key);
            }

            versionSnapshot.Add(registration.Key, registration.Value);
        }

        var stepSnapshot = new Dictionary<(string EventType, int FromVersion), IEventUpcaster>();
        foreach (var upcaster in upcasters)
        {
            ArgumentNullException.ThrowIfNull(upcaster);
            EventContractValidation.ThrowIfInvalidEventType(upcaster.EventType);
            if (string.Equals(
                upcaster.EventType,
                SensitiveObjectDeletedEventContract.EventType,
                StringComparison.Ordinal))
            {
                throw new ReservedSystemEventTypeException(upcaster.EventType);
            }

            if (upcaster.FromSchemaVersion < 1 ||
                upcaster.ToSchemaVersion != upcaster.FromSchemaVersion + 1)
            {
                throw new InvalidUpcasterStepException(
                    upcaster.EventType,
                    upcaster.FromSchemaVersion,
                    upcaster.ToSchemaVersion);
            }

            if (!versionSnapshot.TryGetValue(upcaster.EventType, out var currentVersion))
            {
                throw new UnknownEventTypeException(upcaster.EventType);
            }

            if (upcaster.ToSchemaVersion > currentVersion)
            {
                throw new InvalidUpcasterStepException(
                    upcaster.EventType,
                    upcaster.FromSchemaVersion,
                    upcaster.ToSchemaVersion);
            }

            var key = (upcaster.EventType, upcaster.FromSchemaVersion);
            if (!stepSnapshot.TryAdd(key, upcaster))
            {
                throw new DuplicateUpcasterStepException(
                    upcaster.EventType,
                    upcaster.FromSchemaVersion);
            }
        }

        foreach (var registration in versionSnapshot)
        {
            for (var version = 1; version < registration.Value; version++)
            {
                if (!stepSnapshot.ContainsKey((registration.Key, version)))
                {
                    throw new MissingUpcasterChainException(
                        registration.Key,
                        version,
                        registration.Value);
                }
            }
        }

        _currentVersions = versionSnapshot;
        _steps = stepSnapshot;
    }

    public DecryptedEvent UpcastToCurrent(DecryptedEvent decryptedEvent)
    {
        ArgumentNullException.ThrowIfNull(decryptedEvent);

        var metadata = decryptedEvent.Metadata;

        if (!_currentVersions.TryGetValue(metadata.EventType, out var currentVersion))
        {
            throw new UnknownEventTypeException(metadata.EventType);
        }

        if (metadata.SchemaVersion > currentVersion)
        {
            throw new FutureEventSchemaVersionException(
                metadata.EventType,
                metadata.SchemaVersion,
                currentVersion);
        }

        var payload = decryptedEvent.Payload;
        for (var version = metadata.SchemaVersion; version < currentVersion; version++)
        {
            if (!_steps.TryGetValue((metadata.EventType, version), out var upcaster))
            {
                throw new MissingUpcasterChainException(
                    metadata.EventType,
                    version,
                    currentVersion);
            }

            payload = upcaster.Upcast(payload);
        }

        var currentMetadata = metadata.SchemaVersion == currentVersion
            ? metadata
            : new EventMetadata(
                metadata.StreamId,
                metadata.StreamVersion,
                metadata.EventId,
                metadata.EventType,
                currentVersion,
                metadata.RecordedAtUtc,
                metadata.OperationId,
                metadata.DataKeyId,
                metadata.EncryptionEnvelopeVersion);

        return new DecryptedEvent(currentMetadata, payload);
    }

    public int GetCurrentVersion(string eventType)
    {
        EventContractValidation.ThrowIfInvalidEventType(eventType);
        if (!_currentVersions.TryGetValue(eventType, out var currentVersion))
        {
            throw new UnknownEventTypeException(eventType);
        }

        return currentVersion;
    }
}

public abstract class EventSchemaException : InvalidOperationException
{
    protected EventSchemaException(string message)
        : base(message)
    {
    }
}

public sealed class ReservedSystemEventTypeException : EventSchemaException
{
    public ReservedSystemEventTypeException(string eventType)
        : base($"Event type '{eventType}' is reserved by the system.")
    {
        EventType = eventType;
    }

    public string EventType { get; }
}

public sealed class UnknownEventTypeException : EventSchemaException
{
    public UnknownEventTypeException(string eventType)
        : base($"Event type '{eventType}' is not registered.")
    {
        EventType = eventType;
    }

    public string EventType { get; }
}

public sealed class FutureEventSchemaVersionException : EventSchemaException
{
    public FutureEventSchemaVersionException(
        string eventType,
        int storedSchemaVersion,
        int currentSchemaVersion)
        : base(
            $"Event type '{eventType}' has future schema version {storedSchemaVersion}; " +
            $"the current version is {currentSchemaVersion}.")
    {
        EventType = eventType;
        StoredSchemaVersion = storedSchemaVersion;
        CurrentSchemaVersion = currentSchemaVersion;
    }

    public string EventType { get; }

    public int StoredSchemaVersion { get; }

    public int CurrentSchemaVersion { get; }
}

public sealed class InvalidUpcasterStepException : EventSchemaException
{
    public InvalidUpcasterStepException(string eventType, int fromSchemaVersion, int toSchemaVersion)
        : base(
            $"Upcaster for '{eventType}' must declare one adjacent schema step, but declared " +
            $"{fromSchemaVersion} to {toSchemaVersion}.")
    {
        EventType = eventType;
        FromSchemaVersion = fromSchemaVersion;
        ToSchemaVersion = toSchemaVersion;
    }

    public string EventType { get; }

    public int FromSchemaVersion { get; }

    public int ToSchemaVersion { get; }
}

public sealed class DuplicateUpcasterStepException : EventSchemaException
{
    public DuplicateUpcasterStepException(string eventType, int fromSchemaVersion)
        : base($"More than one upcaster is registered for '{eventType}' schema version {fromSchemaVersion}.")
    {
        EventType = eventType;
        FromSchemaVersion = fromSchemaVersion;
    }

    public string EventType { get; }

    public int FromSchemaVersion { get; }
}

public sealed class MissingUpcasterChainException : EventSchemaException
{
    public MissingUpcasterChainException(
        string eventType,
        int missingFromSchemaVersion,
        int currentSchemaVersion)
        : base(
            $"Event type '{eventType}' has no complete upcaster chain from schema version " +
            $"{missingFromSchemaVersion} to {currentSchemaVersion}.")
    {
        EventType = eventType;
        MissingFromSchemaVersion = missingFromSchemaVersion;
        CurrentSchemaVersion = currentSchemaVersion;
    }

    public string EventType { get; }

    public int MissingFromSchemaVersion { get; }

    public int CurrentSchemaVersion { get; }
}
