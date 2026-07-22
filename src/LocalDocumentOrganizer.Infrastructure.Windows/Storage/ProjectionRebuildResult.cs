using LocalDocumentOrganizer.Core.Events;
using System.Collections.ObjectModel;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public sealed class ProjectionRebuildResult
{
    public ProjectionRebuildResult(
        long totalEventCount,
        IReadOnlyDictionary<StreamId, StreamVersion> streamHeads,
        IReadOnlyDictionary<string, string> projectionChecksums)
    {
        if (totalEventCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(totalEventCount));
        }

        ArgumentNullException.ThrowIfNull(streamHeads);
        ArgumentNullException.ThrowIfNull(projectionChecksums);

        TotalEventCount = totalEventCount;
        StreamHeads = new ReadOnlyDictionary<StreamId, StreamVersion>(
            new Dictionary<StreamId, StreamVersion>(streamHeads));
        ProjectionChecksums = new ReadOnlyDictionary<string, string>(
            new SortedDictionary<string, string>(
                projectionChecksums.ToDictionary(
                    pair => pair.Key,
                    pair => pair.Value,
                    StringComparer.Ordinal),
                StringComparer.Ordinal));
    }

    public long TotalEventCount { get; }

    public IReadOnlyDictionary<StreamId, StreamVersion> StreamHeads { get; }

    public IReadOnlyDictionary<string, string> ProjectionChecksums { get; }
}

public sealed class EventStreamCorruptionException : InvalidOperationException
{
    public EventStreamCorruptionException(string message)
        : base(message)
    {
    }
}

public sealed class InvalidProjectionChecksumException : InvalidOperationException
{
    public InvalidProjectionChecksumException(string projectionName, string checksum)
        : base($"Projection '{projectionName}' returned invalid checksum '{checksum}'.")
    {
        ProjectionName = projectionName;
        Checksum = checksum;
    }

    public string ProjectionName { get; }

    public string Checksum { get; }
}

public sealed class StorageBusyException : InvalidOperationException
{
    public StorageBusyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class StorageCapacityException : IOException
{
    public StorageCapacityException()
        : base("The Vault does not have enough storage capacity to complete the operation.")
    {
    }

    internal StorageCapacityException(Exception innerException)
        : base("The Vault does not have enough storage capacity to complete the operation.", innerException)
    {
    }
}
