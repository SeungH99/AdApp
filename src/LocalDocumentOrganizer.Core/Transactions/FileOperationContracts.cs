using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Core.Transactions;

public enum FileOperationKind
{
    SameVolumeMove = 0,
    UndoSameVolumeMove = 1,
    CrossVolumeMove = 2,
    UndoCrossVolumeMove = 3,
}

public sealed record StableFileIdentity
{
    private readonly byte[] _volumeId;
    private readonly byte[] _fileId;
    private readonly byte[] _keyedFingerprint;

    public StableFileIdentity(
        byte[] volumeId,
        byte[] fileId,
        long length,
        DateTimeOffset lastWriteTimeUtc,
        byte[] keyedFingerprint)
    {
        _volumeId = SnapshotNonEmpty(volumeId, nameof(volumeId));
        _fileId = SnapshotNonEmpty(fileId, nameof(fileId));
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "The file length cannot be negative.");
        }

        if (lastWriteTimeUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("The last write timestamp must use the UTC offset.", nameof(lastWriteTimeUtc));
        }

        _keyedFingerprint = SnapshotNonEmpty(keyedFingerprint, nameof(keyedFingerprint));
        Length = length;
        LastWriteTimeUtc = lastWriteTimeUtc;
    }

    public byte[] VolumeId => _volumeId.ToArray();

    public byte[] FileId => _fileId.ToArray();

    public long Length { get; }

    public DateTimeOffset LastWriteTimeUtc { get; }

    public byte[] KeyedFingerprint => _keyedFingerprint.ToArray();

    private static byte[] SnapshotNonEmpty(byte[] value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0)
        {
            throw new ArgumentException("A stable identity component is required.", parameterName);
        }

        return value.ToArray();
    }
}

public sealed record FileOperationIntent
{
    private readonly byte[] _approvedProposal;

    public FileOperationIntent(
        OperationId operationId,
        SensitiveObjectRef owner,
        FileOperationKind kind,
        string sourcePath,
        string destinationPath,
        string sourceRoot,
        string destinationRoot,
        StreamId streamId,
        StreamVersion expectedStreamVersion,
        ReadOnlyMemory<byte> approvedProposal)
    {
        ValidateOperationId(operationId);
        ValidateOwner(owner);
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), "The file operation kind is not defined.");
        }

        ValidateNonBlank(sourcePath, nameof(sourcePath));
        ValidateNonBlank(destinationPath, nameof(destinationPath));
        ValidateNonBlank(sourceRoot, nameof(sourceRoot));
        ValidateNonBlank(destinationRoot, nameof(destinationRoot));
        ArgumentNullException.ThrowIfNull(streamId);
        if (expectedStreamVersion.Value < -1)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedStreamVersion));
        }

        OperationId = operationId;
        Owner = owner;
        Kind = kind;
        SourcePath = sourcePath;
        DestinationPath = destinationPath;
        SourceRoot = sourceRoot;
        DestinationRoot = destinationRoot;
        StreamId = streamId;
        ExpectedStreamVersion = expectedStreamVersion;
        _approvedProposal = approvedProposal.ToArray();
    }

    public OperationId OperationId { get; }

    public SensitiveObjectRef Owner { get; }

    public FileOperationKind Kind { get; }

    public string SourcePath { get; }

    public string DestinationPath { get; }

    public string SourceRoot { get; }

    public string DestinationRoot { get; }

    public StreamId StreamId { get; }

    public StreamVersion ExpectedStreamVersion { get; }

    public ReadOnlyMemory<byte> ApprovedProposal => _approvedProposal.ToArray();

    private static void ValidateOperationId(OperationId operationId)
    {
        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException("An operation ID cannot be empty.", nameof(operationId));
        }
    }

    private static void ValidateOwner(SensitiveObjectRef owner)
    {
        if (!Enum.IsDefined(owner.Kind) || owner.Id.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid sensitive object owner is required.", nameof(owner));
        }
    }

    private static void ValidateNonBlank(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A non-empty path or root is required.", parameterName);
        }
    }
}

public sealed record FileOperationBatch
{
    public const int MaximumIntentCount = 100;

    public FileOperationBatch(IEnumerable<FileOperationIntent> intents)
    {
        ArgumentNullException.ThrowIfNull(intents);
        var snapshot = intents.ToArray();
        if (snapshot.Length is < 1 or > MaximumIntentCount)
        {
            throw new ArgumentException("A batch must contain between one and 100 intents.", nameof(intents));
        }

        if (snapshot.Any(intent => intent is null))
        {
            throw new ArgumentException("A batch cannot contain a null intent.", nameof(intents));
        }

        if (snapshot.Select(intent => intent.OperationId).Distinct().Count() != snapshot.Length)
        {
            throw new ArgumentException("A batch must contain independent operation IDs.", nameof(intents));
        }

        Intents = Array.AsReadOnly(snapshot);
    }

    public IReadOnlyList<FileOperationIntent> Intents { get; }
}
