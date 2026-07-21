using System.Buffers;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Core.Deletion;

public sealed record DeleteSensitiveObjectCommand
{
    public DeleteSensitiveObjectCommand(
        SensitiveObjectRef target,
        StreamId streamId,
        StreamVersion expectedVersion,
        OperationId operationId,
        EventId tombstoneEventId,
        string reasonCode)
    {
        ValidateTarget(target);
        ArgumentNullException.ThrowIfNull(streamId);
        if (operationId.Value == Guid.Empty || tombstoneEventId.Value == Guid.Empty)
        {
            throw new ArgumentException("Deletion identifiers must be non-empty.");
        }

        SensitiveObjectDeletedEventContract.ValidateReasonCode(reasonCode);

        Target = target;
        StreamId = streamId;
        ExpectedVersion = expectedVersion;
        OperationId = operationId;
        TombstoneEventId = tombstoneEventId;
        ReasonCode = reasonCode;
    }

    public SensitiveObjectRef Target { get; }

    public StreamId StreamId { get; }

    public StreamVersion ExpectedVersion { get; }

    public OperationId OperationId { get; }

    public EventId TombstoneEventId { get; }

    public string ReasonCode { get; }

    private static void ValidateTarget(SensitiveObjectRef target)
    {
        if (!Enum.IsDefined(target.Kind) || target.Id.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid deletion target is required.", nameof(target));
        }
    }
}

public abstract record DeleteSensitiveObjectResult;

public sealed record Deleted : DeleteSensitiveObjectResult;

public sealed record DeletionAlreadyApplied : DeleteSensitiveObjectResult;

public sealed record DeletionConcurrencyConflict(
    StreamVersion ExpectedVersion,
    StreamVersion ActualVersion) : DeleteSensitiveObjectResult;

public sealed record DeletionStorageBusy : DeleteSensitiveObjectResult;

public sealed record DeletionRecoveryRequired(
    string FailureCode) : DeleteSensitiveObjectResult;

public interface ISensitiveDataDeletionStore
{
    Task<DeleteSensitiveObjectResult> DeleteAsync(
        DeleteSensitiveObjectCommand command,
        CancellationToken cancellationToken);
}

public static class SensitiveObjectDeletedEventContract
{
    public const string EventType = "sensitive-object.deleted";

    public const int SchemaVersion = 1;

    public static ReadOnlyMemory<byte> CreatePayload(
        SensitiveObjectRef target,
        string reasonCode)
    {
        if (!Enum.IsDefined(target.Kind) || target.Id.Value == Guid.Empty)
        {
            throw new ArgumentException("A valid deletion target is required.", nameof(target));
        }

        ValidateReasonCode(reasonCode);
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("targetKind", NormalizeKind(target.Kind));
            writer.WriteString("targetId", target.Id.Value);
            writer.WriteString("reasonCode", reasonCode);
            writer.WriteEndObject();
        }

        return buffer.WrittenMemory.ToArray();
    }

    internal static void ValidateReasonCode(string reasonCode)
    {
        if (string.IsNullOrEmpty(reasonCode)
            || reasonCode.Length > 32
            || reasonCode.Any(character =>
                !char.IsAsciiLetterLower(character)
                && !char.IsAsciiDigit(character)
                && character != '-'))
        {
            throw new ArgumentException(
                "The reason code must be a lowercase ASCII token of at most 32 characters.",
                nameof(reasonCode));
        }
    }

    private static string NormalizeKind(SensitiveObjectKind kind) => kind switch
    {
        SensitiveObjectKind.Case => "case",
        SensitiveObjectKind.DocumentEvidence => "document-evidence",
        SensitiveObjectKind.Journal => "journal",
        SensitiveObjectKind.Entitlement => "entitlement",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), "The sensitive object kind is not defined."),
    };
}
