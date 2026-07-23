using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Core.Transactions;

public sealed record FileOperationSideEffect
{
    private readonly byte[] _data;

    public FileOperationSideEffect(string code, ReadOnlyMemory<byte> data = default)
    {
        OperationCommitContractValidation.ValidateCode(code, nameof(code));
        Code = code;
        _data = data.ToArray();
    }

    public string Code { get; }

    public ReadOnlyMemory<byte> Data => _data.ToArray();
}

public sealed record FileOperationUsage
{
    public FileOperationUsage(string code, long units)
    {
        OperationCommitContractValidation.ValidateCode(code, nameof(code));
        if (units <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(units), units, "Usage units must be positive.");
        }

        Code = code;
        Units = units;
    }

    public string Code { get; }

    public long Units { get; }
}

public sealed record CommitFileOperationCommand
{
    public CommitFileOperationCommand(
        OperationId operationId,
        long expectedJournalRevision,
        AppendEventsCommand appendEvents,
        IEnumerable<FileOperationSideEffect> sideEffects,
        FileOperationUsage? usage)
    {
        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException("An operation ID cannot be empty.", nameof(operationId));
        }

        if (expectedJournalRevision <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedJournalRevision),
                expectedJournalRevision,
                "The expected journal revision must be positive.");
        }

        ArgumentNullException.ThrowIfNull(appendEvents);
        ArgumentNullException.ThrowIfNull(sideEffects);
        if (appendEvents.OperationId != operationId)
        {
            throw new ArgumentException("The event append operation ID must match the commit operation ID.", nameof(appendEvents));
        }

        var snapshot = sideEffects.ToArray();
        if (snapshot.Any(sideEffect => sideEffect is null))
        {
            throw new ArgumentException("Side effects cannot contain null entries.", nameof(sideEffects));
        }

        OperationId = operationId;
        ExpectedJournalRevision = expectedJournalRevision;
        AppendEvents = appendEvents;
        SideEffects = Array.AsReadOnly(snapshot);
        Usage = usage;
    }

    public OperationId OperationId { get; }

    public long ExpectedJournalRevision { get; }

    public AppendEventsCommand AppendEvents { get; }

    public IReadOnlyList<FileOperationSideEffect> SideEffects { get; }

    public FileOperationUsage? Usage { get; }
}

public abstract record CommitFileOperationResult
{
    private protected CommitFileOperationResult()
    {
    }
}

public sealed record OperationCommitted(StreamVersion NewVersion)
    : CommitFileOperationResult;

public sealed record AlreadyCommitted(StreamVersion ExistingVersion)
    : CommitFileOperationResult;

public sealed record OperationCommitConflict(OperationId OperationId)
    : CommitFileOperationResult;

public sealed record OperationCommitStorageBusy : CommitFileOperationResult;

public interface IOperationCommitStore
{
    Task<CommitFileOperationResult> CommitAppliedAsync(
        CommitFileOperationCommand command,
        CancellationToken cancellationToken);
}

internal static class OperationCommitContractValidation
{
    public static void ValidateCode(string code, string parameterName)
    {
        if (string.IsNullOrEmpty(code)
            || code.Length > 64
            || code.Any(character =>
                !char.IsAsciiLetterLower(character)
                && !char.IsAsciiDigit(character)
                && character != '-'))
        {
            throw new ArgumentException(
                "The code must be a lowercase ASCII token of at most 64 characters.",
                parameterName);
        }
    }
}
