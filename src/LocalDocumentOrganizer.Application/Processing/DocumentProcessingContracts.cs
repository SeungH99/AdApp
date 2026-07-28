using System.Collections.Immutable;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Application.Processing;

public readonly record struct ExtractionAttemptId
{
    public ExtractionAttemptId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("An extraction attempt ID cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
}

public enum ExtractionOutboxState
{
    Pending = 0,
    Running = 1,
    RetryPending = 2,
    Succeeded = 3,
    TerminalFailure = 4,
}

public enum DocumentProcessingFailureCode
{
    None = 0,
    WorkerUnavailable = 1,
    WorkerTimedOut = 2,
    WorkerAttestationInvalid = 3,
    ResponseBindingInvalid = 4,
    ResponseInvalid = 5,
    UnsupportedDocument = 6,
    CorruptDocument = 7,
    StorageUnavailable = 8,
}

public enum DocumentProcessingOutcome
{
    NoWork = 0,
    Completed = 1,
    RetryScheduled = 2,
    TerminalFailure = 3,
    RecoveryRequired = 4,
}

public sealed record ExtractionOutboxWorkItem(
    Guid OutboxId,
    DocumentId DocumentId,
    InboxId InboxId,
    ContentSha256 ContentSha256,
    ExtractionAttemptId AttemptId,
    int TargetRevision,
    OperationId CommitOperationId,
    ImmutableArray<string> RequestedLanguages,
    ExtractionCapability RequestedCapabilities,
    int AutomaticFailureCount,
    ExtractionOutboxState State,
    DateTimeOffset? LeaseExpiresAtUtc);

public sealed record ExtractionOutboxClaim(
    ExtractionOutboxWorkItem Work,
    Guid OwnerId);

public sealed record DocumentProcessingRequest(
    DocumentId DocumentId,
    InboxId InboxId,
    ExtractionAttemptId AttemptId,
    int TargetRevision,
    OperationId CommitOperationId,
    ContentSha256 ContentSha256,
    ImmutableArray<string> RequestedLanguages,
    ExtractionCapability RequestedCapabilities);

public sealed record DocumentProcessingResponseBinding(
    Guid AttemptId,
    DocumentId DocumentId,
    long SourceLength,
    ContentSha256 ContentSha256,
    string WorkerPackageIdentity);

public abstract record DocumentProcessingDispatchResult
{
    private DocumentProcessingDispatchResult()
    {
    }

    public sealed record Successful(
        DocumentExtractionResponse Response,
        DocumentProcessingResponseBinding Binding,
        string AuthenticatedDraft,
        bool IsComplete,
        string? SuggestedMarket) : DocumentProcessingDispatchResult;

    public sealed record Failed(DocumentProcessingFailureCode FailureCode) : DocumentProcessingDispatchResult;

    public static DocumentProcessingDispatchResult TransientFailure(
        DocumentProcessingFailureCode failureCode) => new Failed(failureCode);
}

public sealed record ExtractionOutboxCompletionCommand(
    ExtractionOutboxClaim Claim,
    ExtractionOutboxState NextState,
    int AutomaticFailureCount,
    DocumentProcessingFailureCode FailureCode,
    CommitExtractionCommand? ExtractionCommit);

public sealed record ExtractionOutboxCompletion(
    int Revision,
    bool AlreadyCompleted);

public sealed record ExplicitReprocessCommand(
    DocumentId DocumentId,
    int ExpectedCurrentRevision,
    OperationId CommandOperationId);

public enum ExplicitReprocessOutcome
{
    Scheduled = 1,
    AlreadyScheduled = 2,
    RevisionConflict = 3,
}

public sealed record ExplicitReprocessResult(
    ExplicitReprocessOutcome Outcome,
    int TargetRevision);

public interface IExtractionOutboxStore
{
    Task<ExtractionOutboxClaim?> ClaimNextAsync(
        Guid ownerId,
        DateTimeOffset nowUtc,
        TimeSpan leaseDuration,
        CancellationToken cancellationToken);

    Task<ExtractionOutboxCompletion> CompleteAsync(
        ExtractionOutboxCompletionCommand command,
        CancellationToken cancellationToken);

    Task<ExplicitReprocessResult> ScheduleReprocessAsync(
        ExplicitReprocessCommand command,
        CancellationToken cancellationToken);
}

public interface IDocumentProcessingDispatcher
{
    Task<DocumentProcessingDispatchResult> DispatchAsync(
        DocumentProcessingRequest request,
        CancellationToken cancellationToken);
}

public sealed record DocumentProcessingResult(
    DocumentProcessingOutcome Outcome,
    DocumentProcessingFailureCode FailureCode)
{
    public static DocumentProcessingResult NoWork() =>
        new(DocumentProcessingOutcome.NoWork, DocumentProcessingFailureCode.None);
}
