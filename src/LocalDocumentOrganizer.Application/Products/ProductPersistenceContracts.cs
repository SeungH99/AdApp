using System.Security.Cryptography;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Application.Products;

public readonly record struct InboxId
{
    public InboxId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("An Inbox ID cannot be empty.", nameof(value));
        }

        Value = value;
    }

    public Guid Value { get; }
}

public sealed class ContentSha256 : IEquatable<ContentSha256>
{
    public const int Size = 32;
    private readonly byte[] _value;

    public ContentSha256(ReadOnlySpan<byte> value)
    {
        if (value.Length != Size)
        {
            throw new ArgumentException("A content SHA-256 must contain exactly 32 bytes.", nameof(value));
        }

        _value = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => _value.ToArray();

    public string Hex => Convert.ToHexString(_value).ToLowerInvariant();

    public bool Equals(ContentSha256? other) =>
        other is not null
        && CryptographicOperations.FixedTimeEquals(_value, other._value);

    public override bool Equals(object? obj) =>
        obj is ContentSha256 other && Equals(other);

    public override int GetHashCode() =>
        BitConverter.ToInt32(SHA256.HashData(_value), 0);
}

public enum ProductInboxStatus
{
    Imported = 0,
    Extracted = 1,
    Reviewed = 2,
    CaseCreated = 3,
}

public enum ProductCaseStatus
{
    Open = 0,
    Closed = 1,
}

public enum ProductTodayStatus
{
    Pending = 0,
    Completed = 1,
}

public sealed record CommitImportCommand
{
    public CommitImportCommand(
        OperationId operationId,
        EventId eventId,
        DocumentId documentId,
        InboxId inboxId,
        ContentSha256 contentSha256,
        DateTimeOffset receivedAtUtc,
        string fileName,
        string authenticatedMetadata)
    {
        ValidateOperation(operationId, eventId);
        ValidateDocument(documentId);
        ArgumentNullException.ThrowIfNull(contentSha256);
        ValidateUtc(receivedAtUtc, nameof(receivedAtUtc));
        if (string.IsNullOrWhiteSpace(fileName)
            || fileName.Length > 255
            || fileName.Contains('/')
            || fileName.Contains('\\'))
        {
            throw new ArgumentException(
                "Only a filename without source path components may be persisted.",
                nameof(fileName));
        }

        ValidateProtectedText(authenticatedMetadata, nameof(authenticatedMetadata));
        OperationId = operationId;
        EventId = eventId;
        DocumentId = documentId;
        InboxId = inboxId;
        ContentSha256 = new ContentSha256(contentSha256.Bytes.Span);
        ReceivedAtUtc = receivedAtUtc;
        FileName = fileName;
        AuthenticatedMetadata = authenticatedMetadata;
    }

    public OperationId OperationId { get; }

    public EventId EventId { get; }

    public DocumentId DocumentId { get; }

    public InboxId InboxId { get; }

    public ContentSha256 ContentSha256 { get; }

    public DateTimeOffset ReceivedAtUtc { get; }

    public string FileName { get; }

    public string AuthenticatedMetadata { get; }

    private static void ValidateProtectedText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 1_048_576)
        {
            throw new ArgumentException("Authenticated metadata is required and bounded.", parameterName);
        }
    }

    internal static void ValidateOperation(OperationId operationId, EventId eventId)
    {
        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException("An operation ID cannot be empty.", nameof(operationId));
        }

        ArgumentNullException.ThrowIfNull(eventId);
    }

    internal static void ValidateDocument(DocumentId documentId)
    {
        if (documentId.Value == Guid.Empty)
        {
            throw new ArgumentException("A document ID cannot be empty.", nameof(documentId));
        }
    }

    internal static void ValidateUtc(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("The timestamp must use the UTC offset.", parameterName);
        }
    }

    internal static void ValidateProtectedPayload(string value, string parameterName) =>
        ValidateProtectedText(value, parameterName);
}

public sealed record CommitExtractionCommand
{
    public CommitExtractionCommand(
        OperationId operationId,
        EventId eventId,
        DocumentId documentId,
        StreamVersion expectedVersion,
        DateTimeOffset extractedAtUtc,
        string authenticatedExtraction)
    {
        CommitImportCommand.ValidateOperation(operationId, eventId);
        CommitImportCommand.ValidateDocument(documentId);
        CommitImportCommand.ValidateUtc(extractedAtUtc, nameof(extractedAtUtc));
        CommitImportCommand.ValidateProtectedPayload(
            authenticatedExtraction,
            nameof(authenticatedExtraction));
        OperationId = operationId;
        EventId = eventId;
        DocumentId = documentId;
        ExpectedVersion = expectedVersion;
        ExtractedAtUtc = extractedAtUtc;
        AuthenticatedExtraction = authenticatedExtraction;
    }

    public OperationId OperationId { get; }

    public EventId EventId { get; }

    public DocumentId DocumentId { get; }

    public StreamVersion ExpectedVersion { get; }

    public DateTimeOffset ExtractedAtUtc { get; }

    public string AuthenticatedExtraction { get; }
}

public sealed record CommitReviewCommand
{
    public CommitReviewCommand(
        OperationId operationId,
        EventId eventId,
        DocumentId documentId,
        StreamVersion expectedVersion,
        DateTimeOffset reviewedAtUtc,
        string authenticatedReview)
    {
        CommitImportCommand.ValidateOperation(operationId, eventId);
        CommitImportCommand.ValidateDocument(documentId);
        CommitImportCommand.ValidateUtc(reviewedAtUtc, nameof(reviewedAtUtc));
        CommitImportCommand.ValidateProtectedPayload(
            authenticatedReview,
            nameof(authenticatedReview));
        OperationId = operationId;
        EventId = eventId;
        DocumentId = documentId;
        ExpectedVersion = expectedVersion;
        ReviewedAtUtc = reviewedAtUtc;
        AuthenticatedReview = authenticatedReview;
    }

    public OperationId OperationId { get; }

    public EventId EventId { get; }

    public DocumentId DocumentId { get; }

    public StreamVersion ExpectedVersion { get; }

    public DateTimeOffset ReviewedAtUtc { get; }

    public string AuthenticatedReview { get; }
}

public sealed record CommitReceivableCaseCommand
{
    public CommitReceivableCaseCommand(
        OperationId operationId,
        EventId eventId,
        CaseId caseId,
        DocumentId sourceDocumentId,
        DateOnly dueDate,
        DateTimeOffset createdAtUtc,
        string authenticatedMetadata)
    {
        CommitImportCommand.ValidateOperation(operationId, eventId);
        if (caseId.Value == Guid.Empty)
        {
            throw new ArgumentException("A Case ID cannot be empty.", nameof(caseId));
        }

        CommitImportCommand.ValidateDocument(sourceDocumentId);
        CommitImportCommand.ValidateUtc(createdAtUtc, nameof(createdAtUtc));
        CommitImportCommand.ValidateProtectedPayload(
            authenticatedMetadata,
            nameof(authenticatedMetadata));
        OperationId = operationId;
        EventId = eventId;
        CaseId = caseId;
        SourceDocumentId = sourceDocumentId;
        DueDate = dueDate;
        CreatedAtUtc = createdAtUtc;
        AuthenticatedMetadata = authenticatedMetadata;
    }

    public OperationId OperationId { get; }

    public EventId EventId { get; }

    public CaseId CaseId { get; }

    public DocumentId SourceDocumentId { get; }

    public DateOnly DueDate { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public string AuthenticatedMetadata { get; }
}

public enum ProductConflictKind
{
    OperationIdentityMismatch,
    StreamVersionMismatch,
    SourceDocumentAlreadyHasCase,
    StorageConstraint,
}

public enum ProductRecoveryKind
{
    StorageBusy,
    StorageFailure,
    ProjectionRebuildRequired,
    ProtectedStateInvalid,
}

public abstract record ProductCommitResult
{
    private protected ProductCommitResult()
    {
    }
}

public abstract record ImportCommitResult : ProductCommitResult
{
    private protected ImportCommitResult()
    {
    }
}

public sealed record ImportCommitted(InboxId InboxId) : ImportCommitResult;

public sealed record ImportAlreadyCommitted(InboxId InboxId) : ImportCommitResult;

public sealed record AlreadyImported(InboxId ExistingInboxId) : ImportCommitResult;

public sealed record ImportConflict(
    ProductConflictKind Kind,
    Guid? ExistingIdentity = null) : ImportCommitResult;

public sealed record ProductCommitted(StreamVersion NewVersion) : ProductCommitResult;

public sealed record ProductAlreadyCommitted(StreamVersion ExistingVersion) : ProductCommitResult;

public sealed record ProductConflict(
    ProductConflictKind Kind,
    Guid? ExistingIdentity = null) : ProductCommitResult;

public sealed record ProductRecoveryRequired(ProductRecoveryKind Kind) : ImportCommitResult;

public interface IProductCommitStore
{
    Task<ImportCommitResult> CommitImportAsync(
        CommitImportCommand command,
        CancellationToken cancellationToken);

    Task<ProductCommitResult> CommitExtractionAsync(
        CommitExtractionCommand command,
        CancellationToken cancellationToken);

    Task<ProductCommitResult> CommitReviewAsync(
        CommitReviewCommand command,
        CancellationToken cancellationToken);

    Task<ProductCommitResult> CommitReceivableCaseAsync(
        CommitReceivableCaseCommand command,
        CancellationToken cancellationToken);
}

public sealed record InboxCursor(
    DateTimeOffset ReceivedAtUtc,
    DocumentId DocumentId);

public sealed record InboxPageRequest
{
    public InboxPageRequest(
        ProductInboxStatus? status,
        int pageSize,
        InboxCursor? after)
    {
        if (pageSize is < 1 or > 200)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pageSize),
                pageSize,
                "Page size must be between 1 and 200.");
        }

        if (status is not null && !Enum.IsDefined(status.Value))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        if (after is not null)
        {
            CommitImportCommand.ValidateUtc(after.ReceivedAtUtc, nameof(after));
            CommitImportCommand.ValidateDocument(after.DocumentId);
        }

        Status = status;
        PageSize = pageSize;
        After = after;
    }

    public ProductInboxStatus? Status { get; }

    public int PageSize { get; }

    public InboxCursor? After { get; }
}

public sealed record InboxListItem(
    InboxId InboxId,
    DocumentId DocumentId,
    DateTimeOffset ReceivedAtUtc,
    ProductInboxStatus Status,
    string FileName);

public sealed record InboxPage(
    IReadOnlyList<InboxListItem> Items,
    InboxCursor? NextCursor);

public sealed record TodayCursor(DateOnly DueDate, CaseId CaseId);

public sealed record TodayPageRequest
{
    public TodayPageRequest(
        ProductTodayStatus? status,
        int pageSize,
        TodayCursor? after)
    {
        if (pageSize is < 1 or > 200)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pageSize),
                pageSize,
                "Page size must be between 1 and 200.");
        }

        if (status is not null && !Enum.IsDefined(status.Value))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        if (after is not null && after.CaseId.Value == Guid.Empty)
        {
            throw new ArgumentException("A cursor Case ID cannot be empty.", nameof(after));
        }

        Status = status;
        PageSize = pageSize;
        After = after;
    }

    public ProductTodayStatus? Status { get; }

    public int PageSize { get; }

    public TodayCursor? After { get; }
}

public sealed record TodayListItem(
    CaseId CaseId,
    DocumentId SourceDocumentId,
    DateOnly DueDate,
    ProductTodayStatus Status);

public sealed record TodayPage(
    IReadOnlyList<TodayListItem> Items,
    TodayCursor? NextCursor);

public interface IProductQueryStore
{
    Task<InboxPage> QueryInboxAsync(
        InboxPageRequest request,
        CancellationToken cancellationToken);

    Task<TodayPage> QueryTodayAsync(
        TodayPageRequest request,
        CancellationToken cancellationToken);
}
