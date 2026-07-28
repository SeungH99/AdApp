using System.Collections.Immutable;
using LocalDocumentOrganizer.Application.Contracts;
using LocalDocumentOrganizer.Application.Processing;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Application.Review;

public static class InvoiceReviewLimits
{
    public const int MaxConfirmedValueUtf8Bytes = 4 * 1024;
    public const int MaxEvidencePerField = 32;
    public const int MaxTotalEvidence = 128;
    public const int MaxProtectedPayloadUtf8Bytes = 1024 * 1024;
}

public sealed record ReviewExtractionField(
    string FieldId,
    string? OriginalNormalizedValue);

public sealed record InvoiceReviewSnapshot(
    DocumentId DocumentId,
    ContentSha256 SourceIdentity,
    int CurrentExtractionRevision,
    int ConfirmedReviewRevision,
    StreamVersion CurrentStreamVersion,
    ProductInboxStatus InboxStatus,
    ImmutableDictionary<string, ReviewExtractionField> Fields,
    int SourcePageCount,
    AuthenticatedExtractionDraft? CurrentDraft = null,
    ImmutableArray<DocumentSourcePage> SourcePages = default);

public sealed record ReviewEvidence(
    int ExtractionRevision,
    EvidenceBox Box,
    EvidenceCoordinateSystem CoordinateSystem =
        EvidenceCoordinateSystem.PdfPagePoints);

public sealed record InvoiceReviewFieldSubmission(
    string FieldId,
    string ConfirmedValue,
    ImmutableArray<ReviewEvidence> Evidence);

public sealed record ConfirmInvoiceReviewCommand(
    OperationId OperationId,
    EventId EventId,
    DocumentId DocumentId,
    int ExpectedExtractionRevision,
    ContentSha256 ExpectedSourceIdentity,
    string ConfirmedMarket,
    bool IsOutboundInvoice,
    bool IsExplicitlyApproved,
    DateTimeOffset ApprovedAtUtc,
    ImmutableArray<InvoiceReviewFieldSubmission> Fields);

public enum InvoiceReviewOutcome
{
    Confirmed = 1,
    AlreadyConfirmed = 2,
    StaleRevision = 3,
    InvalidReview = 4,
    NotSupportedInThisVersion = 5,
    RecoveryRequired = 6,
    ConcurrentConflict = 7,
}

public enum InvoiceReviewFailureCode
{
    None = 0,
    DocumentUnavailable = 1,
    StaleExtractionRevision = 2,
    SourceIdentityMismatch = 3,
    ExactFieldSetRequired = 4,
    EvidenceRequired = 5,
    EvidenceInvalid = 6,
    MarketConfirmationRequired = 7,
    OutboundConfirmationRequired = 8,
    ApprovalRequired = 9,
    InvalidValue = 10,
    StorageConflict = 11,
    StorageRecoveryRequired = 12,
    InputTooLarge = 13,
}

public sealed record ConfirmedInvoiceReview(
    DocumentId DocumentId,
    ContentSha256 SourceIdentity,
    int ExtractionRevision,
    int ReviewRevision,
    string ConfirmedMarket,
    bool IsOutboundInvoice,
    DateTimeOffset ApprovedAtUtc,
    ImmutableArray<ConfirmedInvoiceReviewField> Fields,
    OperationId? CommitOperationId = null,
    EventId? CommitEventId = null,
    StreamVersion? CommittedStreamVersion = null);

public sealed record ConfirmedInvoiceReviewField(
    string FieldId,
    string? OriginalNormalizedValue,
    string ConfirmedDisplayValue,
    string ConfirmedNormalizedValue,
    bool IsCorrected,
    ImmutableArray<ReviewEvidence> Evidence);

/// <summary>Bounded encrypted persistence shape; never accepted from UI.</summary>
public sealed record PersistedConfirmedInvoiceReview(
    string DocumentId,
    string SourceIdentitySha256,
    int ExtractionRevision,
    int ReviewRevision,
    string ConfirmedMarket,
    bool IsOutboundInvoice,
    DateTimeOffset ApprovedAtUtc,
    ImmutableArray<ConfirmedInvoiceReviewField> Fields,
    string? CommitOperationId = null,
    string? CommitEventId = null,
    long? CommittedStreamVersion = null);

public sealed record InvoiceReviewResult(
    InvoiceReviewOutcome Outcome,
    InvoiceReviewFailureCode FailureCode,
    ConfirmedInvoiceReview? Review,
    ConfirmInvoiceReviewCommand? PreservedSubmission);

public interface IInvoiceReviewQueryStore
{
    Task<InvoiceReviewSnapshot?> LoadCurrentAsync(
        DocumentId documentId,
        CancellationToken cancellationToken);

    Task<ConfirmedInvoiceReview?> LoadConfirmedAsync(
        DocumentId documentId,
        CancellationToken cancellationToken);
}
