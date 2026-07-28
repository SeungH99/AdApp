using System.Collections.Immutable;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
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

public sealed record InvoiceReviewOperationHistory(
    OperationId OperationId,
    EventId EventId,
    DocumentId DocumentId,
    string SubmissionFingerprint,
    ConfirmedInvoiceReview Review);

public static class InvoiceReviewSubmissionFingerprint
{
    public static bool TryCreate(
        ConfirmInvoiceReviewCommand command,
        out string fingerprint)
    {
        fingerprint = string.Empty;
        if (command is null
            || command.OperationId.Value == Guid.Empty
            || command.EventId is null
            || command.EventId.Value == Guid.Empty
            || command.DocumentId.Value == Guid.Empty
            || command.ExpectedExtractionRevision <= 0
            || command.ExpectedSourceIdentity is null
            || command.ConfirmedMarket is null
            || Encoding.UTF8.GetByteCount(command.ConfirmedMarket) > 32
            || command.Fields.IsDefault
            || command.Fields.Length > PilotCatalog.RequiredFieldIds.Length)
        {
            return false;
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(hash, "invoice-review-submission.v1");
        Add(hash, command.DocumentId.Value);
        Add(hash, command.ExpectedExtractionRevision);
        Add(hash, command.ExpectedSourceIdentity.Bytes.Span);
        Add(hash, command.ConfirmedMarket);
        Add(hash, command.IsOutboundInvoice);
        Add(hash, command.IsExplicitlyApproved);
        Add(
            hash,
            command.ApprovedAtUtc.ToString(
                "O",
                CultureInfo.InvariantCulture));
        foreach (var field in command.Fields
                     .OrderBy(static field => field?.FieldId, StringComparer.Ordinal))
        {
            if (field is null
                || field.FieldId is null
                || Encoding.UTF8.GetByteCount(field.FieldId) > 128
                || field.ConfirmedValue is null
                || Encoding.UTF8.GetByteCount(field.ConfirmedValue)
                    > InvoiceReviewLimits.MaxConfirmedValueUtf8Bytes
                || field.Evidence.IsDefault
                || field.Evidence.Length > InvoiceReviewLimits.MaxEvidencePerField
                || field.Evidence.Any(static evidence => evidence is null))
            {
                return false;
            }

            Add(hash, field.FieldId);
            Add(hash, field.ConfirmedValue);
            Add(hash, field.Evidence.Length);
            foreach (var evidence in field.Evidence)
            {
                Add(hash, evidence.ExtractionRevision);
                Add(hash, evidence.Box?.SourceIndex ?? -1);
                Add(hash, evidence.Box?.X ?? double.NaN);
                Add(hash, evidence.Box?.Y ?? double.NaN);
                Add(hash, evidence.Box?.Width ?? double.NaN);
                Add(hash, evidence.Box?.Height ?? double.NaN);
                Add(hash, (int)evidence.CoordinateSystem);
            }
        }

        fingerprint = Convert.ToHexString(hash.GetHashAndReset())
            .ToLowerInvariant();
        return true;
    }

    private static void Add(IncrementalHash hash, string value) =>
        Add(hash, Encoding.UTF8.GetBytes(value));

    private static void Add(IncrementalHash hash, Guid value)
    {
        Span<byte> bytes = stackalloc byte[16];
        value.TryWriteBytes(bytes, bigEndian: true, out _);
        Add(hash, bytes);
    }

    private static void Add(IncrementalHash hash, int value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        Add(hash, bytes);
    }

    private static void Add(IncrementalHash hash, bool value) =>
        Add(hash, value ? 1 : 0);

    private static void Add(IncrementalHash hash, double value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(
            bytes,
            BitConverter.DoubleToInt64Bits(value));
        Add(hash, bytes);
    }

    private static void Add(
        IncrementalHash hash,
        ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }
}

public interface IInvoiceReviewQueryStore
{
    Task<InvoiceReviewSnapshot?> LoadCurrentAsync(
        DocumentId documentId,
        CancellationToken cancellationToken);

    Task<ConfirmedInvoiceReview?> LoadConfirmedAsync(
        DocumentId documentId,
        CancellationToken cancellationToken);

    Task<InvoiceReviewOperationHistory?> LoadByOperationAsync(
        OperationId operationId,
        CancellationToken cancellationToken);
}
