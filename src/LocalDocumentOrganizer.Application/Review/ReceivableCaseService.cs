using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Cases.Receivable;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Application.Review;

public sealed record CreateReceivableCaseRequest(
    OperationId OperationId,
    EventId EventId,
    CaseId CaseId,
    ReceivableActionId ActionId,
    DocumentId DocumentId);

public enum ReceivableCaseOutcome
{
    Created = 1,
    AlreadyCreated = 2,
    ReviewUnavailable = 3,
    ReviewInvalid = 4,
    NotSupportedInThisVersion = 5,
    RecoveryRequired = 6,
}

public sealed record ReceivableCaseResult(
    ReceivableCaseOutcome Outcome,
    ReceivableCaseFailureCode? Failure,
    CaseId? CaseId);

public sealed class ReceivableCaseService
{
    private const string SafePaymentReason =
        "Payment confirmation is required.";

    private readonly IInvoiceReviewQueryStore _reviews;
    private readonly IProductCommitStore _commits;

    public ReceivableCaseService(IInvoiceReviewQueryStore reviews, IProductCommitStore commits)
    {
        _reviews = reviews ?? throw new ArgumentNullException(nameof(reviews));
        _commits = commits ?? throw new ArgumentNullException(nameof(commits));
    }

    public async Task<ReceivableCaseResult> CreateAsync(
        CreateReceivableCaseRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var current = await _reviews.LoadCurrentAsync(
                request.DocumentId,
                cancellationToken)
            .ConfigureAwait(false);
        var review = await _reviews.LoadConfirmedAsync(request.DocumentId, cancellationToken)
            .ConfigureAwait(false);
        if (review is null || current is null)
            return new(ReceivableCaseOutcome.ReviewUnavailable, null, null);
        if (review.ExtractionRevision != current.CurrentExtractionRevision
            || !review.SourceIdentity.Equals(current.SourceIdentity))
        {
            return new(
                ReceivableCaseOutcome.ReviewInvalid,
                ReceivableCaseFailureCode.StaleReviewRevision,
                null);
        }
        var fields = review.Fields.ToImmutableDictionary(
            static field => field.FieldId,
            static field => new ConfirmedReceivableField(field.FieldId,
                field.OriginalNormalizedValue, field.ConfirmedNormalizedValue,
                field.IsCorrected, field.Evidence.Select(static evidence =>
                    new ReceivableEvidence(evidence.Box.SourceIndex, evidence.Box.X,
                        evidence.Box.Y, evidence.Box.Width, evidence.Box.Height,
                        evidence.CoordinateSystem)).ToImmutableArray()),
            StringComparer.Ordinal);
        if (!DateOnly.TryParseExact(fields["issue_date"].ConfirmedNormalizedValue, "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out var issue)
            || !DateOnly.TryParseExact(fields["payment_due_date"].ConfirmedNormalizedValue, "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out var due)
            || !decimal.TryParse(fields["total_amount"].ConfirmedNormalizedValue,
                System.Globalization.NumberStyles.Number,
                System.Globalization.CultureInfo.InvariantCulture, out var amount))
            return new(ReceivableCaseOutcome.ReviewInvalid, ReceivableCaseFailureCode.InvalidReview, null);

        var caseId = new CaseId(
            DeriveIdentity(request.OperationId, "receivable-case"));
        var actionId = new ReceivableActionId(
            DeriveIdentity(request.OperationId, "receivable-action"));
        var decision = ReceivableCaseDecider.Decide(new CreateReceivableCaseCommand(
            caseId, actionId, request.DocumentId, review.ExtractionRevision,
            review.ReviewRevision, review.ConfirmedMarket, review.IsOutboundInvoice, true,
            review.ApprovedAtUtc, issue, due, amount,
            fields["currency"].ConfirmedNormalizedValue,
            fields,
            current.CurrentExtractionRevision,
            review.SourceIdentity.Hex,
            current.SourceIdentity.Hex,
            current.SourcePages.IsDefault
                ? null
                : current.SourcePages.ToImmutableDictionary(
                    static page => page.SourceIndex,
                    static page => new ReceivableSourcePage(
                        page.SourceIndex,
                        page.Width,
                        page.Height,
                        page.CoordinateSystem))), null);
        if (decision.Failure is { } failure)
            return new(failure == ReceivableCaseFailureCode.IncomingInvoiceNotSupported
                ? ReceivableCaseOutcome.NotSupportedInThisVersion : ReceivableCaseOutcome.ReviewInvalid,
                failure, null);

        var commit = await _commits.CommitReceivableCaseAsync(
            new CommitReceivableCaseCommand(request.OperationId, request.EventId, caseId,
                request.DocumentId, due, review.ApprovedAtUtc,
                SerializeMetadata(
                    decision.CaseCreated!,
                    decision.ActionRequired!),
                review.ReviewRevision,
                actionId,
                decision.ActionRequired!.ActionType,
                amount,
                fields["currency"].ConfirmedNormalizedValue,
                SafePaymentReason), cancellationToken)
            .ConfigureAwait(false);
        return commit switch
        {
            ProductCommitted => new(ReceivableCaseOutcome.Created, null, caseId),
            ProductAlreadyCommitted => new(ReceivableCaseOutcome.AlreadyCreated, null, caseId),
            ProductConflict { Kind: ProductConflictKind.SourceDocumentAlreadyHasCase, ExistingIdentity: { } id } =>
                new(ReceivableCaseOutcome.AlreadyCreated, ReceivableCaseFailureCode.CaseAlreadyExists, new CaseId(id)),
            ProductConflict => new(ReceivableCaseOutcome.ReviewInvalid, ReceivableCaseFailureCode.StaleReviewRevision, null),
            _ => new(ReceivableCaseOutcome.RecoveryRequired, null, null),
        };
    }

    private static string SerializeMetadata(
        ReceivableCaseCreated created,
        ReceivableActionRequired action) =>
        System.Text.Json.JsonSerializer.Serialize(
            new PersistedReceivableMetadata(
                1,
                created,
                action,
                SafePaymentReason));

    private static Guid DeriveIdentity(
        OperationId operationId,
        string purpose)
    {
        var domain = Encoding.UTF8.GetBytes(
            $"local-document-organizer/{purpose}/v1\n");
        Span<byte> input = stackalloc byte[domain.Length + 16];
        domain.CopyTo(input);
        operationId.Value.TryWriteBytes(input[domain.Length..]);
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(input, digest);
        return new Guid(digest[..16]);
    }

    private sealed record PersistedReceivableMetadata(
        int Version,
        ReceivableCaseCreated Case,
        ReceivableActionRequired Action,
        string SafeReason);
}
