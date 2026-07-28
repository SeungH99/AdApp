using System.Collections.Immutable;
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

        var decision = ReceivableCaseDecider.Decide(new CreateReceivableCaseCommand(
            request.CaseId, request.ActionId, request.DocumentId, review.ExtractionRevision,
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
            new CommitReceivableCaseCommand(request.OperationId, request.EventId, request.CaseId,
                request.DocumentId, due, review.ApprovedAtUtc,
                SerializeMetadata(decision.CaseCreated!), review.ReviewRevision), cancellationToken)
            .ConfigureAwait(false);
        return commit switch
        {
            ProductCommitted => new(ReceivableCaseOutcome.Created, null, request.CaseId),
            ProductAlreadyCommitted => new(ReceivableCaseOutcome.AlreadyCreated, null, request.CaseId),
            ProductConflict { Kind: ProductConflictKind.SourceDocumentAlreadyHasCase, ExistingIdentity: { } id } =>
                new(ReceivableCaseOutcome.AlreadyCreated, ReceivableCaseFailureCode.CaseAlreadyExists, new CaseId(id)),
            ProductConflict => new(ReceivableCaseOutcome.ReviewInvalid, ReceivableCaseFailureCode.StaleReviewRevision, null),
            _ => new(ReceivableCaseOutcome.RecoveryRequired, null, null),
        };
    }

    private static string SerializeMetadata(ReceivableCaseCreated created) =>
        System.Text.Json.JsonSerializer.Serialize(created);
}
