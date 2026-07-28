using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Contracts;
using LocalDocumentOrganizer.Application.Products;

namespace LocalDocumentOrganizer.Application.Review;

public sealed class InvoiceReviewService
{
    private static readonly ImmutableHashSet<string> RequiredFields =
        PilotCatalog.RequiredFieldIds.ToImmutableHashSet(StringComparer.Ordinal);
    private static readonly ImmutableHashSet<string> SupportedCurrencies =
        ImmutableHashSet.Create(StringComparer.Ordinal, "USD", "KRW");

    private readonly IInvoiceReviewQueryStore _reviews;
    private readonly IProductCommitStore _commits;

    public InvoiceReviewService(
        IInvoiceReviewQueryStore reviews,
        IProductCommitStore commits)
    {
        _reviews = reviews ?? throw new ArgumentNullException(nameof(reviews));
        _commits = commits ?? throw new ArgumentNullException(nameof(commits));
    }

    public async Task<InvoiceReviewResult> ConfirmAsync(
        ConfirmInvoiceReviewCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var snapshot = await _reviews.LoadCurrentAsync(command.DocumentId, cancellationToken)
            .ConfigureAwait(false);
        if (snapshot is null)
            return Failed(InvoiceReviewFailureCode.DocumentUnavailable, command);
        if (snapshot.DocumentId != command.DocumentId || !snapshot.SourceIdentity.Equals(command.ExpectedSourceIdentity))
            return Failed(InvoiceReviewFailureCode.SourceIdentityMismatch, command);
        if (snapshot.CurrentExtractionRevision != command.ExpectedExtractionRevision)
            return new(InvoiceReviewOutcome.StaleRevision, InvoiceReviewFailureCode.StaleExtractionRevision, null, command);
        if (snapshot.InboxStatus is not (ProductInboxStatus.ReadyForReview or ProductInboxStatus.NeedsReview))
            return Failed(InvoiceReviewFailureCode.DocumentUnavailable, command);
        if (command.ConfirmedMarket is not ("ko-KR" or "en-US"))
            return Failed(InvoiceReviewFailureCode.MarketConfirmationRequired, command);
        if (!command.IsOutboundInvoice)
            return new(InvoiceReviewOutcome.NotSupportedInThisVersion, InvoiceReviewFailureCode.OutboundConfirmationRequired, null, command);
        if (!command.IsExplicitlyApproved || command.ApprovedAtUtc.Offset != TimeSpan.Zero || command.ApprovedAtUtc == default)
            return Failed(InvoiceReviewFailureCode.ApprovalRequired, command);
        if (!TryValidateFields(command, snapshot, out var fields, out var failure))
            return Failed(failure, command);

        var review = new ConfirmedInvoiceReview(
            command.DocumentId, command.ExpectedSourceIdentity,
            command.ExpectedExtractionRevision, checked(snapshot.ConfirmedReviewRevision + 1),
            command.ConfirmedMarket, true, command.ApprovedAtUtc, fields);
        var payload = SerializeBounded(review);
        var commit = await _commits.CommitReviewAsync(
            new CommitReviewCommand(command.OperationId, command.EventId, command.DocumentId,
                snapshot.CurrentStreamVersion, command.ApprovedAtUtc, payload),
            cancellationToken).ConfigureAwait(false);
        return commit switch
        {
            ProductCommitted => new(InvoiceReviewOutcome.Confirmed, InvoiceReviewFailureCode.None, review, null),
            ProductAlreadyCommitted => new(InvoiceReviewOutcome.AlreadyConfirmed, InvoiceReviewFailureCode.None, review, null),
            ProductConflict { Kind: ProductConflictKind.StreamVersionMismatch } =>
                new(InvoiceReviewOutcome.StaleRevision, InvoiceReviewFailureCode.StaleExtractionRevision, null, command),
            ProductConflict => Failed(InvoiceReviewFailureCode.StorageConflict, command),
            ProductRecoveryRequired => new(InvoiceReviewOutcome.RecoveryRequired, InvoiceReviewFailureCode.StorageRecoveryRequired, null, command),
            _ => new(InvoiceReviewOutcome.RecoveryRequired, InvoiceReviewFailureCode.StorageRecoveryRequired, null, command),
        };
    }

    private static bool TryValidateFields(
        ConfirmInvoiceReviewCommand command,
        InvoiceReviewSnapshot snapshot,
        out ImmutableArray<ConfirmedInvoiceReviewField> fields,
        out InvoiceReviewFailureCode failure)
    {
        fields = ImmutableArray<ConfirmedInvoiceReviewField>.Empty;
        failure = InvoiceReviewFailureCode.ExactFieldSetRequired;
        if (command.Fields.IsDefault || command.Fields.Length != RequiredFields.Count
            || command.Fields.Select(static field => field.FieldId).Distinct(StringComparer.Ordinal).Count() != RequiredFields.Count
            || !command.Fields.Select(static field => field.FieldId).ToImmutableHashSet(StringComparer.Ordinal).SetEquals(RequiredFields)
            || snapshot.Fields.Keys.ToImmutableHashSet(StringComparer.Ordinal).SetEquals(RequiredFields) is false)
            return false;

        var result = ImmutableArray.CreateBuilder<ConfirmedInvoiceReviewField>(RequiredFields.Count);
        foreach (var submission in command.Fields.OrderBy(static field => field.FieldId, StringComparer.Ordinal))
        {
            if (!snapshot.Fields.TryGetValue(submission.FieldId, out var original)
                || string.IsNullOrWhiteSpace(submission.ConfirmedValue)
                || submission.Evidence.IsDefaultOrEmpty)
            {
                failure = InvoiceReviewFailureCode.EvidenceRequired;
                return false;
            }
            if (submission.Evidence.Any(evidence => evidence.ExtractionRevision != command.ExpectedExtractionRevision
                    || !IsValidEvidence(evidence.Box, snapshot.SourcePageCount)))
            {
                failure = InvoiceReviewFailureCode.EvidenceInvalid;
                return false;
            }
            if (!TryNormalize(submission.FieldId, submission.ConfirmedValue, out var display, out var normalized))
            {
                failure = InvoiceReviewFailureCode.InvalidValue;
                return false;
            }
            result.Add(new(submission.FieldId, original.OriginalNormalizedValue, display, normalized,
                !string.Equals(original.OriginalNormalizedValue, normalized, StringComparison.Ordinal), submission.Evidence));
        }
        var byId = result.ToImmutable().ToDictionary(static field => field.FieldId, StringComparer.Ordinal);
        if (!DateOnly.TryParseExact(byId["issue_date"].ConfirmedNormalizedValue, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var issue)
            || !DateOnly.TryParseExact(byId["payment_due_date"].ConfirmedNormalizedValue, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var due)
            || due < issue)
        {
            failure = InvoiceReviewFailureCode.InvalidValue;
            return false;
        }
        fields = result.ToImmutable();
        return true;
    }

    private static bool IsValidEvidence(EvidenceBox box, int pages) =>
        box.SourceIndex >= 0 && box.SourceIndex < pages
        && double.IsFinite(box.X) && double.IsFinite(box.Y)
        && double.IsFinite(box.Width) && double.IsFinite(box.Height)
        && box.Width > 0 && box.Height > 0;

    private static bool TryNormalize(string fieldId, string supplied, out string display, out string normalized)
    {
        display = supplied;
        normalized = supplied;
        switch (fieldId)
        {
            case "issuer_name":
                if (string.IsNullOrWhiteSpace(supplied)) return false;
                normalized = supplied.Normalize(NormalizationForm.FormC);
                return true;
            case "invoice_number":
                display = supplied.Trim(); normalized = display;
                return display.Length > 0;
            case "issue_date":
            case "payment_due_date":
                return DateOnly.TryParse(supplied, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date)
                    && SetDate(date, out display, out normalized);
            case "total_amount":
                return decimal.TryParse(supplied, NumberStyles.Number, CultureInfo.InvariantCulture, out var amount)
                    && amount > 0 && SetAmount(amount, out display, out normalized);
            case "currency":
                display = supplied.Trim().ToUpperInvariant(); normalized = display;
                return SupportedCurrencies.Contains(display);
            default:
                return false;
        }
    }

    private static bool SetDate(DateOnly value, out string display, out string normalized) =>
        (display = normalized = value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)).Length == 10;

    private static bool SetAmount(decimal value, out string display, out string normalized) =>
        (display = normalized = value.ToString("0.#############################", CultureInfo.InvariantCulture)).Length > 0;

    private static string SerializeBounded(ConfirmedInvoiceReview review)
    {
        var json = JsonSerializer.Serialize(new PersistedReview(
            review.DocumentId.Value.ToString("D"), review.SourceIdentity.Hex,
            review.ExtractionRevision, review.ReviewRevision, review.ConfirmedMarket,
            review.IsOutboundInvoice, review.ApprovedAtUtc, review.Fields));
        if (json.Length is 0 or > 1_048_576)
            throw new InvalidOperationException("Validated review serialization was out of bounds.");
        return json;
    }

    private static InvoiceReviewResult Failed(InvoiceReviewFailureCode failure, ConfirmInvoiceReviewCommand command) =>
        new(InvoiceReviewOutcome.InvalidReview, failure, null, command);

    private sealed record PersistedReview(
        string DocumentId,
        string SourceIdentitySha256,
        int ExtractionRevision,
        int ReviewRevision,
        string ConfirmedMarket,
        bool IsOutboundInvoice,
        DateTimeOffset ApprovedAtUtc,
        ImmutableArray<ConfirmedInvoiceReviewField> Fields);
}
