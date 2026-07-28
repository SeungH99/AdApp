using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Contracts;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases.Receivable;

namespace LocalDocumentOrganizer.Application.Review;

public sealed class InvoiceReviewService
{
    private static readonly ImmutableHashSet<string> RequiredFields =
        PilotCatalog.RequiredFieldIds.ToImmutableHashSet(StringComparer.Ordinal);

    private readonly IInvoiceReviewQueryStore _reviews;
    private readonly IProductCommitStore _commits;
    private readonly IInvoiceReviewDraftLabeler? _draftLabeler;

    public InvoiceReviewService(
        IInvoiceReviewQueryStore reviews,
        IProductCommitStore commits,
        IInvoiceReviewDraftLabeler? draftLabeler = null)
    {
        _reviews = reviews ?? throw new ArgumentNullException(nameof(reviews));
        _commits = commits ?? throw new ArgumentNullException(nameof(commits));
        _draftLabeler = draftLabeler;
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
        if (snapshot.InboxStatus is not (
                ProductInboxStatus.ReadyForReview
                or ProductInboxStatus.NeedsReview
                or ProductInboxStatus.Reviewed))
            return Failed(InvoiceReviewFailureCode.DocumentUnavailable, command);
        if (command.ConfirmedMarket is not ("ko-KR" or "en-US"))
            return Failed(InvoiceReviewFailureCode.MarketConfirmationRequired, command);
        if (!command.IsOutboundInvoice)
            return new(InvoiceReviewOutcome.NotSupportedInThisVersion, InvoiceReviewFailureCode.OutboundConfirmationRequired, null, command);
        if (!command.IsExplicitlyApproved || command.ApprovedAtUtc.Offset != TimeSpan.Zero || command.ApprovedAtUtc == default)
            return Failed(InvoiceReviewFailureCode.ApprovalRequired, command);
        if (snapshot.CurrentDraft is not null)
        {
            if (_draftLabeler is null)
                return Failed(
                    InvoiceReviewFailureCode.ExactFieldSetRequired,
                    command);
            try
            {
                snapshot = snapshot with
                {
                    Fields = _draftLabeler.Label(
                        command.ConfirmedMarket,
                        snapshot.CurrentDraft),
                };
            }
            catch (InvoiceRuleException)
            {
                return Failed(
                    InvoiceReviewFailureCode.ExactFieldSetRequired,
                    command);
            }
        }
        if (!TryValidateFields(command, snapshot, out var fields, out var failure))
            return Failed(failure, command);

        if (snapshot.ConfirmedReviewRevision == int.MaxValue)
            return Failed(InvoiceReviewFailureCode.StorageConflict, command);
        var review = new ConfirmedInvoiceReview(
            command.DocumentId, command.ExpectedSourceIdentity,
            command.ExpectedExtractionRevision, snapshot.ConfirmedReviewRevision + 1,
            command.ConfirmedMarket, true, command.ApprovedAtUtc, fields);
        if (!TrySerializeBounded(review, out var payload))
            return Failed(InvoiceReviewFailureCode.InputTooLarge, command);
        var commit = await _commits.CommitReviewAsync(
            new CommitReviewCommand(command.OperationId, command.EventId, command.DocumentId,
                snapshot.CurrentStreamVersion, command.ApprovedAtUtc, payload,
                command.ExpectedExtractionRevision, review.ReviewRevision),
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
        if (command.Fields.IsDefault || command.Fields.Length != RequiredFields.Count)
            return false;

        var totalEvidence = 0;
        foreach (var submission in command.Fields)
        {
            if (submission is null
                || submission.ConfirmedValue is null
                || Encoding.UTF8.GetByteCount(submission.ConfirmedValue)
                    > InvoiceReviewLimits.MaxConfirmedValueUtf8Bytes
                || submission.Evidence.IsDefault
                || submission.Evidence.Length
                    > InvoiceReviewLimits.MaxEvidencePerField
                || totalEvidence
                    > InvoiceReviewLimits.MaxTotalEvidence
                        - submission.Evidence.Length)
            {
                failure = InvoiceReviewFailureCode.InputTooLarge;
                return false;
            }
            totalEvidence += submission.Evidence.Length;
        }

        if (command.Fields.Select(static field => field.FieldId).Distinct(StringComparer.Ordinal).Count() != RequiredFields.Count
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
                    || !IsValidEvidence(evidence, snapshot)))
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

    private static bool IsValidEvidence(
        ReviewEvidence evidence,
        InvoiceReviewSnapshot snapshot)
    {
        var box = evidence.Box;
        if (box.SourceIndex < 0
            || !double.IsFinite(box.X)
            || !double.IsFinite(box.Y)
            || !double.IsFinite(box.Width)
            || !double.IsFinite(box.Height)
            || box.X < 0
            || box.Y < 0
            || box.Width <= 0
            || box.Height <= 0)
        {
            return false;
        }

        if (snapshot.SourcePages.IsDefault)
        {
            return box.SourceIndex < snapshot.SourcePageCount;
        }

        var page = snapshot.SourcePages.SingleOrDefault(
            candidate => candidate.SourceIndex == box.SourceIndex);
        return page is not null
            && page.CoordinateSystem == evidence.CoordinateSystem
            && box.X <= page.Width - box.Width
            && box.Y <= page.Height - box.Height;
    }

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
                return Iso4217CurrencyCatalog.IsValid(display);
            default:
                return false;
        }
    }

    private static bool SetDate(DateOnly value, out string display, out string normalized) =>
        (display = normalized = value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)).Length == 10;

    private static bool SetAmount(decimal value, out string display, out string normalized) =>
        (display = normalized = value.ToString("0.#############################", CultureInfo.InvariantCulture)).Length > 0;

    private static bool TrySerializeBounded(
        ConfirmedInvoiceReview review,
        out string payload)
    {
        payload = JsonSerializer.Serialize(new PersistedConfirmedInvoiceReview(
            review.DocumentId.Value.ToString("D"), review.SourceIdentity.Hex,
            review.ExtractionRevision, review.ReviewRevision, review.ConfirmedMarket,
            review.IsOutboundInvoice, review.ApprovedAtUtc, review.Fields));
        return payload.Length > 0
            && Encoding.UTF8.GetByteCount(payload)
                <= InvoiceReviewLimits.MaxProtectedPayloadUtf8Bytes;
    }

    private static InvoiceReviewResult Failed(InvoiceReviewFailureCode failure, ConfirmInvoiceReviewCommand command) =>
        new(InvoiceReviewOutcome.InvalidReview, failure, null, command);

}
