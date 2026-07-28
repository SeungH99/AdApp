using System.Collections.Immutable;
using System.Globalization;

namespace LocalDocumentOrganizer.Core.Cases.Receivable;

public readonly record struct ReceivableActionId(Guid Value)
{
    public bool IsEmpty => Value == Guid.Empty;
}

public enum ReceivableActionType
{
    ConfirmPaymentReceived = 1,
}

public enum ReceivableCaseFailureCode
{
    IdentityMismatch = 1,
    StaleReviewRevision = 2,
    MarketNotConfirmed = 3,
    ApprovalRequired = 4,
    InvalidReview = 5,
    IncomingInvoiceNotSupported = 6,
    InvalidDueDate = 7,
    InvalidAmount = 8,
    InvalidCurrency = 9,
    CaseAlreadyExists = 10,
}

public sealed record ReceivableEvidence(
    int SourceIndex,
    double X,
    double Y,
    double Width,
    double Height)
{
    public bool IsValid => SourceIndex >= 0
        && double.IsFinite(X) && double.IsFinite(Y)
        && double.IsFinite(Width) && double.IsFinite(Height)
        && Width > 0 && Height > 0;
}

public sealed record ConfirmedReceivableField(
    string FieldId,
    string OriginalNormalizedValue,
    string ConfirmedNormalizedValue,
    bool IsCorrected,
    ImmutableArray<ReceivableEvidence> Evidence);

public sealed record CreateReceivableCaseCommand(
    CaseId CaseId,
    ReceivableActionId ActionId,
    DocumentId SourceDocumentId,
    int ExtractionRevision,
    int ReviewRevision,
    string ConfirmedMarket,
    bool IsOutboundInvoice,
    bool IsExplicitlyApproved,
    DateTimeOffset ApprovedAtUtc,
    DateOnly IssueDate,
    DateOnly DueDate,
    decimal TotalAmount,
    string Currency,
    ImmutableDictionary<string, ConfirmedReceivableField> Fields);

public sealed record ReceivableCaseCreated(
    CaseId CaseId,
    DocumentId SourceDocumentId,
    int ReviewRevision,
    DateOnly DueDate,
    decimal TotalAmount,
    string Currency,
    DateTimeOffset OccurredAtUtc);

public sealed record ReceivableActionRequired(
    CaseId CaseId,
    ReceivableActionId ActionId,
    ReceivableActionType ActionType,
    DocumentId SourceDocumentId,
    DateOnly DueDate,
    DateTimeOffset OccurredAtUtc);

public sealed record ReceivableCaseDecision(
    ReceivableCaseCreated? CaseCreated,
    ReceivableActionRequired? ActionRequired,
    ReceivableCaseFailureCode? Failure)
{
    public static ReceivableCaseDecision Rejected(ReceivableCaseFailureCode failure) =>
        new(null, null, failure);
}

public static class ReceivableCaseDecider
{
    private static readonly ImmutableHashSet<string> RequiredFields =
        ImmutableHashSet.Create(StringComparer.Ordinal,
            "issuer_name", "invoice_number", "issue_date", "payment_due_date",
            "total_amount", "currency");

    private static readonly ImmutableHashSet<string> SupportedCurrencies =
        ImmutableHashSet.Create(StringComparer.Ordinal, "USD", "KRW");

    public static ReceivableCaseDecision Decide(
        CreateReceivableCaseCommand command,
        CaseId? existingCase)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.CaseId.Value == Guid.Empty || command.ActionId.IsEmpty
            || command.SourceDocumentId.Value == Guid.Empty)
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.IdentityMismatch);
        if (existingCase is not null)
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.CaseAlreadyExists);
        if (command.ExtractionRevision <= 0 || command.ReviewRevision <= 0
            || command.ExtractionRevision != command.ReviewRevision)
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.StaleReviewRevision);
        if (command.ConfirmedMarket is not ("ko-KR" or "en-US"))
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.MarketNotConfirmed);
        if (!command.IsOutboundInvoice)
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.IncomingInvoiceNotSupported);
        if (!command.IsExplicitlyApproved || command.ApprovedAtUtc.Offset != TimeSpan.Zero
            || command.ApprovedAtUtc == default)
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.ApprovalRequired);
        if (!HasValidFields(command.Fields))
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.InvalidReview);
        if (command.DueDate < command.IssueDate
            || !MatchesDate(command.Fields["issue_date"].ConfirmedNormalizedValue, command.IssueDate)
            || !MatchesDate(command.Fields["payment_due_date"].ConfirmedNormalizedValue, command.DueDate))
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.InvalidDueDate);
        if (command.TotalAmount <= 0
            || !MatchesAmount(command.Fields["total_amount"].ConfirmedNormalizedValue, command.TotalAmount))
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.InvalidAmount);
        if (!SupportedCurrencies.Contains(command.Currency)
            || !string.Equals(command.Fields["currency"].ConfirmedNormalizedValue, command.Currency, StringComparison.Ordinal))
            return ReceivableCaseDecision.Rejected(ReceivableCaseFailureCode.InvalidCurrency);

        return new ReceivableCaseDecision(
            new ReceivableCaseCreated(command.CaseId, command.SourceDocumentId,
                command.ReviewRevision, command.DueDate, command.TotalAmount,
                command.Currency, command.ApprovedAtUtc),
            new ReceivableActionRequired(command.CaseId, command.ActionId,
                ReceivableActionType.ConfirmPaymentReceived,
                command.SourceDocumentId, command.DueDate, command.ApprovedAtUtc),
            null);
    }

    private static bool HasValidFields(
        ImmutableDictionary<string, ConfirmedReceivableField>? fields) =>
        fields is not null
        && fields.Count == RequiredFields.Count
        && fields.Keys.ToImmutableHashSet(StringComparer.Ordinal).SetEquals(RequiredFields)
        && fields.All(pair => pair.Key == pair.Value.FieldId
            && !string.IsNullOrWhiteSpace(pair.Value.OriginalNormalizedValue)
            && !string.IsNullOrWhiteSpace(pair.Value.ConfirmedNormalizedValue)
            && !pair.Value.Evidence.IsDefaultOrEmpty
            && pair.Value.Evidence.All(static evidence => evidence.IsValid));

    private static bool MatchesDate(string value, DateOnly expected) =>
        DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out var actual) && actual == expected;

    private static bool MatchesAmount(string value, decimal expected) =>
        decimal.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture,
            out var actual) && actual == expected && actual > 0;
}
