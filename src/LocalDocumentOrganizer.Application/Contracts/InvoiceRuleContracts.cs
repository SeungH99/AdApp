using System.Collections.Frozen;
using System.Collections.Immutable;

namespace LocalDocumentOrganizer.Application.Contracts;

public static class PilotCatalog
{
    public const string SchemaVersion = "1";
    public const string ContractId = "invoice-explicit-due-date-v1";

    public static ImmutableArray<string> MarketIds { get; } =
        ["ko-KR", "en-US"];

    public static ImmutableArray<string> RequiredFieldIds { get; } =
    [
        "issuer_name",
        "invoice_number",
        "issue_date",
        "payment_due_date",
        "total_amount",
        "currency",
    ];
}

public enum ApplicationFailureCode
{
    InvalidArguments,
    InvalidState,
    SourceUnverified,
    MissingEvidence,
}

public sealed class InvoiceRuleException : Exception
{
    public InvoiceRuleException(ApplicationFailureCode failureCode)
        : base($"Application invoice rules failed: {failureCode}.") =>
        FailureCode = failureCode;

    public ApplicationFailureCode FailureCode { get; }
}

public sealed record EvidenceBox(
    int SourceIndex,
    double X,
    double Y,
    double Width,
    double Height);

public sealed record LabeledField(
    string FieldId,
    string NormalizedValue,
    ImmutableArray<EvidenceBox> Evidence,
    string RuleId);

public sealed record WorkbenchDocument(
    string DocumentId,
    string ContentSha256,
    string SourceFamilyId,
    string MarketId,
    string ContractId,
    string InputKind,
    string? CodecId,
    string ReceiptId,
    string LifecycleState,
    DateTimeOffset CreatedAtUtc);

public sealed record OfficialRuleSource(
    string Id,
    string Uri,
    string Publisher,
    DateOnly? PublishedOrRevisedOn,
    DateOnly VerifiedOn);

public sealed record OfficialFieldRule(
    string RuleId,
    string FieldId,
    string Normalization,
    ImmutableArray<string> AcceptedVisibleLabels,
    ImmutableArray<string> SourceIds);

public sealed record OfficialRuleCatalogDocument(
    string SchemaVersion,
    string MarketId,
    string ContractId,
    ImmutableArray<OfficialRuleSource> Sources,
    ImmutableArray<OfficialFieldRule> Rules);

public sealed record OfficialRuleCatalogSnapshot(
    OfficialRuleCatalogDocument Document,
    string CatalogSha256,
    FrozenDictionary<string, OfficialFieldRule> RulesByFieldId);
