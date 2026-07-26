using System.Collections.Immutable;
using System.Collections.Frozen;

namespace LocalDocumentOrganizer.CorpusWorkbench.Contracts;

public static class PilotCatalog
{
    public const string SchemaVersion = "1";
    public const string ContractId = "invoice-explicit-due-date-v1";
    public const int HeldOutTargetPerMarket = 40;
    public const int DirectReviewTargetPerMarket = 10;

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

public enum ApprovalMode
{
    DirectReview,
    DelegatedLabel,
    BatchApproval,
}

public enum WorkbenchFailureCode
{
    InvalidArguments,
    InvalidState,
    SourceUnverified,
    ReuseStatusUnknown,
    VaultBoundaryViolation,
    ContentHashMismatch,
    DuplicateContent,
    SourceFamilyLeakage,
    UnsupportedInput,
    MissingRequiredField,
    MissingEvidence,
    StaleRuleSet,
    ReviewCoverageInsufficient,
    InsufficientDirectReview,
    BatchApprovalMissing,
    ApprovalChainInvalid,
    WorkerExecutionFailed,
    WorkerAttestationMismatch,
    CoverageIncomplete,
    InvalidCheckpoint,
    PrivacyLeakDetected,
}

public sealed class WorkbenchException : Exception
{
    public WorkbenchException(
        WorkbenchFailureCode failureCode,
        Exception? innerException = null)
        : base($"Corpus workbench failed: {failureCode}.", innerException) =>
        FailureCode = failureCode;

    public WorkbenchFailureCode FailureCode { get; }
}

public sealed record PilotScope(
    string SchemaVersion,
    string CatalogEpoch,
    string ContractId,
    ImmutableArray<string> MarketIds,
    int HeldOutTargetPerMarket,
    int DirectReviewTargetPerMarket);

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

public sealed record SourceReceipt(
    string SchemaVersion,
    string ReceiptId,
    string SourceUri,
    string Publisher,
    DateTimeOffset RetrievedAtUtc,
    string ReuseStatus,
    string MarketId,
    string ContractId,
    string SourceFamilyId,
    string ExpectedContentSha256);

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

public sealed record LabelRevision(
    string RevisionId,
    string DocumentId,
    string DocumentSha256,
    string MarketId,
    string ContractId,
    string? PreviousRevisionId,
    string? PreviousRevisionSha256,
    string RuleCatalogSha256,
    string WorkerPackageManifestId,
    string WorkerPackageManifestVersion,
    string WorkerPackageSha256,
    string WorkerExecutableRelativePath,
    string WorkerExecutableSha256,
    ImmutableArray<LabeledField> Fields,
    string RevisionSha256,
    DateTimeOffset CreatedAtUtc);

public sealed record ApprovalEntry(
    string EntryId,
    ApprovalMode Mode,
    string ScopeId,
    string? DocumentSha256,
    string? LabelRevisionSha256,
    string RuleCatalogSha256,
    string WorkerPackageSha256,
    string ReviewerId,
    DateTimeOffset ApprovedAtUtc,
    string PreviousEntrySha256,
    string EntrySha256);

public sealed record PilotMarketSummary(
    string MarketId,
    int EligibleDocumentCount,
    int ImagePdfCount,
    int StandaloneRasterCount,
    int SourceFamilyCount,
    int DirectReviewCount,
    int DelegatedLabelCount,
    bool BatchApproved,
    ImmutableDictionary<string, int> AggregateErrorCounts);

public sealed record PilotReportEnvelope(
    string SchemaVersion,
    string CatalogEpoch,
    string ContractId,
    string RuleCatalogSha256,
    string WorkerPackageSha256,
    string LedgerHeadSha256,
    bool PilotComplete,
    WorkbenchFailureCode? PrimaryFailureCode,
    ImmutableArray<WorkbenchFailureCode> BlockingReasons,
    ImmutableArray<PilotMarketSummary> Markets,
    string ReportSha256);

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
