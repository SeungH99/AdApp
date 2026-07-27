# Empirical Corpus Workbench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local-first corpus workbench that curates and validates a two-market invoice pilot without weakening the complete 36-cell production `CorpusEval` gate.

**Architecture:** A new Windows .NET CLI owns the workbench state, content-addressed vault, immutable label revisions, approval ledger, deterministic review sampling, loopback review UI, and sanitized pilot report. It reuses the existing isolated document Worker and Windows filesystem boundaries; originals and empirical state remain outside Git while official rule metadata and code are tracked.

**Tech Stack:** C# 14, .NET 10, Windows 11 SDK target `10.0.26100.0`, Microsoft.Data.Sqlite, existing AppContainer document Worker, System.Text.Json source generation, ASP.NET Core shared framework/Kestrel for a token-protected loopback review UI, MSTest 4.3.2 for ignored local tests.

## Global Constraints

- Work only on `release-issue-7`; never implement directly on `main`.
- `main` must remain deployable and protected.
- Production `CorpusEval` continues to require exactly 36 market-contract cells and 40 held-out documents per cell.
- The pilot scope is `ko-KR` and `en-US`, contract `invoice-explicit-due-date-v1`, target 40 held-out documents per market.
- Required fields are `issuer_name`, `invoice_number`, `issue_date`, `payment_due_date`, `total_amount`, and `currency`.
- `payment_due_date` must be explicitly printed; relative-only payment terms are excluded from this pilot.
- User direct review requires 10 documents per market; remaining documents retain `delegated-label` provenance until explicit `batch-approval`.
- Originals remain unredacted and local. Git, logs, PRs, and sanitized reports must not contain documents, filenames, paths, extracted text, field values, evidence coordinates, or approval payloads.
- Official rule sources must be authoritative government, regulator, standards-body, or official program pages.
- Unknown provenance or reuse status is fail-closed; do not fabricate documents to reach 40.
- No automatic network crawler is added. Acquisition uses explicitly reviewed files and provenance receipts.
- All JSON uses camelCase, required constructor parameters, and `JsonUnmappedMemberHandling.Disallow`.
- Use canonical UTF-8 without BOM and SHA-256 for persisted identity.
- Treat all warnings as errors; keep the solution Release build at zero warnings and zero errors.
- Local tests are written and executed under ignored `tests/`; never stage or commit test source.
- Before every commit run `git diff --cached --name-only | Select-String '^tests/'` and require no match.
- Commit messages use the repository emoji prefixes.
- Use `C:\tmp\dotnet10\dotnet.exe` and `-p:NuGetAudit=false` for deterministic local verification while the existing audit warning is unresolved.

---

## File Structure

### New workbench project

- `tools/CorpusWorkbench/LocalDocumentOrganizer.CorpusWorkbench.csproj` — executable project, references Core, Infrastructure.Windows, CorpusEval, Microsoft.Data.Sqlite, and Microsoft.AspNetCore.App.
- `tools/CorpusWorkbench/Program.cs` — composition root and stable exit-code mapping only.
- `tools/CorpusWorkbench/Commanding/WorkbenchCommandLine.cs` — strict command parsing and command records.
- `tools/CorpusWorkbench/Contracts/WorkbenchContracts.cs` — pilot, document, label, approval, and report contracts.
- `tools/CorpusWorkbench/Serialization/WorkbenchJsonContext.cs` — source-generated JSON metadata.
- `tools/CorpusWorkbench/Rules/OfficialRuleCatalog.cs` — catalog loading, official-domain validation, rule-set hashing.
- `tools/CorpusWorkbench/catalog/invoice-explicit-due-date-v1.ko-KR.json` — Korean official rule metadata.
- `tools/CorpusWorkbench/catalog/invoice-explicit-due-date-v1.en-US.json` — United States official rule metadata.
- `tools/CorpusWorkbench/Vault/CorpusVault.cs` — vault lease and content-addressed source lifecycle.
- `tools/CorpusWorkbench/Persistence/CorpusWorkbenchStore.cs` — SQLite schema, transactions, and immutable repositories.
- `tools/CorpusWorkbench/Ingestion/CorpusIngestionService.cs` — verified import and provenance receipt binding.
- `tools/CorpusWorkbench/Labels/InvoiceDraftLabeler.cs` — deterministic draft field extraction and normalization.
- `tools/CorpusWorkbench/Labels/DraftLabelService.cs` — sealed Worker execution and immutable label revision storage.
- `tools/CorpusWorkbench/Approval/ApprovalLedgerService.cs` — hash-chained direct, delegated, and batch approvals.
- `tools/CorpusWorkbench/Sampling/ReviewSampleSelector.cs` — deterministic, stratified 10-document selection.
- `tools/CorpusWorkbench/Review/DocumentPreviewService.cs` — local PDF/raster page rendering.
- `tools/CorpusWorkbench/Review/ReviewHost.cs` — loopback-only tokenized review API and browser launch.
- `tools/CorpusWorkbench/Review/wwwroot/index.html` — local review page structure.
- `tools/CorpusWorkbench/Review/wwwroot/review.css` — approved review-screen visual hierarchy.
- `tools/CorpusWorkbench/Review/wwwroot/review.js` — in-memory token handling and decision submission.
- `tools/CorpusWorkbench/Validation/PilotValidator.cs` — coverage, approval, identity, and privacy gates.
- `tools/CorpusWorkbench/Validation/PilotCheckpointStore.cs` — authenticated resumable checkpoints.
- `tools/CorpusWorkbench/Validation/PilotReportWriter.cs` — sanitized canonical report envelope.
- `tools/CorpusWorkbench/Security/CorpusPrivacyScanner.cs` — forbidden-content scan for publishable output.

### Shared files modified

- `LocalDocumentOrganizer.sln` — add the workbench project.
- `src/LocalDocumentOrganizer.Infrastructure.Windows/FileSystem/ApprovedRootFileStore.cs` — new shared verified create/open API for files below an approved root.
- `src/LocalDocumentOrganizer.Infrastructure.Windows/FileSystem/WindowsFileSystemNative.cs` — add only the handle operations needed by `ApprovedRootFileStore`.
- `tools/CorpusEval/CorpusWorkerPackageWorkspace.cs` — new public façade over the existing protected-root and sealed-stage implementation.

### Ignored local tests

- `tests/CorpusWorkbench/LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj`
- `tests/CorpusWorkbench/ContractsTests.cs`
- `tests/CorpusWorkbench/OfficialRuleCatalogTests.cs`
- `tests/CorpusWorkbench/CorpusVaultTests.cs`
- `tests/CorpusWorkbench/DraftLabelServiceTests.cs`
- `tests/CorpusWorkbench/ApprovalLedgerServiceTests.cs`
- `tests/CorpusWorkbench/ReviewSampleSelectorTests.cs`
- `tests/CorpusWorkbench/ReviewHostTests.cs`
- `tests/CorpusWorkbench/PilotValidatorTests.cs`
- `tests/CorpusWorkbench/WorkbenchCliTests.cs`

---

### Task 1: Project Skeleton and Immutable Contracts

**Files:**
- Create: `tools/CorpusWorkbench/LocalDocumentOrganizer.CorpusWorkbench.csproj`
- Create: `tools/CorpusWorkbench/Contracts/WorkbenchContracts.cs`
- Create: `tools/CorpusWorkbench/Serialization/WorkbenchJsonContext.cs`
- Create: `tools/CorpusWorkbench/Program.cs`
- Modify: `LocalDocumentOrganizer.sln`
- Test locally: `tests/CorpusWorkbench/ContractsTests.cs`

**Interfaces:**
- Produces: `PilotCatalog`, `WorkbenchFailureCode`, `ApprovalMode`, `EvidenceBox`, `LabeledField`, `LabelRevision`, `SourceReceipt`, `WorkbenchDocument`, `ApprovalEntry`, `PilotReportEnvelope`.
- JSON entry points: `WorkbenchJson.Serialize<T>(T value, JsonTypeInfo<T> typeInfo)` and `WorkbenchJson.Parse<T>(ReadOnlySpan<byte> utf8, JsonTypeInfo<T> typeInfo)`.

- [ ] **Step 1: Write the local failing contract test**

```csharp
[TestMethod]
public void Contracts_RejectUnknownMembers_AndPreserveRequiredPilotScope()
{
    var json = """
        {
          "schemaVersion":"1",
          "catalogEpoch":"pilot-2026-07",
          "contractId":"invoice-explicit-due-date-v1",
          "marketIds":["ko-KR","en-US"],
          "heldOutTargetPerMarket":40,
          "directReviewTargetPerMarket":10,
          "unknown":true
        }
        """u8;

    Assert.Throws<JsonException>(
        () => WorkbenchJson.Parse(
            json,
            WorkbenchJsonContext.Default.PilotScope));
}
```

- [ ] **Step 2: Run the focused test and verify the red state**

Run:

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~ContractsTests
```

Expected: compile failure because `PilotScope` and `WorkbenchJsonContext` do not exist.

- [ ] **Step 3: Create the executable project**

Use:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0-windows10.0.26100.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\LocalDocumentOrganizer.Core\LocalDocumentOrganizer.Core.csproj" />
    <ProjectReference Include="..\..\src\LocalDocumentOrganizer.Infrastructure.Windows\LocalDocumentOrganizer.Infrastructure.Windows.csproj" />
    <ProjectReference Include="..\CorpusEval\LocalDocumentOrganizer.CorpusEval.csproj" />
    <PackageReference Include="Microsoft.Data.Sqlite" />
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
  <ItemGroup>
    <Content Include="Review\wwwroot\**\*" CopyToOutputDirectory="PreserveNewest" />
    <Content Include="catalog\*.json" CopyToOutputDirectory="PreserveNewest" />
  </ItemGroup>
</Project>
```

- [ ] **Step 4: Define exact pilot constants and immutable contracts**

The central constants must be:

```csharp
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
    string? PreviousRevisionId,
    string RuleCatalogSha256,
    string WorkerPackageSha256,
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
```

Use lower-case hex for all SHA-256 fields and ISO 8601 UTC timestamps.

- [ ] **Step 5: Add source-generated strict JSON**

Use:

```csharp
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectRequiredConstructorParameters = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    WriteIndented = false)]
[JsonSerializable(typeof(PilotScope))]
[JsonSerializable(typeof(SourceReceipt))]
[JsonSerializable(typeof(LabelRevision))]
[JsonSerializable(typeof(ApprovalEntry))]
[JsonSerializable(typeof(PilotReportEnvelope))]
public sealed partial class WorkbenchJsonContext : JsonSerializerContext;

public static class WorkbenchJson
{
    public static T Parse<T>(
        ReadOnlySpan<byte> utf8,
        JsonTypeInfo<T> typeInfo) =>
        JsonSerializer.Deserialize(utf8, typeInfo)
        ?? throw new JsonException("Required JSON payload was null.");

    public static byte[] Serialize<T>(
        T value,
        JsonTypeInfo<T> typeInfo) =>
        JsonSerializer.SerializeToUtf8Bytes(value, typeInfo);
}
```

- [ ] **Step 6: Add the project to the solution and verify green**

Run:

```powershell
C:\tmp\dotnet10\dotnet.exe sln LocalDocumentOrganizer.sln add tools\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.csproj
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~ContractsTests
C:\tmp\dotnet10\dotnet.exe build LocalDocumentOrganizer.sln -c Release -p:NuGetAudit=false
```

Expected: focused test passes; solution builds with zero warnings and zero errors.

- [ ] **Step 7: Commit production files only**

```powershell
git add LocalDocumentOrganizer.sln tools\CorpusWorkbench
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ empirical corpus workbench 계약 추가"
```

---

### Task 2: Official Rule Catalog

**Files:**
- Create: `tools/CorpusWorkbench/Rules/OfficialRuleCatalog.cs`
- Create: `tools/CorpusWorkbench/catalog/invoice-explicit-due-date-v1.ko-KR.json`
- Create: `tools/CorpusWorkbench/catalog/invoice-explicit-due-date-v1.en-US.json`
- Modify: `tools/CorpusWorkbench/Contracts/WorkbenchContracts.cs`
- Modify: `tools/CorpusWorkbench/Serialization/WorkbenchJsonContext.cs`
- Test locally: `tests/CorpusWorkbench/OfficialRuleCatalogTests.cs`

**Interfaces:**
- Produces: `OfficialRuleCatalog.LoadAsync(string path, CancellationToken)`.
- Returns: `OfficialRuleCatalogSnapshot` with `CatalogSha256`, `MarketId`, `ContractId`, and field-indexed `Rules`.
- Consumes later: draft normalizer, approval ledger, validator, review UI.

- [ ] **Step 1: Write tests for authority, field coverage, and canonical hash**

```csharp
[TestMethod]
public async Task LoadAsync_RejectsNonOfficialHost_AndRequiresSixFields()
{
    var path = Fixture.WriteCatalog(
        marketId: "en-US",
        sourceUri: "https://untrusted.example/invoice",
        fieldIds: PilotCatalog.RequiredFieldIds);

    var error = await Assert.ThrowsAsync<WorkbenchException>(
        () => OfficialRuleCatalog.LoadAsync(path, CancellationToken.None));

    Assert.AreEqual(
        WorkbenchFailureCode.SourceUnverified,
        error.FailureCode);
}
```

Add a second test that loads the same semantic catalog with reordered object
members and verifies the same canonical SHA-256.

- [ ] **Step 2: Run the focused rule tests and verify failure**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~OfficialRuleCatalogTests
```

Expected: compile failure because the catalog loader does not exist.

- [ ] **Step 3: Define catalog records and allowlisted official hosts**

Add these exact records:

```csharp
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
```

Use exact allowlist entries:

```csharp
private static readonly FrozenSet<string> OfficialHosts =
    new[]
    {
        "www.law.go.kr",
        "law.go.kr",
        "www.nts.go.kr",
        "nts.go.kr",
        "www.acquisition.gov",
        "acquisition.gov",
        "www.rfc-editor.org",
        "www.iso.org",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
```

Reject non-HTTPS URIs, credentials in URIs, fragments, non-default ports, unknown
markets, unknown fields, duplicate rule IDs, duplicate field IDs, and timestamps in
the future.

- [ ] **Step 4: Seed the Korean catalog**

The tracked source metadata must include:

- `https://www.law.go.kr/lsLinkCommonInfo.do?lsJoLnkSeq=1031739479` for
  Value-Added Tax Act Article 32 required tax-invoice fields.
- `https://www.law.go.kr/LSW/lsInfoP.do?efYd=20230516&lsiSeq=251039` for the
  official enforcement-decree field list.
- `https://www.iso.org/iso-4217-currency-codes.html` for ISO 4217 normalization.
- `https://www.rfc-editor.org/rfc/rfc3339` for the emitted date representation.

The explicit due-date rule must state that the value is accepted only when a
calendar date is visibly labeled as a payment deadline in the document; it must not
derive a date from relative terms.

- [ ] **Step 5: Seed the United States catalog**

The tracked source metadata must include:

- `https://www.acquisition.gov/far/32.905` for proper-invoice content.
- `https://www.acquisition.gov/far/52.232-25` for invoice payment due-date rules.
- `https://www.iso.org/iso-4217-currency-codes.html` for ISO 4217 normalization.
- `https://www.rfc-editor.org/rfc/rfc3339` for the emitted date representation.

The pilot still labels only an explicitly printed due date; FAR-derived dates belong
to a future derived-deadline contract.

- [ ] **Step 6: Implement canonical hashing and validation**

The public entry point must have this shape:

```csharp
public static async Task<OfficialRuleCatalogSnapshot> LoadAsync(
    string path,
    CancellationToken cancellationToken)
{
    var bytes = await File.ReadAllBytesAsync(path, cancellationToken)
        .ConfigureAwait(false);
    var document = WorkbenchJson.Parse(
        bytes,
        WorkbenchJsonContext.Default.OfficialRuleCatalogDocument);
    OfficialRuleCatalogValidator.Validate(document);
    var canonical = CanonicalRuleCatalog.Serialize(document);
    return new(
        document,
        Convert.ToHexStringLower(SHA256.HashData(canonical)),
        document.Rules.ToFrozenDictionary(
            static rule => rule.FieldId,
            StringComparer.Ordinal));
}
```

- [ ] **Step 7: Run tests and build**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~OfficialRuleCatalogTests
C:\tmp\dotnet10\dotnet.exe build LocalDocumentOrganizer.sln -c Release -p:NuGetAudit=false
```

Expected: all focused tests pass; zero warnings and zero errors.

- [ ] **Step 8: Commit production catalog and validator**

```powershell
git add tools\CorpusWorkbench\Contracts tools\CorpusWorkbench\Serialization tools\CorpusWorkbench\Rules tools\CorpusWorkbench\catalog
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ 한미 인보이스 공식 규칙 catalog 추가"
```

---

### Task 3: Verified Vault and Idempotent Ingestion

**Files:**
- Create: `src/LocalDocumentOrganizer.Infrastructure.Windows/FileSystem/ApprovedRootFileStore.cs`
- Modify: `src/LocalDocumentOrganizer.Infrastructure.Windows/FileSystem/WindowsFileSystemNative.cs`
- Create: `tools/CorpusWorkbench/Vault/CorpusVault.cs`
- Create: `tools/CorpusWorkbench/Persistence/CorpusWorkbenchStore.cs`
- Create: `tools/CorpusWorkbench/Ingestion/CorpusIngestionService.cs`
- Test locally: `tests/CorpusWorkbench/CorpusVaultTests.cs`

**Interfaces:**
- Produces: `ApprovedRootFileStore.CreateNewVerified`, `CorpusVault.OpenExisting`, `CorpusIngestionService.ImportAsync`.
- `ImportAsync` returns `ImportResult(DocumentId, ContentSha256, WasExisting)`.
- Consumes: strict `SourceReceipt`, approved market and contract, explicit local source file.

Define the result in `CorpusIngestionService.cs`:

```csharp
public sealed record ImportResult(
    string DocumentId,
    string ContentSha256,
    bool WasExisting);
```

- [ ] **Step 1: Write path-attack and idempotency tests**

```csharp
[TestMethod]
public async Task ImportAsync_ReusesContentId_AndRejectsJunctionEscape()
{
    await using var fixture = await VaultFixture.CreateAsync();
    var receipt = fixture.ValidReceipt("ko-KR");

    var first = await fixture.Ingestion.ImportAsync(
        fixture.InvoicePath,
        receipt,
        CancellationToken.None);
    var second = await fixture.Ingestion.ImportAsync(
        fixture.InvoicePath,
        receipt,
        CancellationToken.None);

    Assert.IsFalse(first.WasExisting);
    Assert.IsTrue(second.WasExisting);
    Assert.AreEqual(first.ContentSha256, second.ContentSha256);
    await Assert.ThrowsAsync<FileSystemBoundaryException>(
        () => fixture.TryImportThroughJunctionAsync());
}
```

Add tests for a hardlink, replacement between verification and copy, magic-byte
mismatch, unsupported codec, more than one hardlink, and an oversized input.

- [ ] **Step 2: Run the vault tests and verify failure**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~CorpusVaultTests
```

Expected: compile failure because `CorpusVault` and `CorpusIngestionService` do not
exist.

- [ ] **Step 3: Add a verified approved-root file store**

Expose only relative, normalized content paths:

```csharp
public sealed class ApprovedRootFileStore : IDisposable
{
    public ApprovedRootFileStore(ApprovedRootPathGuard guard);

    public SafeFileHandle CreateNewVerified(
        string relativePath,
        long expectedLength);

    public VerifiedStableSource OpenExistingVerified(
        string relativePath);

    public void Revalidate();
}
```

`CreateNewVerified` must reject rooted paths, `.` or `..`, alternate data streams,
device names, reparse points, multiple hardlinks, cross-volume components, and a
final handle whose physical path or root identity differs from the pinned approved
root.

- [ ] **Step 4: Implement the content-addressed vault layout**

Use:

```text
<vault>/
  workbench.db
  objects/sha256/ab/cd/<64-lower-hex>
  previews/
  checkpoints/
```

The object path is derived only from a validated lower-case SHA-256; never from the
original filename.

- [ ] **Step 5: Create the SQLite schema in one transaction**

Create tables for:

```sql
CREATE TABLE source_receipts (
  receipt_id TEXT PRIMARY KEY,
  receipt_sha256 TEXT NOT NULL UNIQUE,
  canonical_json BLOB NOT NULL
);
CREATE TABLE documents (
  document_id TEXT PRIMARY KEY,
  content_sha256 TEXT NOT NULL UNIQUE,
  source_family_id TEXT NOT NULL,
  market_id TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  input_kind TEXT NOT NULL,
  codec_id TEXT NULL,
  receipt_id TEXT NOT NULL REFERENCES source_receipts(receipt_id),
  lifecycle_state TEXT NOT NULL,
  created_at_utc TEXT NOT NULL
);
CREATE TABLE label_revisions (
  revision_id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(document_id),
  previous_revision_id TEXT NULL,
  revision_sha256 TEXT NOT NULL UNIQUE,
  canonical_json BLOB NOT NULL,
  created_at_utc TEXT NOT NULL
);
CREATE TABLE approval_entries (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id TEXT NOT NULL UNIQUE,
  previous_entry_sha256 TEXT NOT NULL,
  entry_sha256 TEXT NOT NULL UNIQUE,
  canonical_json BLOB NOT NULL
);
CREATE TABLE checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  scope_sha256 TEXT NOT NULL,
  canonical_json BLOB NOT NULL
);
```

Enable foreign keys, WAL, full synchronous mode, and trusted schema off.

- [ ] **Step 6: Implement streaming import**

`ImportAsync` must:

1. open the source using `NtfsFileIdentityProvider`;
2. classify magic bytes;
3. stream SHA-256 while copying to a verified `CreateNew` object;
4. verify length and source identity again;
5. commit the source receipt and document row atomically;
6. delete an uncommitted object on failure;
7. return the existing ID on duplicate content.

- [ ] **Step 7: Run focused security tests and all existing filesystem tests**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~CorpusVaultTests
C:\tmp\dotnet10\dotnet.exe test tests\Security\LocalDocumentOrganizer.Security.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\WorkerContract\LocalDocumentOrganizer.WorkerContract.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~CorpusProtected
```

Expected: all tests pass with no path-boundary regression.

- [ ] **Step 8: Commit verified vault production code**

```powershell
git add src\LocalDocumentOrganizer.Infrastructure.Windows\FileSystem tools\CorpusWorkbench\Vault tools\CorpusWorkbench\Persistence tools\CorpusWorkbench\Ingestion
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ empirical corpus 보안 vault와 ingestion 추가"
```

---

### Task 4: Sealed Worker Draft Labels

**Files:**
- Create: `tools/CorpusEval/CorpusWorkerPackageWorkspace.cs`
- Create: `tools/CorpusWorkbench/Labels/InvoiceDraftLabeler.cs`
- Create: `tools/CorpusWorkbench/Labels/DraftLabelService.cs`
- Modify: `tools/CorpusWorkbench/Persistence/CorpusWorkbenchStore.cs`
- Modify: `tools/CorpusWorkbench/Serialization/WorkbenchJsonContext.cs`
- Test locally: `tests/CorpusWorkbench/DraftLabelServiceTests.cs`

**Interfaces:**
- Produces: `CorpusWorkerPackageWorkspace.OpenAsync(...)`.
- Produces: `DraftLabelService.CreateRevisionAsync(string documentId, CancellationToken)`.
- Returns: immutable `LabelRevision` bound to document hash, rule-set hash, and Worker package identity.

Define the pre-persistence draft in `InvoiceDraftLabeler.cs`:

```csharp
public sealed record LabelDraft(
    ImmutableArray<LabeledField> Fields);
```

- [ ] **Step 1: Write label normalization and package-binding tests**

```csharp
[TestMethod]
public async Task CreateRevisionAsync_BindsWorkerRuleAndEvidence()
{
    var result = await _service.CreateRevisionAsync(
        _fixture.DocumentId,
        CancellationToken.None);

    Assert.AreEqual(_fixture.WorkerPackageSha256, result.WorkerPackageSha256);
    Assert.AreEqual(_fixture.RuleCatalogSha256, result.RuleCatalogSha256);
    CollectionAssert.AreEquivalent(
        PilotCatalog.RequiredFieldIds.ToArray(),
        result.Fields.Select(static field => field.FieldId).ToArray());
    Assert.IsTrue(result.Fields.All(static field => field.Evidence.Length > 0));
}
```

Add tests for Korean and US date formats, comma-grouped amounts, currency symbols,
ambiguous dates, relative-only due terms, missing evidence, Worker timeout, and
package identity change.

- [ ] **Step 2: Run focused tests and verify failure**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~DraftLabelServiceTests
```

Expected: compile failure because the service and package façade do not exist.

- [ ] **Step 3: Add a public protected package workspace façade**

The façade must expose:

```csharp
public sealed class CorpusWorkerPackageWorkspace :
    IDisposable,
    IAsyncDisposable
{
    public string StagedExecutablePath { get; }
    public CorpusWorkerPackageIdentity Identity { get; }

    public static Task<CorpusWorkerPackageWorkspace> OpenAsync(
        string packageRoot,
        string workerExecutablePath,
        string expectedPackageSha256,
        string corpusRoot,
        CancellationToken cancellationToken);
}
```

Its implementation creates a private output root below
`%TEMP%\LocalDocumentOrganizer\CorpusWorkbench\package-workspaces`, constructs the
existing internal protected-root set, uses the existing private sealed stage, and
disposes all leases. Do not duplicate package closure logic.

- [ ] **Step 4: Implement deterministic invoice candidate extraction**

`InvoiceDraftLabeler.CreateDraft` consumes `DocumentExtractionResponse.Fragments`.
It must:

- normalize adjacent token groups without concatenating unrelated pages;
- recognize exact Korean and English labels from the official rule catalog;
- parse dates with market-specific explicit formats;
- reject dates with unresolved day/month ambiguity;
- parse amounts using the visible decimal and grouping separators;
- map `₩` to `KRW` and `$` to `USD` only under the selected market;
- retain the source fragment evidence rectangles;
- reject relative-only `Net N` or `N일 이내` due terms.

The signature is:

```csharp
public LabelDraft CreateDraft(
    WorkbenchDocument document,
    DocumentExtractionResponse extraction,
    OfficialRuleCatalogSnapshot rules);
```

- [ ] **Step 5: Implement the draft label service**

The service must resolve the content object from its validated content hash through
the approved vault, create a `DocumentSourceDescriptor`, and construct
`DocumentExtractionClient` with the same `ApprovedRootPathGuard`. Call the safe
path-based overload:

```csharp
await extractionClient.ExtractAsync(
    vault.GetObjectPathForExtraction(document),
    descriptor,
    cancellationToken);
```

It then canonicalizes the draft, hashes it, links the previous revision, inserts
the new immutable revision transactionally, and never changes approval rows.

- [ ] **Step 6: Run label, Worker contract, and package closure tests**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~DraftLabelServiceTests
C:\tmp\dotnet10\dotnet.exe test tests\WorkerContract\LocalDocumentOrganizer.WorkerContract.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\WorkerSecurity\LocalDocumentOrganizer.WorkerSecurity.Tests.csproj -c Release -p:NuGetAudit=false
```

Expected: all pass; package aggregate and Worker executable identity remain bound.

- [ ] **Step 7: Commit draft labeling production code**

```powershell
git add tools\CorpusEval\CorpusWorkerPackageWorkspace.cs tools\CorpusWorkbench\Labels tools\CorpusWorkbench\Persistence tools\CorpusWorkbench\Serialization
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ sealed Worker 기반 인보이스 draft label 추가"
```

---

### Task 5: Append-only Approval Ledger

**Files:**
- Create: `tools/CorpusWorkbench/Approval/ApprovalLedgerService.cs`
- Modify: `tools/CorpusWorkbench/Persistence/CorpusWorkbenchStore.cs`
- Modify: `tools/CorpusWorkbench/Contracts/WorkbenchContracts.cs`
- Test locally: `tests/CorpusWorkbench/ApprovalLedgerServiceTests.cs`

**Interfaces:**
- Produces: `RecordDirectReviewAsync`, `RecordDelegatedLabelAsync`, `RecordBatchApprovalAsync`, `VerifyAsync`.
- Returns: `ApprovalEntry` and `ApprovalVerificationResult`.
- Consumes: current document hash, label revision hash, rule-set hash, Worker package identity, reviewer ID.

Define verification output in `ApprovalLedgerService.cs`:

```csharp
public sealed record ApprovalVerificationResult(
    bool IsValid,
    WorkbenchFailureCode? FailureCode,
    string LedgerHeadSha256,
    ImmutableArray<string> InvalidEntryIds);

public sealed record DirectReviewDecision(
    string DocumentId,
    string LabelRevisionId,
    string ReviewerId,
    DateTimeOffset ApprovedAtUtc);

public sealed record DelegatedLabelDecision(
    string DocumentId,
    string LabelRevisionId,
    string DelegateId,
    DateTimeOffset LabeledAtUtc);

public sealed record BatchApprovalDecision(
    string MarketId,
    string ReviewerId,
    string BatchSummarySha256,
    DateTimeOffset ApprovedAtUtc);
```

The service methods are:

```csharp
public Task<ApprovalEntry> RecordDirectReviewAsync(
    DirectReviewDecision decision,
    CancellationToken cancellationToken);

public Task<ApprovalEntry> RecordDelegatedLabelAsync(
    DelegatedLabelDecision decision,
    CancellationToken cancellationToken);

public Task<ApprovalEntry> RecordBatchApprovalAsync(
    BatchApprovalDecision decision,
    CancellationToken cancellationToken);

public Task<ApprovalVerificationResult> VerifyAsync(
    CancellationToken cancellationToken);
```

- [ ] **Step 1: Write chain-forgery and invalidation tests**

```csharp
[TestMethod]
public async Task BatchApproval_IsInvalidAfterLabelRevisionChanges()
{
    await _ledger.RecordDirectReviewAsync(
        _fixture.DirectDecision,
        CancellationToken.None);
    await _ledger.RecordBatchApprovalAsync(
        _fixture.BatchDecision,
        CancellationToken.None);
    await _fixture.AppendCorrectedLabelRevisionAsync();

    var verification = await _ledger.VerifyAsync(CancellationToken.None);

    Assert.IsFalse(verification.IsValid);
    Assert.AreEqual(
        WorkbenchFailureCode.ApprovalChainInvalid,
        verification.FailureCode);
}
```

Add tests for reordered rows, a forged previous hash, duplicate decision ID,
stale rule catalog, changed Worker package, and delegated labels without batch
approval.

- [ ] **Step 2: Run focused tests and verify failure**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~ApprovalLedgerServiceTests
```

Expected: compile failure because the ledger service does not exist.

- [ ] **Step 3: Implement canonical hash chaining**

Each entry hash must be:

```csharp
entrySha256 = SHA256(
    UTF8("corpus-approval-entry-v1\n")
    || UTF8(previousEntrySha256)
    || canonicalDecisionJson);
```

The first entry uses 64 lower-case zeroes for `previousEntrySha256`. Insert and
head verification happen in one `BEGIN IMMEDIATE` transaction.

- [ ] **Step 4: Enforce approval semantics**

- `direct-review` requires the reviewer to approve all six current fields and
  evidence boxes.
- `delegated-label` records the delegation source and cannot independently create
  owner-approved state.
- `batch-approval` requires 10 valid direct reviews for that market and no
  unresolved review decision.
- A document, label, rule-set, Worker, or pilot-epoch change invalidates the
  computed owner-approved view without deleting history.

- [ ] **Step 5: Run approval and persistence tests**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter "FullyQualifiedName~ApprovalLedgerServiceTests|FullyQualifiedName~CorpusVaultTests"
```

Expected: all pass.

- [ ] **Step 6: Commit approval production code**

```powershell
git add tools\CorpusWorkbench\Approval tools\CorpusWorkbench\Persistence tools\CorpusWorkbench\Contracts
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ empirical corpus 승인 ledger 추가"
```

---

### Task 6: Deterministic Stratified Review Sampling

**Files:**
- Create: `tools/CorpusWorkbench/Sampling/ReviewSampleSelector.cs`
- Modify: `tools/CorpusWorkbench/Contracts/WorkbenchContracts.cs`
- Test locally: `tests/CorpusWorkbench/ReviewSampleSelectorTests.cs`

**Interfaces:**
- Produces: `ReviewSampleSelector.Select(PilotScope, string marketId, IReadOnlyList<ReviewCandidate>)`.
- Returns: `ReviewSample` with exactly 10 document IDs or a typed coverage failure.

Define:

```csharp
public sealed record ReviewCandidate(
    string DocumentId,
    string ContentSha256,
    string SourceFamilyId,
    string InputKind,
    ImmutableArray<string> EdgeCaseTags);

public sealed record ReviewSample(
    ImmutableArray<string> DocumentIds,
    ImmutableDictionary<string, int> InputKindCounts,
    int SourceFamilyCount,
    ImmutableArray<string> CoveredEdgeCaseTags);
```

- [ ] **Step 1: Write repeatability and coverage tests**

```csharp
[TestMethod]
public void Select_IsOrderIndependent_AndCoversInputKindsAndFamilies()
{
    var first = ReviewSampleSelector.Select(
        _scope,
        "ko-KR",
        _candidates);
    var second = ReviewSampleSelector.Select(
        _scope,
        "ko-KR",
        _candidates.Reverse().ToArray());

    CollectionAssert.AreEqual(
        first.DocumentIds.ToArray(),
        second.DocumentIds.ToArray());
    Assert.AreEqual(5, first.InputKindCounts["image-pdf"]);
    Assert.AreEqual(5, first.InputKindCounts["standalone-raster"]);
    Assert.IsTrue(first.SourceFamilyCount >= 3);
}
```

Add tests for fewer than 10 eligible documents, unavailable 5/5 input-kind
coverage, fewer than three families, duplicate content, and changed catalog epoch.

- [ ] **Step 2: Run sampling tests and verify failure**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~ReviewSampleSelectorTests
```

Expected: compile failure because `ReviewSampleSelector` does not exist.

- [ ] **Step 3: Implement deterministic ranking**

Rank within each stratum by:

```csharp
SHA256(
    UTF8("corpus-review-sample-v1\n")
    || UTF8(scope.CatalogEpoch)
    || UTF8("\n")
    || UTF8(marketId)
    || UTF8("\n")
    || Convert.FromHexString(candidate.ContentSha256));
```

Use ordinal byte ordering, not runtime hash codes or random generators.

- [ ] **Step 4: Enforce strata**

When both input kinds have at least five eligible documents, select exactly five
of each. Require at least three source families and include candidates tagged for
date, amount, currency-symbol, and identifier edge cases. Return
`ReviewCoverageInsufficient` with explicit missing strata rather than relaxing the
sample.

- [ ] **Step 5: Run focused tests**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~ReviewSampleSelectorTests
```

Expected: all pass.

- [ ] **Step 6: Commit sampler production code**

```powershell
git add tools\CorpusWorkbench\Sampling tools\CorpusWorkbench\Contracts
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ 결정론적 corpus 직접 검수 표본 추가"
```

---

### Task 7: Token-protected Local Review Screen

**Files:**
- Create: `tools/CorpusWorkbench/Review/DocumentPreviewService.cs`
- Create: `tools/CorpusWorkbench/Review/ReviewHost.cs`
- Create: `tools/CorpusWorkbench/Review/wwwroot/index.html`
- Create: `tools/CorpusWorkbench/Review/wwwroot/review.css`
- Create: `tools/CorpusWorkbench/Review/wwwroot/review.js`
- Modify: `tools/CorpusWorkbench/Serialization/WorkbenchJsonContext.cs`
- Test locally: `tests/CorpusWorkbench/ReviewHostTests.cs`

**Interfaces:**
- Produces: `ReviewHost.RunAsync(ReviewHostOptions, CancellationToken)`.
- API: `GET /api/review/next`, `GET /api/documents/{id}/pages/{index}.png`, `POST /api/documents/{id}/decisions`.
- All API calls require `X-Corpus-Session`; the token is passed to the page in the URL fragment only.

Define:

```csharp
public sealed record ReviewHostOptions(
    string VaultRoot,
    string ReviewerId,
    bool OpenBrowser);

public enum ReviewDecisionKind
{
    ApproveExact,
    CorrectAndApprove,
    RejectDocument,
    Defer,
}

public sealed record ReviewDecisionRequest(
    string LabelRevisionSha256,
    ReviewDecisionKind Decision,
    ImmutableArray<LabeledField> CorrectedFields);
```

- [ ] **Step 1: Write loopback, token, and no-cache tests**

```csharp
[TestMethod]
public async Task Api_RejectsMissingToken_AndNeverExposesVaultPaths()
{
    await using var host = await ReviewHostFixture.StartAsync();

    var unauthorized = await host.Client.GetAsync("/api/review/next");
    Assert.AreEqual(HttpStatusCode.Unauthorized, unauthorized.StatusCode);

    host.Client.DefaultRequestHeaders.Add(
        "X-Corpus-Session",
        host.Token);
    var body = await host.Client.GetStringAsync("/api/review/next");

    StringAssert.DoesNotContain(body, host.VaultRoot);
    StringAssert.DoesNotContain(body, host.OriginalFileName);
}
```

Add tests for a non-loopback bind attempt, invalid Host header, token in query
logging, cross-origin POST, stale label revision, decision replay, preview traversal,
and `Cache-Control: no-store`.

- [ ] **Step 2: Run focused review tests and verify failure**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~ReviewHostTests
```

Expected: compile failure because `ReviewHost` does not exist.

- [ ] **Step 3: Implement preview rendering**

Open the source through the verified vault. Render PDF pages with
`Windows.Data.Pdf.PdfDocument` and raster pages with
`Windows.Graphics.Imaging.BitmapDecoder`. Encode PNG previews to a verified local
preview cache whose key includes content hash, page index, renderer version, and
orientation.

Never pass a source path to the browser.

- [ ] **Step 4: Configure a loopback-only Kestrel host**

Use:

```csharp
builder.WebHost.ConfigureKestrel(
    options => options.Listen(IPAddress.Loopback, 0));
```

Generate 32 random bytes per session. Put the lower-case hex token in
`http://localhost:<port>/#<token>`, not the query string. Keep it only in browser
memory. Require the token header and `Origin` matching the exact loopback origin on
mutating calls.

- [ ] **Step 5: Add strict response headers**

Every response must set:

```text
Cache-Control: no-store
Pragma: no-cache
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'self'; img-src 'self' blob:; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
```

Do not use CDN assets, analytics, web fonts, local storage, session storage, or
service workers.

- [ ] **Step 6: Implement the approved review UI**

The page must show:

- market and `N of 10`;
- page preview and evidence boxes;
- six normalized fields;
- official rule link and version;
- `Approve exact`, `Correct and approve`, `Reject document`, `Defer`;
- explicit “Local only” status.

Decision POST bodies include the expected current label revision hash. A stale hash
returns HTTP 409 and reloads the document instead of overwriting.

- [ ] **Step 7: Run UI security and browser-contract tests**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~ReviewHostTests
```

Expected: tests pass; the fixture host binds only to loopback; no document path
appears in the HTML, API payloads, response headers, or captured server logs. The
actual browser smoke occurs in Task 10 after eligible documents exist.

- [ ] **Step 8: Commit local review production code**

```powershell
git add tools\CorpusWorkbench\Review tools\CorpusWorkbench\Serialization tools\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.csproj
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ 로컬 corpus 검수 화면 추가"
```

---

### Task 8: Pilot Validation, Checkpoints, and Sanitized Reports

**Files:**
- Create: `tools/CorpusWorkbench/Validation/PilotValidator.cs`
- Create: `tools/CorpusWorkbench/Validation/PilotCheckpointStore.cs`
- Create: `tools/CorpusWorkbench/Validation/PilotReportWriter.cs`
- Create: `tools/CorpusWorkbench/Security/CorpusPrivacyScanner.cs`
- Modify: `tools/CorpusWorkbench/Contracts/WorkbenchContracts.cs`
- Modify: `tools/CorpusWorkbench/Serialization/WorkbenchJsonContext.cs`
- Test locally: `tests/CorpusWorkbench/PilotValidatorTests.cs`

**Interfaces:**
- Produces: `PilotValidator.ValidateAsync(PilotValidationRequest, CancellationToken)`.
- Produces: `PilotReportWriter.WriteAsync(PilotValidationResult, string outputPath, CancellationToken)`.
- Returns a sanitized `PilotReportEnvelope`; never returns a production `CorpusManifest`.

Define:

```csharp
public sealed record PilotValidationRequest(
    PilotScope Scope,
    string RuleCatalogSha256,
    string WorkerPackageSha256,
    string LedgerHeadSha256);

public sealed record PilotValidationResult(
    bool PilotComplete,
    WorkbenchFailureCode? PrimaryFailureCode,
    ImmutableArray<WorkbenchFailureCode> BlockingReasons,
    ImmutableArray<PilotMarketSummary> Markets,
    string RuleCatalogSha256,
    string WorkerPackageSha256,
    string LedgerHeadSha256);
```

- [ ] **Step 1: Write fail-closed and privacy tests**

```csharp
[TestMethod]
public async Task ValidateAsync_ReportsCoverageIncomplete_WithoutPrivatePayload()
{
    var result = await _validator.ValidateAsync(
        _fixture.RequestWithCounts(koKr: 40, enUs: 27),
        CancellationToken.None);

    Assert.IsFalse(result.PilotComplete);
    CollectionAssert.Contains(
        result.BlockingReasons.ToArray(),
        WorkbenchFailureCode.CoverageIncomplete);

    var report = await _writer.SerializeAsync(result, CancellationToken.None);
    StringAssert.DoesNotContain(report, _fixture.PrivateSentinel);
    StringAssert.DoesNotContain(report, _fixture.VaultRoot);
}
```

Add tests for insufficient direct reviews, missing batch approval, stale rules,
mixed Worker identities, duplicate source families, invalid ledger, changed
checkpoint inputs, path strings, filenames, credentials, environment values, and
field-value sentinels.

- [ ] **Step 2: Run focused validation tests and verify failure**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~PilotValidatorTests
```

Expected: compile failure because the validator and report writer do not exist.

- [ ] **Step 3: Implement stable failure precedence**

Use this precedence:

1. vault or identity boundary failure;
2. Worker attestation mismatch;
3. approval-chain invalid;
4. stale rule set;
5. duplicate content or source-family leakage;
6. missing required field or evidence;
7. insufficient direct review;
8. missing batch approval;
9. coverage incomplete.

Report all blocking reasons but select the first by this order as
`primaryFailureCode`.

- [ ] **Step 4: Implement authenticated checkpoints**

Checkpoint identity is:

```csharp
SHA256(
    UTF8("corpus-workbench-checkpoint-v1\n")
    || canonicalScope
    || ruleCatalogSha256
    || workerPackageSha256
    || ledgerHeadSha256
    || canonicalDocumentSet);
```

Resume only when all components match. Store checkpoints inside the verified vault,
not the tracked repository or report output.

- [ ] **Step 5: Implement sanitized report serialization**

The report may include only:

- schema and tool versions;
- catalog epoch and rule-set hashes;
- Worker package identity;
- per-market counts;
- review mode counts;
- aggregate missing-field/error counts;
- report and ledger-head hashes;
- stable blocking codes.

It must not include stable document IDs because those can correlate with the local
vault.

- [ ] **Step 6: Run focused tests and a sentinel scan**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~PilotValidatorTests
rg -n -uu "PRIVATE-LABEL-SENTINEL|C:\\\\Users\\\\|invoice_[0-9]+\\.pdf" artifacts tools\CorpusWorkbench
```

Expected: tests pass; `rg` has no hits in publishable report fixtures or tracked
workbench files.

- [ ] **Step 7: Commit validation production code**

```powershell
git add tools\CorpusWorkbench\Validation tools\CorpusWorkbench\Security tools\CorpusWorkbench\Contracts tools\CorpusWorkbench\Serialization
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ corpus 파일럿 검증과 비식별 report 추가"
```

---

### Task 9: Strict CLI Composition and End-to-End Tooling

**Files:**
- Create: `tools/CorpusWorkbench/Commanding/WorkbenchCommandLine.cs`
- Modify: `tools/CorpusWorkbench/Program.cs`
- Test locally: `tests/CorpusWorkbench/WorkbenchCliTests.cs`

**Interfaces:**
- Commands: `init`, `import`, `label`, `review`, `approve-batch`, `validate`, `schema`.
- Stable stderr prefix: `corpus-workbench:<kebab-case-code>`.
- Exit codes: success `0`, invalid arguments `2`, invalid state `3`, security boundary `4`, Worker failure `5`, incomplete coverage `6`, approval failure `7`, privacy failure `8`.

- [ ] **Step 1: Write strict command and end-to-end tests**

```csharp
[TestMethod]
public async Task ValidateCommand_ReturnsCoverageIncompleteWithoutEmittingManifest()
{
    var result = await CliFixture.RunAsync(
        "validate",
        "--vault", _fixture.VaultRoot,
        "--output", _fixture.ReportPath);

    Assert.AreEqual(6, result.ExitCode);
    StringAssert.Contains(
        result.StandardError,
        "corpus-workbench:coverage-incomplete");
    Assert.IsTrue(File.Exists(_fixture.ReportPath));
    Assert.IsFalse(File.Exists(_fixture.ProductionManifestPath));
}
```

Add tests for duplicate options, unknown options, missing values, relative vault
paths, invalid hashes, review without sample coverage, batch approval without direct
review, and schema output.

- [ ] **Step 2: Run CLI tests and verify failure**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false --filter FullyQualifiedName~WorkbenchCliTests
```

Expected: compile failure because command parsing is not implemented.

- [ ] **Step 3: Implement exact command syntax**

Use:

```text
corpus-workbench init --vault <absolute-dir> --catalog <absolute-json> --epoch <token>
corpus-workbench import --vault <absolute-dir> --source <absolute-file> --receipt <absolute-json>
corpus-workbench label --vault <absolute-dir> --worker <absolute-exe> --worker-package-root <absolute-dir> --worker-package-sha256 <64hex>
corpus-workbench review --vault <absolute-dir>
corpus-workbench approve-batch --vault <absolute-dir> --market <ko-KR|en-US> --reviewer <token>
corpus-workbench validate --vault <absolute-dir> --output <absolute-json>
corpus-workbench schema --output <absolute-json>
```

Reject duplicate options and do not infer defaults for vault, catalog, Worker, or
package identity.

- [ ] **Step 4: Compose services in Program**

`Program.Main` parses once, opens the vault once, maps typed exceptions to stable
exit codes, writes one safe stderr line, and disposes the review host, Worker
workspace, SQLite store, and filesystem leases in reverse order.

- [ ] **Step 5: Run all workbench tests and Release build**

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe build LocalDocumentOrganizer.sln -c Release -p:NuGetAudit=false
```

Expected: all workbench tests pass; solution build has zero warnings and zero
errors.

- [ ] **Step 6: Run a synthetic local end-to-end smoke**

```powershell
C:\tmp\dotnet10\dotnet.exe run --project tools\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.csproj -c Release --no-build -- init --vault C:\tmp\corpus-workbench-e2e --catalog tools\CorpusWorkbench\catalog\invoice-explicit-due-date-v1.ko-KR.json --epoch pilot-2026-07
C:\tmp\dotnet10\dotnet.exe run --project tools\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.csproj -c Release --no-build -- validate --vault C:\tmp\corpus-workbench-e2e --output artifacts\corpus-workbench\e2e-report.json
```

Expected: `init` exits 0; `validate` exits 6 with
`corpus-workbench:coverage-incomplete`; the sanitized report exists; no production
manifest exists.

- [ ] **Step 7: Commit CLI production code**

```powershell
git add tools\CorpusWorkbench\Commanding tools\CorpusWorkbench\Program.cs
git diff --cached --name-only | Select-String '^tests/' | ForEach-Object { throw "tests must not be staged" }
git commit -m "✨ corpus workbench CLI 통합"
```

---

### Task 10: Official Public-document Pilot and Final Verification

**Files:**
- Modify when verified: `tools/CorpusWorkbench/catalog/invoice-explicit-due-date-v1.ko-KR.json`
- Modify when verified: `tools/CorpusWorkbench/catalog/invoice-explicit-due-date-v1.en-US.json`
- Local only: external vault, provenance receipts, labels, approvals, checkpoints, pilot reports

**Interfaces:**
- Consumes: completed CLI and the exact sealed Worker package identity.
- Produces: local pilot report and a PR-ready sanitized summary.
- Does not produce: production `CorpusManifest` or a release-validation claim.

- [ ] **Step 1: Verify official rule pages before acquisition**

Open and record the current revision/verification date for:

- Korean Value-Added Tax Act Article 32 on `law.go.kr`.
- Korean Value-Added Tax Act Enforcement Decree official field list on
  `law.go.kr`.
- FAR 32.905 and FAR 52.232-25 on `acquisition.gov`.
- ISO 4217 currency code page on `iso.org`.
- RFC 3339 on `rfc-editor.org`.

If a source moved, update the catalog to the official replacement URI and rerun
catalog tests before acquiring documents.

- [ ] **Step 2: Build explicit public-source receipts**

For every candidate document, record its literal official HTTPS URI, the publisher
name shown by that official site, the actual UTC retrieval time, the documented
reuse status, `ko-KR` or `en-US`, contract
`invoice-explicit-due-date-v1`, a publisher-layout-version source-family ID, and the
SHA-256 computed from the retrieved bytes. Reject any candidate whose publisher,
reuse status, official URI, source family, or byte hash cannot be documented.

- [ ] **Step 3: Attempt up to 40 eligible documents per market**

Import only explicit PDF, PNG, JPEG, TIFF, or BMP files. Keep an acquisition log
inside the local vault with accepted/rejected counts and typed rejection codes.
Do not count blank templates, generated examples, duplicate layouts with changed
metadata, or documents without an explicit due date as held-out empirical members.

- [ ] **Step 4: Produce draft labels with one sealed Worker identity**

Run the `label` command once per stable document set. If the package identity,
catalog hash, or document set changes, start a new checkpoint lineage and invalidate
prior approvals.

- [ ] **Step 5: Complete the user’s direct review**

Run `review` for `ko-KR` and `en-US`. The user must finish exactly 10 deterministic
reviews per market. Corrections create new label revisions; rejected documents leave
the eligible set and require deterministic resampling.

- [ ] **Step 6: Complete delegated labels and batch approval**

After every remaining eligible document passes the six-field/evidence checks, show
the sanitized market summary. Record `batch-approval` only after the user explicitly
approves that summary.

- [ ] **Step 7: Validate and preserve the correct blocked/complete state**

```powershell
C:\tmp\dotnet10\dotnet.exe run --project tools\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.csproj -c Release --no-build -- validate --vault C:\Users\seung\Documents\ProofToClosureCorpus\pilot-2026-07 --output artifacts\corpus-workbench\pilot-report.json
```

Expected:

- exit 0 only if both markets have 40 eligible documents, 10 direct reviews, valid
  delegated labels, and batch approvals;
- exit 6 with `CoverageIncomplete` if lawful public supply is below 40 in either
  market;
- production `CorpusEval` remains blocked because the other 34 cells are absent.

- [ ] **Step 8: Run the full local regression suite**

Run sequentially:

```powershell
C:\tmp\dotnet10\dotnet.exe test tests\Architecture\LocalDocumentOrganizer.Architecture.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\Core\LocalDocumentOrganizer.Core.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\Security\LocalDocumentOrganizer.Security.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\Storage\LocalDocumentOrganizer.Storage.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\Transactions\LocalDocumentOrganizer.Transactions.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\WorkerContract\LocalDocumentOrganizer.WorkerContract.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\WorkerSecurity\LocalDocumentOrganizer.WorkerSecurity.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe test tests\CorpusWorkbench\LocalDocumentOrganizer.CorpusWorkbench.Tests.csproj -c Release -p:NuGetAudit=false
C:\tmp\dotnet10\dotnet.exe build LocalDocumentOrganizer.sln -c Release -p:NuGetAudit=false
```

Expected: no failures; only the previously accepted optional NTFS cross-volume
environment skip; Release build zero warnings and zero errors.

- [ ] **Step 9: Verify repository privacy and tracked-file policy**

```powershell
git status --short
git ls-files tests artifacts
git diff --check main...HEAD
git diff --cached --name-only | Select-String '^tests/|^artifacts/' | ForEach-Object { throw "private or test artifacts must not be staged" }
```

Expected: no tracked test or artifact files, no uncommitted production changes, and
no whitespace errors.

- [ ] **Step 10: Commit only verified catalog metadata changes**

If official source metadata changed after verification:

```powershell
git add tools\CorpusWorkbench\catalog
git diff --cached --name-only | Select-String '^tests/|^artifacts/' | ForEach-Object { throw "private or test artifacts must not be staged" }
git commit -m "📝 empirical 파일럿 공식 출처 검증"
```

If the tracked catalog did not change, do not create an empty commit. Record local
pilot commands and sanitized results in the merge request body.

---

## Plan Self-review Checklist

- [x] Every approved design requirement maps to at least one task.
- [x] The workbench partial schema never emits or relaxes a production
  `CorpusManifest`.
- [x] Direct review, delegated labeling, and batch approval are distinct persisted
  states.
- [x] Worker package, document, rule-set, and approval identities invalidate safely.
- [x] The review host is loopback-only, tokenized, no-store, and external-asset free.
- [x] Official source metadata is tracked; source documents and labels remain local.
- [x] Every code task has a red test, minimal implementation, green test, and
  production-only commit.
- [x] Test and artifact paths are absent from every staging command.
- [x] No step contains an unresolved placeholder or ambiguous “implement later”
  instruction.
- [x] Final verification covers all existing suites, the new local suite, Release
  build, privacy, and Git policy.
