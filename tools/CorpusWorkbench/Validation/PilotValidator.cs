using System.Collections.Immutable;
using System.Security.Cryptography;
using LocalDocumentOrganizer.CorpusWorkbench.Approval;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Ingestion;
using LocalDocumentOrganizer.CorpusWorkbench.Labels;
using LocalDocumentOrganizer.CorpusWorkbench.Persistence;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

namespace LocalDocumentOrganizer.CorpusWorkbench.Validation;

public sealed class PilotValidator
{
    private static readonly ImmutableArray<WorkbenchFailureCode>
        FailurePrecedence =
        [
            WorkbenchFailureCode.VaultBoundaryViolation,
            WorkbenchFailureCode.ContentHashMismatch,
            WorkbenchFailureCode.SourceUnverified,
            WorkbenchFailureCode.ReuseStatusUnknown,
            WorkbenchFailureCode.WorkerAttestationMismatch,
            WorkbenchFailureCode.ApprovalChainInvalid,
            WorkbenchFailureCode.StaleRuleSet,
            WorkbenchFailureCode.DuplicateContent,
            WorkbenchFailureCode.SourceFamilyLeakage,
            WorkbenchFailureCode.MissingRequiredField,
            WorkbenchFailureCode.MissingEvidence,
            WorkbenchFailureCode.InsufficientDirectReview,
            WorkbenchFailureCode.BatchApprovalMissing,
            WorkbenchFailureCode.CoverageIncomplete,
        ];

    private readonly Func<
        CancellationToken,
        ValueTask<PilotValidationSnapshot>> _load;

    public PilotValidator(
        CorpusVault vault,
        ApprovalLedgerService approvalLedger)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(approvalLedger);
        _load = cancellationToken => LoadAsync(
            vault,
            approvalLedger,
            cancellationToken);
    }

    internal PilotValidator(
        Func<
            CancellationToken,
            ValueTask<PilotValidationSnapshot>> load) =>
        _load = load ?? throw new ArgumentNullException(nameof(load));

    public async Task<PilotValidationResult> ValidateAsync(
        PilotValidationRequest request,
        CancellationToken cancellationToken)
    {
        ValidateRequest(request);
        cancellationToken.ThrowIfCancellationRequested();

        PilotValidationSnapshot snapshot;
        try
        {
            snapshot = await _load(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException exception)
        {
            return FailureResult(
                request,
                NormalizeBoundaryFailure(exception.FailureCode));
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or IOException
                or UnauthorizedAccessException
                or System.Text.Json.JsonException
                or CryptographicException)
        {
            return FailureResult(
                request,
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (snapshot.Documents.IsDefault)
        {
            return FailureResult(
                request,
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        var reasons = new HashSet<WorkbenchFailureCode>();
        if (!snapshot.VaultBoundaryValid)
        {
            reasons.Add(WorkbenchFailureCode.VaultBoundaryViolation);
        }

        if (!snapshot.LedgerValid
            || !FixedHashEquals(
                snapshot.LedgerHeadSha256,
                request.LedgerHeadSha256))
        {
            reasons.Add(WorkbenchFailureCode.ApprovalChainInvalid);
        }

        FindDocumentWideFailures(
            snapshot.Documents,
            request,
            reasons);

        var summaries = ImmutableArray.CreateBuilder<
            PilotMarketSummary>(request.Scope.MarketIds.Length);
        foreach (var marketId in request.Scope.MarketIds
                     .Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var documents = snapshot.Documents
                .Where(document => string.Equals(
                    document.MarketId,
                    marketId,
                    StringComparison.Ordinal))
                .OrderBy(
                    static document => document.DocumentId,
                    StringComparer.Ordinal)
                .ToArray();
            summaries.Add(
                SummarizeMarket(
                    marketId,
                    documents,
                    request.Scope,
                    reasons));
        }

        var orderedReasons = OrderFailures(reasons);
        return new PilotValidationResult(
            orderedReasons.IsEmpty,
            orderedReasons.IsEmpty ? null : orderedReasons[0],
            orderedReasons,
            summaries.MoveToImmutable(),
            request.RuleCatalogSha256,
            request.WorkerPackageSha256,
            request.LedgerHeadSha256)
        {
            Scope = CanonicalScope(request.Scope),
        };
    }

    private static void FindDocumentWideFailures(
        ImmutableArray<PilotValidationDocument> documents,
        PilotValidationRequest request,
        HashSet<WorkbenchFailureCode> reasons)
    {
        var contentHashes = new HashSet<string>(
            StringComparer.Ordinal);
        var sourceFamilies = new HashSet<string>(
            StringComparer.Ordinal);
        foreach (var document in documents)
        {
            if (!request.Scope.MarketIds.Contains(
                    document.MarketId,
                    StringComparer.Ordinal))
            {
                reasons.Add(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }

            if (!string.Equals(
                    document.ContractId,
                    request.Scope.ContractId,
                    StringComparison.Ordinal))
            {
                reasons.Add(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }

            if (document.InputKind
                    is not CorpusIngestionService.ImagePdfInputKind
                    and not CorpusIngestionService
                        .StandaloneRasterInputKind)
            {
                reasons.Add(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }

            if (!IsLowerSha256(document.ContentSha256)
                || !string.Equals(
                    document.DocumentId,
                    "document-" + document.ContentSha256,
                    StringComparison.Ordinal))
            {
                reasons.Add(
                    WorkbenchFailureCode.ContentHashMismatch);
            }

            if (!contentHashes.Add(document.ContentSha256))
            {
                reasons.Add(WorkbenchFailureCode.DuplicateContent);
            }

            if (string.IsNullOrWhiteSpace(document.SourceFamilyId)
                || !sourceFamilies.Add(document.SourceFamilyId))
            {
                reasons.Add(
                    WorkbenchFailureCode.SourceFamilyLeakage);
            }

            if (!FixedHashEquals(
                    document.RuleCatalogSha256,
                    request.RuleCatalogSha256))
            {
                reasons.Add(WorkbenchFailureCode.StaleRuleSet);
            }

            if (!FixedHashEquals(
                    document.WorkerPackageSha256,
                    request.WorkerPackageSha256))
            {
                reasons.Add(
                    WorkbenchFailureCode.WorkerAttestationMismatch);
            }
        }
    }

    private static PilotMarketSummary SummarizeMarket(
        string marketId,
        IReadOnlyList<PilotValidationDocument> documents,
        PilotScope scope,
        HashSet<WorkbenchFailureCode> reasons)
    {
        var missingFieldCount = 0;
        var missingEvidenceCount = 0;
        foreach (var document in documents)
        {
            CountFieldFailures(
                document.Fields,
                ref missingFieldCount,
                ref missingEvidenceCount);
        }

        if (missingFieldCount != 0)
        {
            reasons.Add(WorkbenchFailureCode.MissingRequiredField);
        }

        if (missingEvidenceCount != 0)
        {
            reasons.Add(WorkbenchFailureCode.MissingEvidence);
        }

        var directReviewCount = documents.Count(document =>
            document.ApprovalMode == ApprovalMode.DirectReview);
        var batchApprovalCount = documents.Count(document =>
            document.ApprovalMode == ApprovalMode.BatchApproval);
        if (directReviewCount < scope.DirectReviewTargetPerMarket)
        {
            reasons.Add(
                WorkbenchFailureCode.InsufficientDirectReview);
        }

        var requiredBatchCount = Math.Max(
            0,
            documents.Count - directReviewCount);
        var batchApproved = requiredBatchCount != 0
            && batchApprovalCount == requiredBatchCount;
        if (!batchApproved)
        {
            reasons.Add(WorkbenchFailureCode.BatchApprovalMissing);
        }

        if (documents.Count < scope.HeldOutTargetPerMarket)
        {
            reasons.Add(WorkbenchFailureCode.CoverageIncomplete);
        }

        var aggregateErrors =
            ImmutableDictionary<string, int>.Empty;
        if (missingFieldCount != 0)
        {
            aggregateErrors = aggregateErrors.Add(
                nameof(WorkbenchFailureCode.MissingRequiredField),
                missingFieldCount);
        }

        if (missingEvidenceCount != 0)
        {
            aggregateErrors = aggregateErrors.Add(
                nameof(WorkbenchFailureCode.MissingEvidence),
                missingEvidenceCount);
        }

        return new PilotMarketSummary(
            marketId,
            documents.Count,
            documents.Count(document => string.Equals(
                document.InputKind,
                CorpusIngestionService.ImagePdfInputKind,
                StringComparison.Ordinal)),
            documents.Count(document => string.Equals(
                document.InputKind,
                CorpusIngestionService.StandaloneRasterInputKind,
                StringComparison.Ordinal)),
            documents.Select(
                    static document => document.SourceFamilyId)
                .Distinct(StringComparer.Ordinal)
                .Count(),
            directReviewCount,
            batchApprovalCount,
            batchApproved,
            aggregateErrors);
    }

    private static void CountFieldFailures(
        ImmutableArray<LabeledField> fields,
        ref int missingFieldCount,
        ref int missingEvidenceCount)
    {
        if (fields.IsDefault)
        {
            missingFieldCount = checked(
                missingFieldCount
                + PilotCatalog.RequiredFieldIds.Length);
            return;
        }

        foreach (var fieldId in PilotCatalog.RequiredFieldIds)
        {
            LabeledField? candidate = null;
            var candidateCount = 0;
            foreach (var field in fields)
            {
                if (field is null
                    || !string.Equals(
                        field.FieldId,
                        fieldId,
                        StringComparison.Ordinal))
                {
                    continue;
                }

                candidate = field;
                candidateCount = checked(candidateCount + 1);
            }

            if (candidateCount != 1
                || candidate is null
                || string.IsNullOrWhiteSpace(
                    candidate.NormalizedValue)
                || candidate.NormalizedValue
                    is InvoiceDraftLabeler.AbsentValue
                    or InvoiceDraftLabeler.UncertainValue)
            {
                missingFieldCount = checked(missingFieldCount + 1);
                continue;
            }

            if (candidate.Evidence.IsDefaultOrEmpty)
            {
                missingEvidenceCount = checked(
                    missingEvidenceCount + 1);
            }
        }
    }

    private static async ValueTask<PilotValidationSnapshot> LoadAsync(
        CorpusVault vault,
        ApprovalLedgerService approvalLedger,
        CancellationToken cancellationToken)
    {
        var states = await vault.Store.ExecuteApprovalReadAsync(
                (connection, transaction) =>
                    vault.Store.ReadAllApprovalLabelStatesAsync(
                        connection,
                        transaction),
                cancellationToken)
            .ConfigureAwait(false);
        var verification = await approvalLedger.VerifyAsync(
                cancellationToken)
            .ConfigureAwait(false);
        var approvals = verification.IsValid
            ? await approvalLedger.GetOwnerApprovalViewAsync(
                    cancellationToken)
                .ConfigureAwait(false)
            : new OwnerApprovalView(
                verification.LedgerHeadSha256,
                []);
        var approvalByDocument = approvals.Documents.ToDictionary(
            static item => item.DocumentId,
            static item => ParseApprovalMode(item.ApprovalMode),
            StringComparer.Ordinal);
        var documents = states.Select(state =>
        {
            approvalByDocument.TryGetValue(
                state.Document.DocumentId,
                out var mode);
            return new PilotValidationDocument(
                state.Document.DocumentId,
                state.Document.ContentSha256,
                state.Document.SourceFamilyId,
                state.Document.MarketId,
                state.Document.ContractId,
                state.Document.InputKind,
                state.PreviousRevision?.RuleCatalogSha256,
                state.PreviousRevision?.WorkerPackageSha256,
                state.PreviousRevision?.Fields ?? [],
                mode);
        }).ToImmutableArray();
        return new PilotValidationSnapshot(
            documents,
            VaultBoundaryValid: true,
            verification.IsValid,
            verification.LedgerHeadSha256);
    }

    private static ApprovalMode? ParseApprovalMode(string value) =>
        Enum.TryParse<ApprovalMode>(
            value,
            ignoreCase: false,
            out var mode)
            ? mode
            : null;

    private static PilotValidationResult FailureResult(
        PilotValidationRequest request,
        WorkbenchFailureCode failureCode) =>
        new(
            PilotComplete: false,
            failureCode,
            [failureCode],
            [
                .. request.Scope.MarketIds
                    .Order(StringComparer.Ordinal)
                    .Select(marketId => new PilotMarketSummary(
                        marketId,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        BatchApproved: false,
                        ImmutableDictionary<string, int>.Empty)),
            ],
            request.RuleCatalogSha256,
            request.WorkerPackageSha256,
            request.LedgerHeadSha256)
        {
            Scope = CanonicalScope(request.Scope),
        };

    private static WorkbenchFailureCode NormalizeBoundaryFailure(
        WorkbenchFailureCode failureCode) =>
        FailurePrecedence.Contains(failureCode)
            ? failureCode
            : WorkbenchFailureCode.VaultBoundaryViolation;

    private static void ValidateRequest(PilotValidationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Scope);
        var scope = request.Scope;
        if (!string.Equals(
                scope.SchemaVersion,
                PilotCatalog.SchemaVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                scope.ContractId,
                PilotCatalog.ContractId,
                StringComparison.Ordinal)
            || !IsSafeIdentifier(scope.CatalogEpoch)
            || scope.HeldOutTargetPerMarket
                != PilotCatalog.HeldOutTargetPerMarket
            || scope.DirectReviewTargetPerMarket
                != PilotCatalog.DirectReviewTargetPerMarket
            || scope.MarketIds.IsDefaultOrEmpty
            || scope.MarketIds.Distinct(StringComparer.Ordinal).Count()
                != scope.MarketIds.Length
            || scope.MarketIds.Any(marketId =>
                !PilotCatalog.MarketIds.Contains(
                    marketId,
                    StringComparer.Ordinal))
            || !IsLowerSha256(request.RuleCatalogSha256)
            || !IsLowerSha256(request.WorkerPackageSha256)
            || !IsLowerSha256(request.LedgerHeadSha256))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }
    }

    private static PilotScope CanonicalScope(PilotScope scope) =>
        scope with
        {
            MarketIds =
            [
                .. scope.MarketIds.Order(StringComparer.Ordinal),
            ],
        };

    private static bool IsSafeIdentifier(string? value) =>
        value is { Length: > 0 and <= 64 }
        && value.All(static character =>
            char.IsAsciiLetterOrDigit(character)
            || character is '-' or '_' or '.');

    private static bool FixedHashEquals(
        string? left,
        string? right) =>
        IsLowerSha256(left)
        && IsLowerSha256(right)
        && CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left!),
            Convert.FromHexString(right!));

    internal static bool IsLowerSha256(string? value) =>
        value is { Length: 64 }
        && value.All(static character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    internal static void ValidateCheckpointRequest(
        PilotValidationRequest request) =>
        ValidateRequest(request);

    internal static ImmutableArray<WorkbenchFailureCode>
        OrderFailures(IEnumerable<WorkbenchFailureCode> reasons)
    {
        ArgumentNullException.ThrowIfNull(reasons);
        var unique = reasons.ToHashSet();
        return FailurePrecedence
            .Where(unique.Contains)
            .ToImmutableArray();
    }
}

internal sealed record PilotValidationDocument(
    string DocumentId,
    string ContentSha256,
    string SourceFamilyId,
    string MarketId,
    string ContractId,
    string InputKind,
    string? RuleCatalogSha256,
    string? WorkerPackageSha256,
    ImmutableArray<LabeledField> Fields,
    ApprovalMode? ApprovalMode);

internal sealed record PilotValidationSnapshot(
    ImmutableArray<PilotValidationDocument> Documents,
    bool VaultBoundaryValid,
    bool LedgerValid,
    string LedgerHeadSha256);
