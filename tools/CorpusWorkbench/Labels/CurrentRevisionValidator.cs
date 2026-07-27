using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.CorpusEval;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;

namespace LocalDocumentOrganizer.CorpusWorkbench.Labels;

internal static class CurrentRevisionValidator
{
    private const double MaximumCoordinate = 1_000_000d;

    internal static void Validate(
        WorkbenchDocument document,
        LabelRevision revision,
        OfficialRuleCatalogSnapshot rules,
        CorpusWorkerPackageIdentity workerIdentity,
        int? pageCount)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(revision);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(workerIdentity);
        if (!string.Equals(
                document.DocumentId,
                "document-" + document.ContentSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                revision.RevisionId,
                "revision-" + revision.RevisionSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                revision.DocumentId,
                document.DocumentId,
                StringComparison.Ordinal)
            || !string.Equals(
                revision.DocumentSha256,
                document.ContentSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                revision.MarketId,
                document.MarketId,
                StringComparison.Ordinal)
            || !string.Equals(
                revision.ContractId,
                document.ContractId,
                StringComparison.Ordinal)
            || !string.Equals(
                revision.ContractId,
                PilotCatalog.ContractId,
                StringComparison.Ordinal)
            || !string.Equals(
                rules.Document.MarketId,
                document.MarketId,
                StringComparison.Ordinal)
            || !string.Equals(
                rules.Document.ContractId,
                document.ContractId,
                StringComparison.Ordinal)
            || !FixedHashEquals(
                revision.RuleCatalogSha256,
                rules.CatalogSha256)
            || !IdentityEquals(revision, workerIdentity)
            || !CorpusWorkerPackageManifest
                .IsCanonicalExecutionIdentity(workerIdentity)
            || !DraftLabelService.HasValidCanonicalHash(revision))
        {
            throw InvalidState();
        }

        ValidateFields(
            revision.Fields,
            rules.RulesByFieldId.ToDictionary(
                static pair => pair.Key,
                static pair => pair.Value.RuleId,
                StringComparer.Ordinal),
            pageCount);
    }

    internal static void ValidateFields(
        ImmutableArray<LabeledField> fields,
        IReadOnlyDictionary<string, string>? ruleIds,
        int? pageCount)
    {
        if (pageCount is <= 0 or > 256
            || fields.IsDefault
            || fields.Length
                != PilotCatalog.RequiredFieldIds.Length
            || !fields.Select(static field => field.FieldId)
                .SequenceEqual(
                    PilotCatalog.RequiredFieldIds,
                    StringComparer.Ordinal))
        {
            throw InvalidState();
        }

        foreach (var field in fields)
        {
            var absent = string.Equals(
                field.NormalizedValue,
                InvoiceDraftLabeler.AbsentValue,
                StringComparison.Ordinal);
            var uncertain = string.Equals(
                field.NormalizedValue,
                InvoiceDraftLabeler.UncertainValue,
                StringComparison.Ordinal);
            var sentinel = absent || uncertain;
            if (field.NormalizedValue is null
                || field.NormalizedValue.Length is 0 or > 1024
                || !field.NormalizedValue.IsNormalized(
                    NormalizationForm.FormC)
                || field.NormalizedValue
                    != field.NormalizedValue.Trim()
                || field.NormalizedValue.Any(
                    static character =>
                        char.IsControl(character)
                        || char.IsSurrogate(character))
                || ruleIds is not null
                && (!ruleIds.TryGetValue(
                        field.FieldId,
                        out var expectedRuleId)
                    || !string.Equals(
                        field.RuleId,
                        expectedRuleId,
                        StringComparison.Ordinal))
                || field.Evidence.IsDefault
                || sentinel && !field.Evidence.IsEmpty
                || !sentinel && field.Evidence.IsEmpty
                || !IsCanonicalEvidence(field.Evidence)
                || field.Evidence.Any(evidence =>
                    evidence.SourceIndex < 0
                    || pageCount is not null
                    && evidence.SourceIndex >= pageCount.Value
                    || !IsBounded(evidence)))
            {
                throw InvalidState();
            }
        }
    }

    private static bool IsCanonicalEvidence(
        ImmutableArray<EvidenceBox> evidence) =>
        evidence.AsSpan().SequenceEqual(
            evidence
                .OrderBy(static item => item.SourceIndex)
                .ThenBy(static item => item.Y)
                .ThenBy(static item => item.X)
                .ThenBy(static item => item.Width)
                .ThenBy(static item => item.Height)
                .ToArray()
                .AsSpan());

    private static bool IsBounded(EvidenceBox evidence) =>
        double.IsFinite(evidence.X)
        && double.IsFinite(evidence.Y)
        && double.IsFinite(evidence.Width)
        && double.IsFinite(evidence.Height)
        && evidence.X >= 0
        && evidence.Y >= 0
        && evidence.Width > 0
        && evidence.Height > 0
        && evidence.X <= MaximumCoordinate
        && evidence.Y <= MaximumCoordinate
        && evidence.Width <= MaximumCoordinate
        && evidence.Height <= MaximumCoordinate
        && evidence.X + evidence.Width <= MaximumCoordinate
        && evidence.Y + evidence.Height <= MaximumCoordinate;

    private static bool IdentityEquals(
        LabelRevision revision,
        CorpusWorkerPackageIdentity identity) =>
        string.Equals(
            revision.WorkerPackageManifestId,
            identity.ManifestId,
            StringComparison.Ordinal)
        && string.Equals(
            revision.WorkerPackageManifestVersion,
            identity.ManifestVersion,
            StringComparison.Ordinal)
        && FixedHashEquals(
            revision.WorkerPackageSha256,
            identity.Sha256)
        && string.Equals(
            revision.WorkerExecutableRelativePath,
            identity.ExecutableRelativePath,
            StringComparison.Ordinal)
        && FixedHashEquals(
            revision.WorkerExecutableSha256,
            identity.ExecutableSha256);

    private static bool FixedHashEquals(
        string left,
        string right)
    {
        if (!IsLowerSha256(left) || !IsLowerSha256(right))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));
    }

    private static bool IsLowerSha256(string? value) =>
        value is not null
        && value.Length == 64
        && value.All(static character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static WorkbenchException InvalidState() =>
        new(WorkbenchFailureCode.InvalidState);
}
