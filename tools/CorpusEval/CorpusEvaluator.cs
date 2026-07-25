using System.Text;

namespace LocalDocumentOrganizer.CorpusEval;

public static class CorpusEvaluator
{
    public static CorpusReport Evaluate(CorpusManifest manifest)
    {
        CorpusManifestValidator.Validate(manifest);
        return CreateReport(
            manifest,
            static document => EvaluateDocument(document),
            runIdentityId: null);
    }

    internal static CorpusReport CreateReport(
        CorpusManifest manifest,
        Func<CorpusHeldOutDocument, CorpusDocumentScore> scoreProvider,
        string? runIdentityId)
    {
        var cells = manifest.Cells
            .OrderBy(static cell => cell.MarketId, StringComparer.Ordinal)
            .ThenBy(static cell => cell.ContractId, StringComparer.Ordinal)
            .Select(
                cell => EvaluateCell(
                    cell.MarketId,
                    cell.ContractId,
                    cell.HeldOutDocuments
                        .OrderBy(static document => document.InputKind)
                        .ThenBy(
                            static document =>
                                document.StableDocumentId,
                            StringComparer.Ordinal)
                        .Select(scoreProvider)
                        .ToArray()))
            .ToArray();
        var perturbationsPassed = manifest.CodecPerturbations.All(
            static perturbation =>
                perturbation.RequiredFieldsInvariant
                && perturbation.EvidenceInvariant
                && perturbation.SafeRejection);
        var aggregate = new CorpusAggregateReport(
            cells.Length,
            cells.Count(static cell => cell.Passed),
            cells.Count(static cell => !cell.Passed),
            cells.Sum(static cell => cell.DocumentCount),
            cells.Sum(static cell => cell.RequiredFieldExactSuccesses),
            cells.Sum(static cell => cell.CriticalValueErrors),
            cells.Sum(static cell => cell.CriticalEvidenceErrors),
            cells.Sum(static cell => cell.CriticalCoordinateErrors),
            perturbationsPassed,
            perturbationsPassed && cells.All(static cell => cell.Passed));
        return new CorpusReport("1", runIdentityId, cells, aggregate);
    }

    public static CorpusCellReport EvaluateCell(
        string marketId,
        string contractId,
        IReadOnlyList<CorpusDocumentScore> scores)
    {
        ArgumentNullException.ThrowIfNull(scores);
        var ordered = scores
            .OrderBy(static score => score.InputKind)
            .ThenBy(
                static score => score.StableDocumentId,
                StringComparer.Ordinal)
            .ToArray();
        var documentCount = ordered.Length;
        var exact = ordered.Count(
            static score => score.RequiredFieldsExact);
        var valueErrors = ordered.Sum(
            static score => score.CriticalValueErrors);
        var evidenceErrors = ordered.Sum(
            static score => score.CriticalEvidenceErrors);
        var coordinateErrors = ordered.Sum(
            static score => score.CriticalCoordinateErrors);
        var bound = documentCount == 0
            ? 0
            : WilsonInterval.OneSided95LowerBound(exact, documentCount);
        var passed = CorpusCellGate.Passes(
            exact,
            documentCount,
            valueErrors,
            evidenceErrors,
            coordinateErrors);
        return new CorpusCellReport(
            marketId,
            contractId,
            documentCount,
            ordered.Count(
                static score =>
                    score.InputKind == CorpusInputKind.ImagePdf),
            ordered.Count(
                static score =>
                    score.InputKind == CorpusInputKind.StandaloneRaster),
            exact,
            documentCount == 0 ? 0 : (double)exact / documentCount,
            bound,
            valueErrors,
            evidenceErrors,
            coordinateErrors,
            passed);
    }

    public static CorpusDocumentScore EvaluateDocument(
        CorpusHeldOutDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (document.OutputDisposition != CorpusOutputDisposition.Accepted)
        {
            return new CorpusDocumentScore(
                document.StableDocumentId,
                document.InputKind,
                false,
                0,
                0,
                0);
        }

        var observations = document.ObservedFields
            .GroupBy(
                static field => field.FieldId,
                StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => group.ToArray(),
                StringComparer.Ordinal);
        var exact = true;
        var valueErrors = 0;
        var evidenceErrors = 0;
        var coordinateErrors = 0;
        foreach (var expected in document.ExpectedFields)
        {
            if (!observations.TryGetValue(
                    expected.FieldId,
                    out var observed)
                || observed.Length != 1)
            {
                exact = false;
                valueErrors++;
                continue;
            }

            var actual = observed[0];
            if (!string.Equals(
                    Normalize(expected.NormalizedValue),
                    Normalize(actual.NormalizedValue),
                    StringComparison.Ordinal))
            {
                exact = false;
                valueErrors++;
            }

            if (actual.Evidence is null)
            {
                evidenceErrors++;
            }
            else if (!SameRectangle(expected.Evidence, actual.Evidence))
            {
                coordinateErrors++;
            }
        }

        var expectedIds = document.ExpectedFields
            .Select(static field => field.FieldId)
            .ToHashSet(StringComparer.Ordinal);
        valueErrors += observations.Keys.Count(
            fieldId => !expectedIds.Contains(fieldId));
        if (valueErrors != 0)
        {
            exact = false;
        }

        return new CorpusDocumentScore(
            document.StableDocumentId,
            document.InputKind,
            exact,
            valueErrors,
            evidenceErrors,
            coordinateErrors);
    }

    private static string Normalize(string value)
    {
        var normalized = value.Normalize(NormalizationForm.FormKC);
        var output = new StringBuilder(normalized.Length);
        var pendingSpace = false;
        foreach (var character in normalized)
        {
            if (char.IsWhiteSpace(character))
            {
                pendingSpace = output.Length > 0;
                continue;
            }

            if (pendingSpace)
            {
                output.Append(' ');
                pendingSpace = false;
            }

            output.Append(character);
        }

        return output.ToString();
    }

    private static bool SameRectangle(
        CorpusEvidenceRectangle expected,
        CorpusEvidenceRectangle actual) =>
        expected.SourceIndex == actual.SourceIndex
        && expected.X.Equals(actual.X)
        && expected.Y.Equals(actual.Y)
        && expected.Width.Equals(actual.Width)
        && expected.Height.Equals(actual.Height);
}
