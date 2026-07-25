using System.Text;
using LocalDocumentOrganizer.Core.Documents;

namespace LocalDocumentOrganizer.CorpusEval;

public sealed record CorpusObservationRequest(
    string CorpusRoot,
    CorpusHeldOutDocument Document);

public sealed record CorpusObservation(
    string SourceContentSha256,
    DocumentExtractionResponse Response);

public interface ICorpusObservationRunner
    : IAsyncDisposable
{
    bool IsEmpirical { get; }

    string WorkerSha256 =>
        CorpusRuntimeTrust.SyntheticWorkerSha256;

    ValueTask<CorpusObservation> ObserveAsync(
        CorpusObservationRequest request,
        CancellationToken cancellationToken);

    ValueTask IAsyncDisposable.DisposeAsync() => ValueTask.CompletedTask;
}

public static class CorpusEvaluator
{
    public static CorpusDocumentScore EvaluateObservation(
        CorpusHeldOutDocument document,
        CorpusObservation observation)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(observation);
        if (!CorpusHashing.FixedTimeEquals(
                document.ContentSha256,
                observation.SourceContentSha256))
        {
            throw new InvalidOperationException(
                "The observed source does not match the manifest.");
        }

        if (observation.Response.Outcome != DocumentExtractionOutcome.Success)
        {
            return new CorpusDocumentScore(
                document.StableDocumentId,
                document.InputKind,
                false,
                0,
                0,
                0);
        }

        var exact = true;
        var valueErrors = 0;
        var evidenceErrors = 0;
        var coordinateErrors = 0;
        foreach (var expected in document.ExpectedFields)
        {
            var matchingValue = observation.Response.Fragments
                .Where(
                    fragment =>
                        string.Equals(
                            Normalize(expected.NormalizedValue),
                            Normalize(fragment.Text),
                            StringComparison.Ordinal))
                .ToArray();
            if (matchingValue.Length == 0)
            {
                exact = false;
                valueErrors++;
                continue;
            }

            if (matchingValue.Any(
                    fragment =>
                        SameRectangle(expected.Evidence, fragment)))
            {
                continue;
            }

            exact = false;
            coordinateErrors++;
        }

        if (observation.Response.Fragments.IsDefault)
        {
            evidenceErrors++;
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

    internal static CorpusReport CreateReport(
        CorpusManifest manifest,
        IReadOnlyDictionary<string, CorpusDocumentScore> scores,
        string runIdentityId,
        IReadOnlyList<CorpusPerturbationResult> perturbations,
        bool empirical)
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
                        .Select(
                            document =>
                                scores[CorpusWorkItem.CreateId(
                                    cell.MarketId,
                                    cell.ContractId,
                                    document)])
                        .ToArray()))
            .ToArray();
        var aggregate = new CorpusAggregateReport(
            cells.Length,
            cells.Count(static cell => cell.Passed),
            cells.Count(static cell => !cell.Passed),
            cells.Sum(static cell => cell.DocumentCount),
            cells.Sum(static cell => cell.RequiredFieldExactSuccesses),
            cells.Sum(static cell => cell.CriticalValueErrors),
            cells.Sum(static cell => cell.CriticalEvidenceErrors),
            cells.Sum(static cell => cell.CriticalCoordinateErrors),
            perturbations.All(static result => result.Passed),
            perturbations.All(static result => result.Passed)
                && cells.All(static cell => cell.Passed));
        return new CorpusReport(
            "1",
            runIdentityId,
            manifest.CorpusKind,
            empirical,
            empirical && aggregate.Passed,
            perturbations,
            cells,
            aggregate);
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

    internal static bool EquivalentForPerturbation(
        CorpusDocumentScore baseline,
        CorpusDocumentScore variant) =>
        baseline.RequiredFieldsExact == variant.RequiredFieldsExact
        && baseline.CriticalValueErrors == variant.CriticalValueErrors
        && baseline.CriticalEvidenceErrors == variant.CriticalEvidenceErrors
        && baseline.CriticalCoordinateErrors
            == variant.CriticalCoordinateErrors;

    internal static bool EvaluatePerturbation(
        CorpusHeldOutDocument baseline,
        CorpusObservation baselineObservation,
        CorpusHeldOutDocument variant,
        CorpusObservation variantObservation,
        CorpusPerturbationKind kind)
    {
        var baselineScore = EvaluateObservation(
            baseline,
            baselineObservation);
        var variantScore = EvaluateObservation(
            variant,
            variantObservation);
        if (!baselineScore.RequiredFieldsExact
            || !variantScore.RequiredFieldsExact)
        {
            return false;
        }

        var baselineFields = baseline.ExpectedFields
            .OrderBy(static field => field.FieldId, StringComparer.Ordinal)
            .ToArray();
        var variantFields = variant.ExpectedFields
            .OrderBy(static field => field.FieldId, StringComparer.Ordinal)
            .ToArray();
        if (baselineFields.Length != variantFields.Length)
        {
            return false;
        }

        for (var index = 0; index < baselineFields.Length; index++)
        {
            if (baselineFields[index].FieldId != variantFields[index].FieldId
                || Normalize(baselineFields[index].NormalizedValue)
                    != Normalize(variantFields[index].NormalizedValue)
                || kind is not CorpusPerturbationKind.Orientation
                    && baselineFields[index].Evidence
                        != variantFields[index].Evidence)
            {
                return false;
            }
        }

        return true;
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
        TextFragment actual) =>
        expected.SourceIndex == actual.SourceIndex
        && expected.X.Equals(actual.Evidence.X)
        && expected.Y.Equals(actual.Evidence.Y)
        && expected.Width.Equals(actual.Evidence.Width)
        && expected.Height.Equals(actual.Evidence.Height);
}
