namespace LocalDocumentOrganizer.CorpusEval;

public static class WilsonInterval
{
    private const double OneSided95Z = 1.6448536269514722;

    public static double OneSided95LowerBound(int successes, int trials)
    {
        if (trials <= 0 || successes < 0 || successes > trials)
        {
            throw new ArgumentOutOfRangeException(nameof(successes));
        }

        var proportion = (double)successes / trials;
        var zSquared = OneSided95Z * OneSided95Z;
        var denominator = 1 + zSquared / trials;
        var center = proportion + zSquared / (2 * trials);
        var margin = OneSided95Z * Math.Sqrt(
            proportion * (1 - proportion) / trials
            + zSquared / (4.0 * trials * trials));
        return (center - margin) / denominator;
    }
}

public static class CorpusCellGate
{
    public static bool Passes(
        int requiredFieldExactSuccesses,
        int documentCount,
        int criticalValueErrors,
        int criticalEvidenceErrors,
        int criticalCoordinateErrors) =>
        documentCount >= 40
        && requiredFieldExactSuccesses * 40L >= documentCount * 39L
        && WilsonInterval.OneSided95LowerBound(
            requiredFieldExactSuccesses,
            documentCount) > 0.85
        && criticalValueErrors == 0
        && criticalEvidenceErrors == 0
        && criticalCoordinateErrors == 0;
}
