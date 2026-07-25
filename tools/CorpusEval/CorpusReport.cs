using System.Security.Cryptography;
using System.Text.Json;

namespace LocalDocumentOrganizer.CorpusEval;

public sealed record CorpusDocumentScore(
    string StableDocumentId,
    CorpusInputKind InputKind,
    bool RequiredFieldsExact,
    int CriticalValueErrors,
    int CriticalEvidenceErrors,
    int CriticalCoordinateErrors);

public sealed record CorpusCellReport(
    string MarketId,
    string ContractId,
    int DocumentCount,
    int ImagePdfDocumentCount,
    int StandaloneRasterDocumentCount,
    int RequiredFieldExactSuccesses,
    double RequiredFieldExactRate,
    double WilsonOneSided95LowerBound,
    int CriticalValueErrors,
    int CriticalEvidenceErrors,
    int CriticalCoordinateErrors,
    bool Passed);

public sealed record CorpusAggregateReport(
    int TotalCells,
    int PassedCells,
    int FailedCells,
    int TotalDocuments,
    int RequiredFieldExactSuccesses,
    int CriticalValueErrors,
    int CriticalEvidenceErrors,
    int CriticalCoordinateErrors,
    bool PerturbationsPassed,
    bool Passed);

public sealed record CorpusReport(
    string SchemaVersion,
    string? RunIdentityId,
    bool Empirical,
    bool EmpiricalGatePassed,
    IReadOnlyList<CorpusCellReport> Cells,
    CorpusAggregateReport Aggregate);

public static class CorpusReportJson
{
    private static readonly JsonSerializerOptions Options =
        new(JsonSerializerDefaults.Web);

    public static byte[] Serialize(CorpusReport report) =>
        JsonSerializer.SerializeToUtf8Bytes(report, Options);

    public static string ComputeSha256(CorpusReport report) =>
        Convert.ToHexString(SHA256.HashData(Serialize(report)))
            .ToLowerInvariant();
}
