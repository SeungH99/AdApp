using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LocalDocumentOrganizer.CorpusEval;

public sealed record CorpusOcrLanguageVersion(
    string LanguageId,
    string Version);

public sealed record CorpusRunIdentity(
    string Id,
    string AppVersion,
    string CatalogEpoch,
    string AdapterId,
    string AdapterVersion,
    string OcrRuntimeVersion,
    IReadOnlyList<CorpusOcrLanguageVersion> OcrLanguageVersions,
    string ManifestSha256,
    string OsBuild,
    string MachineClass)
{
    public static CorpusRunIdentity Create(
        CorpusManifest manifest,
        ReadOnlySpan<byte> manifestBytes)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var languages = manifest.OcrLanguageVersions
            .OrderBy(static pair => pair.Key, StringComparer.Ordinal)
            .Select(
                static pair =>
                    new CorpusOcrLanguageVersion(pair.Key, pair.Value))
            .ToArray();
        var payload = new CorpusRunIdentityPayload(
            manifest.AppVersion,
            manifest.CatalogEpoch,
            manifest.AdapterId,
            manifest.AdapterVersion,
            manifest.OcrRuntimeVersion,
            languages,
            CorpusHashing.Sha256(manifestBytes),
            manifest.OsBuild,
            manifest.MachineClass);
        var id = CorpusHashing.Sha256(
            JsonSerializer.SerializeToUtf8Bytes(payload, CorpusJson.Options));
        return new CorpusRunIdentity(
            id,
            payload.AppVersion,
            payload.CatalogEpoch,
            payload.AdapterId,
            payload.AdapterVersion,
            payload.OcrRuntimeVersion,
            payload.OcrLanguageVersions,
            payload.ManifestSha256,
            payload.OsBuild,
            payload.MachineClass);
    }
}

public static class CorpusHashing
{
    public static string Sha256(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    internal static string Sha256(string value) =>
        Sha256(Encoding.UTF8.GetBytes(value));

    internal static bool FixedTimeEquals(string expected, string actual)
    {
        if (expected.Length != actual.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(actual));
    }
}

public enum CorpusResumeFailureCode
{
    IdentityMismatch,
    CorruptResumeState,
}

public sealed class CorpusResumeException : Exception
{
    public CorpusResumeException(CorpusResumeFailureCode failureCode)
        : base($"corpus-resume:{failureCode}")
    {
        FailureCode = failureCode;
    }

    public CorpusResumeFailureCode FailureCode { get; }
}

public sealed record CorpusRunResult(
    string RunIdentityId,
    string RunDirectory,
    bool Completed,
    int CompletedDocuments,
    int TotalDocuments,
    string? ReportSha256,
    bool? GatePassed);

public static class CorpusEvaluationRunner
{
    public static CorpusRunResult Run(
        CorpusManifest manifest,
        ReadOnlyMemory<byte> manifestBytes,
        string outputDirectory,
        int? maximumDocuments = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        if (maximumDocuments is < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDocuments));
        }

        CorpusManifestValidator.Validate(manifest);
        var identity = CorpusRunIdentity.Create(
            manifest,
            manifestBytes.Span);
        var root = Path.GetFullPath(outputDirectory);
        var runDirectory = Path.Combine(root, identity.Id);
        var scoreDirectory = Path.Combine(runDirectory, "scores");
        Directory.CreateDirectory(scoreDirectory);
        DeleteInterruptedTemporaryFiles(runDirectory);
        EnsureIdentity(runDirectory, identity);

        var workItems = EnumerateWorkItems(manifest);
        var expectedByFileName = workItems.ToDictionary(
            static item => ScoreFileName(item.WorkItemId),
            StringComparer.Ordinal);
        var scores = LoadScores(
            scoreDirectory,
            expectedByFileName,
            identity);
        ValidateCheckpointIfPresent(
            runDirectory,
            identity,
            scores);
        ValidateExistingReportIfPresent(runDirectory, identity);

        var remainingLimit = maximumDocuments ?? int.MaxValue;
        foreach (var item in workItems)
        {
            if (scores.ContainsKey(item.WorkItemId))
            {
                continue;
            }

            if (remainingLimit == 0)
            {
                break;
            }

            var persisted = new PersistedCorpusScore(
                item.WorkItemId,
                item.MarketId,
                item.ContractId,
                CorpusEvaluator.EvaluateDocument(item.Document));
            var hash = CorpusHashing.Sha256(
                JsonSerializer.SerializeToUtf8Bytes(
                    persisted,
                    CorpusJson.Options));
            var scoreFile = new CorpusScoreFile(persisted, hash);
            AtomicJson.Write(
                Path.Combine(
                    scoreDirectory,
                    ScoreFileName(item.WorkItemId)),
                scoreFile);
            scores.Add(item.WorkItemId, scoreFile);
            WriteCheckpoint(runDirectory, identity, scores);
            remainingLimit--;
        }

        var completed = scores.Count == workItems.Count;
        if (!completed)
        {
            return new CorpusRunResult(
                identity.Id,
                runDirectory,
                false,
                scores.Count,
                workItems.Count,
                null,
                null);
        }

        var report = CorpusEvaluator.CreateReport(
            manifest,
            document =>
            {
                var item = workItemsByDocument(manifest, document);
                return scores[item].Score.Score;
            },
            identity.Id);
        var reportHash = CorpusReportJson.ComputeSha256(report);
        AtomicJson.Write(
            Path.Combine(runDirectory, "report.json"),
            new CorpusReportFile(report, reportHash));
        AtomicJson.Write(
            Path.Combine(runDirectory, "cells.json"),
            report.Cells);
        AtomicJson.Write(
            Path.Combine(runDirectory, "aggregate.json"),
            report.Aggregate);
        return new CorpusRunResult(
            identity.Id,
            runDirectory,
            true,
            scores.Count,
            workItems.Count,
            reportHash,
            report.Aggregate.Passed);
    }

    private static string workItemsByDocument(
        CorpusManifest manifest,
        CorpusHeldOutDocument document)
    {
        var cell = manifest.Cells.Single(
            cell => cell.HeldOutDocuments.Contains(document));
        return WorkItemId(cell.MarketId, cell.ContractId, document);
    }

    private static List<CorpusWorkItem> EnumerateWorkItems(
        CorpusManifest manifest) =>
        manifest.Cells
            .OrderBy(static cell => cell.MarketId, StringComparer.Ordinal)
            .ThenBy(static cell => cell.ContractId, StringComparer.Ordinal)
            .SelectMany(
                static cell => cell.HeldOutDocuments
                    .OrderBy(static document => document.InputKind)
                    .ThenBy(
                        static document => document.StableDocumentId,
                        StringComparer.Ordinal)
                    .Select(
                        document => new CorpusWorkItem(
                            WorkItemId(
                                cell.MarketId,
                                cell.ContractId,
                                document),
                            cell.MarketId,
                            cell.ContractId,
                            document)))
            .ToList();

    private static string WorkItemId(
        string marketId,
        string contractId,
        CorpusHeldOutDocument document) =>
        $"{marketId}\u001f{contractId}\u001f{(int)document.InputKind}"
        + $"\u001f{document.StableDocumentId}";

    private static string ScoreFileName(string workItemId) =>
        $"{CorpusHashing.Sha256(workItemId)}.json";

    private static Dictionary<string, CorpusScoreFile> LoadScores(
        string scoreDirectory,
        IReadOnlyDictionary<string, CorpusWorkItem> expectedByFileName,
        CorpusRunIdentity identity)
    {
        var scores = new Dictionary<string, CorpusScoreFile>(
            StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFiles(
                     scoreDirectory,
                     "*.json",
                     SearchOption.TopDirectoryOnly))
        {
            var fileName = Path.GetFileName(path);
            if (!expectedByFileName.TryGetValue(fileName, out var expected))
            {
                Corrupt();
            }

            CorpusScoreFile scoreFile;
            try
            {
                scoreFile = AtomicJson.Read<CorpusScoreFile>(path);
            }
            catch (Exception exception) when (
                exception is JsonException
                    or IOException
                    or UnauthorizedAccessException)
            {
                Corrupt();
                throw;
            }

            var scoreBytes = JsonSerializer.SerializeToUtf8Bytes(
                scoreFile.Score,
                CorpusJson.Options);
            if (!CorpusHashing.FixedTimeEquals(
                    CorpusHashing.Sha256(scoreBytes),
                    scoreFile.IntegritySha256)
                || scoreFile.Score.WorkItemId != expected.WorkItemId
                || scoreFile.Score.MarketId != expected.MarketId
                || scoreFile.Score.ContractId != expected.ContractId
                || scoreFile.Score.Score.StableDocumentId
                    != expected.Document.StableDocumentId
                || !scores.TryAdd(
                    scoreFile.Score.WorkItemId,
                    scoreFile))
            {
                Corrupt();
            }
        }

        return scores;
    }

    private static void EnsureIdentity(
        string runDirectory,
        CorpusRunIdentity expected)
    {
        var path = Path.Combine(runDirectory, "run-identity.json");
        if (!File.Exists(path))
        {
            if (Directory.EnumerateFileSystemEntries(runDirectory)
                .Any(
                    entry =>
                        !string.Equals(
                            entry,
                            Path.Combine(runDirectory, "scores"),
                            StringComparison.OrdinalIgnoreCase)))
            {
                IdentityMismatch();
            }

            var bytes = JsonSerializer.SerializeToUtf8Bytes(
                expected,
                CorpusJson.Options);
            AtomicJson.Write(
                path,
                new CorpusIdentityFile(
                    expected,
                    CorpusHashing.Sha256(bytes)));
            return;
        }

        try
        {
            var file = AtomicJson.Read<CorpusIdentityFile>(path);
            var identityBytes = JsonSerializer.SerializeToUtf8Bytes(
                file.Identity,
                CorpusJson.Options);
            if (!CorpusHashing.FixedTimeEquals(
                    CorpusHashing.Sha256(identityBytes),
                    file.IntegritySha256)
                || file.Identity.Id != expected.Id)
            {
                IdentityMismatch();
            }
        }
        catch (CorpusResumeException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException
                or IOException
                or UnauthorizedAccessException)
        {
            IdentityMismatch();
        }
    }

    private static void ValidateCheckpointIfPresent(
        string runDirectory,
        CorpusRunIdentity identity,
        IReadOnlyDictionary<string, CorpusScoreFile> scores)
    {
        var path = Path.Combine(runDirectory, "checkpoint.json");
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var file = AtomicJson.Read<CorpusCheckpointFile>(path);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(
                file.Checkpoint,
                CorpusJson.Options);
            if (!CorpusHashing.FixedTimeEquals(
                    CorpusHashing.Sha256(bytes),
                    file.IntegritySha256)
                || file.Checkpoint.RunIdentityId != identity.Id
                || file.Checkpoint.ManifestSha256
                    != identity.ManifestSha256)
            {
                Corrupt();
            }

            foreach (var entry in file.Checkpoint.CompletedScores)
            {
                if (!scores.TryGetValue(
                        entry.WorkItemId,
                        out var score)
                    || score.IntegritySha256 != entry.ScoreSha256)
                {
                    Corrupt();
                }
            }
        }
        catch (CorpusResumeException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException
                or IOException
                or UnauthorizedAccessException)
        {
            Corrupt();
        }
    }

    private static void ValidateExistingReportIfPresent(
        string runDirectory,
        CorpusRunIdentity identity)
    {
        var path = Path.Combine(runDirectory, "report.json");
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var file = AtomicJson.Read<CorpusReportFile>(path);
            var actualHash = CorpusReportJson.ComputeSha256(file.Report);
            if (!CorpusHashing.FixedTimeEquals(
                    actualHash,
                    file.ReportSha256)
                || file.Report.RunIdentityId != identity.Id)
            {
                Corrupt();
            }
        }
        catch (CorpusResumeException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException
                or IOException
                or UnauthorizedAccessException)
        {
            Corrupt();
        }
    }

    private static void WriteCheckpoint(
        string runDirectory,
        CorpusRunIdentity identity,
        IReadOnlyDictionary<string, CorpusScoreFile> scores)
    {
        var checkpoint = new CorpusCheckpoint(
            identity.Id,
            identity.ManifestSha256,
            scores
                .OrderBy(static pair => pair.Key, StringComparer.Ordinal)
                .Select(
                    static pair =>
                        new CorpusCheckpointEntry(
                            pair.Key,
                            pair.Value.IntegritySha256))
                .ToArray());
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            checkpoint,
            CorpusJson.Options);
        AtomicJson.Write(
            Path.Combine(runDirectory, "checkpoint.json"),
            new CorpusCheckpointFile(
                checkpoint,
                CorpusHashing.Sha256(bytes)));
    }

    private static void DeleteInterruptedTemporaryFiles(string runDirectory)
    {
        foreach (var path in Directory.EnumerateFiles(
                     runDirectory,
                     "*.tmp",
                     SearchOption.AllDirectories))
        {
            File.Delete(path);
        }
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Corrupt() =>
        throw new CorpusResumeException(
            CorpusResumeFailureCode.CorruptResumeState);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void IdentityMismatch() =>
        throw new CorpusResumeException(
            CorpusResumeFailureCode.IdentityMismatch);
}

internal static class CorpusJson
{
    internal static JsonSerializerOptions Options { get; } =
        new(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
}

internal static class AtomicJson
{
    internal static T Read<T>(string path) =>
        JsonSerializer.Deserialize<T>(
            File.ReadAllBytes(path),
            CorpusJson.Options)
        ?? throw new JsonException("Empty persisted corpus record.");

    internal static void Write<T>(string path, T value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(
            value,
            CorpusJson.Options);
        var temporaryPath = path + ".tmp";
        using (var stream = new FileStream(
                   temporaryPath,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None,
                   4096,
                   FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporaryPath, path, overwrite: true);
    }
}

internal sealed record CorpusRunIdentityPayload(
    string AppVersion,
    string CatalogEpoch,
    string AdapterId,
    string AdapterVersion,
    string OcrRuntimeVersion,
    IReadOnlyList<CorpusOcrLanguageVersion> OcrLanguageVersions,
    string ManifestSha256,
    string OsBuild,
    string MachineClass);

internal sealed record CorpusIdentityFile(
    CorpusRunIdentity Identity,
    string IntegritySha256);

internal sealed record CorpusWorkItem(
    string WorkItemId,
    string MarketId,
    string ContractId,
    CorpusHeldOutDocument Document);

internal sealed record PersistedCorpusScore(
    string WorkItemId,
    string MarketId,
    string ContractId,
    CorpusDocumentScore Score);

internal sealed record CorpusScoreFile(
    PersistedCorpusScore Score,
    string IntegritySha256);

internal sealed record CorpusCheckpointEntry(
    string WorkItemId,
    string ScoreSha256);

internal sealed record CorpusCheckpoint(
    string RunIdentityId,
    string ManifestSha256,
    IReadOnlyList<CorpusCheckpointEntry> CompletedScores);

internal sealed record CorpusCheckpointFile(
    CorpusCheckpoint Checkpoint,
    string IntegritySha256);

internal sealed record CorpusReportFile(
    CorpusReport Report,
    string ReportSha256);
