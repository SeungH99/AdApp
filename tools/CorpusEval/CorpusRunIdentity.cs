using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LocalDocumentOrganizer.Core.Documents;

namespace LocalDocumentOrganizer.CorpusEval;

public sealed record CorpusOcrLanguageVersion(
    string LanguageId,
    string Version);

public sealed record CorpusActualRuntimeIdentity(
    string AdapterId,
    string AdapterVersion,
    string DecoderVersion,
    string OcrVersion);

public sealed record CorpusRunIdentity(
    string Id,
    string AppVersion,
    string CatalogEpoch,
    CorpusActualRuntimeIdentity Runtime,
    IReadOnlyList<CorpusOcrLanguageVersion> OcrLanguageVersions,
    string ManifestSha256,
    string OsBuild,
    string MachineClass,
    bool Empirical)
{
    public static CorpusRunIdentity Create(
        CorpusManifest manifest,
        ReadOnlySpan<byte> manifestBytes,
        CorpusActualRuntimeIdentity runtime,
        bool empirical)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(runtime);
        var languages = manifest.Cells
            .Select(static cell => cell.MarketId)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static language => language, StringComparer.Ordinal)
            .Select(
                language =>
                    new CorpusOcrLanguageVersion(
                        language,
                        runtime.OcrVersion))
            .ToArray();
        var assembly = typeof(CorpusRunIdentity).Assembly;
        var appVersion = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion
            ?? assembly.GetName().Version?.ToString()
            ?? "unknown";
        var payload = new CorpusRunIdentityPayload(
            appVersion,
            manifest.CatalogEpoch,
            runtime,
            languages,
            CorpusHashing.Sha256(manifestBytes),
            Environment.OSVersion.Version.ToString(),
            $"{RuntimeInformation.OSArchitecture}-cpu"
                + Environment.ProcessorCount,
            empirical);
        var id = CorpusHashing.Sha256(
            JsonSerializer.SerializeToUtf8Bytes(payload, CorpusJson.Options));
        return new CorpusRunIdentity(
            id,
            payload.AppVersion,
            payload.CatalogEpoch,
            payload.Runtime,
            payload.OcrLanguageVersions,
            payload.ManifestSha256,
            payload.OsBuild,
            payload.MachineClass,
            payload.Empirical);
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
    bool? GatePassed,
    bool? EmpiricalGatePassed);

public static class CorpusEvaluationRunner
{
    public static async Task<CorpusRunResult> RunAsync(
        CorpusManifest manifest,
        ReadOnlyMemory<byte> manifestBytes,
        string corpusRoot,
        string outputDirectory,
        ICorpusObservationRunner observationRunner,
        int? maximumDocuments,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(corpusRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentNullException.ThrowIfNull(observationRunner);
        if (maximumDocuments is < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDocuments));
        }

        CorpusManifestValidator.Validate(manifest);
        if ((manifest.CorpusKind == CorpusKind.OwnerApproved)
            != observationRunner.IsEmpirical)
        {
            throw new InvalidOperationException(
                "The observation runner does not match the corpus kind.");
        }

        var workItems = EnumerateWorkItems(manifest);
        var observations = new Dictionary<string, CorpusObservation>(
            StringComparer.Ordinal);
        ExtractionRuntimeMetadata? actualMetadata = null;
        foreach (var item in workItems)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var observation = await observationRunner.ObserveAsync(
                    new CorpusObservationRequest(corpusRoot, item.Document),
                    cancellationToken)
                .ConfigureAwait(false);
            ValidateObservation(item, observation);
            observations.Add(item.WorkItemId, observation);
            if (observation.Response.Outcome
                == DocumentExtractionOutcome.Success)
            {
                actualMetadata = observation.Response.RuntimeMetadata;
                break;
            }
        }

        if (actualMetadata is null)
        {
            throw new InvalidOperationException(
                "No successful adapter observation established runtime identity.");
        }

        var runtime = ToRuntime(actualMetadata);
        var identity = CorpusRunIdentity.Create(
            manifest,
            manifestBytes.Span,
            runtime,
            observationRunner.IsEmpirical);
        var root = Path.GetFullPath(outputDirectory);
        var runDirectory = Path.Combine(root, identity.Id);
        var scoreDirectory = Path.Combine(runDirectory, "scores");
        Directory.CreateDirectory(scoreDirectory);
        DeleteInterruptedTemporaryFiles(runDirectory);
        EnsureIdentity(runDirectory, identity);

        var expectedByFileName = workItems.ToDictionary(
            static item => ScoreFileName(item.WorkItemId),
            StringComparer.Ordinal);
        var scores = LoadScores(
            scoreDirectory,
            expectedByFileName,
            identity);
        ValidateCheckpointIfPresent(runDirectory, identity, scores);
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

            if (!observations.Remove(
                    item.WorkItemId,
                    out var observation))
            {
                observation = await observationRunner.ObserveAsync(
                        new CorpusObservationRequest(
                            corpusRoot,
                            item.Document),
                        cancellationToken)
                    .ConfigureAwait(false);
                ValidateObservation(item, observation);
            }

            if (observation.Response.Outcome
                    == DocumentExtractionOutcome.Success
                && ToRuntime(observation.Response.RuntimeMetadata) != runtime)
            {
                throw new InvalidOperationException(
                    "The adapter runtime changed during the run.");
            }

            var score = CorpusEvaluator.EvaluateObservation(
                item.Document,
                observation);
            var persisted = PersistedCorpusScore.Create(
                identity,
                item,
                score);
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
                null,
                null);
        }

        var scoreMap = scores.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value.Score.Score,
            StringComparer.Ordinal);
        var scoresByDocument = workItems.ToDictionary(
            static item => item.Document.StableDocumentId,
            item => scoreMap[item.WorkItemId],
            StringComparer.Ordinal);
        var perturbationsPassed = manifest.CodecPerturbations.All(
            perturbation =>
                CorpusEvaluator.EquivalentForPerturbation(
                    scoresByDocument[perturbation.BaselineDocumentId],
                    scoresByDocument[perturbation.VariantDocumentId]));
        var report = CorpusEvaluator.CreateReport(
            manifest,
            scoreMap,
            identity.Id,
            perturbationsPassed,
            observationRunner.IsEmpirical);
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
            report.Aggregate.Passed,
            report.EmpiricalGatePassed);
    }

    private static void ValidateObservation(
        CorpusWorkItem item,
        CorpusObservation observation)
    {
        if (!CorpusHashing.FixedTimeEquals(
                item.Document.ContentSha256,
                observation.SourceContentSha256))
        {
            throw new InvalidOperationException(
                "The observed source fingerprint is invalid.");
        }

        if (observation.Response.ProtocolVersion
                != DocumentExtractionProtocol.CurrentVersion
            || !Enum.IsDefined(observation.Response.Outcome))
        {
            throw new InvalidOperationException(
                "The observation response contract is invalid.");
        }
    }

    private static CorpusActualRuntimeIdentity ToRuntime(
        ExtractionRuntimeMetadata metadata) =>
        new(
            metadata.AdapterId,
            metadata.AdapterVersion,
            metadata.DecoderVersion,
            metadata.OcrVersion ?? string.Empty);

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
                        document => CorpusWorkItem.Create(
                            cell.MarketId,
                            cell.ContractId,
                            document)))
            .ToList();

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
            try
            {
                var fileName = Path.GetFileName(path);
                if (!expectedByFileName.TryGetValue(
                        fileName,
                        out var expected))
                {
                    Corrupt();
                }

                var scoreFile = AtomicJson.Read<CorpusScoreFile>(path);
                var scoreBytes = JsonSerializer.SerializeToUtf8Bytes(
                    scoreFile.Score,
                    CorpusJson.Options);
                var binding = PersistedCorpusScore.CreateBinding(
                    identity,
                    expected);
                if (!CorpusHashing.FixedTimeEquals(
                        CorpusHashing.Sha256(scoreBytes),
                        scoreFile.IntegritySha256)
                    || scoreFile.Score.RunIdentityId != identity.Id
                    || scoreFile.Score.ManifestSha256
                        != identity.ManifestSha256
                    || scoreFile.Score.Runtime != identity.Runtime
                    || scoreFile.Score.WorkItemId != expected.WorkItemId
                    || scoreFile.Score.MarketId != expected.MarketId
                    || scoreFile.Score.ContractId != expected.ContractId
                    || scoreFile.Score.InputKind
                        != expected.Document.InputKind
                    || scoreFile.Score.StableDocumentId
                        != expected.Document.StableDocumentId
                    || !CorpusHashing.FixedTimeEquals(
                        binding,
                        scoreFile.Score.SourceBindingSha256)
                    || !scores.TryAdd(
                        scoreFile.Score.WorkItemId,
                        scoreFile))
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
                    or UnauthorizedAccessException
                    or ArgumentException)
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
            var bytes = JsonSerializer.SerializeToUtf8Bytes(
                file.Identity,
                CorpusJson.Options);
            if (!CorpusHashing.FixedTimeEquals(
                    CorpusHashing.Sha256(bytes),
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
                    != identity.ManifestSha256
                || file.Checkpoint.CompletedScores.Any(
                    entry =>
                        !scores.TryGetValue(
                            entry.WorkItemId,
                            out var score)
                        || score.IntegritySha256
                            != entry.ScoreSha256))
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
            if (!CorpusHashing.FixedTimeEquals(
                    CorpusReportJson.ComputeSha256(file.Report),
                    file.ReportSha256)
                || file.Report.RunIdentityId != identity.Id
                || file.Report.Empirical != identity.Empirical)
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
        CorpusManifestJson.CreateOptions();
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
    CorpusActualRuntimeIdentity Runtime,
    IReadOnlyList<CorpusOcrLanguageVersion> OcrLanguageVersions,
    string ManifestSha256,
    string OsBuild,
    string MachineClass,
    bool Empirical);

internal sealed record CorpusIdentityFile(
    CorpusRunIdentity Identity,
    string IntegritySha256);

internal sealed record CorpusWorkItem(
    string WorkItemId,
    string MarketId,
    string ContractId,
    CorpusHeldOutDocument Document)
{
    internal static CorpusWorkItem Create(
        string marketId,
        string contractId,
        CorpusHeldOutDocument document) =>
        new(CreateId(marketId, contractId, document), marketId, contractId, document);

    internal static string CreateId(
        string marketId,
        string contractId,
        CorpusHeldOutDocument document) =>
        $"{marketId}\u001f{contractId}\u001f{document.InputKind}"
        + $"\u001f{document.StableDocumentId}";
}

internal sealed record PersistedCorpusScore(
    string RunIdentityId,
    string ManifestSha256,
    CorpusActualRuntimeIdentity Runtime,
    string WorkItemId,
    string MarketId,
    string ContractId,
    CorpusInputKind InputKind,
    string StableDocumentId,
    string SourceBindingSha256,
    CorpusDocumentScore Score)
{
    internal static PersistedCorpusScore Create(
        CorpusRunIdentity identity,
        CorpusWorkItem item,
        CorpusDocumentScore score) =>
        new(
            identity.Id,
            identity.ManifestSha256,
            identity.Runtime,
            item.WorkItemId,
            item.MarketId,
            item.ContractId,
            item.Document.InputKind,
            item.Document.StableDocumentId,
            CreateBinding(identity, item),
            score);

    internal static string CreateBinding(
        CorpusRunIdentity identity,
        CorpusWorkItem item) =>
        CorpusHashing.Sha256(
            string.Join(
                "\u001f",
                identity.Id,
                identity.ManifestSha256,
                identity.Runtime.AdapterId,
                identity.Runtime.AdapterVersion,
                identity.Runtime.DecoderVersion,
                identity.Runtime.OcrVersion,
                item.WorkItemId,
                item.MarketId,
                item.ContractId,
                item.Document.InputKind,
                item.Document.StableDocumentId,
                item.Document.ContentSha256));
}

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
