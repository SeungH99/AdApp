using System.Collections.Immutable;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;
using Microsoft.Win32.SafeHandles;
using UglyToad.PdfPig;

namespace LocalDocumentOrganizer.DocumentAdapterBench;

public static class BenchmarkAdapterIds
{
    public const string CandidateA = "windows-native-pdf-ocr";
    public const string CandidateB = "pdfpig-embedded-text";
}

public sealed record ExpectedBenchmarkRectangle(
    int SourceIndex,
    double X,
    double Y,
    double Width,
    double Height);

public sealed record ExpectedBenchmarkField(
    string Name,
    string Value,
    ExpectedBenchmarkRectangle? Evidence);

public sealed record AdapterBenchmarkFixture(
    string Id,
    string Category,
    string Path,
    string MimeType,
    string Language,
    IReadOnlyList<ExpectedBenchmarkField> RequiredFields,
    string? OcrLanguage = null);

public sealed record AdapterBenchmarkManifest(
    string SchemaVersion,
    IReadOnlyList<AdapterBenchmarkFixture> Fixtures);

public sealed record AdapterCandidateMeasurement(
    string AdapterId,
    int RequiredFieldExactMatches,
    int RequiredFieldCount,
    double P95ElapsedMilliseconds,
    long PeakWorkingSetBytes,
    IReadOnlyList<string> RejectionReasons,
    IReadOnlyList<AdapterFixtureMeasurement>? FixtureMeasurements = null);

public sealed record AdapterObservedField(
    string Name,
    bool ValueMatched,
    EvidenceRectangle? Evidence);

public sealed record AdapterFixtureMeasurement(
    string FixtureId,
    double ElapsedMilliseconds,
    int RequiredFieldExactMatches,
    int RequiredFieldCount,
    IReadOnlyList<AdapterObservedField> Fields);

public sealed record AdapterSelectionPackageVersions(
    string PdfPig,
    string PdfPigLicense,
    string WindowsDataPdf,
    string WindowsGraphicsImaging,
    string WindowsMediaOcr);

public sealed record AdapterSelectionReport(
    string SchemaVersion,
    AdapterSelectionPackageVersions PackageApiVersions,
    string FixtureHash,
    IReadOnlyList<AdapterCandidateMeasurement> Candidates,
    string? SelectedAdapterId,
    IReadOnlyList<string> RejectionReasons);

public static class BenchmarkManifestValidator
{
    private static readonly string[] Categories =
        ["embedded-pdf", "image-only-pdf", "raster-image"];

    public static void Validate(AdapterBenchmarkManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (manifest.SchemaVersion != "1"
            || manifest.Fixtures is null
            || manifest.Fixtures.Count != 12)
        {
            throw new InvalidDataException(
                "The benchmark manifest must contain exactly 12 version-1 fixtures.");
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var category in Categories)
        {
            if (manifest.Fixtures.Count(
                    fixture => fixture.Category == category) != 4)
            {
                throw new InvalidDataException(
                    "The benchmark requires exactly four fixtures in each category.");
            }
        }

        foreach (var fixture in manifest.Fixtures)
        {
            if (string.IsNullOrWhiteSpace(fixture.Id)
                || !ids.Add(fixture.Id)
                || string.IsNullOrWhiteSpace(fixture.Path)
                || string.IsNullOrWhiteSpace(fixture.Language)
                || fixture.RequiredFields is null
                || fixture.RequiredFields.Count == 0
                || fixture.RequiredFields.Any(
                    static field =>
                        string.IsNullOrWhiteSpace(field.Name)
                        || string.IsNullOrWhiteSpace(field.Value)))
            {
                throw new InvalidDataException(
                    "Each benchmark fixture must have a unique ID and literal expectations.");
            }

            var expectedMime = fixture.Category == "raster-image"
                ? fixture.MimeType is
                    "image/jpeg" or "image/png" or "image/tiff" or "image/bmp"
                : fixture.MimeType == "application/pdf";
            if (!expectedMime)
            {
                throw new InvalidDataException(
                    "A fixture MIME type does not match its category.");
            }
        }

        if (!manifest.Fixtures.Any(
                static fixture =>
                    fixture.Language.StartsWith("en", StringComparison.Ordinal))
            || !manifest.Fixtures.Any(
                static fixture =>
                    fixture.Language.StartsWith("ko", StringComparison.Ordinal)))
        {
            throw new InvalidDataException(
                "The benchmark must represent both English and Korean.");
        }
    }
}

public static class AdapterBenchmarkSelector
{
    public static string Select(
        IReadOnlyList<AdapterCandidateMeasurement> candidates)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        var passing = candidates
            .Where(static candidate => candidate.RejectionReasons.Count == 0)
            .ToArray();
        if (passing.Length == 0)
        {
            throw new InvalidOperationException(
                "Every document adapter candidate was rejected.");
        }

        if (passing.Length == 1)
        {
            return passing[0].AdapterId;
        }

        var candidateA = passing.SingleOrDefault(
            static candidate =>
                candidate.AdapterId == BenchmarkAdapterIds.CandidateA);
        var candidateB = passing.SingleOrDefault(
            static candidate =>
                candidate.AdapterId == BenchmarkAdapterIds.CandidateB);
        if (candidateA is not null && candidateB is not null)
        {
            var exactMatchImprovement =
                (long)candidateB.RequiredFieldExactMatches * 100
                >= (long)candidateA.RequiredFieldExactMatches * 110
                && candidateB.RequiredFieldExactMatches
                    > candidateA.RequiredFieldExactMatches;
            var p95Improvement =
                candidateA.P95ElapsedMilliseconds > 0
                && candidateB.P95ElapsedMilliseconds * 100
                    <= candidateA.P95ElapsedMilliseconds * 90;
            return exactMatchImprovement || p95Improvement
                ? candidateB.AdapterId
                : candidateA.AdapterId;
        }

        return passing
            .OrderBy(static candidate => candidate.PeakWorkingSetBytes)
            .ThenBy(static candidate => candidate.AdapterId, StringComparer.Ordinal)
            .First()
            .AdapterId;
    }
}

public static class Program
{
    private const string PdfPigExpectedVersion = "0.1.15";
    private const string PdfPigLicense = "Apache-2.0";

    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = ParseArguments(args);
            var manifestPath = System.IO.Path.GetFullPath(options.ManifestPath);
            var manifestBytes = await File.ReadAllBytesAsync(manifestPath)
                .ConfigureAwait(false);
            var manifest = JsonSerializer.Deserialize<AdapterBenchmarkManifest>(
                    manifestBytes,
                    JsonOptions())
                ?? throw new InvalidDataException("The benchmark manifest is empty.");
            BenchmarkManifestValidator.Validate(manifest);

            var baseDirectory =
                System.IO.Path.GetDirectoryName(manifestPath)
                ?? throw new InvalidDataException(
                    "The benchmark manifest has no base directory.");
            ValidateFixtureFiles(manifest, baseDirectory);
            var measurements = new[]
            {
                await MeasureCandidateAsync(
                        BenchmarkAdapterIds.CandidateA,
                        manifest,
                        baseDirectory)
                    .ConfigureAwait(false),
                await MeasureCandidateAsync(
                        BenchmarkAdapterIds.CandidateB,
                        manifest,
                        baseDirectory)
                    .ConfigureAwait(false),
            };

            string? selected = null;
            var reportRejections = new List<string>();
            try
            {
                selected = AdapterBenchmarkSelector.Select(measurements);
            }
            catch (InvalidOperationException exception)
            {
                reportRejections.Add(exception.Message);
            }

            var report = new AdapterSelectionReport(
                "1",
                new AdapterSelectionPackageVersions(
                    PdfPigExpectedVersion,
                    PdfPigLicense,
                    "UniversalApiContract-v1",
                    "UniversalApiContract-v1",
                    "UniversalApiContract-v1"),
                ComputeFixtureHash(manifestBytes, manifest, baseDirectory),
                measurements,
                selected,
                reportRejections);
            var outputPath = System.IO.Path.GetFullPath(options.OutputPath);
            Directory.CreateDirectory(
                System.IO.Path.GetDirectoryName(outputPath)
                ?? throw new InvalidDataException(
                    "The benchmark output has no parent directory."));
            await File.WriteAllBytesAsync(
                    outputPath,
                    JsonSerializer.SerializeToUtf8Bytes(report, JsonOptions(indented: true)))
                .ConfigureAwait(false);
            return selected is null ? 2 : 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"document-adapter-bench:{exception.GetType().Name}");
            return 1;
        }
    }

    private static async Task<AdapterCandidateMeasurement> MeasureCandidateAsync(
        string adapterId,
        AdapterBenchmarkManifest manifest,
        string baseDirectory)
    {
        var exactMatches = 0;
        var requiredFieldCount = 0;
        var elapsed = new List<double>(manifest.Fixtures.Count);
        var rejectionReasons = new SortedSet<string>(StringComparer.Ordinal);
        var fixtureMeasurements = new List<AdapterFixtureMeasurement>();
        var process = Process.GetCurrentProcess();
        var peakWorkingSet = process.WorkingSet64;

        if (adapterId == BenchmarkAdapterIds.CandidateB
            && !HasExpectedPdfPigPackage())
        {
            rejectionReasons.Add("package-license-failure");
        }

        foreach (var fixture in manifest.Fixtures)
        {
            requiredFieldCount += fixture.RequiredFields.Count;
            var fixturePath = ResolveFixturePath(baseDirectory, fixture.Path);
            using var fixtureSource = FixtureSource.Open(fixturePath);
            var container = fixture.Category == "raster-image"
                ? DocumentContainerKind.RasterImage
                : DocumentContainerKind.Pdf;
            var capabilities = fixture.Category == "raster-image"
                ? ExtractionCapability.Ocr
                : adapterId == BenchmarkAdapterIds.CandidateA
                    ? ExtractionCapability.Ocr
                    : ExtractionCapability.EmbeddedText | ExtractionCapability.Ocr;
            var request = fixtureSource.CreateRequest(
                container,
                fixture.MimeType,
                capabilities,
                fixture.OcrLanguage ?? fixture.Language);
            IDocumentExtractionAdapter adapter = fixture.Category == "raster-image"
                ? new WindowsRasterOcrAdapter()
                : adapterId == BenchmarkAdapterIds.CandidateA
                    ? new WindowsNativePdfAdapter()
                    : new PdfPigEmbeddedTextAdapter();
            var processor = new DocumentExtractionProcessor([adapter]);
            using var timeout = new CancellationTokenSource(
                DocumentExtractionLimits.ExtractionTimeoutMilliseconds);
            var stopwatch = Stopwatch.StartNew();
            var response = await processor.ProcessAsync(request, timeout.Token)
                .ConfigureAwait(false);
            stopwatch.Stop();
            elapsed.Add(stopwatch.Elapsed.TotalMilliseconds);
            process.Refresh();
            peakWorkingSet = Math.Max(peakWorkingSet, process.WorkingSet64);

            if (timeout.IsCancellationRequested)
            {
                rejectionReasons.Add($"{fixture.Id}:timeout");
                fixtureMeasurements.Add(
                    FailedFixtureMeasurement(
                        fixture,
                        stopwatch.Elapsed.TotalMilliseconds));
                continue;
            }

            if (response.Outcome != DocumentExtractionOutcome.Success)
            {
                rejectionReasons.Add(
                    $"{fixture.Id}:failure:{response.FailureCode}");
                fixtureMeasurements.Add(
                    FailedFixtureMeasurement(
                        fixture,
                        stopwatch.Elapsed.TotalMilliseconds));
                continue;
            }

            var validation = DocumentExtractionValidator.ValidateResponse(
                request,
                response);
            if (!validation.IsValid)
            {
                rejectionReasons.Add(
                    $"{fixture.Id}:limit-bypass:{validation.FailureCode}");
                fixtureMeasurements.Add(
                    FailedFixtureMeasurement(
                        fixture,
                        stopwatch.Elapsed.TotalMilliseconds));
                continue;
            }

            var fixtureExactMatches = 0;
            var observedFields = new List<AdapterObservedField>();
            foreach (var expected in fixture.RequiredFields)
            {
                var normalizedExpected = Normalize(expected.Value);
                var matching = response.Fragments
                    .Where(
                        fragment =>
                            Normalize(fragment.Text) == normalizedExpected)
                    .ToArray();
                if (matching.Length == 0
                    && Normalize(
                        string.Join(
                            " ",
                            response.Fragments.Select(
                                static fragment => fragment.Text)))
                        == normalizedExpected)
                {
                    exactMatches++;
                    fixtureExactMatches++;
                    observedFields.Add(
                        new AdapterObservedField(expected.Name, true, null));
                    continue;
                }

                if (matching.Length == 0)
                {
                    rejectionReasons.Add($"{fixture.Id}:{expected.Name}:value-error");
                    observedFields.Add(
                        new AdapterObservedField(expected.Name, false, null));
                    continue;
                }

                exactMatches++;
                fixtureExactMatches++;
                observedFields.Add(
                    new AdapterObservedField(
                        expected.Name,
                        true,
                        matching[0].Evidence));
                if (expected.Evidence is not null
                    && !matching.Any(
                        fragment =>
                            fragment.SourceIndex == expected.Evidence.SourceIndex
                            && CoordinateError(
                                fragment.Evidence,
                                expected.Evidence) <= 0.5))
                {
                    rejectionReasons.Add(
                        $"{fixture.Id}:{expected.Name}:coordinate-error");
                }
            }

            fixtureMeasurements.Add(
                new AdapterFixtureMeasurement(
                    fixture.Id,
                    stopwatch.Elapsed.TotalMilliseconds,
                    fixtureExactMatches,
                    fixture.RequiredFields.Count,
                    observedFields));
        }

        if (peakWorkingSet > DocumentExtractionLimits.MaxWorkerCommitMemoryBytes)
        {
            rejectionReasons.Add("worker-memory-limit-bypass");
        }

        return new AdapterCandidateMeasurement(
            adapterId,
            exactMatches,
            requiredFieldCount,
            Percentile95(elapsed),
            peakWorkingSet,
            rejectionReasons.ToArray(),
            fixtureMeasurements);
    }

    private static AdapterFixtureMeasurement FailedFixtureMeasurement(
        AdapterBenchmarkFixture fixture,
        double elapsedMilliseconds) =>
        new(
            fixture.Id,
            elapsedMilliseconds,
            0,
            fixture.RequiredFields.Count,
            []);

    private static bool HasExpectedPdfPigPackage()
    {
        var assembly = typeof(PdfDocument).Assembly;
        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        var assemblyVersion = assembly.GetName().Version?.ToString();
        return (informational?.StartsWith(
                    PdfPigExpectedVersion,
                    StringComparison.Ordinal) == true
                || assemblyVersion?.StartsWith(
                    PdfPigExpectedVersion,
                    StringComparison.Ordinal) == true)
            && PdfPigLicense == "Apache-2.0";
    }

    private static double Percentile95(IReadOnlyList<double> values)
    {
        if (values.Count == 0)
        {
            return 0;
        }

        var ordered = values.Order().ToArray();
        var index = Math.Max(0, (int)Math.Ceiling(ordered.Length * 0.95) - 1);
        return ordered[index];
    }

    private static double CoordinateError(
        EvidenceRectangle actual,
        ExpectedBenchmarkRectangle expected) =>
        new[]
        {
            Math.Abs(actual.X - expected.X),
            Math.Abs(actual.Y - expected.Y),
            Math.Abs(actual.Width - expected.Width),
            Math.Abs(actual.Height - expected.Height),
        }.Max();

    private static string Normalize(string value) =>
        string.Join(
            " ",
            value.Split(
                (char[]?)null,
                StringSplitOptions.RemoveEmptyEntries
                    | StringSplitOptions.TrimEntries));

    private static void ValidateFixtureFiles(
        AdapterBenchmarkManifest manifest,
        string baseDirectory)
    {
        foreach (var fixture in manifest.Fixtures)
        {
            var path = ResolveFixturePath(baseDirectory, fixture.Path);
            var length = new FileInfo(path).Length;
            if (length <= 0
                || length > DocumentExtractionLimits.MaxEncodedInputBytes)
            {
                throw new InvalidDataException(
                    "A fixture violates the encoded input boundary.");
            }
        }
    }

    private static string ComputeFixtureHash(
        byte[] manifestBytes,
        AdapterBenchmarkManifest manifest,
        string baseDirectory)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(manifestBytes);
        foreach (var fixture in manifest.Fixtures.OrderBy(
                     static fixture => fixture.Id,
                     StringComparer.Ordinal))
        {
            hash.AppendData(Encoding.UTF8.GetBytes(fixture.Id));
            hash.AppendData(
                File.ReadAllBytes(ResolveFixturePath(baseDirectory, fixture.Path)));
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static string ResolveFixturePath(
        string baseDirectory,
        string relativePath)
    {
        if (System.IO.Path.IsPathRooted(relativePath))
        {
            throw new InvalidDataException("Fixture paths must be relative.");
        }

        var baseFullPath = System.IO.Path.GetFullPath(baseDirectory)
            .TrimEnd(System.IO.Path.DirectorySeparatorChar)
            + System.IO.Path.DirectorySeparatorChar;
        var fullPath = System.IO.Path.GetFullPath(
            System.IO.Path.Combine(baseDirectory, relativePath));
        if (!fullPath.StartsWith(
                baseFullPath,
                StringComparison.OrdinalIgnoreCase)
            || !File.Exists(fullPath))
        {
            throw new InvalidDataException(
                "A fixture path escapes or is missing from the manifest directory.");
        }

        return fullPath;
    }

    private static (string ManifestPath, string OutputPath) ParseArguments(
        IReadOnlyList<string> args)
    {
        string? manifest = null;
        string? output = null;
        for (var index = 0; index < args.Count; index++)
        {
            if (args[index] == "--manifest" && index + 1 < args.Count)
            {
                manifest = args[++index];
            }
            else if (args[index] == "--output" && index + 1 < args.Count)
            {
                output = args[++index];
            }
            else
            {
                throw new ArgumentException("Unknown benchmark argument.");
            }
        }

        return string.IsNullOrWhiteSpace(manifest)
            || string.IsNullOrWhiteSpace(output)
            ? throw new ArgumentException(
                "Both --manifest and --output are required.")
            : (manifest, output);
    }

    private static JsonSerializerOptions JsonOptions(bool indented = false) =>
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = indented,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

    private sealed class FixtureSource : IDisposable
    {
        private readonly FileStream stream;
        private readonly byte[] bytes;

        private FixtureSource(FileStream stream, byte[] bytes)
        {
            this.stream = stream;
            this.bytes = bytes;
        }

        public static FixtureSource Open(string path)
        {
            var bytes = File.ReadAllBytes(path);
            var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);
            return new FixtureSource(stream, bytes);
        }

        public DocumentExtractionRequest CreateRequest(
            DocumentContainerKind container,
            string mimeType,
            ExtractionCapability capabilities,
            string language) =>
            new(
                DocumentExtractionProtocol.CurrentVersion,
                Guid.NewGuid(),
                new DocumentSourceDescriptor(
                    unchecked((ulong)stream.SafeFileHandle.DangerousGetHandle().ToInt64()),
                    container,
                    mimeType,
                    bytes.LongLength,
                    ImmutableArray.Create(SHA256.HashData(bytes))),
                capabilities,
                [language]);

        public void Dispose() => stream.Dispose();
    }
}
