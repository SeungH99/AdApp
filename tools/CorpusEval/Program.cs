using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Infrastructure.Windows.Documents;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

namespace LocalDocumentOrganizer.CorpusEval;

public static class CorpusEvalExitCodes
{
    public const int Success = 0;
    public const int InvalidArguments = 1;
    public const int InvalidManifest = 2;
    public const int CorruptResumeState = 3;
    public const int GateFailure = 4;
    public const int EvaluationFailure = 5;
    public const int WorkerRequired = 6;
    public const int WorkerAttestationFailed = 7;
}

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        CorpusEvalOptions options;
        try
        {
            options = ParseArguments(args);
        }
        catch (ArgumentException)
        {
            Console.Error.WriteLine("corpus-eval:invalid-arguments");
            return CorpusEvalExitCodes.InvalidArguments;
        }

        try
        {
            var manifestPath = Path.GetFullPath(options.ManifestPath);
            var corpusRoot = Path.GetDirectoryName(manifestPath)
                ?? throw new ArgumentException("Manifest root is unavailable.");
            var outputDirectory = Path.GetFullPath(options.OutputDirectory);
            var manifestBytes = await File.ReadAllBytesAsync(manifestPath)
                .ConfigureAwait(false);
            var manifest = CorpusManifestJson.Parse(manifestBytes);
            CorpusManifestValidator.Validate(manifest);
            if (manifest.CorpusKind == CorpusKind.OwnerApproved
                && (options.WorkerPath is null
                    || options.WorkerPackageRoot is null
                    || options.WorkerPackageSha256 is null
                    || !Path.IsPathFullyQualified(options.WorkerPath)
                    || !Path.IsPathFullyQualified(
                        options.WorkerPackageRoot)
                    || !File.Exists(options.WorkerPath)))
            {
                Console.Error.WriteLine("corpus-eval:worker-required");
                return CorpusEvalExitCodes.WorkerRequired;
            }

            if (manifest.CorpusKind == CorpusKind.Synthetic
                && (options.WorkerPath is not null
                    || options.WorkerPackageRoot is not null
                    || options.WorkerPackageSha256 is not null))
            {
                Console.Error.WriteLine("corpus-eval:invalid-arguments");
                return CorpusEvalExitCodes.InvalidArguments;
            }

            ICorpusObservationRunner runner =
                manifest.CorpusKind == CorpusKind.Synthetic
                    ? new SyntheticCorpusObservationRunner()
                    : await PublishedWorkerCorpusObservationRunner.CreateAsync(
                            corpusRoot,
                            outputDirectory,
                            options.WorkerPackageRoot!,
                            options.WorkerPath!,
                            options.WorkerPackageSha256!,
                            ConfiguredOcrLanguages(manifest),
                            CancellationToken.None)
                        .ConfigureAwait(false);
            await using (runner.ConfigureAwait(false))
            {
                Directory.CreateDirectory(outputDirectory);
                await WriteSchemaAsync(
                        Path.Combine(
                            outputDirectory,
                            "corpus-manifest.schema.json"))
                    .ConfigureAwait(false);
                var result = await CorpusEvaluationRunner.RunAsync(
                        manifest,
                        manifestBytes,
                        corpusRoot,
                        outputDirectory,
                        runner,
                        maximumDocuments: null,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                if (!result.Completed)
                {
                    Console.Error.WriteLine("corpus-eval:evaluation-failure");
                    return CorpusEvalExitCodes.EvaluationFailure;
                }

                if (result.GatePassed != true)
                {
                    Console.Error.WriteLine("corpus-eval:gate-failure");
                    return CorpusEvalExitCodes.GateFailure;
                }
            }

            return CorpusEvalExitCodes.Success;
        }
        catch (CorpusManifestException)
        {
            Console.Error.WriteLine("corpus-eval:invalid-manifest");
            return CorpusEvalExitCodes.InvalidManifest;
        }
        catch (CorpusResumeException)
        {
            Console.Error.WriteLine("corpus-eval:corrupt-resume-state");
            return CorpusEvalExitCodes.CorruptResumeState;
        }
        catch (CorpusWorkerAttestationException)
        {
            Console.Error.WriteLine(
                "corpus-eval:worker-attestation-failed");
            return CorpusEvalExitCodes.WorkerAttestationFailed;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException
                or ArgumentException
                or InvalidOperationException
                or DocumentExtractionException)
        {
            Console.Error.WriteLine("corpus-eval:evaluation-failure");
            return CorpusEvalExitCodes.EvaluationFailure;
        }
    }

    private static CorpusEvalOptions ParseArguments(
        IReadOnlyList<string> args)
    {
        string? manifest = null;
        string? output = null;
        string? worker = null;
        string? workerPackageRoot = null;
        string? workerPackageSha256 = null;
        for (var index = 0; index < args.Count; index++)
        {
            if (args[index] == "--manifest"
                && index + 1 < args.Count
                && manifest is null)
            {
                manifest = args[++index];
            }
            else if (args[index] == "--output"
                     && index + 1 < args.Count
                     && output is null)
            {
                output = args[++index];
            }
            else if (args[index] == "--worker"
                     && index + 1 < args.Count
                     && worker is null)
            {
                worker = args[++index];
            }
            else if (args[index] == "--worker-package-root"
                     && index + 1 < args.Count
                     && workerPackageRoot is null)
            {
                workerPackageRoot = args[++index];
            }
            else if (args[index] == "--worker-package-sha256"
                     && index + 1 < args.Count
                     && workerPackageSha256 is null)
            {
                workerPackageSha256 = args[++index];
            }
            else
            {
                throw new ArgumentException(
                    "Invalid CorpusEval arguments.",
                    nameof(args));
            }
        }

        if (string.IsNullOrWhiteSpace(manifest)
            || string.IsNullOrWhiteSpace(output))
        {
            throw new ArgumentException(
                "CorpusEval requires a manifest and output directory.",
                nameof(args));
        }

        return new CorpusEvalOptions(
            manifest,
            output,
            worker,
            workerPackageRoot,
            workerPackageSha256);
    }

    private static async Task WriteSchemaAsync(string path)
    {
        var temporaryPath = path + ".tmp";
        var bytes = Encoding.UTF8.GetBytes(
            CorpusManifestJson.GenerateSchema());
        await using (var stream = new FileStream(
                         temporaryPath,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.WriteThrough))
        {
            await stream.WriteAsync(bytes).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporaryPath, path, overwrite: true);
    }

    private sealed record CorpusEvalOptions(
        string ManifestPath,
        string OutputDirectory,
        string? WorkerPath,
        string? WorkerPackageRoot,
        string? WorkerPackageSha256);

    private static IReadOnlyList<string> ConfiguredOcrLanguages(
        CorpusManifest manifest) =>
        manifest.Cells
            .SelectMany(
                static cell =>
                    cell.CalibrationDocuments
                        .Select(static document => document.LanguageId)
                        .Concat(
                            cell.HeldOutDocuments.Select(
                                static document => document.LanguageId))
                        .Concat(
                            cell.PerturbationVariants.Select(
                                static document => document.LanguageId)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.Ordinal)
            .ToArray();
}

public sealed class CorpusWorkerAttestationException : Exception
{
    public CorpusWorkerAttestationException()
        : base("corpus-worker-attestation-failed")
    {
    }
}

public static class SyntheticCorpusSource
{
    public static byte[] CreateBytes(CorpusHeldOutDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        return JsonSerializer.SerializeToUtf8Bytes(
            new SyntheticSourceFile(
                "1",
                document.StableDocumentId,
                document.ExpectedFields
                    .Select(
                        static field =>
                            new SyntheticSourceFragment(
                                field.NormalizedValue,
                                field.Evidence))
                    .ToArray()),
            CorpusJson.Options);
    }

    private sealed record SyntheticSourceFile(
        string SchemaVersion,
        string StableDocumentId,
        IReadOnlyList<SyntheticSourceFragment> Fragments);

    private sealed record SyntheticSourceFragment(
        string Text,
        CorpusEvidenceRectangle Evidence);

    internal static IReadOnlyList<(string Text, CorpusEvidenceRectangle Evidence)>
        Parse(ReadOnlySpan<byte> bytes)
    {
        var source = JsonSerializer.Deserialize<SyntheticSourceFile>(
                bytes,
                CorpusJson.Options)
            ?? throw new InvalidOperationException(
                "The synthetic source is invalid.");
        if (source.SchemaVersion != "1"
            || string.IsNullOrWhiteSpace(source.StableDocumentId)
            || source.Fragments.Count == 0)
        {
            throw new InvalidOperationException(
                "The synthetic source is invalid.");
        }

        return source.Fragments
            .Select(static fragment => (fragment.Text, fragment.Evidence))
            .ToArray();
    }
}

public sealed class SyntheticCorpusObservationRunner
    : ICorpusObservationRunner
{
    public bool IsEmpirical => false;

    public async ValueTask<CorpusObservation> ObserveAsync(
        CorpusObservationRequest request,
        CancellationToken cancellationToken)
    {
        var sourcePath = ResolveSourcePath(
            request.CorpusRoot,
            request.Document.SourceLocator);
        var bytes = await File.ReadAllBytesAsync(
                sourcePath,
                cancellationToken)
            .ConfigureAwait(false);
        var hash = CorpusHashing.Sha256(bytes);
        if (!CorpusHashing.FixedTimeEquals(
                request.Document.ContentSha256,
                hash))
        {
            throw new InvalidOperationException(
                "The synthetic source fingerprint is invalid.");
        }

        var coordinateSystem =
            request.Document.InputKind == CorpusInputKind.ImagePdf
                ? EvidenceCoordinateSystem.PdfPagePoints
                : EvidenceCoordinateSystem.OrientedRasterPixels;
        var fragments = SyntheticCorpusSource.Parse(bytes)
            .Select(
                item =>
                    new TextFragment(
                        item.Text,
                        item.Evidence.SourceIndex,
                        coordinateSystem,
                        new EvidenceRectangle(
                            item.Evidence.X,
                            item.Evidence.Y,
                            item.Evidence.Width,
                            item.Evidence.Height),
                        new OrientationTransform(1, 0, 0, 1, 0, 0),
                        ExtractionCapability.Ocr,
                        "synthetic-decoder-v1",
                        "synthetic-ocr-v1"))
            .ToImmutableArray();
        var response = new DocumentExtractionResponse(
            DocumentExtractionProtocol.CurrentVersion,
            Guid.NewGuid(),
            DocumentExtractionOutcome.Success,
            fragments,
            [
                new DocumentSourcePage(
                    0,
                    1000,
                    1000,
                    coordinateSystem),
            ],
            new ExtractionRuntimeMetadata(
                "synthetic-observation-runner",
                "1",
                "synthetic-decoder-v1",
                "synthetic-ocr-v1"),
            1,
            DocumentExtractionFailureCode.None);
        return new CorpusObservation(hash, response);
    }

    private static string ResolveSourcePath(
        string root,
        string relativeLocator)
    {
        var fullRoot = Path.GetFullPath(root);
        var candidate = Path.GetFullPath(
            Path.Combine(
                fullRoot,
                relativeLocator.Replace(
                    '/',
                    Path.DirectorySeparatorChar)));
        var prefix = Path.EndsInDirectorySeparator(fullRoot)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(
                prefix,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The synthetic source is outside the corpus root.");
        }

        return candidate;
    }
}

public sealed class PublishedWorkerCorpusObservationRunner
    : ICorpusObservationRunner
{
    private readonly DocumentExtractionClient _client;
    private readonly CorpusWorkerPackageLease _packageLease;
    private int _attestationCompleted;

    private PublishedWorkerCorpusObservationRunner(
        string corpusRoot,
        CorpusWorkerPackageLease packageLease,
        IReadOnlyList<string> defaultOcrLanguages,
        CorpusWorkerPackageIdentity packageIdentity)
    {
        var approvedRoot = new ApprovedRootPathGuard(corpusRoot);
        _client = new DocumentExtractionClient(
            packageLease.StagedExecutablePath,
            defaultOcrLanguages,
            approvedRoot);
        WorkerPackageIdentity = packageIdentity;
        _packageLease = packageLease;
    }

    public bool IsEmpirical => true;

    public CorpusWorkerPackageIdentity WorkerPackageIdentity { get; }

    public static async Task<PublishedWorkerCorpusObservationRunner>
        CreateAsync(
            string corpusRoot,
            string outputDirectory,
            string workerPackageRoot,
            string workerExecutablePath,
            string expectedWorkerPackageSha256,
            IReadOnlyList<string> defaultOcrLanguages,
            CancellationToken cancellationToken)
    {
        if (!Path.IsPathFullyQualified(workerPackageRoot)
            || !Path.IsPathFullyQualified(workerExecutablePath)
            || !Path.IsPathFullyQualified(corpusRoot)
            || !Path.IsPathFullyQualified(outputDirectory))
        {
            throw new CorpusWorkerAttestationException();
        }

        CorpusWorkerPackageLease? lease = null;
        try
        {
            lease = await CorpusWorkerPackageLease.CreateAsync(
                    workerPackageRoot,
                    workerExecutablePath,
                    expectedWorkerPackageSha256,
                    [corpusRoot, outputDirectory],
                    cancellationToken)
                .ConfigureAwait(false);
            var runner = new PublishedWorkerCorpusObservationRunner(
                corpusRoot,
                lease,
                defaultOcrLanguages,
                lease.Identity);
            lease = null;
            return runner;
        }
        catch (CorpusWorkerAttestationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or StableSourceBoundaryException
                or FileSystemBoundaryException)
        {
            throw new CorpusWorkerAttestationException();
        }
        finally
        {
            if (lease is not null)
            {
                await lease.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    public ValueTask DisposeAsync() =>
        _packageLease.DisposeAsync();

    public async Task CompleteAttestationAsync(
        CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(
                ref _attestationCompleted,
                1) != 0)
        {
            return;
        }

        await _packageLease.VerifyAsync(cancellationToken)
            .ConfigureAwait(false);
        await _packageLease.DisposeAsync().ConfigureAwait(false);
    }

    public async ValueTask<CorpusObservation> ObserveAsync(
        CorpusObservationRequest request,
        CancellationToken cancellationToken)
    {
        var path = Path.GetFullPath(
            Path.Combine(
                request.CorpusRoot,
                request.Document.SourceLocator.Replace(
                    '/',
                    Path.DirectorySeparatorChar)));
        var descriptor = new DocumentSourceDescriptor(
            0,
            request.Document.InputKind == CorpusInputKind.ImagePdf
                ? DocumentContainerKind.Pdf
                : DocumentContainerKind.RasterImage,
            MimeType(request.Document),
            new FileInfo(path).Length,
            ImmutableArray<byte>.Empty);
        var result = await _client.ExtractForEvaluationAsync(
                path,
                descriptor,
                ImmutableArray.Create(request.Document.LanguageId),
                cancellationToken)
            .ConfigureAwait(false);
        return new CorpusObservation(
            Convert.ToHexString(result.SourceSha256.AsSpan())
                .ToLowerInvariant(),
            result.Response);
    }

    private static string MimeType(CorpusHeldOutDocument document) =>
        document.InputKind == CorpusInputKind.ImagePdf
            ? "application/pdf"
            : document.CodecId switch
            {
                "jpeg" => "image/jpeg",
                "png" => "image/png",
                "tiff" => "image/tiff",
                "bmp" => "image/bmp",
                _ => throw new InvalidOperationException(
                    "The raster codec is invalid."),
            };
}
