using System.Text;

namespace LocalDocumentOrganizer.CorpusEval;

public static class CorpusEvalExitCodes
{
    public const int Success = 0;
    public const int InvalidArguments = 1;
    public const int InvalidManifest = 2;
    public const int CorruptResumeState = 3;
    public const int GateFailure = 4;
    public const int EvaluationFailure = 5;
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
            var outputDirectory = Path.GetFullPath(options.OutputDirectory);
            var manifestBytes = await File.ReadAllBytesAsync(manifestPath)
                .ConfigureAwait(false);
            var manifest = CorpusManifestJson.Parse(manifestBytes);
            CorpusManifestValidator.Validate(manifest);
            Directory.CreateDirectory(outputDirectory);
            await WriteSchemaAsync(
                    Path.Combine(
                        outputDirectory,
                        "corpus-manifest.schema.json"))
                .ConfigureAwait(false);
            var result = CorpusEvaluationRunner.Run(
                manifest,
                manifestBytes,
                outputDirectory);
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
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException
                or ArgumentException
                or InvalidOperationException)
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

        return new CorpusEvalOptions(manifest, output);
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
        string OutputDirectory);
}
