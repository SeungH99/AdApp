using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Security;

namespace LocalDocumentOrganizer.CorpusWorkbench.Commanding;

internal abstract record WorkbenchCommand;

internal sealed record InitCommand(
    string VaultPath,
    string CatalogPath,
    string Epoch) : WorkbenchCommand;

internal sealed record ImportCommand(
    string VaultPath,
    string SourcePath,
    string ReceiptPath) : WorkbenchCommand;

internal sealed record LabelCommand(
    string VaultPath,
    string WorkerPath,
    string WorkerPackageRoot,
    string WorkerPackageSha256) : WorkbenchCommand;

internal sealed record ReviewCommand(
    string VaultPath) : WorkbenchCommand;

internal sealed record ApproveBatchCommand(
    string VaultPath,
    string MarketId,
    string ReviewerId) : WorkbenchCommand;

internal sealed record ValidateCommand(
    string VaultPath,
    string OutputPath) : WorkbenchCommand;

internal sealed record SchemaCommand(
    string OutputPath) : WorkbenchCommand;

internal static class WorkbenchCommandLine
{
    internal static WorkbenchCommand Parse(string[]? arguments)
    {
        if (arguments is null || arguments.Length == 0)
        {
            throw InvalidArguments();
        }

        return arguments[0] switch
        {
            "init" => ParseInit(arguments),
            "import" => ParseImport(arguments),
            "label" => ParseLabel(arguments),
            "review" => ParseReview(arguments),
            "approve-batch" => ParseApproveBatch(arguments),
            "validate" => ParseValidate(arguments),
            "schema" => ParseSchema(arguments),
            _ => throw InvalidArguments(),
        };
    }

    private static InitCommand ParseInit(string[] arguments)
    {
        var options = ParseOptions(
            arguments,
            "--vault",
            "--catalog",
            "--epoch");
        return new InitCommand(
            RequireAbsoluteLocalPath(options["--vault"]),
            RequireAbsoluteLocalPath(options["--catalog"]),
            RequireToken(options["--epoch"], maximumLength: 64));
    }

    private static ImportCommand ParseImport(string[] arguments)
    {
        var options = ParseOptions(
            arguments,
            "--vault",
            "--source",
            "--receipt");
        return new ImportCommand(
            RequireAbsoluteLocalPath(options["--vault"]),
            RequireAbsoluteLocalPath(options["--source"]),
            RequireAbsoluteLocalPath(options["--receipt"]));
    }

    private static LabelCommand ParseLabel(string[] arguments)
    {
        var options = ParseOptions(
            arguments,
            "--vault",
            "--worker",
            "--worker-package-root",
            "--worker-package-sha256");
        return new LabelCommand(
            RequireAbsoluteLocalPath(options["--vault"]),
            RequireAbsoluteLocalPath(options["--worker"]),
            RequireAbsoluteLocalPath(options["--worker-package-root"]),
            RequireLowerSha256(options["--worker-package-sha256"]));
    }

    private static ReviewCommand ParseReview(string[] arguments)
    {
        var options = ParseOptions(arguments, "--vault");
        return new ReviewCommand(
            RequireAbsoluteLocalPath(options["--vault"]));
    }

    private static ApproveBatchCommand ParseApproveBatch(
        string[] arguments)
    {
        var options = ParseOptions(
            arguments,
            "--vault",
            "--market",
            "--reviewer");
        var market = options["--market"];
        if (market is not ("ko-KR" or "en-US"))
        {
            throw InvalidArguments();
        }

        return new ApproveBatchCommand(
            RequireAbsoluteLocalPath(options["--vault"]),
            market,
            RequireToken(options["--reviewer"], maximumLength: 128));
    }

    private static ValidateCommand ParseValidate(string[] arguments)
    {
        var options = ParseOptions(
            arguments,
            "--vault",
            "--output");
        return new ValidateCommand(
            RequireAbsoluteLocalPath(options["--vault"]),
            RequireAbsoluteLocalPath(options["--output"]));
    }

    private static SchemaCommand ParseSchema(string[] arguments)
    {
        var options = ParseOptions(arguments, "--output");
        return new SchemaCommand(
            RequireAbsoluteLocalPath(options["--output"]));
    }

    private static Dictionary<string, string> ParseOptions(
        string[] arguments,
        params string[] expectedOptions)
    {
        if (arguments.Length != 1 + (expectedOptions.Length * 2))
        {
            throw InvalidArguments();
        }

        var expected = expectedOptions.ToHashSet(StringComparer.Ordinal);
        var parsed = new Dictionary<string, string>(
            expectedOptions.Length,
            StringComparer.Ordinal);
        for (var index = 1; index < arguments.Length; index += 2)
        {
            var option = arguments[index];
            var value = arguments[index + 1];
            if (option is null
                || !expected.Contains(option)
                || !parsed.TryAdd(option, value)
                || string.IsNullOrEmpty(value)
                || value.StartsWith("--", StringComparison.Ordinal))
            {
                throw InvalidArguments();
            }
        }

        if (parsed.Count != expectedOptions.Length)
        {
            throw InvalidArguments();
        }

        return parsed;
    }

    private static string RequireAbsoluteLocalPath(string value)
    {
        if (!CanonicalWindowsPath.IsAccepted(value))
        {
            throw InvalidArguments();
        }

        return value;
    }

    private static string RequireToken(
        string value,
        int maximumLength)
    {
        if (value.Length is 0
            || value.Length > maximumLength
            || !value.All(static character =>
                character is >= 'a' and <= 'z'
                    or >= 'A' and <= 'Z'
                    or >= '0' and <= '9'
                    or '-'
                    or '_'
                    or '.'))
        {
            throw InvalidArguments();
        }

        return value;
    }

    private static string RequireLowerSha256(string value)
    {
        if (value.Length != 64
            || !value.All(static character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f'))
        {
            throw InvalidArguments();
        }

        return value;
    }

    private static WorkbenchException InvalidArguments() =>
        new(WorkbenchFailureCode.InvalidArguments);
}
