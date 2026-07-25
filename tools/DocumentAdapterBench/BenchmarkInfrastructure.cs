using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace LocalDocumentOrganizer.DocumentAdapterBench;

public sealed record PdfPigPackageMetadata(
    string Id,
    string Version,
    string License,
    string PackageSha512);

public static class PdfPigPackageInspector
{
    public const string ExpectedId = "PdfPig";
    public const string ExpectedVersion = "0.1.15";
    public const string ExpectedLicense = "Apache-2.0";

    public static PdfPigPackageMetadata Inspect(string? packageRoot = null)
    {
        packageRoot = string.IsNullOrWhiteSpace(packageRoot)
            ? ResolveActivePackageRoot()
            : Path.GetFullPath(packageRoot);
        var directory = Path.Combine(
            packageRoot,
            ExpectedId.ToLowerInvariant(),
            ExpectedVersion);
        var nuspecPath = Path.Combine(directory, "pdfpig.nuspec");
        var packagePath = Path.Combine(
            directory,
            $"pdfpig.{ExpectedVersion}.nupkg");
        var hashPath = packagePath + ".sha512";
        if (!File.Exists(nuspecPath)
            || !File.Exists(packagePath)
            || !File.Exists(hashPath))
        {
            throw new InvalidDataException(
                "The active PdfPig package is incomplete.");
        }

        var document = XDocument.Load(
            nuspecPath,
            LoadOptions.None);
        var metadata = document.Root?
            .Elements()
            .SingleOrDefault(static element => element.Name.LocalName == "metadata")
            ?? throw new InvalidDataException(
                "The PdfPig nuspec has no metadata element.");
        var id = RequiredValue(metadata, "id");
        var version = RequiredValue(metadata, "version");
        var licenseElement = metadata.Elements().SingleOrDefault(
            static element => element.Name.LocalName == "license");
        var license = licenseElement?.Value?.Trim();
        var licenseType = licenseElement?.Attribute("type")?.Value;
        if (!string.Equals(id, ExpectedId, StringComparison.Ordinal)
            || !string.Equals(version, ExpectedVersion, StringComparison.Ordinal)
            || !string.Equals(
                licenseType,
                "expression",
                StringComparison.Ordinal)
            || !string.Equals(
                license,
                ExpectedLicense,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The active PdfPig package metadata is not the pinned package.");
        }

        var expectedHash = File.ReadAllText(hashPath).Trim();
        byte[] expectedHashBytes;
        try
        {
            expectedHashBytes = Convert.FromBase64String(expectedHash);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "The PdfPig package hash is malformed.",
                exception);
        }

        using var package = new FileStream(
            packagePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        var actualHashBytes = SHA512.HashData(package);
        if (!CryptographicOperations.FixedTimeEquals(
                expectedHashBytes,
                actualHashBytes))
        {
            throw new InvalidDataException(
                "The PdfPig package hash does not match its NuGet hash.");
        }

        return new PdfPigPackageMetadata(
            id,
            version,
            license!,
            Convert.ToHexString(actualHashBytes).ToLowerInvariant());
    }

    public static string ResolveActivePackageRoot()
    {
        var configured = Environment.GetEnvironmentVariable("NUGET_PACKAGES");
        return string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".nuget",
                "packages")
            : Path.GetFullPath(configured);
    }

    private static string RequiredValue(XElement metadata, string localName)
    {
        var value = metadata.Elements()
            .SingleOrDefault(element => element.Name.LocalName == localName)
            ?.Value
            ?.Trim();
        return string.IsNullOrWhiteSpace(value)
            ? throw new InvalidDataException(
                $"The PdfPig nuspec is missing {localName}.")
            : value;
    }
}

public static class BenchmarkHashing
{
    private const int BufferSize = 81_920;

    public static string ComputeSha256(Stream stream) =>
        Convert.ToHexString(ComputeHash(stream, HashAlgorithmName.SHA256))
            .ToLowerInvariant();

    public static byte[] ComputeHash(
        Stream stream,
        HashAlgorithmName algorithmName)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek)
        {
            throw new ArgumentException(
                "Benchmark streams must be readable and seekable.",
                nameof(stream));
        }

        var originalPosition = stream.Position;
        try
        {
            stream.Position = 0;
            using var hash = IncrementalHash.CreateHash(algorithmName);
            var buffer = new byte[BufferSize];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                hash.AppendData(buffer, 0, read);
            }

            return hash.GetHashAndReset();
        }
        finally
        {
            stream.Position = originalPosition;
        }
    }

    public static void AppendStream(
        IncrementalHash hash,
        Stream stream)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek)
        {
            throw new ArgumentException(
                "Benchmark streams must be readable and seekable.",
                nameof(stream));
        }

        var originalPosition = stream.Position;
        try
        {
            stream.Position = 0;
            var buffer = new byte[BufferSize];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                hash.AppendData(buffer, 0, read);
            }
        }
        finally
        {
            stream.Position = originalPosition;
        }
    }
}

public sealed record BenchmarkChildProcessSpec(
    string FileName,
    IReadOnlyList<string> Arguments,
    string ResultPath);

public static class BenchmarkChildProcessRunner
{
    public static async Task<IReadOnlyList<AdapterCandidateMeasurement>>
        RunAllAsync(
            IReadOnlyList<BenchmarkChildProcessSpec> specifications,
            TimeSpan timeout,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(specifications);
        var results = new List<AdapterCandidateMeasurement>(
            specifications.Count);
        foreach (var specification in specifications)
        {
            results.Add(
                await RunAsync(specification, timeout, cancellationToken)
                    .ConfigureAwait(false));
        }

        return results
            .OrderBy(
                static measurement => measurement.AdapterId,
                StringComparer.Ordinal)
            .ToArray();
    }

    public static async Task<AdapterCandidateMeasurement> RunAsync(
        BenchmarkChildProcessSpec specification,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(specification);
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        var resultPath = Path.GetFullPath(specification.ResultPath);
        File.Delete(resultPath);
        var startInfo = new ProcessStartInfo
        {
            FileName = specification.FileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in specification.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "The benchmark child process could not be started.");
        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        var wait = process.WaitForExitAsync(cancellationToken);
        var completed = await Task.WhenAny(
                wait,
                Task.Delay(timeout, cancellationToken))
            .ConfigureAwait(false);
        if (completed != wait)
        {
            KillProcess(process);
            await process.WaitForExitAsync(CancellationToken.None)
                .ConfigureAwait(false);
            throw new TimeoutException(
                "The benchmark child process exceeded its timeout.");
        }

        await wait.ConfigureAwait(false);
        var errorText = await stderr.ConfigureAwait(false);
        _ = await stdout.ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"The benchmark child exited with code {process.ExitCode}: "
                + errorText.Trim());
        }

        if (!File.Exists(resultPath))
        {
            throw new InvalidDataException(
                "The benchmark child did not write its result.");
        }

        await using var result = new FileStream(
            resultPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        return await JsonSerializer.DeserializeAsync<AdapterCandidateMeasurement>(
                result,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                },
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException(
                "The benchmark child result was empty.");
    }

    private static void KillProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
            // The process exited between the state check and kill request.
        }
    }
}
