using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.CorpusWorkbench.Validation;

public sealed class PilotReportWriter
{
    private const string ReportHashDomain =
        "corpus-workbench-report-v1\n";
    internal const int MaximumReportBytes = 64 * 1024;
    private readonly PilotAuthenticationService _authentication;
    private readonly Action<PilotReportFaultPoint>? _injectFault;

    public PilotReportWriter(CorpusWorkbench.Vault.CorpusVault vault)
    {
        _authentication = new PilotAuthenticationService(vault);
    }

    internal PilotReportWriter(
        PilotAuthenticationService authentication,
        Action<PilotReportFaultPoint>? injectFault = null)
    {
        _authentication = authentication
            ?? throw new ArgumentNullException(
                nameof(authentication));
        _injectFault = injectFault;
    }

    public async Task<string> SerializeAsync(
        PilotValidationResult result,
        CancellationToken cancellationToken) =>
        Encoding.UTF8.GetString(
            await SerializeBytesAsync(result, cancellationToken)
                .ConfigureAwait(false));

    public async Task<byte[]> SerializeBytesAsync(
        PilotValidationResult result,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var envelope = await CreateEnvelopeAsync(
                result,
                cancellationToken)
            .ConfigureAwait(false);
        var bytes = SerializeCanonical(envelope);
        CorpusPrivacyScanner.ScanOrThrow(
            bytes,
            cancellationToken: cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return bytes;
    }

    public async Task<PilotReportEnvelope> WriteAsync(
        PilotValidationResult result,
        string outputPath,
        CancellationToken cancellationToken)
    {
        var envelope = await CreateEnvelopeAsync(
                result,
                cancellationToken)
            .ConfigureAwait(false);
        var bytes = SerializeCanonical(envelope);
        CorpusPrivacyScanner.ScanOrThrow(
            bytes,
            cancellationToken: cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        await PublishAtomicAsync(
                outputPath,
                bytes,
                cancellationToken)
            .ConfigureAwait(false);
        return envelope;
    }

    private async ValueTask<PilotReportEnvelope> CreateEnvelopeAsync(
        PilotValidationResult result,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        await PilotResultAttestation.VerifyAsync(
                result,
                _authentication,
                cancellationToken)
            .ConfigureAwait(false);
        var scope = result.Scope
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        ValidateResult(result, scope);
        ImmutableArray<PilotMarketSummary> canonicalMarkets =
        [
            .. result.Markets
                .OrderBy(
                    static market => market.MarketId,
                    StringComparer.Ordinal)
                .Select(CanonicalMarket),
        ];
        ImmutableArray<WorkbenchFailureCode> canonicalReasons =
        [
            .. result.BlockingReasons,
        ];
        var unhashed = new PilotReportEnvelope(
            scope.SchemaVersion,
            scope.CatalogEpoch,
            scope.ContractId,
            result.RuleCatalogSha256,
            result.WorkerPackageSha256,
            result.LedgerHeadSha256,
            result.PilotComplete,
            result.PrimaryFailureCode,
            canonicalReasons,
            canonicalMarkets,
            ReportSha256: string.Empty);
        var payload = SerializeCanonical(
            unhashed,
            includeReportHash: false);
        var hashInput = new byte[
            Encoding.UTF8.GetByteCount(ReportHashDomain)
            + payload.Length];
        var domainLength = Encoding.UTF8.GetBytes(
            ReportHashDomain,
            hashInput);
        payload.CopyTo(hashInput.AsSpan(domainLength));
        var reportHash = Convert.ToHexStringLower(
            SHA256.HashData(hashInput));
        return unhashed with
        {
            ReportSha256 = reportHash,
        };
    }

    private static void ValidateResult(
        PilotValidationResult result,
        PilotScope scope)
    {
        if (!string.Equals(
                scope.SchemaVersion,
                PilotCatalog.SchemaVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                scope.ContractId,
                PilotCatalog.ContractId,
                StringComparison.Ordinal)
            || scope.CatalogEpoch is not { Length: > 0 and <= 64 }
            || scope.HeldOutTargetPerMarket
                != PilotCatalog.HeldOutTargetPerMarket
            || scope.DirectReviewTargetPerMarket
                != PilotCatalog.DirectReviewTargetPerMarket
            || !PilotValidator.IsLowerSha256(
                result.RuleCatalogSha256)
            || !PilotValidator.IsLowerSha256(
                result.WorkerPackageSha256)
            || !PilotValidator.IsLowerSha256(
                result.LedgerHeadSha256)
            || result.BlockingReasons.IsDefault
            || result.BlockingReasons.Length > 32
            || result.Markets.IsDefault
            || result.PilotComplete
                != result.BlockingReasons.IsEmpty
            || result.PrimaryFailureCode
                != (result.BlockingReasons.IsEmpty
                    ? null
                    : result.BlockingReasons[0])
            || !PilotValidator.OrderFailures(
                    result.BlockingReasons)
                .AsSpan()
                .SequenceEqual(result.BlockingReasons.AsSpan())
            || scope.MarketIds.IsDefaultOrEmpty
            || scope.MarketIds.Length != PilotCatalog.MarketIds.Length
            || !scope.MarketIds.Order(StringComparer.Ordinal)
                .SequenceEqual(
                    PilotCatalog.MarketIds.Order(
                        StringComparer.Ordinal),
                    StringComparer.Ordinal)
            || result.Markets.Length != PilotCatalog.MarketIds.Length
            || scope.MarketIds
                .Order(StringComparer.Ordinal)
                .SequenceEqual(
                    result.Markets
                        .Select(static market => market.MarketId)
                        .Order(StringComparer.Ordinal),
                    StringComparer.Ordinal)
                is false
            || result.Markets
                .Select(static market => market.MarketId)
                .Distinct(StringComparer.Ordinal)
                .Count() != result.Markets.Length
            || result.PilotComplete
                && result.Markets.Any(static market =>
                    market.EligibleDocumentCount
                        != PilotCatalog.HeldOutTargetPerMarket
                    || market.DirectReviewCount
                        != PilotCatalog
                            .DirectReviewTargetPerMarket
                    || market.DelegatedLabelCount
                        != PilotCatalog.HeldOutTargetPerMarket
                            - PilotCatalog
                                .DirectReviewTargetPerMarket
                    || !market.BatchApproved
                    || market.AggregateErrorCounts is null
                    || market.AggregateErrorCounts.Count != 0)
            || result.Markets.Any(IsInvalidMarket))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.PrivacyLeakDetected);
        }
    }

    private static bool IsInvalidMarket(PilotMarketSummary market) =>
        market is null
        || market.EligibleDocumentCount < 0
        || market.ImagePdfCount < 0
        || market.StandaloneRasterCount < 0
        || market.SourceFamilyCount < 0
        || market.DirectReviewCount < 0
        || market.DelegatedLabelCount < 0
        || market.EligibleDocumentCount
            > PilotCatalog.HeldOutTargetPerMarket
        || market.ImagePdfCount + market.StandaloneRasterCount
            > market.EligibleDocumentCount
        || market.SourceFamilyCount
            > market.EligibleDocumentCount
        || market.DirectReviewCount
            + market.DelegatedLabelCount
            > market.EligibleDocumentCount
        || market.AggregateErrorCounts is null
        || market.AggregateErrorCounts.Count > 32
        || market.AggregateErrorCounts.Any(pair =>
            !Enum.TryParse<WorkbenchFailureCode>(
                pair.Key,
                ignoreCase: false,
                out _)
            || pair.Value <= 0);

    private static PilotMarketSummary CanonicalMarket(
        PilotMarketSummary market)
    {
        ArgumentNullException.ThrowIfNull(market);
        if (market.AggregateErrorCounts is null)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.PrivacyLeakDetected);
        }

        return market with
        {
            AggregateErrorCounts =
                ImmutableDictionary.CreateRange(
                    StringComparer.Ordinal,
                    market.AggregateErrorCounts
                        .OrderBy(
                            static pair => pair.Key,
                            StringComparer.Ordinal)),
        };
    }

    private static byte[] SerializeCanonical(
        PilotReportEnvelope envelope,
        bool includeReportHash = true)
    {
        try
        {
            using var stream =
                new BoundedMemoryStream(MaximumReportBytes);
            using (var writer = new Utf8JsonWriter(
                       stream,
                       new JsonWriterOptions
                       {
                           Indented = false,
                           SkipValidation = false,
                       }))
            {
                writer.WriteStartObject();
                writer.WriteString(
                    "schemaVersion",
                    envelope.SchemaVersion);
                writer.WriteString(
                    "catalogEpoch",
                    envelope.CatalogEpoch);
                writer.WriteString("contractId", envelope.ContractId);
                writer.WriteString(
                    "ruleCatalogSha256",
                    envelope.RuleCatalogSha256);
                writer.WriteString(
                    "workerPackageSha256",
                    envelope.WorkerPackageSha256);
                writer.WriteString(
                    "ledgerHeadSha256",
                    envelope.LedgerHeadSha256);
                writer.WriteBoolean(
                    "pilotComplete",
                    envelope.PilotComplete);
                if (envelope.PrimaryFailureCode is { } primary)
                {
                    writer.WriteString(
                        "primaryFailureCode",
                        primary.ToString());
                }
                else
                {
                    writer.WriteNull("primaryFailureCode");
                }

                writer.WriteStartArray("blockingReasons");
                foreach (var reason in envelope.BlockingReasons)
                {
                    writer.WriteStringValue(reason.ToString());
                }

                writer.WriteEndArray();
                writer.WriteStartArray("markets");
                foreach (var market in envelope.Markets)
                {
                    WriteMarket(writer, market);
                }

                writer.WriteEndArray();
                if (includeReportHash)
                {
                    writer.WriteString(
                        "reportSha256",
                        envelope.ReportSha256);
                }

                writer.WriteEndObject();
            }

            return stream.ToArray();
        }
        catch (BoundedBufferExceededException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.PrivacyLeakDetected,
                exception);
        }
    }

    private static void WriteMarket(
        Utf8JsonWriter writer,
        PilotMarketSummary market)
    {
        writer.WriteStartObject();
        writer.WriteString("marketId", market.MarketId);
        writer.WriteNumber(
            "eligibleDocumentCount",
            market.EligibleDocumentCount);
        writer.WriteNumber("imagePdfCount", market.ImagePdfCount);
        writer.WriteNumber(
            "standaloneRasterCount",
            market.StandaloneRasterCount);
        writer.WriteNumber(
            "sourceFamilyCount",
            market.SourceFamilyCount);
        writer.WriteNumber(
            "directReviewCount",
            market.DirectReviewCount);
        writer.WriteNumber(
            "delegatedLabelCount",
            market.DelegatedLabelCount);
        writer.WriteBoolean(
            "batchApproved",
            market.BatchApproved);
        writer.WriteStartObject("aggregateErrorCounts");
        foreach (var pair in market.AggregateErrorCounts
                     .OrderBy(
                         static item => item.Key,
                         StringComparer.Ordinal))
        {
            writer.WriteNumber(pair.Key, pair.Value);
        }

        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private async Task PublishAtomicAsync(
        string outputPath,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        if (!Path.IsPathFullyQualified(outputPath)
            || !string.Equals(
                Path.GetFullPath(outputPath),
                outputPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        var parent = Path.GetDirectoryName(outputPath);
        var fileName = Path.GetFileName(outputPath);
        if (string.IsNullOrWhiteSpace(parent)
            || string.IsNullOrWhiteSpace(fileName)
            || fileName.EndsWith(' ')
            || fileName.EndsWith('.'))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        try
        {
            var guard = new ApprovedRootPathGuard(parent);
            using var store = new ApprovedRootFileStore(guard);
            SafeFileHandle? staged = null;
            string? stagedName = null;
            var ownership = new FilePromotionOwnership();
            try
            {
                for (var attempt = 0; attempt < 16; attempt++)
                {
                    stagedName = ".pilot-report-"
                        + Guid.NewGuid().ToString("N")
                        + ".tmp";
                    try
                    {
                        staged = store.CreateNewPromotableVerified(
                            stagedName,
                            bytes.Length);
                        break;
                    }
                    catch (FileStoreEntryAlreadyExistsException)
                    {
                    }
                }

                if (staged is null || stagedName is null)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidState);
                }

                await RandomAccess.WriteAsync(
                        staged,
                        bytes,
                        fileOffset: 0,
                        cancellationToken)
                    .ConfigureAwait(false);
                RandomAccess.FlushToDisk(staged);
                store.RevalidateCreated(
                    staged,
                    stagedName,
                    bytes.Length);
                CorpusPrivacyScanner.ScanOrThrow(
                    bytes,
                    cancellationToken: cancellationToken);
                _injectFault?.Invoke(
                    PilotReportFaultPoint
                        .AfterStagingBeforePublish);
                cancellationToken.ThrowIfCancellationRequested();
                if (!store.PromoteCreatedNoReplace(
                        staged,
                        stagedName,
                        fileName,
                        bytes.Length,
                        ownership))
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.InvalidState);
                }
            }
            finally
            {
                if (staged is not null
                    && stagedName is not null
                    && !ownership.IsTransferred)
                {
                    try
                    {
                        store.DeleteOwnedOnClose(
                            staged,
                            stagedName,
                            bytes.Length);
                    }
                    catch
                    {
                        // The publication or cancellation failure stays
                        // primary; the owned handle still closes below.
                    }
                }

                staged?.Dispose();
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or IOException
                or UnauthorizedAccessException
                or System.Security.SecurityException
                or ArgumentException
                or NotSupportedException
                or PathTooLongException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }
    }
}

internal enum PilotReportFaultPoint
{
    AfterStagingBeforePublish = 0,
}
