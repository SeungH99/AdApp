using System.Text.Json;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Security;

namespace LocalDocumentOrganizer.CorpusWorkbench.Validation;

internal static class PilotResultAttestation
{
    internal const string Version =
        "corpus-workbench-result-attestation-v1";
    private const int MaximumCanonicalBytes = 64 * 1024;
    private const int MaximumStringLength = 4 * 1024;
    private const int MaximumBlockingReasons = 32;
    private const int MaximumAggregateEntries = 32;

    internal static async ValueTask<PilotValidationResult> IssueAsync(
        PilotValidationResult result,
        PilotAuthenticationService authentication,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        var canonical = SerializeCanonical(
            result,
            cancellationToken);
        byte[] attestation;
        try
        {
            attestation = await authentication.AttestResultAsync(
                    canonical,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (PilotAuthenticationException exception)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation,
                exception);
        }

        return result with
        {
            AttestationVersion = Version,
            Attestation = attestation,
        };
    }

    internal static async ValueTask VerifyAsync(
        PilotValidationResult result,
        PilotAuthenticationService authentication,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(authentication);
        if (!string.Equals(
                result.AttestationVersion,
                Version,
                StringComparison.Ordinal)
            || result.Attestation is not { Length: 32 } attestation)
        {
            throw InvalidAttestation();
        }

        var canonical = SerializeCanonical(
            result,
            cancellationToken);
        try
        {
            if (!await authentication.VerifyResultAsync(
                        canonical,
                        attestation,
                        cancellationToken)
                    .ConfigureAwait(false))
            {
                throw InvalidAttestation();
            }
        }
        catch (PilotAuthenticationException exception)
        {
            throw InvalidAttestation(exception);
        }
    }

    private static byte[] SerializeCanonical(
        PilotValidationResult result,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        cancellationToken.ThrowIfCancellationRequested();
        var scope = result.Scope ?? throw InvalidAttestation();
        ValidateString(scope.SchemaVersion);
        ValidateString(scope.CatalogEpoch);
        ValidateString(scope.ContractId);
        ValidateString(result.RuleCatalogSha256);
        ValidateString(result.LedgerHeadSha256);
        ValidateWorkerValidationState(result);
        if (scope.MarketIds.IsDefault
            || scope.MarketIds.Length > PilotCatalog.MarketIds.Length
            || result.Markets.IsDefault
            || result.Markets.Length > PilotCatalog.MarketIds.Length
            || result.BlockingReasons.IsDefault
            || result.BlockingReasons.Length > MaximumBlockingReasons)
        {
            throw InvalidAttestation();
        }

        try
        {
            using var stream =
                new BoundedMemoryStream(MaximumCanonicalBytes);
            using (var writer = new Utf8JsonWriter(
                       stream,
                       new JsonWriterOptions
                       {
                           Indented = false,
                           SkipValidation = false,
                       }))
            {
                writer.WriteStartObject();
                writer.WriteString("version", Version);
                writer.WriteStartObject("scope");
                writer.WriteString(
                    "schemaVersion",
                    scope.SchemaVersion);
                writer.WriteString(
                    "catalogEpoch",
                    scope.CatalogEpoch);
                writer.WriteString("contractId", scope.ContractId);
                writer.WriteStartArray("marketIds");
                foreach (var marketId in scope.MarketIds)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ValidateString(marketId);
                    writer.WriteStringValue(marketId);
                }

                writer.WriteEndArray();
                writer.WriteNumber(
                    "heldOutTargetPerMarket",
                    scope.HeldOutTargetPerMarket);
                writer.WriteNumber(
                    "directReviewTargetPerMarket",
                    scope.DirectReviewTargetPerMarket);
                writer.WriteEndObject();
                writer.WriteString(
                    "ruleCatalogSha256",
                    result.RuleCatalogSha256);
                writer.WriteString(
                    "workerValidationMode",
                    result.WorkerValidationMode
                        == PilotWorkerValidationMode.BoundWorker
                        ? "bound"
                        : "pending");
                if (result.WorkerPackageSha256 is { } workerHash)
                {
                    writer.WriteString(
                        "workerPackageSha256",
                        workerHash);
                }
                else
                {
                    writer.WriteNull("workerPackageSha256");
                }

                if (result.ValidationSnapshotSha256 is { } snapshot)
                {
                    writer.WriteString(
                        "validationSnapshotSha256",
                        snapshot);
                }
                else
                {
                    writer.WriteNull("validationSnapshotSha256");
                }

                if (result.ConfigurationIdentitySha256 is { } config)
                {
                    writer.WriteString(
                        "configurationIdentitySha256",
                        config);
                }
                else
                {
                    writer.WriteNull(
                        "configurationIdentitySha256");
                }
                writer.WriteString(
                    "ledgerHeadSha256",
                    result.LedgerHeadSha256);
                writer.WriteBoolean(
                    "pilotComplete",
                    result.PilotComplete);
                if (result.PrimaryFailureCode is { } primary)
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
                foreach (var reason in result.BlockingReasons)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    writer.WriteStringValue(reason.ToString());
                }

                writer.WriteEndArray();
                writer.WriteStartArray("markets");
                foreach (var market in result.Markets)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    WriteMarket(
                        writer,
                        market,
                        cancellationToken);
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            return stream.ToArray();
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
            exception is BoundedBufferExceededException
                or InvalidOperationException
                or ArgumentException
                or OverflowException)
        {
            throw InvalidAttestation(exception);
        }
    }

    private static void WriteMarket(
        Utf8JsonWriter writer,
        PilotMarketSummary market,
        CancellationToken cancellationToken)
    {
        if (market is null
            || market.AggregateErrorCounts is null
            || market.AggregateErrorCounts.Count
                > MaximumAggregateEntries)
        {
            throw InvalidAttestation();
        }

        ValidateString(market.MarketId);
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
        writer.WriteBoolean("batchApproved", market.BatchApproved);
        writer.WriteStartObject("aggregateErrorCounts");
        foreach (var pair in market.AggregateErrorCounts
                     .OrderBy(
                         static pair => pair.Key,
                         StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateString(pair.Key);
            writer.WriteNumber(pair.Key, pair.Value);
        }

        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void ValidateString(string? value)
    {
        if (value is null || value.Length > MaximumStringLength)
        {
            throw InvalidAttestation();
        }
    }

    private static void ValidateWorkerValidationState(
        PilotValidationResult result)
    {
        if (result.WorkerValidationMode
                == PilotWorkerValidationMode.BoundWorker
            && PilotValidator.IsLowerSha256(
                result.WorkerPackageSha256)
            && result.ValidationSnapshotSha256 is null
            && result.ConfigurationIdentitySha256 is null)
        {
            return;
        }

        if (result.WorkerValidationMode
                == PilotWorkerValidationMode.PendingUnassigned
            && result.WorkerPackageSha256 is null
            && !result.PilotComplete
            && result.PrimaryFailureCode
                == WorkbenchFailureCode.CoverageIncomplete
            && result.BlockingReasons.AsSpan().SequenceEqual(
                [WorkbenchFailureCode.CoverageIncomplete])
            && PilotValidator.IsLowerSha256(
                result.ValidationSnapshotSha256)
            && PilotValidator.IsLowerSha256(
                result.ConfigurationIdentitySha256))
        {
            return;
        }

        throw InvalidAttestation();
    }

    private static WorkbenchException InvalidAttestation(
        Exception? inner = null) =>
        new(WorkbenchFailureCode.InvalidState, inner);
}
