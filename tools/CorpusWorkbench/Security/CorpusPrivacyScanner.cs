using System.Collections;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;

namespace LocalDocumentOrganizer.CorpusWorkbench.Security;

public static class CorpusPrivacyScanner
{
    internal const int MaximumReportBytes = 64 * 1024;
    private const int MaximumJsonDepth = 12;
    private const int MaximumDecodedStringLength = 4 * 1024;
    private const int MaximumBlockingReasons = 32;
    private const int MaximumAggregateEntries = 32;
    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly HashSet<string> RootKeys =
        new(StringComparer.Ordinal)
        {
            "schemaVersion",
            "catalogEpoch",
            "contractId",
            "ruleCatalogSha256",
            "workerValidationMode",
            "workerPackageSha256",
            "ledgerHeadSha256",
            "pilotComplete",
            "primaryFailureCode",
            "blockingReasons",
            "markets",
            "reportSha256",
        };
    private static readonly HashSet<string> MarketKeys =
        new(StringComparer.Ordinal)
        {
            "marketId",
            "eligibleDocumentCount",
            "imagePdfCount",
            "standaloneRasterCount",
            "sourceFamilyCount",
            "directReviewCount",
            "delegatedLabelCount",
            "batchApproved",
            "aggregateErrorCounts",
        };
    private static readonly string PrivateSentinel =
        "PRIVATE" + "-LABEL-SENTINEL";

    public static void ScanOrThrow(
        ReadOnlySpan<byte> utf8,
        IEnumerable<string>? privateSentinels = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (utf8.Length is 0 or > MaximumReportBytes)
            {
                throw PrivacyFailure();
            }

            var text = StrictUtf8.GetString(utf8);
            if (text.IndexOf('\0') >= 0
                || ContainsPrivateText(text)
                || ContainsEnvironmentValue(
                    text,
                    cancellationToken)
                || ContainsSentinel(
                    text,
                    privateSentinels,
                    cancellationToken))
            {
                throw PrivacyFailure();
            }

            cancellationToken.ThrowIfCancellationRequested();
            using var document = JsonDocument.Parse(
                utf8.ToArray(),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = MaximumJsonDepth,
                });
            ScanDecoded(
                document.RootElement,
                privateSentinels,
                cancellationToken);
            ValidateRoot(
                document.RootElement,
                cancellationToken);
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
            exception is JsonException
                or DecoderFallbackException
                or InvalidOperationException
                or FormatException
                or OverflowException)
        {
            throw PrivacyFailure(exception);
        }
    }

    private static void ValidateRoot(
        JsonElement root,
        CancellationToken cancellationToken)
    {
        RequireObjectKeys(root, RootKeys, cancellationToken);
        RequireString(
            root,
            "schemaVersion",
            PilotCatalog.SchemaVersion);
        RequireSafeIdentifier(root, "catalogEpoch");
        RequireString(
            root,
            "contractId",
            PilotCatalog.ContractId);
        RequireSha256(root, "ruleCatalogSha256");
        ValidateWorkerIdentity(root);
        RequireSha256(root, "ledgerHeadSha256");
        RequireBoolean(root, "pilotComplete");
        ValidateNullableFailureCode(root, "primaryFailureCode");
        ValidateBlockingReasons(
            root.GetProperty("blockingReasons"),
            cancellationToken);
        ValidateMarkets(
            root.GetProperty("markets"),
            cancellationToken);
        RequireSha256(root, "reportSha256");
    }

    private static void ValidateWorkerIdentity(JsonElement root)
    {
        var mode = RequireStringValue(
            root,
            "workerValidationMode");
        var packageHash = root.GetProperty(
            "workerPackageSha256");
        if (string.Equals(mode, "pending", StringComparison.Ordinal)
            && packageHash.ValueKind == JsonValueKind.Null)
        {
            return;
        }

        if (!string.Equals(mode, "bound", StringComparison.Ordinal)
            || packageHash.ValueKind != JsonValueKind.String
            || !Validation.PilotValidator.IsLowerSha256(
                packageHash.GetString()))
        {
            throw PrivacyFailure();
        }
    }

    private static void ValidateBlockingReasons(
        JsonElement reasons,
        CancellationToken cancellationToken)
    {
        if (reasons.ValueKind != JsonValueKind.Array)
        {
            throw PrivacyFailure();
        }

        var seen = new HashSet<WorkbenchFailureCode>();
        foreach (var reason in reasons.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (seen.Count >= MaximumBlockingReasons)
            {
                throw PrivacyFailure();
            }

            if (reason.ValueKind != JsonValueKind.String
                || !Enum.TryParse<WorkbenchFailureCode>(
                    reason.GetString(),
                    ignoreCase: false,
                    out var code)
                || !seen.Add(code))
            {
                throw PrivacyFailure();
            }
        }
    }

    private static void ValidateMarkets(
        JsonElement markets,
        CancellationToken cancellationToken)
    {
        if (markets.ValueKind != JsonValueKind.Array)
        {
            throw PrivacyFailure();
        }

        var previous = string.Empty;
        var count = 0;
        foreach (var market in markets.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            count = checked(count + 1);
            if (count > PilotCatalog.MarketIds.Length)
            {
                throw PrivacyFailure();
            }

            RequireObjectKeys(
                market,
                MarketKeys,
                cancellationToken);
            var marketId = RequireStringValue(market, "marketId");
            if (!PilotCatalog.MarketIds.Contains(
                    marketId,
                    StringComparer.Ordinal)
                || string.CompareOrdinal(previous, marketId) >= 0)
            {
                throw PrivacyFailure();
            }

            previous = marketId;
            RequireNonNegativeInteger(
                market,
                "eligibleDocumentCount");
            RequireNonNegativeInteger(market, "imagePdfCount");
            RequireNonNegativeInteger(
                market,
                "standaloneRasterCount");
            RequireNonNegativeInteger(
                market,
                "sourceFamilyCount");
            RequireNonNegativeInteger(
                market,
                "directReviewCount");
            RequireNonNegativeInteger(
                market,
                "delegatedLabelCount");
            RequireBoolean(market, "batchApproved");
            ValidateAggregateErrors(
                market.GetProperty("aggregateErrorCounts"),
                cancellationToken);
        }

        if (count != PilotCatalog.MarketIds.Length)
        {
            throw PrivacyFailure();
        }
    }

    private static void ValidateAggregateErrors(
        JsonElement errors,
        CancellationToken cancellationToken)
    {
        if (errors.ValueKind != JsonValueKind.Object)
        {
            throw PrivacyFailure();
        }

        var previous = string.Empty;
        var entryCount = 0;
        foreach (var property in errors.EnumerateObject())
        {
            cancellationToken.ThrowIfCancellationRequested();
            entryCount = checked(entryCount + 1);
            if (entryCount > MaximumAggregateEntries)
            {
                throw PrivacyFailure();
            }

            if (string.CompareOrdinal(previous, property.Name) >= 0
                || !Enum.TryParse<WorkbenchFailureCode>(
                    property.Name,
                    ignoreCase: false,
                    out _)
                || property.Value.ValueKind != JsonValueKind.Number
                || !property.Value.TryGetInt32(out var valueCount)
                || valueCount <= 0)
            {
                throw PrivacyFailure();
            }

            previous = property.Name;
        }
    }

    private static void RequireObjectKeys(
        JsonElement value,
        IReadOnlySet<string> allowed,
        CancellationToken cancellationToken)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw PrivacyFailure();
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!allowed.Contains(property.Name)
                || !seen.Add(property.Name))
            {
                throw PrivacyFailure();
            }
        }

        if (seen.Count != allowed.Count)
        {
            throw PrivacyFailure();
        }
    }

    private static void ScanDecoded(
        JsonElement value,
        IEnumerable<string>? privateSentinels,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in value.EnumerateObject())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ScanDecodedText(
                        property.Name,
                        privateSentinels,
                        cancellationToken);
                    ScanDecoded(
                        property.Value,
                        privateSentinels,
                        cancellationToken);
                }

                break;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ScanDecoded(
                        item,
                        privateSentinels,
                        cancellationToken);
                }

                break;
            case JsonValueKind.String:
                ScanDecodedText(
                    value.GetString() ?? throw PrivacyFailure(),
                    privateSentinels,
                    cancellationToken);
                break;
        }
    }

    private static void ScanDecodedText(
        string text,
        IEnumerable<string>? privateSentinels,
        CancellationToken cancellationToken)
    {
        if (text.Length > MaximumDecodedStringLength
            || text.IndexOf('\0') >= 0
            || ContainsPrivateText(text)
            || ContainsEnvironmentValue(text, cancellationToken)
            || ContainsSentinel(
                text,
                privateSentinels,
                cancellationToken))
        {
            throw PrivacyFailure();
        }
    }

    private static void RequireString(
        JsonElement value,
        string propertyName,
        string expected)
    {
        if (!string.Equals(
                RequireStringValue(value, propertyName),
                expected,
                StringComparison.Ordinal))
        {
            throw PrivacyFailure();
        }
    }

    private static string RequireStringValue(
        JsonElement value,
        string propertyName)
    {
        var property = value.GetProperty(propertyName);
        if (property.ValueKind != JsonValueKind.String)
        {
            throw PrivacyFailure();
        }

        return property.GetString() ?? throw PrivacyFailure();
    }

    private static void RequireSafeIdentifier(
        JsonElement value,
        string propertyName)
    {
        var text = RequireStringValue(value, propertyName);
        if (text.Length is 0 or > 64
            || text.Any(static character =>
                !char.IsAsciiLetterOrDigit(character)
                && character is not ('-' or '_' or '.')))
        {
            throw PrivacyFailure();
        }
    }

    private static void RequireSha256(
        JsonElement value,
        string propertyName)
    {
        if (!Validation.PilotValidator.IsLowerSha256(
                RequireStringValue(value, propertyName)))
        {
            throw PrivacyFailure();
        }
    }

    private static void RequireBoolean(
        JsonElement value,
        string propertyName)
    {
        if (value.GetProperty(propertyName).ValueKind
            is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw PrivacyFailure();
        }
    }

    private static void RequireNonNegativeInteger(
        JsonElement value,
        string propertyName)
    {
        var property = value.GetProperty(propertyName);
        if (property.ValueKind != JsonValueKind.Number
            || !property.TryGetInt32(out var number)
            || number < 0)
        {
            throw PrivacyFailure();
        }
    }

    private static void ValidateNullableFailureCode(
        JsonElement value,
        string propertyName)
    {
        var property = value.GetProperty(propertyName);
        if (property.ValueKind == JsonValueKind.Null)
        {
            return;
        }

        if (property.ValueKind != JsonValueKind.String
            || !Enum.TryParse<WorkbenchFailureCode>(
                property.GetString(),
                ignoreCase: false,
                out _))
        {
            throw PrivacyFailure();
        }
    }

    private static bool ContainsPrivateText(string text)
    {
        var lower = text.ToLowerInvariant();
        return lower.Contains("document-", StringComparison.Ordinal)
            || lower.Contains("source-family", StringComparison.Ordinal)
            || lower.Contains("family-", StringComparison.Ordinal)
            || lower.Contains("receipt-", StringComparison.Ordinal)
            || lower.Contains("revision-", StringComparison.Ordinal)
            || lower.Contains("bearer ", StringComparison.Ordinal)
            || lower.Contains("authorization:", StringComparison.Ordinal)
            || lower.Contains("password=", StringComparison.Ordinal)
            || lower.Contains("password:", StringComparison.Ordinal)
            || lower.Contains("token=", StringComparison.Ordinal)
            || lower.Contains("token:", StringComparison.Ordinal)
            || lower.Contains("secret=", StringComparison.Ordinal)
            || lower.Contains("secret:", StringComparison.Ordinal)
            || lower.Contains("api_key", StringComparison.Ordinal)
            || lower.Contains("apikey", StringComparison.Ordinal)
            || lower.Contains("client_secret", StringComparison.Ordinal)
            || lower.Contains(".pdf", StringComparison.Ordinal)
            || lower.Contains(".doc", StringComparison.Ordinal)
            || lower.Contains(".docx", StringComparison.Ordinal)
            || lower.Contains(".xls", StringComparison.Ordinal)
            || lower.Contains(".xlsx", StringComparison.Ordinal)
            || lower.Contains(".csv", StringComparison.Ordinal)
            || lower.Contains(".png", StringComparison.Ordinal)
            || lower.Contains(".jpg", StringComparison.Ordinal)
            || lower.Contains(".jpeg", StringComparison.Ordinal)
            || lower.Contains(".tif", StringComparison.Ordinal)
            || lower.Contains(".tiff", StringComparison.Ordinal)
            || lower.Contains(@"\\", StringComparison.Ordinal)
            || lower.Contains("approval-", StringComparison.Ordinal)
            || lower.Contains("entry-", StringComparison.Ordinal)
            || lower.Contains("/home/", StringComparison.Ordinal)
            || lower.Contains("/users/", StringComparison.Ordinal)
            || ContainsDrivePath(text)
            || ContainsPosixPath(text);
    }

    private static bool ContainsDrivePath(string text)
    {
        for (var index = 0; index + 2 < text.Length; index++)
        {
            if (char.IsAsciiLetter(text[index])
                && text[index + 1] == ':'
                && text[index + 2] is '\\' or '/')
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsPosixPath(string text)
    {
        for (var index = 0; index < text.Length; index++)
        {
            if (text[index] != '/')
            {
                continue;
            }

            if (index + 1 < text.Length
                && text[index + 1] is not '/' and not ' ')
            {
                return true;
            }
        }

        return text.Contains("../", StringComparison.Ordinal)
            || text.Contains("./", StringComparison.Ordinal);
    }

    private static bool ContainsEnvironmentValue(
        string text,
        CancellationToken cancellationToken)
    {
        foreach (DictionaryEntry entry in
                 Environment.GetEnvironmentVariables())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.Value is not string value
                || value.Length < 8
                || value.All(char.IsDigit))
            {
                continue;
            }

            if (text.Contains(
                    value,
                    StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsSentinel(
        string text,
        IEnumerable<string>? sentinels,
        CancellationToken cancellationToken)
    {
        if (text.Contains(
                PrivateSentinel,
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (sentinels is null)
        {
            return false;
        }

        foreach (var sentinel in sentinels)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(sentinel)
                || sentinel.Length > 4096)
            {
                throw PrivacyFailure();
            }

            if (text.Contains(
                    sentinel,
                    StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static WorkbenchException PrivacyFailure(
        Exception? inner = null) =>
        new(WorkbenchFailureCode.PrivacyLeakDetected, inner);
}
