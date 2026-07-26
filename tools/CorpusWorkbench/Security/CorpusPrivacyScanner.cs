using System.Collections;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;

namespace LocalDocumentOrganizer.CorpusWorkbench.Security;

public static class CorpusPrivacyScanner
{
    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly HashSet<string> RootKeys =
        new(StringComparer.Ordinal)
        {
            "schemaVersion",
            "catalogEpoch",
            "contractId",
            "ruleCatalogSha256",
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
        IEnumerable<string>? privateSentinels = null)
    {
        try
        {
            var text = StrictUtf8.GetString(utf8);
            if (text.Length == 0
                || text.IndexOf('\0') >= 0
                || ContainsPrivateText(text)
                || ContainsEnvironmentValue(text)
                || ContainsSentinel(text, privateSentinels))
            {
                throw PrivacyFailure();
            }

            using var document = JsonDocument.Parse(
                utf8.ToArray(),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = 16,
                });
            ValidateRoot(document.RootElement);
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

    private static void ValidateRoot(JsonElement root)
    {
        RequireObjectKeys(root, RootKeys);
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
        RequireSha256(root, "workerPackageSha256");
        RequireSha256(root, "ledgerHeadSha256");
        RequireBoolean(root, "pilotComplete");
        ValidateNullableFailureCode(root, "primaryFailureCode");
        ValidateBlockingReasons(root.GetProperty("blockingReasons"));
        ValidateMarkets(root.GetProperty("markets"));
        RequireSha256(root, "reportSha256");
    }

    private static void ValidateBlockingReasons(JsonElement reasons)
    {
        if (reasons.ValueKind != JsonValueKind.Array)
        {
            throw PrivacyFailure();
        }

        var seen = new HashSet<WorkbenchFailureCode>();
        foreach (var reason in reasons.EnumerateArray())
        {
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

    private static void ValidateMarkets(JsonElement markets)
    {
        if (markets.ValueKind != JsonValueKind.Array)
        {
            throw PrivacyFailure();
        }

        var previous = string.Empty;
        foreach (var market in markets.EnumerateArray())
        {
            RequireObjectKeys(market, MarketKeys);
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
                market.GetProperty("aggregateErrorCounts"));
        }
    }

    private static void ValidateAggregateErrors(JsonElement errors)
    {
        if (errors.ValueKind != JsonValueKind.Object)
        {
            throw PrivacyFailure();
        }

        var previous = string.Empty;
        foreach (var property in errors.EnumerateObject())
        {
            if (string.CompareOrdinal(previous, property.Name) >= 0
                || !Enum.TryParse<WorkbenchFailureCode>(
                    property.Name,
                    ignoreCase: false,
                    out _)
                || property.Value.ValueKind != JsonValueKind.Number
                || !property.Value.TryGetInt32(out var count)
                || count <= 0)
            {
                throw PrivacyFailure();
            }

            previous = property.Name;
        }
    }

    private static void RequireObjectKeys(
        JsonElement value,
        IReadOnlySet<string> allowed)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw PrivacyFailure();
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
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
            || lower.Contains("password=", StringComparison.Ordinal)
            || lower.Contains("password:", StringComparison.Ordinal)
            || lower.Contains("token=", StringComparison.Ordinal)
            || lower.Contains("secret=", StringComparison.Ordinal)
            || lower.Contains(".pdf", StringComparison.Ordinal)
            || lower.Contains(".png", StringComparison.Ordinal)
            || lower.Contains(".jpg", StringComparison.Ordinal)
            || lower.Contains(".jpeg", StringComparison.Ordinal)
            || lower.Contains(".tif", StringComparison.Ordinal)
            || lower.Contains(".tiff", StringComparison.Ordinal)
            || lower.Contains(@"\\", StringComparison.Ordinal)
            || lower.Contains("/home/", StringComparison.Ordinal)
            || lower.Contains("/users/", StringComparison.Ordinal)
            || ContainsDrivePath(text);
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

    private static bool ContainsEnvironmentValue(string text)
    {
        foreach (DictionaryEntry entry in
                 Environment.GetEnvironmentVariables())
        {
            if (entry.Value is not string value
                || value.Length < 8
                || value.All(char.IsDigit))
            {
                continue;
            }

            if (text.Contains(value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsSentinel(
        string text,
        IEnumerable<string>? sentinels)
    {
        if (text.Contains(PrivateSentinel, StringComparison.Ordinal))
        {
            return true;
        }

        if (sentinels is null)
        {
            return false;
        }

        foreach (var sentinel in sentinels)
        {
            if (string.IsNullOrEmpty(sentinel)
                || sentinel.Length > 4096)
            {
                throw PrivacyFailure();
            }

            if (text.Contains(sentinel, StringComparison.Ordinal))
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
