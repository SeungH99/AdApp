using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Text.RegularExpressions;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Contracts;
using LocalDocumentOrganizer.Application.Rules;
using LocalDocumentOrganizer.Core.Documents;

namespace LocalDocumentOrganizer.Application.Processing;

/// <summary>
/// The protected result of one immutable extraction attempt. A market is only
/// recorded when the worker evidence supports exactly one pilot market.
/// </summary>
public sealed record AuthenticatedExtractionDraft(
    DocumentExtractionResponse Extraction,
    string? SuggestedMarket,
    bool IsComplete);

public sealed class ExtractionDraftSerializationException : Exception
{
}

public static class AuthenticatedExtractionDraftSerializer
{
    public static string Serialize(
        DocumentExtractionResponse extraction,
        ExtractionMarketSuggestion marketSuggestion,
        bool isComplete)
    {
        ArgumentNullException.ThrowIfNull(extraction);
        ArgumentNullException.ThrowIfNull(marketSuggestion);
        if (marketSuggestion.MarketId is { } marketId
            && !PilotCatalog.MarketIds.Contains(marketId, StringComparer.Ordinal))
        {
            throw new InvoiceRuleException(ApplicationFailureCode.InvalidState);
        }

        var serialized = JsonSerializer.Serialize(
            new AuthenticatedExtractionDraft(extraction, marketSuggestion.MarketId, isComplete));
        if (serialized.Length > DocumentExtractionLimits.MaxSerializedResponseBytes)
        {
            throw new ExtractionDraftSerializationException();
        }

        return serialized;
    }
}

public sealed record ExtractionMarketSuggestion(string? MarketId)
{
    public static ExtractionMarketSuggestion Uncertain { get; } = new((string?)null);
}

public interface IExtractionMarketSuggester
{
    ExtractionMarketSuggestion Suggest(DocumentExtractionResponse extraction);
}

/// <summary>
/// Uses the same signed official-rule catalogs as invoice labeling. It treats
/// source text as evidence only; requested OCR languages are deliberately not
/// an input to this decision.
/// </summary>
public sealed class OfficialRuleMarketSuggester : IExtractionMarketSuggester
{
    private static readonly Regex Hangul = new("[\\uAC00-\\uD7A3]", RegexOptions.CultureInvariant);
    private static readonly Regex KoreanCurrency = new(@"(?<![A-Z])KRW(?![A-Z])|₩|원", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly Regex UsCurrency = new(@"(?<![A-Z])USD(?![A-Z])|US\\$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private readonly FrozenDictionary<string, ImmutableArray<string>> _officialLabelsByMarket;

    public OfficialRuleMarketSuggester(IEnumerable<OfficialRuleCatalogSnapshot> catalogs)
    {
        ArgumentNullException.ThrowIfNull(catalogs);
        var labels = new Dictionary<string, ImmutableArray<string>>(StringComparer.Ordinal);
        foreach (var catalog in catalogs)
        {
            ArgumentNullException.ThrowIfNull(catalog);
            OfficialRuleCatalog.Validate(catalog.Document);
            if (!PilotCatalog.MarketIds.Contains(catalog.Document.MarketId, StringComparer.Ordinal)
                || labels.ContainsKey(catalog.Document.MarketId))
            {
                throw new InvoiceRuleException(ApplicationFailureCode.InvalidArguments);
            }

            labels.Add(
                catalog.Document.MarketId,
                catalog.Document.Rules
                    .SelectMany(static rule => rule.AcceptedVisibleLabels)
                    .Where(static label => !string.IsNullOrWhiteSpace(label))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Order(StringComparer.OrdinalIgnoreCase)
                    .ToImmutableArray());
        }

        _officialLabelsByMarket = labels.ToFrozenDictionary(StringComparer.Ordinal);
    }

    public ExtractionMarketSuggestion Suggest(DocumentExtractionResponse extraction)
    {
        ArgumentNullException.ThrowIfNull(extraction);
        if (extraction.ProtocolVersion != DocumentExtractionProtocol.CurrentVersion
            || extraction.Outcome != DocumentExtractionOutcome.Success
            || extraction.FailureCode != DocumentExtractionFailureCode.None
            || extraction.Fragments.IsDefaultOrEmpty)
        {
            return ExtractionMarketSuggestion.Uncertain;
        }

        var text = string.Join('\n', extraction.Fragments
            .OrderBy(static fragment => fragment.SourceIndex)
            .Select(static fragment => fragment.Text));
        var candidates = new HashSet<string>(StringComparer.Ordinal);
        if (Hangul.IsMatch(text) || KoreanCurrency.IsMatch(text))
            candidates.Add("ko-KR");
        if (UsCurrency.IsMatch(text))
            candidates.Add("en-US");

        foreach (var (marketId, labels) in _officialLabelsByMarket)
        {
            if (labels.Any(label => text.Contains(label, StringComparison.OrdinalIgnoreCase)))
                candidates.Add(marketId);
        }

        return candidates.Count == 1
            ? new ExtractionMarketSuggestion(candidates.Single())
            : ExtractionMarketSuggestion.Uncertain;
    }
}
