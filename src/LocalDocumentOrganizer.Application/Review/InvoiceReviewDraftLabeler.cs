using System.Collections.Frozen;
using System.Collections.Immutable;
using LocalDocumentOrganizer.Application.Contracts;
using LocalDocumentOrganizer.Application.Labels;
using LocalDocumentOrganizer.Application.Processing;
using LocalDocumentOrganizer.Application.Rules;

namespace LocalDocumentOrganizer.Application.Review;

public interface IInvoiceReviewDraftLabeler
{
    ImmutableDictionary<string, ReviewExtractionField> Label(
        string confirmedMarket,
        AuthenticatedExtractionDraft draft);
}

public sealed class OfficialInvoiceReviewDraftLabeler :
    IInvoiceReviewDraftLabeler
{
    private readonly FrozenDictionary<string, OfficialRuleCatalogSnapshot>
        _rulesByMarket;
    private readonly InvoiceDraftLabeler _labeler = new();

    public OfficialInvoiceReviewDraftLabeler(
        IEnumerable<OfficialRuleCatalogSnapshot> catalogs)
    {
        ArgumentNullException.ThrowIfNull(catalogs);
        var rules = new Dictionary<string, OfficialRuleCatalogSnapshot>(
            StringComparer.Ordinal);
        foreach (var catalog in catalogs)
        {
            ArgumentNullException.ThrowIfNull(catalog);
            OfficialRuleCatalog.Validate(catalog.Document);
            if (!PilotCatalog.MarketIds.Contains(
                    catalog.Document.MarketId,
                    StringComparer.Ordinal)
                || !rules.TryAdd(catalog.Document.MarketId, catalog))
            {
                throw new InvoiceRuleException(
                    ApplicationFailureCode.InvalidArguments);
            }
        }

        _rulesByMarket = rules.ToFrozenDictionary(StringComparer.Ordinal);
    }

    public ImmutableDictionary<string, ReviewExtractionField> Label(
        string confirmedMarket,
        AuthenticatedExtractionDraft draft)
    {
        ArgumentNullException.ThrowIfNull(draft);
        if (!_rulesByMarket.TryGetValue(confirmedMarket, out var rules))
        {
            throw new InvoiceRuleException(
                ApplicationFailureCode.InvalidArguments);
        }

        var labeled = _labeler.CreateDraft(
            new InvoiceLabelingContext(
                confirmedMarket,
                PilotCatalog.ContractId),
            draft.Extraction,
            rules);
        return labeled.Fields.ToImmutableDictionary(
            static field => field.FieldId,
            static field => new ReviewExtractionField(
                field.FieldId,
                field.NormalizedValue is InvoiceDraftLabeler.AbsentValue
                    or InvoiceDraftLabeler.UncertainValue
                    ? null
                    : field.NormalizedValue),
            StringComparer.Ordinal);
    }
}
