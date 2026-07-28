using System.Collections.Frozen;
using System.Collections.Immutable;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Labels;
using ApplicationContracts = LocalDocumentOrganizer.Application.Contracts;
using ApplicationRules = LocalDocumentOrganizer.Application.Rules;

namespace LocalDocumentOrganizer.CorpusWorkbench.Rules;

public static class OfficialRuleCatalog
{
    public static async Task<OfficialRuleCatalogSnapshot> LoadAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            return ToWorkbench(await ApplicationRules.OfficialRuleCatalog.LoadAsync(
                path,
                cancellationToken).ConfigureAwait(false));
        }
        catch (ApplicationContracts.InvoiceRuleException error)
        {
            throw InvoiceDraftLabeler.ToWorkbench(error);
        }
    }

    internal static string ComputePilotCatalogSha256(
        IEnumerable<OfficialRuleCatalogSnapshot> snapshots)
    {
        try
        {
            return ApplicationRules.OfficialRuleCatalog.ComputeCatalogSha256(
                snapshots.Select(InvoiceDraftLabeler.ToApplication));
        }
        catch (ApplicationContracts.InvoiceRuleException error)
        {
            throw InvoiceDraftLabeler.ToWorkbench(error);
        }
    }

    private static OfficialRuleCatalogSnapshot ToWorkbench(
        ApplicationContracts.OfficialRuleCatalogSnapshot snapshot) =>
        new(
            new OfficialRuleCatalogDocument(
                snapshot.Document.SchemaVersion,
                snapshot.Document.MarketId,
                snapshot.Document.ContractId,
                snapshot.Document.Sources.Select(static source => new OfficialRuleSource(
                    source.Id,
                    source.Uri,
                    source.Publisher,
                    source.PublishedOrRevisedOn,
                    source.VerifiedOn)).ToImmutableArray(),
                snapshot.Document.Rules.Select(static rule => new OfficialFieldRule(
                    rule.RuleId,
                    rule.FieldId,
                    rule.Normalization,
                    rule.AcceptedVisibleLabels,
                    rule.SourceIds)).ToImmutableArray()),
            snapshot.CatalogSha256,
            snapshot.RulesByFieldId.ToFrozenDictionary(
                static pair => pair.Key,
                static pair => new OfficialFieldRule(
                    pair.Value.RuleId,
                    pair.Value.FieldId,
                    pair.Value.Normalization,
                    pair.Value.AcceptedVisibleLabels,
                    pair.Value.SourceIds),
                StringComparer.Ordinal));
}

internal static class OfficialRuleCatalogValidator
{
    public static void Validate(OfficialRuleCatalogDocument document)
    {
        try
        {
            ApplicationRules.OfficialRuleCatalog.Validate(
                InvoiceDraftLabeler.ToApplication(document));
        }
        catch (ApplicationContracts.InvoiceRuleException error)
        {
            throw InvoiceDraftLabeler.ToWorkbench(error);
        }
    }
}

internal static class CanonicalRuleCatalog
{
    public static byte[] Serialize(OfficialRuleCatalogDocument document) =>
        ApplicationRules.OfficialRuleCatalog.SerializeCanonical(
            InvoiceDraftLabeler.ToApplication(document));
}
