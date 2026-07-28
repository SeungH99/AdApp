using System.Collections.Frozen;
using System.Collections.Immutable;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using ApplicationContracts = LocalDocumentOrganizer.Application.Contracts;
using ApplicationLabels = LocalDocumentOrganizer.Application.Labels;

namespace LocalDocumentOrganizer.CorpusWorkbench.Labels;

public sealed record LabelDraft(ImmutableArray<LabeledField> Fields);

// Keeps the corpus tool's legacy contracts at its edge while reusing the
// product-owned invoice labeling behavior.
public sealed class InvoiceDraftLabeler
{
    public const string AbsentValue = ApplicationLabels.InvoiceDraftLabeler.AbsentValue;
    public const string UncertainValue = ApplicationLabels.InvoiceDraftLabeler.UncertainValue;

    private readonly ApplicationLabels.InvoiceDraftLabeler _labeler = new();

    public LabelDraft CreateDraft(
        WorkbenchDocument document,
        DocumentExtractionResponse extraction,
        OfficialRuleCatalogSnapshot rules)
    {
        try
        {
            var draft = _labeler.CreateDraft(
                new ApplicationContracts.WorkbenchDocument(
                    document.DocumentId,
                    document.ContentSha256,
                    document.SourceFamilyId,
                    document.MarketId,
                    document.ContractId,
                    document.InputKind,
                    document.CodecId,
                    document.ReceiptId,
                    document.LifecycleState,
                    document.CreatedAtUtc),
                extraction,
                ToApplication(rules));
            return new LabelDraft(
                draft.Fields.Select(static field => new LabeledField(
                    field.FieldId,
                    field.NormalizedValue,
                    field.Evidence.Select(static evidence => new EvidenceBox(
                        evidence.SourceIndex,
                        evidence.X,
                        evidence.Y,
                        evidence.Width,
                        evidence.Height)).ToImmutableArray(),
                    field.RuleId)).ToImmutableArray());
        }
        catch (ApplicationContracts.InvoiceRuleException error)
        {
            throw ToWorkbench(error);
        }
    }

    internal static ApplicationContracts.OfficialRuleCatalogSnapshot ToApplication(
        OfficialRuleCatalogSnapshot snapshot) =>
        new(
            ToApplication(snapshot.Document),
            snapshot.CatalogSha256,
            snapshot.RulesByFieldId.ToFrozenDictionary(
                static pair => pair.Key,
                static pair => new ApplicationContracts.OfficialFieldRule(
                    pair.Value.RuleId,
                    pair.Value.FieldId,
                    pair.Value.Normalization,
                    pair.Value.AcceptedVisibleLabels,
                    pair.Value.SourceIds),
                StringComparer.Ordinal));

    internal static ApplicationContracts.OfficialRuleCatalogDocument ToApplication(
        OfficialRuleCatalogDocument document) =>
        new(
            document.SchemaVersion,
            document.MarketId,
            document.ContractId,
            document.Sources.Select(static source =>
                new ApplicationContracts.OfficialRuleSource(
                    source.Id,
                    source.Uri,
                    source.Publisher,
                    source.PublishedOrRevisedOn,
                    source.VerifiedOn)).ToImmutableArray(),
            document.Rules.Select(static rule =>
                new ApplicationContracts.OfficialFieldRule(
                    rule.RuleId,
                    rule.FieldId,
                    rule.Normalization,
                    rule.AcceptedVisibleLabels,
                    rule.SourceIds)).ToImmutableArray());

    internal static WorkbenchException ToWorkbench(
        ApplicationContracts.InvoiceRuleException error) =>
        new(error.FailureCode switch
        {
            ApplicationContracts.ApplicationFailureCode.InvalidArguments =>
                WorkbenchFailureCode.InvalidArguments,
            ApplicationContracts.ApplicationFailureCode.SourceUnverified =>
                WorkbenchFailureCode.SourceUnverified,
            ApplicationContracts.ApplicationFailureCode.MissingEvidence =>
                WorkbenchFailureCode.MissingEvidence,
            _ => WorkbenchFailureCode.InvalidState,
        });
}
