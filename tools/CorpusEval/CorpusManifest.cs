using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LocalDocumentOrganizer.CorpusEval;

public static class LaunchCorpusCatalog
{
    public static IReadOnlyList<string> MarketIds { get; } =
        ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"];

    public static IReadOnlyList<string> ContractIds { get; } =
        ["A1", "A2", "B1", "B2", "C1", "C2"];

    public static IReadOnlyList<string> AdvertisedRasterCodecIds { get; } =
        ["jpeg", "png", "tiff", "bmp"];
}

public enum CorpusKind
{
    [JsonStringEnumMemberName("synthetic")]
    Synthetic,

    [JsonStringEnumMemberName("owner-approved")]
    OwnerApproved,
}

public enum CorpusInputKind
{
    [JsonStringEnumMemberName("image-pdf")]
    ImagePdf,

    [JsonStringEnumMemberName("standalone-raster")]
    StandaloneRaster,
}

public enum CorpusPerturbationKind
{
    [JsonStringEnumMemberName("recompression")]
    Recompression,

    [JsonStringEnumMemberName("orientation")]
    Orientation,

    [JsonStringEnumMemberName("metadata")]
    Metadata,
}

public sealed record CorpusOwnerApproval(
    bool Approved,
    string ApprovalId,
    DateTimeOffset ApprovedAtUtc);

public sealed record CorpusLabelingSource(
    string Id,
    string Reference,
    bool IsOfficial);

public sealed record CorpusEvidenceRectangle(
    int SourceIndex,
    double X,
    double Y,
    double Width,
    double Height);

public sealed record CorpusExpectedField(
    string FieldId,
    string NormalizedValue,
    CorpusEvidenceRectangle Evidence);

public sealed record CorpusPerturbationLineage(
    string BaselineStableDocumentId,
    string BaselineContentSha256,
    CorpusPerturbationKind TransformationKind);

public sealed record CorpusCalibrationDocument(
    string StableDocumentId,
    string SourceFamilyId,
    string ContentSha256,
    string SourceLocator,
    string LanguageId,
    IReadOnlyList<string> LabelingSourceIds,
    bool OwnerApproved);

public sealed record CorpusHeldOutDocument(
    string StableDocumentId,
    string SourceFamilyId,
    string ContentSha256,
    string SourceLocator,
    string LanguageId,
    CorpusInputKind InputKind,
    string? CodecId,
    IReadOnlyList<string> LabelingSourceIds,
    bool OwnerApproved,
    IReadOnlyList<CorpusExpectedField> ExpectedFields,
    CorpusPerturbationLineage? PerturbationLineage = null);

public sealed record CorpusCell(
    string MarketId,
    string ContractId,
    IReadOnlyList<CorpusCalibrationDocument> CalibrationDocuments,
    IReadOnlyList<CorpusHeldOutDocument> HeldOutDocuments);

public sealed record CorpusCodecPerturbation(
    string CodecId,
    CorpusPerturbationKind Kind,
    string BaselineDocumentId,
    string VariantDocumentId);

public sealed record CorpusManifest(
    string SchemaVersion,
    CorpusKind CorpusKind,
    CorpusOwnerApproval OwnerApproval,
    string CatalogEpoch,
    IReadOnlyList<CorpusLabelingSource> LabelingSources,
    IReadOnlyList<string> AdvertisedRasterCodecs,
    IReadOnlyList<CorpusCell> Cells,
    IReadOnlyList<CorpusCodecPerturbation> CodecPerturbations);

public enum CorpusManifestFailureCode
{
    UnknownJsonMember,
    MalformedJson,
    InvalidLaunchCellSet,
    InsufficientHeldOutCoverage,
    DuplicateContentHash,
    SourceFamilyLeakage,
    OwnerApprovalRequired,
    InvalidLabelingSource,
    UnknownCatalogIdentifier,
    IncompleteCodecPerturbations,
    InvalidCodecPerturbation,
    DocumentLanguageMismatch,
    InvalidManifest,
}

public sealed class CorpusManifestException : Exception
{
    public CorpusManifestException(CorpusManifestFailureCode failureCode)
        : base($"corpus-manifest:{failureCode}")
    {
        FailureCode = failureCode;
    }

    public CorpusManifestFailureCode FailureCode { get; }
}

public static class CorpusManifestJson
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    public static byte[] Serialize(CorpusManifest manifest) =>
        JsonSerializer.SerializeToUtf8Bytes(manifest, Options);

    public static CorpusManifest Parse(ReadOnlySpan<byte> json)
    {
        try
        {
            return JsonSerializer.Deserialize<CorpusManifest>(json, Options)
                ?? throw new CorpusManifestException(
                    CorpusManifestFailureCode.MalformedJson);
        }
        catch (CorpusManifestException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            var code = exception.Message.Contains(
                "could not be mapped",
                StringComparison.OrdinalIgnoreCase)
                ? CorpusManifestFailureCode.UnknownJsonMember
                : CorpusManifestFailureCode.MalformedJson;
            throw new CorpusManifestException(code);
        }
    }

    public static string GenerateSchema() =>
        """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "title": "LocalDocumentOrganizer Corpus Manifest",
          "type": "object",
          "additionalProperties": false,
          "required": ["schemaVersion", "corpusKind", "ownerApproval", "catalogEpoch", "labelingSources", "advertisedRasterCodecs", "cells", "codecPerturbations"],
          "properties": {
            "schemaVersion": { "const": "1" },
            "corpusKind": { "enum": ["synthetic", "owner-approved"] },
            "ownerApproval": { "$ref": "#/$defs/ownerApproval" },
            "catalogEpoch": { "$ref": "#/$defs/token" },
            "labelingSources": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/labelingSource" } },
            "advertisedRasterCodecs": { "type": "array", "minItems": 4, "maxItems": 4, "uniqueItems": true, "items": { "enum": ["jpeg", "png", "tiff", "bmp"] } },
            "cells": { "type": "array", "minItems": 36, "maxItems": 36, "items": { "$ref": "#/$defs/cell" } },
            "codecPerturbations": { "type": "array", "minItems": 12, "maxItems": 12, "items": { "$ref": "#/$defs/codecPerturbation" } }
          },
          "$defs": {
            "token": { "type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$" },
            "id": { "type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" },
            "sha256": { "type": "string", "pattern": "^[A-Fa-f0-9]{64}$" },
            "sourceLocator": { "type": "string", "minLength": 1, "maxLength": 512, "pattern": "^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$" },
            "ownerApproval": {
              "type": "object",
              "additionalProperties": false,
              "required": ["approved", "approvalId", "approvedAtUtc"],
              "properties": {
                "approved": { "const": true },
                "approvalId": { "$ref": "#/$defs/id" },
                "approvedAtUtc": { "type": "string", "format": "date-time" }
              }
            },
            "labelingSource": {
              "type": "object",
              "additionalProperties": false,
              "required": ["id", "reference", "isOfficial"],
              "properties": {
                "id": { "$ref": "#/$defs/id" },
                "reference": { "type": "string", "minLength": 1, "maxLength": 2048, "format": "uri", "pattern": "^https://" },
                "isOfficial": { "const": true }
              }
            },
            "evidence": {
              "type": "object",
              "additionalProperties": false,
              "required": ["sourceIndex", "x", "y", "width", "height"],
              "properties": {
                "sourceIndex": { "type": "integer", "minimum": 0 },
                "x": { "type": "number", "minimum": 0 },
                "y": { "type": "number", "minimum": 0 },
                "width": { "type": "number", "exclusiveMinimum": 0 },
                "height": { "type": "number", "exclusiveMinimum": 0 }
              }
            },
            "expectedField": {
              "type": "object",
              "additionalProperties": false,
              "required": ["fieldId", "normalizedValue", "evidence"],
              "properties": {
                "fieldId": { "$ref": "#/$defs/id" },
                "normalizedValue": { "type": "string", "minLength": 1 },
                "evidence": { "$ref": "#/$defs/evidence" }
              }
            },
            "calibrationDocument": {
              "type": "object",
              "additionalProperties": false,
              "required": ["stableDocumentId", "sourceFamilyId", "contentSha256", "sourceLocator", "languageId", "labelingSourceIds", "ownerApproved"],
              "properties": {
                "stableDocumentId": { "$ref": "#/$defs/id" },
                "sourceFamilyId": { "$ref": "#/$defs/id" },
                "contentSha256": { "$ref": "#/$defs/sha256" },
                "sourceLocator": { "$ref": "#/$defs/sourceLocator" },
                "languageId": { "enum": ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"] },
                "labelingSourceIds": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/id" } },
                "ownerApproved": { "const": true }
              }
            },
            "heldOutDocument": {
              "type": "object",
              "additionalProperties": false,
              "required": ["stableDocumentId", "sourceFamilyId", "contentSha256", "sourceLocator", "languageId", "inputKind", "codecId", "labelingSourceIds", "ownerApproved", "expectedFields", "perturbationLineage"],
              "properties": {
                "stableDocumentId": { "$ref": "#/$defs/id" },
                "sourceFamilyId": { "$ref": "#/$defs/id" },
                "contentSha256": { "$ref": "#/$defs/sha256" },
                "sourceLocator": { "$ref": "#/$defs/sourceLocator" },
                "languageId": { "enum": ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"] },
                "inputKind": { "enum": ["image-pdf", "standalone-raster"] },
                "codecId": { "type": ["string", "null"], "enum": ["jpeg", "png", "tiff", "bmp", null] },
                "labelingSourceIds": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/id" } },
                "ownerApproved": { "const": true },
                "expectedFields": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/expectedField" } },
                "perturbationLineage": {
                  "oneOf": [
                    { "type": "null" },
                    { "$ref": "#/$defs/perturbationLineage" }
                  ]
                }
              }
            },
            "perturbationLineage": {
              "type": "object",
              "additionalProperties": false,
              "required": ["baselineStableDocumentId", "baselineContentSha256", "transformationKind"],
              "properties": {
                "baselineStableDocumentId": { "$ref": "#/$defs/id" },
                "baselineContentSha256": { "$ref": "#/$defs/sha256" },
                "transformationKind": { "enum": ["recompression", "orientation", "metadata"] }
              }
            },
            "cell": {
              "type": "object",
              "additionalProperties": false,
              "required": ["marketId", "contractId", "calibrationDocuments", "heldOutDocuments"],
              "properties": {
                "marketId": { "enum": ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"] },
                "contractId": { "enum": ["A1", "A2", "B1", "B2", "C1", "C2"] },
                "calibrationDocuments": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/calibrationDocument" } },
                "heldOutDocuments": { "type": "array", "minItems": 40, "items": { "$ref": "#/$defs/heldOutDocument" } }
              }
            },
            "codecPerturbation": {
              "type": "object",
              "additionalProperties": false,
              "required": ["codecId", "kind", "baselineDocumentId", "variantDocumentId"],
              "properties": {
                "codecId": { "enum": ["jpeg", "png", "tiff", "bmp"] },
                "kind": { "enum": ["recompression", "orientation", "metadata"] },
                "baselineDocumentId": { "$ref": "#/$defs/id" },
                "variantDocumentId": { "$ref": "#/$defs/id" }
              }
            }
          }
        }
        """;

    internal static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            NumberHandling = JsonNumberHandling.Strict,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
        };
        options.Converters.Add(
            new JsonStringEnumConverter<CorpusKind>(
                namingPolicy: null,
                allowIntegerValues: false));
        options.Converters.Add(
            new JsonStringEnumConverter<CorpusInputKind>(
                namingPolicy: null,
                allowIntegerValues: false));
        options.Converters.Add(
            new JsonStringEnumConverter<CorpusPerturbationKind>(
                namingPolicy: null,
                allowIntegerValues: false));
        return options;
    }
}

public static class CorpusManifestValidator
{
    public static void Validate(CorpusManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (manifest.SchemaVersion != "1"
            || !Enum.IsDefined(manifest.CorpusKind)
            || !IsToken(manifest.CatalogEpoch))
        {
            Fail(CorpusManifestFailureCode.InvalidManifest);
        }

        if (!manifest.OwnerApproval.Approved
            || !IsId(manifest.OwnerApproval.ApprovalId))
        {
            Fail(CorpusManifestFailureCode.OwnerApprovalRequired);
        }

        var labelingSourceIds = manifest.LabelingSources
            .Select(static source => source.Id)
            .ToHashSet(StringComparer.Ordinal);
        if (manifest.LabelingSources.Count == 0
            || labelingSourceIds.Count != manifest.LabelingSources.Count
            || manifest.LabelingSources.Any(
                static source =>
                    !source.IsOfficial
                    || !IsId(source.Id)
                    || !IsPublicHttpsReference(source.Reference)))
        {
            Fail(CorpusManifestFailureCode.InvalidLabelingSource);
        }

        if (!SetEquals(
                manifest.AdvertisedRasterCodecs,
                LaunchCorpusCatalog.AdvertisedRasterCodecIds))
        {
            Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
        }

        var expectedCells = (
            from market in LaunchCorpusCatalog.MarketIds
            from contract in LaunchCorpusCatalog.ContractIds
            select $"{market}\u001f{contract}")
            .ToHashSet(StringComparer.Ordinal);
        var actualCells = manifest.Cells
            .Select(static cell => $"{cell.MarketId}\u001f{cell.ContractId}")
            .ToArray();
        if (actualCells.Length != expectedCells.Count
            || actualCells.Distinct(StringComparer.Ordinal).Count()
                != actualCells.Length
            || actualCells.Any(cell => !expectedCells.Contains(cell)))
        {
            Fail(CorpusManifestFailureCode.InvalidLaunchCellSet);
        }

        ValidateDocuments(manifest, labelingSourceIds);
        ValidatePerturbations(manifest);
    }

    private static void ValidateDocuments(
        CorpusManifest manifest,
        IReadOnlySet<string> labelingSourceIds)
    {
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stableIds = new HashSet<string>(StringComparer.Ordinal);
        var locators = new HashSet<string>(StringComparer.Ordinal);
        var calibrationFamilies = new HashSet<string>(StringComparer.Ordinal);
        var heldOutFamilies = new HashSet<string>(StringComparer.Ordinal);

        foreach (var cell in manifest.Cells)
        {
            if (!LaunchCorpusCatalog.MarketIds.Contains(
                    cell.MarketId,
                    StringComparer.Ordinal)
                || !LaunchCorpusCatalog.ContractIds.Contains(
                    cell.ContractId,
                    StringComparer.Ordinal))
            {
                Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
            }

            if (cell.HeldOutDocuments.Count(
                    static document =>
                        document.InputKind == CorpusInputKind.ImagePdf)
                < 20
                || cell.HeldOutDocuments.Count(
                    static document =>
                        document.InputKind
                        == CorpusInputKind.StandaloneRaster)
                < 20)
            {
                Fail(CorpusManifestFailureCode.InsufficientHeldOutCoverage);
            }

            foreach (var document in cell.CalibrationDocuments)
            {
                if (document.LanguageId != cell.MarketId)
                {
                    Fail(CorpusManifestFailureCode.DocumentLanguageMismatch);
                }

                ValidateCommon(
                    document.StableDocumentId,
                    document.SourceFamilyId,
                    document.ContentSha256,
                    document.SourceLocator,
                    document.LabelingSourceIds,
                    document.OwnerApproved,
                    labelingSourceIds,
                    hashes,
                    stableIds,
                    locators);
                if (!calibrationFamilies.Add(document.SourceFamilyId))
                {
                    Fail(CorpusManifestFailureCode.SourceFamilyLeakage);
                }
            }

            foreach (var document in cell.HeldOutDocuments)
            {
                if (document.LanguageId != cell.MarketId)
                {
                    Fail(CorpusManifestFailureCode.DocumentLanguageMismatch);
                }

                if (!Enum.IsDefined(document.InputKind)
                    || document.InputKind == CorpusInputKind.ImagePdf
                        && document.CodecId is not null
                    || document.InputKind == CorpusInputKind.StandaloneRaster
                        && !LaunchCorpusCatalog.AdvertisedRasterCodecIds
                            .Contains(
                                document.CodecId!,
                                StringComparer.Ordinal))
                {
                    Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
                }

                ValidateCommon(
                    document.StableDocumentId,
                    document.SourceFamilyId,
                    document.ContentSha256,
                    document.SourceLocator,
                    document.LabelingSourceIds,
                    document.OwnerApproved,
                    labelingSourceIds,
                    hashes,
                    stableIds,
                    locators);
                heldOutFamilies.Add(document.SourceFamilyId);

                if (document.ExpectedFields.Count == 0
                    || document.ExpectedFields
                        .Select(static field => field.FieldId)
                        .Distinct(StringComparer.Ordinal)
                        .Count() != document.ExpectedFields.Count
                    || document.ExpectedFields.Any(
                        static field =>
                            !IsId(field.FieldId)
                            || string.IsNullOrWhiteSpace(
                                field.NormalizedValue)
                            || !IsEvidenceValid(field.Evidence)))
                {
                    Fail(CorpusManifestFailureCode.InvalidManifest);
                }
            }
        }

        if (calibrationFamilies.Overlaps(heldOutFamilies))
        {
            Fail(CorpusManifestFailureCode.SourceFamilyLeakage);
        }
    }

    private static void ValidateCommon(
        string stableDocumentId,
        string sourceFamilyId,
        string contentSha256,
        string sourceLocator,
        IReadOnlyList<string> sourceIds,
        bool ownerApproved,
        IReadOnlySet<string> knownSourceIds,
        ISet<string> hashes,
        ISet<string> stableIds,
        ISet<string> locators)
    {
        if (!IsId(stableDocumentId)
            || !IsId(sourceFamilyId)
            || !IsSha256(contentSha256)
            || !IsSafeRelativeLocator(sourceLocator)
            || !stableIds.Add(stableDocumentId)
            || !locators.Add(sourceLocator))
        {
            Fail(CorpusManifestFailureCode.InvalidManifest);
        }

        if (!hashes.Add(contentSha256))
        {
            Fail(CorpusManifestFailureCode.DuplicateContentHash);
        }

        if (!ownerApproved)
        {
            Fail(CorpusManifestFailureCode.OwnerApprovalRequired);
        }

        if (sourceIds.Count == 0
            || sourceIds.Distinct(StringComparer.Ordinal).Count()
                != sourceIds.Count
            || sourceIds.Any(id => !knownSourceIds.Contains(id)))
        {
            Fail(CorpusManifestFailureCode.InvalidLabelingSource);
        }
    }

    private static void ValidatePerturbations(CorpusManifest manifest)
    {
        var expectedPairs = (
            from codec in LaunchCorpusCatalog.AdvertisedRasterCodecIds
            from kind in Enum.GetValues<CorpusPerturbationKind>()
            select $"{codec}\u001f{kind}")
            .ToHashSet(StringComparer.Ordinal);
        var actualPairs = manifest.CodecPerturbations
            .Select(static item => $"{item.CodecId}\u001f{item.Kind}")
            .ToArray();
        if (actualPairs.Length != 12
            || actualPairs.Distinct(StringComparer.Ordinal).Count() != 12
            || actualPairs.Any(pair => !expectedPairs.Contains(pair)))
        {
            Fail(CorpusManifestFailureCode.IncompleteCodecPerturbations);
        }

        var heldOut = manifest.Cells
            .SelectMany(
                static cell => cell.HeldOutDocuments.Select(
                    document => new
                    {
                        Cell = cell,
                        Document = document,
                    }))
            .ToDictionary(
                static item => item.Document.StableDocumentId,
                StringComparer.Ordinal);
        var used = new HashSet<string>(StringComparer.Ordinal);
        var usedVariants = new HashSet<string>(StringComparer.Ordinal);
        foreach (var perturbation in manifest.CodecPerturbations)
        {
            if (perturbation.BaselineDocumentId
                == perturbation.VariantDocumentId)
            {
                Fail(CorpusManifestFailureCode.InvalidCodecPerturbation);
            }

            if (!heldOut.TryGetValue(
                    perturbation.BaselineDocumentId,
                    out var baselineItem))
            {
                Fail(CorpusManifestFailureCode.InvalidCodecPerturbation);
            }

            if (!heldOut.TryGetValue(
                    perturbation.VariantDocumentId,
                    out var variantItem))
            {
                Fail(CorpusManifestFailureCode.InvalidCodecPerturbation);
            }

            if (baselineItem.Cell.MarketId != variantItem.Cell.MarketId
                || baselineItem.Cell.ContractId != variantItem.Cell.ContractId
                || baselineItem.Document.SourceFamilyId
                    != variantItem.Document.SourceFamilyId
                || baselineItem.Document.ContentSha256
                    == variantItem.Document.ContentSha256
                || baselineItem.Document.PerturbationLineage is not null
                || variantItem.Document.PerturbationLineage is not
                    { } lineage
                || lineage.BaselineStableDocumentId
                    != baselineItem.Document.StableDocumentId
                || !string.Equals(
                    lineage.BaselineContentSha256,
                    baselineItem.Document.ContentSha256,
                    StringComparison.OrdinalIgnoreCase)
                || lineage.TransformationKind != perturbation.Kind
                || !ExpectedFieldsHaveApprovedRelation(
                    baselineItem.Document,
                    variantItem.Document,
                    perturbation.Kind)
                || !usedVariants.Add(
                    variantItem.Document.StableDocumentId)
                || !used.Add(baselineItem.Document.StableDocumentId)
                || !used.Add(variantItem.Document.StableDocumentId))
            {
                Fail(CorpusManifestFailureCode.InvalidCodecPerturbation);
            }

            var baseline = baselineItem.Document;
            var variant = variantItem.Document;
            if (baseline.InputKind != CorpusInputKind.StandaloneRaster
                || variant.InputKind != CorpusInputKind.StandaloneRaster
                || baseline.CodecId != perturbation.CodecId
                || variant.CodecId != perturbation.CodecId)
            {
                Fail(CorpusManifestFailureCode.InvalidCodecPerturbation);
            }
        }

        if (heldOut.Values.Any(
                item =>
                    item.Document.PerturbationLineage is not null
                    && !usedVariants.Contains(
                        item.Document.StableDocumentId)))
        {
            Fail(CorpusManifestFailureCode.InvalidCodecPerturbation);
        }

        foreach (var family in heldOut.Values.GroupBy(
                     static item => item.Document.SourceFamilyId,
                     StringComparer.Ordinal))
        {
            var documents = family
                .Select(static item => item.Document)
                .ToArray();
            if (documents.Length == 1)
            {
                continue;
            }

            if (documents.Length != 2
                || !manifest.CodecPerturbations.Any(
                    pair =>
                        documents.Any(
                            document =>
                                document.StableDocumentId
                                == pair.BaselineDocumentId)
                        && documents.Any(
                            document =>
                                document.StableDocumentId
                                == pair.VariantDocumentId)))
            {
                Fail(CorpusManifestFailureCode.InvalidCodecPerturbation);
            }
        }
    }

    private static bool ExpectedFieldsHaveApprovedRelation(
        CorpusHeldOutDocument baseline,
        CorpusHeldOutDocument variant,
        CorpusPerturbationKind kind)
    {
        var baselineFields = baseline.ExpectedFields
            .OrderBy(static field => field.FieldId, StringComparer.Ordinal)
            .ToArray();
        var variantFields = variant.ExpectedFields
            .OrderBy(static field => field.FieldId, StringComparer.Ordinal)
            .ToArray();
        if (baselineFields.Length != variantFields.Length)
        {
            return false;
        }

        for (var index = 0; index < baselineFields.Length; index++)
        {
            if (baselineFields[index].FieldId != variantFields[index].FieldId
                || baselineFields[index].NormalizedValue
                    != variantFields[index].NormalizedValue)
            {
                return false;
            }

            if (kind is not CorpusPerturbationKind.Orientation
                && baselineFields[index].Evidence
                    != variantFields[index].Evidence)
            {
                return false;
            }
        }

        return true;
    }

    private static bool SetEquals(
        IReadOnlyList<string> actual,
        IReadOnlyList<string> expected) =>
        actual.Count == expected.Count
        && actual.ToHashSet(StringComparer.Ordinal)
            .SetEquals(expected);

    private static bool IsEvidenceValid(CorpusEvidenceRectangle evidence) =>
        evidence.SourceIndex >= 0
        && double.IsFinite(evidence.X)
        && evidence.X >= 0
        && double.IsFinite(evidence.Y)
        && evidence.Y >= 0
        && double.IsFinite(evidence.Width)
        && evidence.Width > 0
        && double.IsFinite(evidence.Height)
        && evidence.Height > 0;

    private static bool IsSafeRelativeLocator(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 512
            || Path.IsPathFullyQualified(value)
            || value.Contains('\\')
            || value.Split(
                    '/',
                    StringSplitOptions.RemoveEmptyEntries)
                .Any(static segment => segment is "." or ".."))
        {
            return false;
        }

        return value.All(
            static character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-' or '/');
    }

    private static bool IsPublicHttpsReference(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps
        && !string.IsNullOrWhiteSpace(uri.Host)
        && string.IsNullOrEmpty(uri.UserInfo);

    private static bool IsId(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128
        && char.IsAsciiLetterOrDigit(value[0])
        && value.All(
            static character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-');

    private static bool IsToken(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128
        && char.IsAsciiLetterOrDigit(value[0])
        && value.All(
            static character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-' or '+');

    private static bool IsSha256(string value) =>
        value is not null
        && value.Length == 64
        && value.All(Uri.IsHexDigit);

    [DoesNotReturn]
    private static void Fail(CorpusManifestFailureCode code) =>
        throw new CorpusManifestException(code);
}
