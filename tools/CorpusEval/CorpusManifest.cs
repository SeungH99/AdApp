using System.Text.Json;
using System.Text.Json.Serialization;
using System.Diagnostics.CodeAnalysis;

namespace LocalDocumentOrganizer.CorpusEval;

public static class LaunchCorpusCatalog
{
    public static IReadOnlyList<string> MarketIds { get; } =
        ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"];

    public static IReadOnlyList<string> ContractIds { get; } =
        ["A1", "A2", "B1", "B2", "C1", "C2"];

    public static IReadOnlyList<string> LanguageIds { get; } =
        ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"];

    public static IReadOnlyList<string> AdvertisedRasterCodecIds { get; } =
        ["jpeg", "png", "tiff", "bmp"];
}

[JsonConverter(typeof(JsonStringEnumConverter<CorpusInputKind>))]
public enum CorpusInputKind
{
    [JsonStringEnumMemberName("image-pdf")]
    ImagePdf,

    [JsonStringEnumMemberName("standalone-raster")]
    StandaloneRaster,
}

[JsonConverter(typeof(JsonStringEnumConverter<CorpusPerturbationKind>))]
public enum CorpusPerturbationKind
{
    [JsonStringEnumMemberName("recompression")]
    Recompression,

    [JsonStringEnumMemberName("orientation")]
    Orientation,

    [JsonStringEnumMemberName("metadata")]
    Metadata,
}

[JsonConverter(typeof(JsonStringEnumConverter<CorpusOutputDisposition>))]
public enum CorpusOutputDisposition
{
    [JsonStringEnumMemberName("accepted")]
    Accepted,

    [JsonStringEnumMemberName("needs-review")]
    NeedsReview,

    [JsonStringEnumMemberName("unsupported")]
    Unsupported,
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

public sealed record CorpusObservedField(
    string FieldId,
    string NormalizedValue,
    CorpusEvidenceRectangle? Evidence);

public sealed record CorpusCalibrationDocument(
    string StableDocumentId,
    string SourceFamilyId,
    string ContentSha256,
    string LanguageId,
    IReadOnlyList<string> LabelingSourceIds,
    bool OwnerApproved);

public sealed record CorpusHeldOutDocument(
    string StableDocumentId,
    string SourceFamilyId,
    string ContentSha256,
    string LanguageId,
    CorpusInputKind InputKind,
    string? CodecId,
    IReadOnlyList<string> LabelingSourceIds,
    bool OwnerApproved,
    IReadOnlyList<CorpusExpectedField> ExpectedFields,
    IReadOnlyList<CorpusObservedField> ObservedFields,
    CorpusOutputDisposition OutputDisposition);

public sealed record CorpusCell(
    string MarketId,
    string ContractId,
    IReadOnlyList<CorpusCalibrationDocument> CalibrationDocuments,
    IReadOnlyList<CorpusHeldOutDocument> HeldOutDocuments);

public sealed record CorpusCodecPerturbation(
    string CodecId,
    CorpusPerturbationKind Kind,
    string BaselineId,
    string VariantId,
    bool RequiredFieldsInvariant,
    bool EvidenceInvariant,
    bool SafeRejection);

public sealed record CorpusManifest(
    string SchemaVersion,
    CorpusOwnerApproval OwnerApproval,
    string CatalogEpoch,
    string AppVersion,
    string AdapterId,
    string AdapterVersion,
    string OcrRuntimeVersion,
    IReadOnlyDictionary<string, string> OcrLanguageVersions,
    string OsBuild,
    string MachineClass,
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
    private static readonly JsonSerializerOptions Options =
        new(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };

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
          "required": ["schemaVersion", "ownerApproval", "catalogEpoch", "appVersion", "adapterId", "adapterVersion", "ocrRuntimeVersion", "ocrLanguageVersions", "osBuild", "machineClass", "labelingSources", "advertisedRasterCodecs", "cells", "codecPerturbations"],
          "properties": {
            "schemaVersion": { "const": "1" },
            "ownerApproval": { "$ref": "#/$defs/ownerApproval" },
            "catalogEpoch": { "$ref": "#/$defs/token" },
            "appVersion": { "$ref": "#/$defs/token" },
            "adapterId": { "$ref": "#/$defs/token" },
            "adapterVersion": { "$ref": "#/$defs/token" },
            "ocrRuntimeVersion": { "$ref": "#/$defs/token" },
            "ocrLanguageVersions": {
              "type": "object",
              "minProperties": 6,
              "maxProperties": 6,
              "propertyNames": { "enum": ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"] },
              "additionalProperties": { "$ref": "#/$defs/token" }
            },
            "osBuild": { "$ref": "#/$defs/token" },
            "machineClass": { "$ref": "#/$defs/token" },
            "labelingSources": {
              "type": "array",
              "minItems": 1,
              "items": { "$ref": "#/$defs/labelingSource" }
            },
            "advertisedRasterCodecs": {
              "type": "array",
              "minItems": 4,
              "maxItems": 4,
              "uniqueItems": true,
              "items": { "enum": ["jpeg", "png", "tiff", "bmp"] }
            },
            "cells": {
              "type": "array",
              "minItems": 36,
              "maxItems": 36,
              "items": { "$ref": "#/$defs/cell" }
            },
            "codecPerturbations": {
              "type": "array",
              "minItems": 12,
              "maxItems": 12,
              "items": { "$ref": "#/$defs/codecPerturbation" }
            }
          },
          "$defs": {
            "token": {
              "type": "string",
              "minLength": 1,
              "maxLength": 128,
              "pattern": "^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$"
            },
            "opaqueId": {
              "type": "string",
              "minLength": 1,
              "maxLength": 128,
              "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
            },
            "sha256": {
              "type": "string",
              "pattern": "^[A-Fa-f0-9]{64}$"
            },
            "ownerApproval": {
              "type": "object",
              "additionalProperties": false,
              "required": ["approved", "approvalId", "approvedAtUtc"],
              "properties": {
                "approved": { "const": true },
                "approvalId": { "$ref": "#/$defs/opaqueId" },
                "approvedAtUtc": { "type": "string", "format": "date-time" }
              }
            },
            "labelingSource": {
              "type": "object",
              "additionalProperties": false,
              "required": ["id", "reference", "isOfficial"],
              "properties": {
                "id": { "$ref": "#/$defs/opaqueId" },
                "reference": { "type": "string", "format": "uri", "pattern": "^https://" },
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
                "fieldId": { "$ref": "#/$defs/opaqueId" },
                "normalizedValue": { "type": "string", "minLength": 1 },
                "evidence": { "$ref": "#/$defs/evidence" }
              }
            },
            "observedField": {
              "type": "object",
              "additionalProperties": false,
              "required": ["fieldId", "normalizedValue", "evidence"],
              "properties": {
                "fieldId": { "$ref": "#/$defs/opaqueId" },
                "normalizedValue": { "type": "string" },
                "evidence": {
                  "oneOf": [
                    { "$ref": "#/$defs/evidence" },
                    { "type": "null" }
                  ]
                }
              }
            },
            "calibrationDocument": {
              "type": "object",
              "additionalProperties": false,
              "required": ["stableDocumentId", "sourceFamilyId", "contentSha256", "languageId", "labelingSourceIds", "ownerApproved"],
              "properties": {
                "stableDocumentId": { "$ref": "#/$defs/opaqueId" },
                "sourceFamilyId": { "$ref": "#/$defs/opaqueId" },
                "contentSha256": { "$ref": "#/$defs/sha256" },
                "languageId": { "enum": ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"] },
                "labelingSourceIds": {
                  "type": "array",
                  "minItems": 1,
                  "uniqueItems": true,
                  "items": { "$ref": "#/$defs/opaqueId" }
                },
                "ownerApproved": { "const": true }
              }
            },
            "heldOutDocument": {
              "type": "object",
              "additionalProperties": false,
              "required": ["stableDocumentId", "sourceFamilyId", "contentSha256", "languageId", "inputKind", "codecId", "labelingSourceIds", "ownerApproved", "expectedFields", "observedFields", "outputDisposition"],
              "properties": {
                "stableDocumentId": { "$ref": "#/$defs/opaqueId" },
                "sourceFamilyId": { "$ref": "#/$defs/opaqueId" },
                "contentSha256": { "$ref": "#/$defs/sha256" },
                "languageId": { "enum": ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"] },
                "inputKind": { "enum": ["image-pdf", "standalone-raster"] },
                "codecId": {
                  "oneOf": [
                    { "enum": ["jpeg", "png", "tiff", "bmp"] },
                    { "type": "null" }
                  ]
                },
                "labelingSourceIds": {
                  "type": "array",
                  "minItems": 1,
                  "uniqueItems": true,
                  "items": { "$ref": "#/$defs/opaqueId" }
                },
                "ownerApproved": { "const": true },
                "expectedFields": {
                  "type": "array",
                  "minItems": 1,
                  "items": { "$ref": "#/$defs/expectedField" }
                },
                "observedFields": {
                  "type": "array",
                  "items": { "$ref": "#/$defs/observedField" }
                },
                "outputDisposition": { "enum": ["accepted", "needs-review", "unsupported"] }
              }
            },
            "cell": {
              "type": "object",
              "additionalProperties": false,
              "required": ["marketId", "contractId", "calibrationDocuments", "heldOutDocuments"],
              "properties": {
                "marketId": { "enum": ["en-US", "ko-KR", "ja-JP", "de-DE", "fr-FR", "es-ES"] },
                "contractId": { "enum": ["A1", "A2", "B1", "B2", "C1", "C2"] },
                "calibrationDocuments": {
                  "type": "array",
                  "minItems": 1,
                  "items": { "$ref": "#/$defs/calibrationDocument" }
                },
                "heldOutDocuments": {
                  "type": "array",
                  "minItems": 40,
                  "items": { "$ref": "#/$defs/heldOutDocument" }
                }
              }
            },
            "codecPerturbation": {
              "type": "object",
              "additionalProperties": false,
              "required": ["codecId", "kind", "baselineId", "variantId", "requiredFieldsInvariant", "evidenceInvariant", "safeRejection"],
              "properties": {
                "codecId": { "enum": ["jpeg", "png", "tiff", "bmp"] },
                "kind": { "enum": ["recompression", "orientation", "metadata"] },
                "baselineId": { "$ref": "#/$defs/opaqueId" },
                "variantId": { "$ref": "#/$defs/opaqueId" },
                "requiredFieldsInvariant": { "type": "boolean" },
                "evidenceInvariant": { "type": "boolean" },
                "safeRejection": { "type": "boolean" }
              }
            }
          }
        }
        """;
}

public static class CorpusManifestValidator
{
    public static void Validate(CorpusManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (manifest.SchemaVersion != "1")
        {
            Fail(CorpusManifestFailureCode.InvalidManifest);
        }

        if (!IsSafeToken(manifest.CatalogEpoch)
            || !IsSafeToken(manifest.AppVersion)
            || !IsSafeToken(manifest.AdapterId)
            || !IsSafeToken(manifest.AdapterVersion)
            || !IsSafeToken(manifest.OcrRuntimeVersion)
            || !IsSafeToken(manifest.OsBuild)
            || !IsSafeToken(manifest.MachineClass))
        {
            Fail(CorpusManifestFailureCode.InvalidManifest);
        }

        if (manifest.OwnerApproval is null
            || !manifest.OwnerApproval.Approved
            || !IsSafeOpaqueId(manifest.OwnerApproval.ApprovalId))
        {
            Fail(CorpusManifestFailureCode.OwnerApprovalRequired);
        }

        var sources = ValidateSources(manifest.LabelingSources);
        ValidateCatalog(manifest);
        ValidateCells(manifest.Cells, sources);
        ValidatePerturbations(
            manifest.AdvertisedRasterCodecs,
            manifest.CodecPerturbations);
    }

    private static HashSet<string> ValidateSources(
        IReadOnlyList<CorpusLabelingSource> labelingSources)
    {
        if (labelingSources is null || labelingSources.Count == 0)
        {
            Fail(CorpusManifestFailureCode.InvalidLabelingSource);
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in labelingSources)
        {
            if (source is null
                || !source.IsOfficial
                || !IsSafeOpaqueId(source.Id)
                || !ids.Add(source.Id)
                || !Uri.TryCreate(
                    source.Reference,
                    UriKind.Absolute,
                    out var uri)
                || uri.Scheme != Uri.UriSchemeHttps)
            {
                Fail(CorpusManifestFailureCode.InvalidLabelingSource);
            }
        }

        return ids;
    }

    private static void ValidateCatalog(CorpusManifest manifest)
    {
        if (manifest.AdvertisedRasterCodecs is null
            || manifest.AdvertisedRasterCodecs.Count
                != LaunchCorpusCatalog.AdvertisedRasterCodecIds.Count
            || manifest.AdvertisedRasterCodecs
                .Except(
                    LaunchCorpusCatalog.AdvertisedRasterCodecIds,
                    StringComparer.Ordinal)
                .Any()
            || LaunchCorpusCatalog.AdvertisedRasterCodecIds
                .Except(
                    manifest.AdvertisedRasterCodecs,
                    StringComparer.Ordinal)
                .Any()
            || manifest.OcrLanguageVersions is null
            || manifest.OcrLanguageVersions.Count
                != LaunchCorpusCatalog.LanguageIds.Count
            || manifest.OcrLanguageVersions.Keys
                .Except(
                    LaunchCorpusCatalog.LanguageIds,
                    StringComparer.Ordinal)
                .Any()
            || LaunchCorpusCatalog.LanguageIds
                .Except(
                    manifest.OcrLanguageVersions.Keys,
                    StringComparer.Ordinal)
                .Any()
            || manifest.OcrLanguageVersions.Values.Any(
                static version => !IsSafeToken(version)))
        {
            Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
        }
    }

    private static void ValidateCells(
        IReadOnlyList<CorpusCell> cells,
        IReadOnlySet<string> labelingSourceIds)
    {
        if (cells is null || cells.Count != 36)
        {
            Fail(CorpusManifestFailureCode.InvalidLaunchCellSet);
        }

        var expectedCells = (
            from market in LaunchCorpusCatalog.MarketIds
            from contract in LaunchCorpusCatalog.ContractIds
            select $"{market}\0{contract}")
            .ToHashSet(StringComparer.Ordinal);
        var actualCells = new HashSet<string>(StringComparer.Ordinal);
        var calibrationFamilies = new HashSet<string>(StringComparer.Ordinal);
        var heldOutFamilies = new HashSet<string>(StringComparer.Ordinal);
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stableDocumentIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var cell in cells)
        {
            if (cell is null
                || !LaunchCorpusCatalog.MarketIds.Contains(
                    cell.MarketId,
                    StringComparer.Ordinal)
                || !LaunchCorpusCatalog.ContractIds.Contains(
                    cell.ContractId,
                    StringComparer.Ordinal))
            {
                Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
            }

            if (!actualCells.Add($"{cell.MarketId}\0{cell.ContractId}"))
            {
                Fail(CorpusManifestFailureCode.InvalidLaunchCellSet);
            }

            if (cell.CalibrationDocuments is null
                || cell.HeldOutDocuments is null
                || cell.HeldOutDocuments.Any(
                    static document =>
                        document is null
                        || !Enum.IsDefined(document.InputKind)
                        || !Enum.IsDefined(document.OutputDisposition))
            )
            {
                Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
            }

            if (cell.HeldOutDocuments.Count(
                    static document =>
                        document.InputKind == CorpusInputKind.ImagePdf) < 20
                || cell.HeldOutDocuments.Count(
                    static document =>
                        document.InputKind
                        == CorpusInputKind.StandaloneRaster) < 20)
            {
                Fail(CorpusManifestFailureCode.InsufficientHeldOutCoverage);
            }

            foreach (var document in cell.CalibrationDocuments)
            {
                if (document is null)
                {
                    Fail(CorpusManifestFailureCode.InvalidManifest);
                }

                ValidateDocument(
                    document.StableDocumentId,
                    document.SourceFamilyId,
                    document.ContentSha256,
                    document.LanguageId,
                    document.LabelingSourceIds,
                    document.OwnerApproved,
                    labelingSourceIds,
                    hashes,
                    stableDocumentIds);
                calibrationFamilies.Add(document.SourceFamilyId);
            }

            foreach (var document in cell.HeldOutDocuments)
            {
                ValidateDocument(
                    document.StableDocumentId,
                    document.SourceFamilyId,
                    document.ContentSha256,
                    document.LanguageId,
                    document.LabelingSourceIds,
                    document.OwnerApproved,
                    labelingSourceIds,
                    hashes,
                    stableDocumentIds);
                if (!heldOutFamilies.Add(document.SourceFamilyId))
                {
                    Fail(CorpusManifestFailureCode.SourceFamilyLeakage);
                }

                if (document.InputKind == CorpusInputKind.StandaloneRaster
                    && !LaunchCorpusCatalog.AdvertisedRasterCodecIds.Contains(
                        document.CodecId,
                        StringComparer.Ordinal))
                {
                    Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
                }

                if (document.InputKind == CorpusInputKind.ImagePdf
                    && document.CodecId is not null)
                {
                    Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
                }

                ValidateFields(document);
            }
        }

        if (!expectedCells.SetEquals(actualCells))
        {
            Fail(CorpusManifestFailureCode.InvalidLaunchCellSet);
        }

        if (calibrationFamilies.Overlaps(heldOutFamilies))
        {
            Fail(CorpusManifestFailureCode.SourceFamilyLeakage);
        }
    }

    private static void ValidateDocument(
        string stableDocumentId,
        string sourceFamilyId,
        string contentSha256,
        string languageId,
        IReadOnlyList<string> sourceIds,
        bool ownerApproved,
        IReadOnlySet<string> labelingSourceIds,
        ISet<string> hashes,
        ISet<string> stableDocumentIds)
    {
        if (!IsSafeOpaqueId(stableDocumentId)
            || !IsSafeOpaqueId(sourceFamilyId)
            || contentSha256 is null
            || contentSha256.Length != 64
            || !contentSha256.All(Uri.IsHexDigit))
        {
            Fail(CorpusManifestFailureCode.InvalidManifest);
        }

        if (!stableDocumentIds.Add(stableDocumentId))
        {
            Fail(CorpusManifestFailureCode.InvalidManifest);
        }

        if (!hashes.Add(contentSha256))
        {
            Fail(CorpusManifestFailureCode.DuplicateContentHash);
        }

        if (!LaunchCorpusCatalog.LanguageIds.Contains(
                languageId,
                StringComparer.Ordinal))
        {
            Fail(CorpusManifestFailureCode.UnknownCatalogIdentifier);
        }

        if (!ownerApproved
            || sourceIds is null
            || sourceIds.Count == 0
            || sourceIds.Any(sourceId => !labelingSourceIds.Contains(sourceId)))
        {
            Fail(CorpusManifestFailureCode.OwnerApprovalRequired);
        }
    }

    private static void ValidatePerturbations(
        IReadOnlyList<string> codecs,
        IReadOnlyList<CorpusCodecPerturbation> perturbations)
    {
        if (perturbations is null)
        {
            Fail(CorpusManifestFailureCode.IncompleteCodecPerturbations);
        }

        foreach (var codec in codecs)
        {
            foreach (var kind in Enum.GetValues<CorpusPerturbationKind>())
            {
                var matches = perturbations.Where(
                        perturbation =>
                            perturbation.CodecId == codec
                            && perturbation.Kind == kind)
                    .ToArray();
                if (matches.Length != 1
                    || !IsSafeOpaqueId(matches[0].BaselineId)
                    || !IsSafeOpaqueId(matches[0].VariantId)
                    || matches[0].BaselineId == matches[0].VariantId)
                {
                    Fail(
                        CorpusManifestFailureCode
                            .IncompleteCodecPerturbations);
                }
            }
        }
    }

    private static void ValidateFields(CorpusHeldOutDocument document)
    {
        if (document.ExpectedFields is null
            || document.ExpectedFields.Count == 0
            || document.ObservedFields is null)
        {
            Fail(CorpusManifestFailureCode.InvalidManifest);
        }

        var expectedIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in document.ExpectedFields)
        {
            if (field is null
                || !IsSafeOpaqueId(field.FieldId)
                || string.IsNullOrWhiteSpace(field.NormalizedValue)
                || field.Evidence is null
                || !IsValidEvidence(field.Evidence)
                || !expectedIds.Add(field.FieldId))
            {
                Fail(CorpusManifestFailureCode.InvalidManifest);
            }
        }

        foreach (var field in document.ObservedFields)
        {
            if (field is null
                || !IsSafeOpaqueId(field.FieldId)
                || field.NormalizedValue is null)
            {
                Fail(CorpusManifestFailureCode.InvalidManifest);
            }
        }
    }

    private static bool IsValidEvidence(CorpusEvidenceRectangle evidence) =>
        evidence.SourceIndex >= 0
        && double.IsFinite(evidence.X)
        && double.IsFinite(evidence.Y)
        && double.IsFinite(evidence.Width)
        && double.IsFinite(evidence.Height)
        && evidence.X >= 0
        && evidence.Y >= 0
        && evidence.Width > 0
        && evidence.Height > 0;

    private static bool IsSafeToken(string? value) =>
        IsSafeAsciiIdentifier(value, allowPlus: true);

    private static bool IsSafeOpaqueId(string? value) =>
        IsSafeAsciiIdentifier(value, allowPlus: false);

    private static bool IsSafeAsciiIdentifier(
        string? value,
        bool allowPlus)
    {
        if (string.IsNullOrEmpty(value)
            || value.Length > 128
            || !char.IsAsciiLetterOrDigit(value[0]))
        {
            return false;
        }

        foreach (var character in value.AsSpan(1))
        {
            if (!char.IsAsciiLetterOrDigit(character)
                && character is not ('.' or '_' or '-')
                && (!allowPlus || character != '+'))
            {
                return false;
            }
        }

        return true;
    }

    [DoesNotReturn]
    private static void Fail(CorpusManifestFailureCode code) =>
        throw new CorpusManifestException(code);
}
