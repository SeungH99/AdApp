using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Labels;

namespace LocalDocumentOrganizer.CorpusWorkbench.Serialization;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectRequiredConstructorParameters = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    WriteIndented = false)]
[JsonSerializable(typeof(PilotScope))]
[JsonSerializable(typeof(SourceReceipt))]
[JsonSerializable(typeof(LabelRevision))]
[JsonSerializable(typeof(LabelDraft))]
[JsonSerializable(typeof(ApprovalEntry))]
[JsonSerializable(typeof(ApprovalEntryReference))]
[JsonSerializable(typeof(PilotReportEnvelope))]
[JsonSerializable(typeof(OfficialRuleCatalogDocument))]
public sealed partial class WorkbenchJsonContext : JsonSerializerContext;

public static class WorkbenchJson
{
    public static T Parse<T>(
        ReadOnlySpan<byte> utf8,
        JsonTypeInfo<T> typeInfo) =>
        JsonSerializer.Deserialize(utf8, typeInfo)
        ?? throw new JsonException("Required JSON payload was null.");

    public static byte[] Serialize<T>(
        T value,
        JsonTypeInfo<T> typeInfo) =>
        JsonSerializer.SerializeToUtf8Bytes(value, typeInfo);
}
