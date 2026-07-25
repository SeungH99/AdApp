using System.Text.Json.Serialization;

namespace LocalDocumentOrganizer.Core.Documents;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(DocumentExtractionRequest))]
[JsonSerializable(typeof(DocumentExtractionResponse))]
public sealed partial class DocumentExtractionJsonContext : JsonSerializerContext;
