using System.Text.Json.Serialization;

namespace LocalDocumentOrganizer.Core.Documents;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectRequiredConstructorParameters = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(DocumentExtractionRequest))]
[JsonSerializable(typeof(DocumentExtractionResponse))]
public sealed partial class DocumentExtractionJsonContext : JsonSerializerContext;
