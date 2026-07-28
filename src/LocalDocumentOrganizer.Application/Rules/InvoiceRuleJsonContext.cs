using System.Text.Json.Serialization;
using LocalDocumentOrganizer.Application.Contracts;

namespace LocalDocumentOrganizer.Application.Rules;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectRequiredConstructorParameters = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    WriteIndented = false)]
[JsonSerializable(typeof(OfficialRuleCatalogDocument))]
internal sealed partial class InvoiceRuleJsonContext : JsonSerializerContext;
