using System.Collections.Frozen;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Contracts;

namespace LocalDocumentOrganizer.Application.Rules;

public static class OfficialRuleCatalog
{
    private const string PilotIdentityDomain =
        "corpus-workbench-official-rule-catalog-set-v1\n";

    public static async Task<OfficialRuleCatalogSnapshot> LoadAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var bytes = await File.ReadAllBytesAsync(path, cancellationToken)
            .ConfigureAwait(false);
        var document = JsonSerializer.Deserialize(
            bytes,
            InvoiceRuleJsonContext.Default.OfficialRuleCatalogDocument)
            ?? throw new JsonException("Required JSON payload was null.");
        OfficialRuleCatalogValidator.Validate(document);
        var canonical = CanonicalRuleCatalog.Serialize(document);
        return new(
            document,
            Convert.ToHexStringLower(SHA256.HashData(canonical)),
            document.Rules.ToFrozenDictionary(
                static rule => rule.FieldId,
                StringComparer.Ordinal));
    }

    public static string ComputeCatalogSha256(
        IEnumerable<OfficialRuleCatalogSnapshot> snapshots)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        var canonical = new List<OfficialRuleCatalogSnapshot>(
            PilotCatalog.MarketIds.Length);
        foreach (var snapshot in snapshots)
        {
            if (snapshot is null
                || snapshot.Document is null
                || canonical.Count >= PilotCatalog.MarketIds.Length)
            {
                throw new InvoiceRuleException(
                    ApplicationFailureCode.InvalidArguments);
            }

            canonical.Add(snapshot);
        }

        canonical.Sort(static (left, right) =>
            string.CompareOrdinal(
                left.Document.MarketId,
                right.Document.MarketId));
        if (canonical.Count != PilotCatalog.MarketIds.Length
            || canonical.Select(
                    static snapshot => snapshot.Document.MarketId)
                .Distinct(StringComparer.Ordinal)
                .Count() != canonical.Count
            || !canonical.Select(
                    static snapshot => snapshot.Document.MarketId)
                .SequenceEqual(
                    PilotCatalog.MarketIds.Order(
                        StringComparer.Ordinal),
                    StringComparer.Ordinal))
        {
            throw new InvoiceRuleException(
                ApplicationFailureCode.InvalidArguments);
        }

        using var hash = IncrementalHash.CreateHash(
            HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(PilotIdentityDomain));
        AppendInt32(hash, canonical.Count);
        foreach (var snapshot in canonical)
        {
            OfficialRuleCatalogValidator.Validate(snapshot.Document);
            var expected = Convert.ToHexStringLower(
                SHA256.HashData(
                    CanonicalRuleCatalog.Serialize(
                        snapshot.Document)));
            if (!string.Equals(
                    expected,
                    snapshot.CatalogSha256,
                    StringComparison.Ordinal))
            {
                throw new InvoiceRuleException(
                    ApplicationFailureCode.InvalidArguments);
            }

            AppendLengthPrefixed(
                hash,
                snapshot.Document.MarketId);
            AppendLengthPrefixed(hash, snapshot.CatalogSha256);
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    public static void Validate(OfficialRuleCatalogDocument document) =>
        OfficialRuleCatalogValidator.Validate(document);

    public static byte[] SerializeCanonical(
        OfficialRuleCatalogDocument document) =>
        CanonicalRuleCatalog.Serialize(document);

    private static void AppendLengthPrefixed(
        IncrementalHash hash,
        string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        AppendInt32(hash, bytes.Length);
        hash.AppendData(bytes);
    }

    private static void AppendInt32(
        IncrementalHash hash,
        int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        hash.AppendData(bytes);
    }
}

internal static class OfficialRuleCatalogValidator
{
    private const string ExplicitPaymentDeadlineNormalization =
        "explicit-visibly-printed-calendar-date-labeled-payment-deadline-no-relative-payment-terms-derivation-v1";

    private static readonly FrozenSet<string> OfficialHosts =
        new[]
        {
            "www.law.go.kr",
            "law.go.kr",
            "www.nts.go.kr",
            "nts.go.kr",
            "www.acquisition.gov",
            "acquisition.gov",
            "www.rfc-editor.org",
            "www.iso.org",
        }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    public static void Validate(OfficialRuleCatalogDocument document)
    {
        if (document.SchemaVersion != PilotCatalog.SchemaVersion ||
            document.ContractId != PilotCatalog.ContractId ||
            !PilotCatalog.MarketIds.Contains(document.MarketId, StringComparer.Ordinal))
        {
            throw InvalidState();
        }

        if (document.Sources.IsDefaultOrEmpty || document.Rules.IsDefaultOrEmpty ||
            HasDuplicate(document.Sources.Select(static source => source.Id)) ||
            HasDuplicate(document.Rules.Select(static rule => rule.RuleId)) ||
            HasDuplicate(document.Rules.Select(static rule => rule.FieldId)))
        {
            throw InvalidState();
        }

        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        foreach (var source in document.Sources)
        {
            if (string.IsNullOrWhiteSpace(source.Id) || string.IsNullOrWhiteSpace(source.Publisher) ||
                source.VerifiedOn > today ||
                (source.PublishedOrRevisedOn is { } publishedOrRevisedOn && publishedOrRevisedOn > today))
            {
                throw InvalidState();
            }

            if (!IsOfficialUri(source.Uri))
            {
                throw new InvoiceRuleException(ApplicationFailureCode.SourceUnverified);
            }
        }

        var sourceIds = document.Sources.Select(static source => source.Id).ToFrozenSet(StringComparer.Ordinal);
        foreach (var rule in document.Rules)
        {
            if (string.IsNullOrWhiteSpace(rule.RuleId) ||
                !PilotCatalog.RequiredFieldIds.Contains(rule.FieldId, StringComparer.Ordinal) ||
                string.IsNullOrWhiteSpace(rule.Normalization) ||
                rule.AcceptedVisibleLabels.IsDefaultOrEmpty ||
                rule.AcceptedVisibleLabels.Any(string.IsNullOrWhiteSpace) ||
                rule.SourceIds.IsDefaultOrEmpty ||
                rule.SourceIds.Any(string.IsNullOrWhiteSpace) ||
                HasDuplicate(rule.SourceIds) ||
                rule.SourceIds.Any(sourceId => !sourceIds.Contains(sourceId)))
            {
                throw InvalidState();
            }
        }

        var fields = document.Rules.Select(static rule => rule.FieldId).ToFrozenSet(StringComparer.Ordinal);
        if (fields.Count != PilotCatalog.RequiredFieldIds.Length ||
            PilotCatalog.RequiredFieldIds.Any(fieldId => !fields.Contains(fieldId)))
        {
            throw InvalidState();
        }

        var dueDateRule = document.Rules.Single(static rule => rule.FieldId == "payment_due_date");
        if (!string.Equals(
                dueDateRule.Normalization,
                ExplicitPaymentDeadlineNormalization,
                StringComparison.Ordinal))
        {
            throw InvalidState();
        }
    }

    private static bool HasDuplicate(IEnumerable<string> values) =>
        values.Any(string.IsNullOrWhiteSpace) ||
        values.GroupBy(static value => value, StringComparer.Ordinal).Any(static group => group.Count() != 1);

    private static bool IsOfficialUri(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Fragment) &&
        uri.IsDefaultPort &&
        OfficialHosts.Contains(uri.Host);

    private static InvoiceRuleException InvalidState() =>
        new(ApplicationFailureCode.InvalidState);
}

internal static class CanonicalRuleCatalog
{
    public static byte[] Serialize(OfficialRuleCatalogDocument document)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", document.SchemaVersion);
            writer.WriteString("marketId", document.MarketId);
            writer.WriteString("contractId", document.ContractId);
            writer.WritePropertyName("sources");
            writer.WriteStartArray();
            foreach (var source in document.Sources.OrderBy(static source => source.Id, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("id", source.Id);
                writer.WriteString("uri", source.Uri);
                writer.WriteString("publisher", source.Publisher);
                writer.WritePropertyName("publishedOrRevisedOn");
                if (source.PublishedOrRevisedOn is { } publishedOn)
                {
                    writer.WriteStringValue(publishedOn.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
                }
                else
                {
                    writer.WriteNullValue();
                }

                writer.WriteString("verifiedOn", source.VerifiedOn.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WritePropertyName("rules");
            writer.WriteStartArray();
            foreach (var rule in document.Rules.OrderBy(static rule => rule.FieldId, StringComparer.Ordinal))
            {
                writer.WriteStartObject();
                writer.WriteString("ruleId", rule.RuleId);
                writer.WriteString("fieldId", rule.FieldId);
                writer.WriteString("normalization", rule.Normalization);
                WriteSortedStrings(writer, "acceptedVisibleLabels", rule.AcceptedVisibleLabels);
                WriteSortedStrings(writer, "sourceIds", rule.SourceIds);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static void WriteSortedStrings(
        Utf8JsonWriter writer,
        string name,
        IEnumerable<string> values)
    {
        writer.WritePropertyName(name);
        writer.WriteStartArray();
        foreach (var value in values.OrderBy(static value => value, StringComparer.Ordinal))
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }
}
