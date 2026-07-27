using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;

namespace LocalDocumentOrganizer.CorpusWorkbench.Labels;

public sealed record LabelDraft(
    ImmutableArray<LabeledField> Fields);

public sealed class InvoiceDraftLabeler
{
    public const string AbsentValue = "__absent__";
    public const string UncertainValue = "__uncertain__";

    private static readonly Regex Whitespace =
        new(@"\s+", RegexOptions.CultureInvariant);
    private static readonly Regex GroupedAmount =
        new(
            @"^\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?$",
            RegexOptions.CultureInvariant);
    private static readonly Regex PlainAmount =
        new(
            @"^\d+(?:\.\d{1,2})?$",
            RegexOptions.CultureInvariant);
    private static readonly Regex RelativeDueTerm =
        new(
            @"^(?:net\s*\d+|\d+\s*days?|\d+\s*일\s*(?:이내|내))$",
            RegexOptions.CultureInvariant
                | RegexOptions.IgnoreCase);
    private static readonly Regex IsoCurrency =
        new(
            @"^[A-Za-z]{3}$",
            RegexOptions.CultureInvariant);
    private static readonly FrozenSet<string> KnownIsoCurrencies =
        new[]
        {
            "AED", "ARS", "AUD", "BRL", "CAD", "CHF", "CLP", "CNY",
            "COP", "CZK", "DKK", "EGP", "EUR", "GBP", "HKD", "HUF",
            "IDR", "ILS", "INR", "JPY", "KRW", "MXN", "MYR", "NGN",
            "NOK", "NZD", "PEN", "PHP", "PLN", "QAR", "RON", "RUB",
            "SAR", "SEK", "SGD", "THB", "TRY", "TWD", "UAH", "USD",
            "VND", "ZAR",
        }.ToFrozenSet(StringComparer.Ordinal);

    public LabelDraft CreateDraft(
        WorkbenchDocument document,
        DocumentExtractionResponse extraction,
        OfficialRuleCatalogSnapshot rules)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(extraction);
        ArgumentNullException.ThrowIfNull(rules);
        RequireCompatible(document, extraction, rules);
        var fragments = ValidateAndOrderFragments(extraction);
        var fields = ImmutableArray.CreateBuilder<LabeledField>(
            PilotCatalog.RequiredFieldIds.Length);
        CandidateResolution? totalAmount = null;
        foreach (var fieldId in PilotCatalog.RequiredFieldIds)
        {
            var rule = rules.RulesByFieldId[fieldId];
            CandidateResolution resolution;
            if (fieldId == "currency")
            {
                resolution = ResolveCurrency(
                    fragments,
                    rule,
                    document.MarketId,
                    totalAmount);
            }
            else
            {
                resolution = ResolveField(
                    fragments,
                    rule,
                    document.MarketId);
                if (fieldId == "total_amount")
                {
                    totalAmount = resolution;
                }
            }

            fields.Add(
                new LabeledField(
                    fieldId,
                    resolution.Value,
                    resolution.Evidence,
                    rule.RuleId));
        }

        return new LabelDraft(fields.MoveToImmutable());
    }

    private static void RequireCompatible(
        WorkbenchDocument document,
        DocumentExtractionResponse extraction,
        OfficialRuleCatalogSnapshot rules)
    {
        if (!string.Equals(
                document.MarketId,
                rules.Document.MarketId,
                StringComparison.Ordinal)
            || !string.Equals(
                document.ContractId,
                rules.Document.ContractId,
                StringComparison.Ordinal)
            || document.ContractId != PilotCatalog.ContractId
            || extraction.ProtocolVersion
                != DocumentExtractionProtocol.CurrentVersion
            || extraction.JobId == Guid.Empty
            || extraction.Outcome != DocumentExtractionOutcome.Success
            || extraction.FailureCode
                != DocumentExtractionFailureCode.None
            || extraction.Fragments.IsDefault
            || extraction.SourcePages.IsDefaultOrEmpty
            || extraction.ElapsedMilliseconds < 0
            || rules.RulesByFieldId.Count
                != PilotCatalog.RequiredFieldIds.Length
            || PilotCatalog.RequiredFieldIds.Any(
                fieldId =>
                    !rules.RulesByFieldId.ContainsKey(fieldId)))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState);
        }
    }

    private static ImmutableArray<OrderedFragment>
        ValidateAndOrderFragments(
        DocumentExtractionResponse extraction)
    {
        var pages = extraction.SourcePages
            .GroupBy(static page => page.SourceIndex)
            .ToArray();
        if (pages.Any(
                static group =>
                    group.Count() != 1
                    || group.Key < 0
                    || !IsFinitePositive(group.Single().Width)
                    || !IsFinitePositive(group.Single().Height)
                    || !Enum.IsDefined(
                        group.Single().CoordinateSystem)))
        {
            throw MissingEvidence();
        }

        var pagesByIndex = pages.ToFrozenDictionary(
            static group => group.Key,
            static group => group.Single());
        var ordered = ImmutableArray.CreateBuilder<OrderedFragment>(
            extraction.Fragments.Length);
        foreach (var fragment in extraction.Fragments)
        {
            if (string.IsNullOrWhiteSpace(fragment.Text)
                || !pagesByIndex.TryGetValue(
                    fragment.SourceIndex,
                    out var page)
                || fragment.CoordinateSystem
                    != page.CoordinateSystem
                || !IsFinitePositive(page.Width)
                || !IsFinitePositive(page.Height)
                || !IsValidEvidence(
                    fragment.Evidence,
                    page.Width,
                    page.Height))
            {
                throw MissingEvidence();
            }

            ordered.Add(
                new OrderedFragment(
                    NormalizeVisibleText(fragment.Text),
                    fragment.SourceIndex,
                    fragment.CoordinateSystem,
                    fragment.Evidence));
        }

        return ordered
            .OrderBy(static fragment => fragment.SourceIndex)
            .ThenBy(static fragment => fragment.Evidence.Y)
            .ThenBy(static fragment => fragment.Evidence.X)
            .ThenBy(static fragment => fragment.Text, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static CandidateResolution ResolveField(
        ImmutableArray<OrderedFragment> fragments,
        OfficialFieldRule rule,
        string marketId)
    {
        var candidates = CollectCandidates(
            fragments,
            rule,
            marketId);
        return ResolveCandidates(candidates);
    }

    private static CandidateResolution ResolveCurrency(
        ImmutableArray<OrderedFragment> fragments,
        OfficialFieldRule rule,
        string marketId,
        CandidateResolution? totalAmount)
    {
        var explicitCandidates = CollectCandidates(
            fragments,
            rule,
            marketId);
        if (explicitCandidates.Any(static candidate => candidate.IsValid))
        {
            return ResolveCandidates(explicitCandidates);
        }

        var inferred = ImmutableArray.CreateBuilder<Candidate>();
        if (totalAmount is { RawValue: { } rawValue })
        {
            var marker = CurrencyMarker(rawValue);
            if (marker is not null)
            {
                var value = NormalizeCurrency(marker, marketId);
                inferred.Add(
                    new Candidate(
                        value,
                        value is not null
                            && !totalAmount.InferenceEvidence.IsEmpty,
                        totalAmount.InferenceEvidence,
                        totalAmount.Order,
                        rawValue));
            }
        }

        return inferred.Count > 0
            ? ResolveCandidates(inferred.ToImmutable())
            : ResolveCandidates(explicitCandidates);
    }

    private static ImmutableArray<Candidate> CollectCandidates(
        ImmutableArray<OrderedFragment> fragments,
        OfficialFieldRule rule,
        string marketId)
    {
        var candidates = ImmutableArray.CreateBuilder<Candidate>();
        var labels = rule.AcceptedVisibleLabels
            .OrderByDescending(static label => label.Length)
            .ThenBy(static label => label, StringComparer.Ordinal)
            .ToArray();
        for (var start = 0; start < fragments.Length; start++)
        {
            var combined = new StringBuilder();
            for (var end = start;
                 end < fragments.Length && end < start + 6;
                 end++)
            {
                if (end > start
                    && !AreAdjacent(fragments[end - 1], fragments[end]))
                {
                    break;
                }

                if (combined.Length > 0)
                {
                    combined.Append(' ');
                }

                combined.Append(fragments[end].Text);
                var addedValidCandidate = false;
                foreach (var label in labels)
                {
                    if (!TryGetLabeledValue(
                            combined.ToString(),
                            label,
                            out var rawValue))
                    {
                        continue;
                    }

                    if (rawValue.Length == 0)
                    {
                        continue;
                    }

                    var normalized = NormalizeCandidate(
                        rule.FieldId,
                        rawValue,
                        marketId);
                    candidates.Add(
                        new Candidate(
                            normalized,
                            normalized is not null,
                            Evidence(fragments, start, end),
                            new CandidateOrder(
                                fragments[start].SourceIndex,
                                fragments[start].Evidence.Y,
                                fragments[start].Evidence.X,
                                label),
                            rawValue));
                    if (normalized is not null)
                    {
                        addedValidCandidate = true;
                        break;
                    }
                }

                if (addedValidCandidate)
                {
                    break;
                }
            }
        }

        return candidates.ToImmutable();
    }

    private static CandidateResolution ResolveCandidates(
        ImmutableArray<Candidate> candidates)
    {
        var valid = candidates
            .Where(static candidate => candidate.IsValid)
            .OrderBy(static candidate => candidate.Order)
            .ToArray();
        if (valid.Length == 0)
        {
            if (candidates.Length == 0)
            {
                return CandidateResolution.Absent;
            }

            var rejected = candidates
                .OrderBy(static candidate => candidate.Order)
                .First();
            return new CandidateResolution(
                UncertainValue,
                ImmutableArray<EvidenceBox>.Empty,
                rejected.Order,
                rejected.RawValue,
                rejected.Evidence);
        }

        if (valid.Select(static candidate => candidate.Value)
            .Distinct(StringComparer.Ordinal)
            .Skip(1)
            .Any())
        {
            return CandidateResolution.Uncertain;
        }

        var selected = valid[0];
        return new CandidateResolution(
            selected.Value!,
            selected.Evidence,
            selected.Order,
            selected.RawValue,
            selected.Evidence);
    }

    private static string? NormalizeCandidate(
        string fieldId,
        string rawValue,
        string marketId) =>
        fieldId switch
        {
            "issuer_name" or "invoice_number" =>
                NormalizeTextValue(rawValue),
            "issue_date" =>
                NormalizeDate(rawValue, marketId, dueDate: false),
            "payment_due_date" =>
                NormalizeDate(rawValue, marketId, dueDate: true),
            "total_amount" =>
                NormalizeAmount(rawValue),
            "currency" =>
                NormalizeCurrency(rawValue, marketId),
            _ => null,
        };

    private static string? NormalizeTextValue(string value)
    {
        var normalized = NormalizeVisibleText(value)
            .Trim(' ', ':', '-', '–', '—');
        return normalized.Length == 0
            || normalized is AbsentValue or UncertainValue
            ? null
            : normalized.Normalize(NormalizationForm.FormC);
    }

    private static string? NormalizeDate(
        string value,
        string marketId,
        bool dueDate)
    {
        var normalized = NormalizeVisibleText(value)
            .Trim(' ', '.', ',', ';');
        if (dueDate && RelativeDueTerm.IsMatch(normalized))
        {
            return null;
        }

        DateTime parsed;
        if (marketId == "ko-KR")
        {
            var formats = new[]
            {
                "yyyy-M-d",
                "yyyy-MM-dd",
                "yyyy.M.d",
                "yyyy.MM.dd",
                "yyyy/M/d",
                "yyyy/MM/dd",
                "yyyy년 M월 d일",
                "yyyy년 MM월 dd일",
            };
            return DateTime.TryParseExact(
                    normalized,
                    formats,
                    CultureInfo.GetCultureInfo("ko-KR"),
                    DateTimeStyles.None,
                    out parsed)
                ? parsed.ToString(
                    "yyyy-MM-dd",
                    CultureInfo.InvariantCulture)
                : null;
        }

        if (marketId != "en-US")
        {
            return null;
        }

        var numeric = Regex.Match(
            normalized,
            @"^(?<month>\d{1,2})/(?<day>\d{1,2})/(?<year>\d{4})$",
            RegexOptions.CultureInvariant);
        if (numeric.Success)
        {
            var month = int.Parse(
                numeric.Groups["month"].Value,
                CultureInfo.InvariantCulture);
            var day = int.Parse(
                numeric.Groups["day"].Value,
                CultureInfo.InvariantCulture);
            if (month is >= 1 and <= 12
                && day is >= 1 and <= 12)
            {
                return null;
            }
        }

        var usFormats = new[]
        {
            "M/d/yyyy",
            "MM/dd/yyyy",
            "MMMM d, yyyy",
            "MMMM dd, yyyy",
            "MMM d, yyyy",
            "MMM dd, yyyy",
            "yyyy-M-d",
            "yyyy-MM-dd",
        };
        return DateTime.TryParseExact(
                normalized,
                usFormats,
                CultureInfo.GetCultureInfo("en-US"),
                DateTimeStyles.None,
                out parsed)
            ? parsed.ToString(
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture)
            : null;
    }

    private static string? NormalizeAmount(string value)
    {
        var normalized = NormalizeVisibleText(value);
        normalized = Regex.Replace(
            normalized,
            @"^(?:₩|원|\$|[A-Za-z]{3})\s*",
            string.Empty,
            RegexOptions.CultureInvariant);
        normalized = Regex.Replace(
            normalized,
            @"\s*(?:₩|원|\$|[A-Za-z]{3})$",
            string.Empty,
            RegexOptions.CultureInvariant);
        normalized = normalized.Replace(" ", string.Empty);
        if (!GroupedAmount.IsMatch(normalized)
            && !PlainAmount.IsMatch(normalized))
        {
            return null;
        }

        var invariant = normalized.Replace(",", string.Empty);
        if (!decimal.TryParse(
                invariant,
                NumberStyles.AllowDecimalPoint,
                CultureInfo.InvariantCulture,
                out var amount))
        {
            return null;
        }

        return amount.ToString("0.##", CultureInfo.InvariantCulture);
    }

    private static string? NormalizeCurrency(
        string value,
        string marketId)
    {
        var normalized = NormalizeVisibleText(value)
            .Trim(' ', '.', ',', ';', ':');
        if (normalized is "₩" or "원")
        {
            return marketId == "ko-KR" ? "KRW" : null;
        }

        if (normalized == "$")
        {
            return marketId == "en-US" ? "USD" : null;
        }

        if (!IsoCurrency.IsMatch(normalized))
        {
            return null;
        }

        var upper = normalized.ToUpperInvariant();
        return KnownIsoCurrencies.Contains(upper) ? upper : null;
    }

    private static string? CurrencyMarker(string value)
    {
        if (value.Contains('₩'))
        {
            return "₩";
        }

        if (value.Contains('원'))
        {
            return "원";
        }

        if (value.Contains('$'))
        {
            return "$";
        }

        var code = Regex.Match(
            value,
            @"(?:^|\s)(?<code>[A-Za-z]{3})(?=\s|$)",
            RegexOptions.CultureInvariant);
        if (!code.Success)
        {
            code = Regex.Match(
                value,
                @"^(?<code>[A-Za-z]{3})(?=\d)",
                RegexOptions.CultureInvariant);
        }

        return code.Success ? code.Groups["code"].Value : null;
    }

    private static bool TryGetLabeledValue(
        string combined,
        string label,
        out string value)
    {
        value = string.Empty;
        if (!combined.StartsWith(label, StringComparison.Ordinal))
        {
            return false;
        }

        var remainder = combined[label.Length..];
        if (remainder.Length > 0
            && !char.IsWhiteSpace(remainder[0])
            && remainder[0] is not ':' and not '-' and not '–' and not '—')
        {
            return false;
        }

        value = remainder
            .TrimStart()
            .TrimStart(':', '-', '–', '—')
            .Trim();
        return true;
    }

    private static bool AreAdjacent(
        OrderedFragment left,
        OrderedFragment right)
    {
        if (left.SourceIndex != right.SourceIndex
            || left.CoordinateSystem != right.CoordinateSystem)
        {
            return false;
        }

        var leftCenter =
            left.Evidence.Y + left.Evidence.Height / 2;
        var rightCenter =
            right.Evidence.Y + right.Evidence.Height / 2;
        var height = Math.Max(
            left.Evidence.Height,
            right.Evidence.Height);
        var gap = right.Evidence.X
            - (left.Evidence.X + left.Evidence.Width);
        return Math.Abs(leftCenter - rightCenter) <= height * 0.6
            && gap >= -1
            && gap <= Math.Max(24, height * 3);
    }

    private static ImmutableArray<EvidenceBox> Evidence(
        ImmutableArray<OrderedFragment> fragments,
        int start,
        int end)
    {
        var evidence = ImmutableArray.CreateBuilder<EvidenceBox>(
            end - start + 1);
        for (var index = start; index <= end; index++)
        {
            var fragment = fragments[index];
            evidence.Add(
                new EvidenceBox(
                    fragment.SourceIndex,
                    fragment.Evidence.X,
                    fragment.Evidence.Y,
                    fragment.Evidence.Width,
                    fragment.Evidence.Height));
        }

        return evidence.MoveToImmutable();
    }

    private static string NormalizeVisibleText(string value) =>
        Whitespace.Replace(
                value.Normalize(NormalizationForm.FormC),
                " ")
            .Trim();

    private static bool IsFinitePositive(double value) =>
        double.IsFinite(value) && value > 0;

    private static bool IsValidEvidence(
        EvidenceRectangle evidence,
        double pageWidth,
        double pageHeight) =>
        double.IsFinite(evidence.X)
        && double.IsFinite(evidence.Y)
        && IsFinitePositive(evidence.Width)
        && IsFinitePositive(evidence.Height)
        && evidence.X >= 0
        && evidence.Y >= 0
        && evidence.X + evidence.Width <= pageWidth
        && evidence.Y + evidence.Height <= pageHeight;

    private static WorkbenchException MissingEvidence() =>
        new(WorkbenchFailureCode.MissingEvidence);

    private sealed record OrderedFragment(
        string Text,
        int SourceIndex,
        EvidenceCoordinateSystem CoordinateSystem,
        EvidenceRectangle Evidence);

    private sealed record Candidate(
        string? Value,
        bool IsValid,
        ImmutableArray<EvidenceBox> Evidence,
        CandidateOrder Order,
        string RawValue);

    private readonly record struct CandidateOrder(
        int SourceIndex,
        double Y,
        double X,
        string Label)
        : IComparable<CandidateOrder>
    {
        public int CompareTo(CandidateOrder other)
        {
            var comparison = SourceIndex.CompareTo(other.SourceIndex);
            if (comparison != 0)
            {
                return comparison;
            }

            comparison = Y.CompareTo(other.Y);
            if (comparison != 0)
            {
                return comparison;
            }

            comparison = X.CompareTo(other.X);
            return comparison != 0
                ? comparison
                : StringComparer.Ordinal.Compare(Label, other.Label);
        }
    }

    private sealed record CandidateResolution(
        string Value,
        ImmutableArray<EvidenceBox> Evidence,
        CandidateOrder Order,
        string? RawValue,
        ImmutableArray<EvidenceBox> InferenceEvidence)
    {
        internal static CandidateResolution Absent { get; } =
            new(
                AbsentValue,
                ImmutableArray<EvidenceBox>.Empty,
                default,
                null,
                ImmutableArray<EvidenceBox>.Empty);

        internal static CandidateResolution Uncertain { get; } =
            new(
                UncertainValue,
                ImmutableArray<EvidenceBox>.Empty,
                default,
                null,
                ImmutableArray<EvidenceBox>.Empty);
    }
}
