using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;

namespace LocalDocumentOrganizer.CorpusWorkbench.Sampling;

/// <summary>
/// Selects the lexicographically smallest ranked set that meets all direct-review strata.
/// Rank ties are resolved by content hash and then document ID, both using ordinal comparison.
/// </summary>
public static class ReviewSampleSelector
{
    private const string ImagePdf = "image-pdf";
    private const string StandaloneRaster = "standalone-raster";
    private const int PerKindTarget = 5;
    private const int SampleTarget = 10;
    private const int MinimumFamilyCount = 3;
    private const int MaximumPilotCandidates = 64;

    private static readonly ImmutableArray<string> RequiredTags =
    [
        "date",
        "amount",
        "currency-symbol",
        "identifier",
    ];

    private static readonly ImmutableHashSet<string> ApprovedTags =
        RequiredTags.ToImmutableHashSet(StringComparer.Ordinal);

    public static ReviewSample Select(
        PilotScope scope,
        string marketId,
        IReadOnlyList<ReviewCandidate> candidates)
    {
        ValidateScope(scope, marketId);
        if (candidates is null || candidates.Count > MaximumPilotCandidates)
        {
            throw InvalidArguments();
        }

        var ranked = ValidateAndRank(scope, marketId, candidates);
        var missingStrata = GetGloballyUnsatisfiedStrata(ranked);
        if (!missingStrata.IsEmpty)
        {
            throw CoverageInsufficient(missingStrata);
        }

        var selection = new List<RankedCandidate>(SampleTarget);
        if (!TrySelect(
                ranked,
                startIndex: 0,
                selection,
                imagePdfCount: 0,
                rasterCount: 0,
                families: new HashSet<string>(StringComparer.Ordinal),
                tags: new HashSet<string>(StringComparer.Ordinal)))
        {
            throw CoverageInsufficient(["feasible-combination"]);
        }

        var selectedTags = selection
            .SelectMany(static item => item.Candidate.EdgeCaseTags)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static tag => tag, StringComparer.Ordinal)
            .ToImmutableArray();
        var selectedFamilies = selection
            .Select(static item => item.Candidate.SourceFamilyId)
            .Distinct(StringComparer.Ordinal)
            .Count();
        var inputKindCounts = ImmutableDictionary.CreateRange(
            StringComparer.Ordinal,
            new[]
            {
                new KeyValuePair<string, int>(ImagePdf, PerKindTarget),
                new KeyValuePair<string, int>(StandaloneRaster, PerKindTarget),
            });

        return new ReviewSample(
            [.. selection.Select(static item => item.Candidate.DocumentId)],
            inputKindCounts,
            selectedFamilies,
            selectedTags);
    }

    private static bool TrySelect(
        IReadOnlyList<RankedCandidate> ranked,
        int startIndex,
        List<RankedCandidate> selection,
        int imagePdfCount,
        int rasterCount,
        HashSet<string> families,
        HashSet<string> tags)
    {
        if (selection.Count == SampleTarget)
        {
            return imagePdfCount == PerKindTarget
                && rasterCount == PerKindTarget
                && families.Count >= MinimumFamilyCount
                && RequiredTags.All(tags.Contains);
        }

        if (!CanStillSatisfy(
                ranked,
                startIndex,
                selection.Count,
                imagePdfCount,
                rasterCount,
                families,
                tags))
        {
            return false;
        }

        for (var index = startIndex; index < ranked.Count; index++)
        {
            var candidate = ranked[index];
            var isImagePdf = candidate.Candidate.InputKind == ImagePdf;
            if ((isImagePdf && imagePdfCount == PerKindTarget)
                || (!isImagePdf && rasterCount == PerKindTarget))
            {
                continue;
            }

            selection.Add(candidate);
            var familyWasAdded = families.Add(candidate.Candidate.SourceFamilyId);
            var addedTags = AddTags(tags, candidate.Candidate.EdgeCaseTags);
            if (TrySelect(
                    ranked,
                    index + 1,
                    selection,
                    imagePdfCount + (isImagePdf ? 1 : 0),
                    rasterCount + (isImagePdf ? 0 : 1),
                    families,
                    tags))
            {
                return true;
            }

            RemoveTags(tags, addedTags);
            if (familyWasAdded)
            {
                families.Remove(candidate.Candidate.SourceFamilyId);
            }

            selection.RemoveAt(selection.Count - 1);
        }

        return false;
    }

    private static bool CanStillSatisfy(
        IReadOnlyList<RankedCandidate> ranked,
        int startIndex,
        int selectedCount,
        int imagePdfCount,
        int rasterCount,
        IReadOnlySet<string> families,
        IReadOnlySet<string> tags)
    {
        if (ranked.Count - startIndex < SampleTarget - selectedCount)
        {
            return false;
        }

        var availableImagePdf = 0;
        var availableRaster = 0;
        var possibleFamilies = new HashSet<string>(families, StringComparer.Ordinal);
        var possibleTags = new HashSet<string>(tags, StringComparer.Ordinal);
        for (var index = startIndex; index < ranked.Count; index++)
        {
            var candidate = ranked[index].Candidate;
            if (candidate.InputKind == ImagePdf)
            {
                availableImagePdf++;
            }
            else
            {
                availableRaster++;
            }

            possibleFamilies.Add(candidate.SourceFamilyId);
            possibleTags.UnionWith(candidate.EdgeCaseTags);
        }

        return availableImagePdf >= PerKindTarget - imagePdfCount
            && availableRaster >= PerKindTarget - rasterCount
            && possibleFamilies.Count >= MinimumFamilyCount
            && RequiredTags.All(possibleTags.Contains);
    }

    private static ImmutableArray<RankedCandidate> ValidateAndRank(
        PilotScope scope,
        string marketId,
        IReadOnlyList<ReviewCandidate> candidates)
    {
        var documentIds = new HashSet<string>(StringComparer.Ordinal);
        var contentHashes = new HashSet<string>(StringComparer.Ordinal);
        var ranked = ImmutableArray.CreateBuilder<RankedCandidate>(candidates.Count);
        foreach (var candidate in candidates)
        {
            if (!IsValidCandidate(candidate)
                || !documentIds.Add(candidate.DocumentId)
                || !contentHashes.Add(candidate.ContentSha256))
            {
                throw InvalidArguments();
            }

            ranked.Add(new RankedCandidate(candidate, GetRank(scope, marketId, candidate.ContentSha256)));
        }

        return ranked
            .OrderBy(static item => item, RankedCandidateComparer.Instance)
            .ToImmutableArray();
    }

    private static ImmutableArray<string> GetGloballyUnsatisfiedStrata(
        IReadOnlyList<RankedCandidate> ranked)
    {
        var result = ImmutableArray.CreateBuilder<string>();
        if (ranked.Count < SampleTarget)
        {
            result.Add("total-count");
        }

        if (ranked.Count(item => item.Candidate.InputKind == ImagePdf) < PerKindTarget)
        {
            result.Add("image-pdf-count");
        }

        if (ranked.Count(item => item.Candidate.InputKind == StandaloneRaster) < PerKindTarget)
        {
            result.Add("standalone-raster-count");
        }

        if (ranked.Select(static item => item.Candidate.SourceFamilyId)
                .Distinct(StringComparer.Ordinal).Count() < MinimumFamilyCount)
        {
            result.Add("source-family-count");
        }

        var availableTags = ranked
            .SelectMany(static item => item.Candidate.EdgeCaseTags)
            .ToImmutableHashSet(StringComparer.Ordinal);
        foreach (var tag in RequiredTags)
        {
            if (!availableTags.Contains(tag))
            {
                result.Add($"edge-tag:{tag}");
            }
        }

        return result.ToImmutable();
    }

    private static byte[] GetRank(
        PilotScope scope,
        string marketId,
        string contentSha256)
    {
        var prefix = Encoding.UTF8.GetBytes(
            $"corpus-review-sample-v1\n{scope.CatalogEpoch}\n{marketId}\n");
        var contentHashBytes = Convert.FromHexString(contentSha256);
        var bytes = new byte[prefix.Length + contentHashBytes.Length];
        Buffer.BlockCopy(prefix, 0, bytes, 0, prefix.Length);
        Buffer.BlockCopy(contentHashBytes, 0, bytes, prefix.Length, contentHashBytes.Length);
        return SHA256.HashData(bytes);
    }

    private static bool IsValidCandidate(ReviewCandidate? candidate) =>
        candidate is not null
        && IsNormalizedIdentifier(candidate.DocumentId)
        && IsLowerSha256(candidate.ContentSha256)
        && IsNormalizedIdentifier(candidate.SourceFamilyId)
        && (candidate.InputKind == ImagePdf || candidate.InputKind == StandaloneRaster)
        && !candidate.EdgeCaseTags.IsDefault
        && candidate.EdgeCaseTags.All(IsApprovedNormalizedTag)
        && candidate.EdgeCaseTags.Distinct(StringComparer.Ordinal).Count()
            == candidate.EdgeCaseTags.Length;

    private static bool IsApprovedNormalizedTag(string? value) =>
        value is not null
        && value.IsNormalized(NormalizationForm.FormC)
        && ApprovedTags.Contains(value);

    private static void ValidateScope(PilotScope? scope, string? marketId)
    {
        if (scope is null
            || scope.SchemaVersion != PilotCatalog.SchemaVersion
            || scope.ContractId != PilotCatalog.ContractId
            || !IsNormalizedText(scope.CatalogEpoch, 128)
            || scope.HeldOutTargetPerMarket != PilotCatalog.HeldOutTargetPerMarket
            || scope.DirectReviewTargetPerMarket != PilotCatalog.DirectReviewTargetPerMarket
            || scope.MarketIds.IsDefaultOrEmpty
            || scope.MarketIds.Distinct(StringComparer.Ordinal).Count() != scope.MarketIds.Length
            || scope.MarketIds.Any(market =>
                !PilotCatalog.MarketIds.Contains(market, StringComparer.Ordinal))
            || marketId is null
            || !marketId.IsNormalized(NormalizationForm.FormC)
            || !scope.MarketIds.Contains(marketId, StringComparer.Ordinal)
            || !PilotCatalog.MarketIds.Contains(marketId, StringComparer.Ordinal))
        {
            throw InvalidArguments();
        }
    }

    private static bool IsNormalizedIdentifier(string? value) =>
        value is not null
        && value.IsNormalized(NormalizationForm.FormC)
        && value.Length is > 0 and <= 128
        && !char.IsWhiteSpace(value[0])
        && char.IsLetterOrDigit(value[0])
        && value.All(static character =>
            character is >= 'a' and <= 'z'
                or >= 'A' and <= 'Z'
                or >= '0' and <= '9'
                or '-'
                or '_'
                or '.'
                or ':');

    private static bool IsNormalizedText(string? value, int maximumLength) =>
        value is not null
        && value.IsNormalized(NormalizationForm.FormC)
        && !string.IsNullOrWhiteSpace(value)
        && value == value.Trim()
        && value.Length <= maximumLength
        && value.All(static character =>
            !char.IsControl(character) && !char.IsSurrogate(character));

    private static bool IsLowerSha256(string? value) =>
        value is not null
        && value.Length == 64
        && value.All(static character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static List<string> AddTags(
        ISet<string> tags,
        ImmutableArray<string> candidateTags)
    {
        var added = new List<string>(candidateTags.Length);
        foreach (var tag in candidateTags)
        {
            if (tags.Add(tag))
            {
                added.Add(tag);
            }
        }

        return added;
    }

    private static void RemoveTags(ISet<string> tags, IEnumerable<string> addedTags)
    {
        foreach (var tag in addedTags)
        {
            tags.Remove(tag);
        }
    }

    private static WorkbenchException CoverageInsufficient(
        ImmutableArray<string> unsatisfiedStrata) =>
        new(
            WorkbenchFailureCode.ReviewCoverageInsufficient,
            detail: $"Unsatisfied strata: {string.Join(", ", unsatisfiedStrata)}.");

    private static WorkbenchException InvalidArguments() =>
        new(WorkbenchFailureCode.InvalidArguments);

    private sealed record RankedCandidate(ReviewCandidate Candidate, byte[] Rank);

    private sealed class RankedCandidateComparer : IComparer<RankedCandidate>
    {
        public static RankedCandidateComparer Instance { get; } = new();

        public int Compare(RankedCandidate? left, RankedCandidate? right)
        {
            if (ReferenceEquals(left, right))
            {
                return 0;
            }

            if (left is null)
            {
                return -1;
            }

            if (right is null)
            {
                return 1;
            }

            var rankComparison = left.Rank.AsSpan().SequenceCompareTo(right.Rank);
            if (rankComparison != 0)
            {
                return rankComparison;
            }

            var hashComparison = StringComparer.Ordinal.Compare(
                left.Candidate.ContentSha256,
                right.Candidate.ContentSha256);
            return hashComparison != 0
                ? hashComparison
                : StringComparer.Ordinal.Compare(
                    left.Candidate.DocumentId,
                    right.Candidate.DocumentId);
        }
    }
}
