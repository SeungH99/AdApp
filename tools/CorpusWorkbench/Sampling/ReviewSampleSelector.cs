using System.Collections.Immutable;
using System.Numerics;
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

        var solver = new FeasibilitySolver(ranked, requireTags: true, requireFamilies: true);
        var initialState = solver.CreateInitialState();
        if (!solver.CanComplete(initialState))
        {
            throw CoverageInsufficient(GetCombinedCapacityStrata(ranked));
        }

        var selection = solver.ReconstructLexicographicallyFirstSelection(initialState);

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

    // The result of each state is independent of traversal order, which makes the
    // bounded solver safe to use as a feasibility oracle during rank-first selection.
    private static ImmutableArray<string> GetCombinedCapacityStrata(
        IReadOnlyList<RankedCandidate> ranked)
    {
        var canCompleteWithoutTags = new FeasibilitySolver(
                ranked,
                requireTags: false,
                requireFamilies: true)
            .CanComplete();
        var canCompleteWithoutFamilies = new FeasibilitySolver(
                ranked,
                requireTags: true,
                requireFamilies: false)
            .CanComplete();

        if (canCompleteWithoutTags && canCompleteWithoutFamilies)
        {
            return ["combined-strata-capacity"];
        }

        return canCompleteWithoutTags
            ? ["combined-input-kind-edge-case-capacity"]
            : canCompleteWithoutFamilies
                ? ["combined-input-kind-source-family-capacity"]
                : ["combined-strata-capacity"];
    }

    // Local tests use this deterministic diagnostic to assert the bounded search
    // state-space without relying on a wall-clock threshold.
    internal static int GetFeasibilityStateCount(
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
        var solver = new FeasibilitySolver(ranked, requireTags: true, requireFamilies: true);
        _ = solver.CanComplete();
        return solver.StateCount;
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

    private static WorkbenchException CoverageInsufficient(
        ImmutableArray<string> unsatisfiedStrata) =>
        new(
            WorkbenchFailureCode.ReviewCoverageInsufficient,
            detail: $"Unsatisfied strata: {string.Join(", ", unsatisfiedStrata)}.");

    private static WorkbenchException InvalidArguments() =>
        new(WorkbenchFailureCode.InvalidArguments);

    private sealed class FeasibilitySolver
    {
        private const byte RequiredTagMask = 0b1111;

        private readonly ImmutableArray<SolverCandidate> _candidates;
        private readonly int[] _remainingImagePdf;
        private readonly int[] _remainingRaster;
        private readonly byte[] _remainingTagMasks;
        private readonly ulong[] _remainingFamilyMasks;
        private readonly bool _requireTags;
        private readonly bool _requireFamilies;
        private readonly Dictionary<FeasibilityState, bool> _memo =
            new(FeasibilityStateComparer.Instance);

        public FeasibilitySolver(
            IReadOnlyList<RankedCandidate> ranked,
            bool requireTags,
            bool requireFamilies)
        {
            _requireTags = requireTags;
            _requireFamilies = requireFamilies;

            var families = ranked
                .Select(static item => item.Candidate.SourceFamilyId)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(static family => family, StringComparer.Ordinal)
                .ToArray();
            _candidates = ranked
                .Select(item => new SolverCandidate(
                    item,
                    item.Candidate.InputKind == ImagePdf,
                    GetTagMask(item.Candidate.EdgeCaseTags),
                    1UL << Array.BinarySearch(
                        families,
                        item.Candidate.SourceFamilyId,
                        StringComparer.Ordinal)))
                .ToImmutableArray();

            _remainingImagePdf = new int[_candidates.Length + 1];
            _remainingRaster = new int[_candidates.Length + 1];
            _remainingTagMasks = new byte[_candidates.Length + 1];
            _remainingFamilyMasks = new ulong[_candidates.Length + 1];
            for (var index = _candidates.Length - 1; index >= 0; index--)
            {
                var candidate = _candidates[index];
                _remainingImagePdf[index] = _remainingImagePdf[index + 1]
                    + (candidate.IsImagePdf ? 1 : 0);
                _remainingRaster[index] = _remainingRaster[index + 1]
                    + (candidate.IsImagePdf ? 0 : 1);
                _remainingTagMasks[index] = (byte)(
                    _remainingTagMasks[index + 1] | candidate.TagMask);
                _remainingFamilyMasks[index] = _remainingFamilyMasks[index + 1]
                    | candidate.FamilyBit;
            }
        }

        public int StateCount => _memo.Count;

        public FeasibilityState CreateInitialState() =>
            new(0, PerKindTarget, PerKindTarget, 0, 0, !_requireFamilies);

        public bool CanComplete() => CanComplete(CreateInitialState());

        public bool CanComplete(FeasibilityState state)
        {
            if (_memo.TryGetValue(state, out var result))
            {
                return result;
            }

            result = CanCompleteUncached(state);
            _memo.Add(state, result);
            return result;
        }

        public List<RankedCandidate> ReconstructLexicographicallyFirstSelection(
            FeasibilityState initialState)
        {
            var result = new List<RankedCandidate>(SampleTarget);
            var state = initialState;
            while (state.ImagePdfSlots > 0 || state.RasterSlots > 0)
            {
                var candidate = _candidates[state.RankIndex];
                if (TryInclude(state, candidate, out var included)
                    && CanComplete(included))
                {
                    result.Add(candidate.Ranked);
                    state = included;
                }
                else
                {
                    state = state with { RankIndex = state.RankIndex + 1 };
                }
            }

            return result;
        }

        private bool CanCompleteUncached(FeasibilityState state)
        {
            if (state.ImagePdfSlots == 0 && state.RasterSlots == 0)
            {
                return (!_requireTags || state.CoveredTagMask == RequiredTagMask)
                    && (!_requireFamilies || state.HasThreeFamilies);
            }

            if (state.RankIndex == _candidates.Length
                || _candidates.Length - state.RankIndex < state.ImagePdfSlots + state.RasterSlots
                || _remainingImagePdf[state.RankIndex] < state.ImagePdfSlots
                || _remainingRaster[state.RankIndex] < state.RasterSlots
                || (_requireTags
                    && (state.CoveredTagMask | _remainingTagMasks[state.RankIndex])
                        != RequiredTagMask)
                || (_requireFamilies
                    && !state.HasThreeFamilies
                    && BitOperations.PopCount(
                        state.SelectedFamilyMask | _remainingFamilyMasks[state.RankIndex])
                        < MinimumFamilyCount))
            {
                return false;
            }

            var candidate = _candidates[state.RankIndex];
            return (TryInclude(state, candidate, out var included) && CanComplete(included))
                || CanComplete(state with { RankIndex = state.RankIndex + 1 });
        }

        private bool TryInclude(
            FeasibilityState state,
            SolverCandidate candidate,
            out FeasibilityState included)
        {
            if ((candidate.IsImagePdf && state.ImagePdfSlots == 0)
                || (!candidate.IsImagePdf && state.RasterSlots == 0))
            {
                included = default;
                return false;
            }

            var selectedFamilyMask = state.SelectedFamilyMask;
            var hasThreeFamilies = state.HasThreeFamilies;
            if (_requireFamilies && !hasThreeFamilies)
            {
                selectedFamilyMask |= candidate.FamilyBit;
                if (BitOperations.PopCount(selectedFamilyMask) >= MinimumFamilyCount)
                {
                    selectedFamilyMask = 0;
                    hasThreeFamilies = true;
                }
            }

            included = new(
                state.RankIndex + 1,
                state.ImagePdfSlots - (candidate.IsImagePdf ? 1 : 0),
                state.RasterSlots - (candidate.IsImagePdf ? 0 : 1),
                _requireTags ? (byte)(state.CoveredTagMask | candidate.TagMask) : (byte)0,
                selectedFamilyMask,
                hasThreeFamilies);
            return true;
        }

        private static byte GetTagMask(ImmutableArray<string> tags)
        {
            var result = (byte)0;
            foreach (var tag in tags)
            {
                for (var index = 0; index < RequiredTags.Length; index++)
                {
                    if (string.Equals(tag, RequiredTags[index], StringComparison.Ordinal))
                    {
                        result |= (byte)(1 << index);
                        break;
                    }
                }
            }

            return result;
        }
    }

    private readonly record struct FeasibilityState(
        int RankIndex,
        int ImagePdfSlots,
        int RasterSlots,
        byte CoveredTagMask,
        ulong SelectedFamilyMask,
        bool HasThreeFamilies);

    private sealed class FeasibilityStateComparer : IEqualityComparer<FeasibilityState>
    {
        public static FeasibilityStateComparer Instance { get; } = new();

        public bool Equals(FeasibilityState left, FeasibilityState right) => left == right;

        public int GetHashCode(FeasibilityState value)
        {
            unchecked
            {
                var hash = (uint)value.RankIndex;
                hash = (hash * 31) + (uint)value.ImagePdfSlots;
                hash = (hash * 31) + (uint)value.RasterSlots;
                hash = (hash * 31) + value.CoveredTagMask;
                hash = (hash * 31) + (uint)value.SelectedFamilyMask;
                hash = (hash * 31) + (uint)(value.SelectedFamilyMask >> 32);
                hash = (hash * 31) + (value.HasThreeFamilies ? 1U : 0U);
                return (int)hash;
            }
        }
    }

    private sealed record SolverCandidate(
        RankedCandidate Ranked,
        bool IsImagePdf,
        byte TagMask,
        ulong FamilyBit);

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
