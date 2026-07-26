using System.Collections.Immutable;
using System.Security.Cryptography;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Serialization;

namespace LocalDocumentOrganizer.CorpusWorkbench.Sampling;

public sealed record ReviewSampleProof(
    string SchemaVersion,
    string CatalogEpoch,
    string ContractId,
    string MarketId,
    ImmutableArray<ReviewCandidate> Candidates,
    ImmutableArray<string> OrderedDocumentIds,
    ImmutableDictionary<string, int> InputKindCounts,
    int SourceFamilyCount,
    ImmutableArray<string> CoveredEdgeCaseTags,
    string CandidateSetSha256,
    string SampleSha256)
{
    public static ReviewSampleProof Create(
        PilotScope scope,
        string marketId,
        IReadOnlyList<ReviewCandidate> candidates)
    {
        var sample = ReviewSampleSelector.Select(
            scope,
            marketId,
            candidates);
        var canonicalCandidates = candidates
            .OrderBy(
                static candidate => candidate.DocumentId,
                StringComparer.Ordinal)
            .ToImmutableArray();
        var proof = new ReviewSampleProof(
            scope.SchemaVersion,
            scope.CatalogEpoch,
            scope.ContractId,
            marketId,
            canonicalCandidates,
            sample.DocumentIds,
            sample.InputKindCounts,
            sample.SourceFamilyCount,
            sample.CoveredEdgeCaseTags,
            HashCandidates(candidates),
            string.Empty);
        return proof with
        {
            SampleSha256 = HashProof(proof),
        };
    }

    public ReviewSample Validate(
        PilotScope scope,
        IReadOnlyList<ReviewCandidate> candidates)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(candidates);
        ValidateCanonical();
        if (!string.Equals(
                SchemaVersion,
                scope.SchemaVersion,
                StringComparison.Ordinal)
            || !string.Equals(
                CatalogEpoch,
                scope.CatalogEpoch,
                StringComparison.Ordinal)
            || !string.Equals(
                ContractId,
                scope.ContractId,
                StringComparison.Ordinal)
            || !scope.MarketIds.Contains(
                MarketId,
                StringComparer.Ordinal)
            || !CandidatesEqual(
                Candidates,
                candidates
                    .OrderBy(
                        static candidate => candidate.DocumentId,
                        StringComparer.Ordinal)
                    .ToArray())
            || !FixedEquals(
                CandidateSetSha256,
                HashCandidates(candidates)))
        {
            throw InvalidState();
        }

        var selected = ReviewSampleSelector.Select(
            scope,
            MarketId,
            candidates);
        if (!OrderedDocumentIds.AsSpan()
                .SequenceEqual(selected.DocumentIds.AsSpan())
            || SourceFamilyCount != selected.SourceFamilyCount
            || !CoveredEdgeCaseTags.AsSpan()
                .SequenceEqual(
                    selected.CoveredEdgeCaseTags.AsSpan())
            || InputKindCounts.Count
                != selected.InputKindCounts.Count
            || InputKindCounts.Any(pair =>
                !selected.InputKindCounts.TryGetValue(
                    pair.Key,
                    out var count)
                || count != pair.Value))
        {
            throw InvalidState();
        }

        return selected;
    }

    internal void ValidateCanonical()
    {
        if (SchemaVersion != PilotCatalog.SchemaVersion
            || string.IsNullOrWhiteSpace(CatalogEpoch)
            || CatalogEpoch != CatalogEpoch.Trim()
            || ContractId != PilotCatalog.ContractId
            || !PilotCatalog.MarketIds.Contains(
                MarketId,
                StringComparer.Ordinal)
            || Candidates.IsDefaultOrEmpty
            || !CandidatesEqual(
                Candidates,
                Candidates
                    .OrderBy(
                        static candidate => candidate.DocumentId,
                        StringComparer.Ordinal)
                    .ToArray())
            || OrderedDocumentIds.IsDefault
            || OrderedDocumentIds.Length
                != PilotCatalog.DirectReviewTargetPerMarket
            || OrderedDocumentIds.Distinct(
                    StringComparer.Ordinal).Count()
                != OrderedDocumentIds.Length
            || OrderedDocumentIds.Any(
                static id => string.IsNullOrWhiteSpace(id))
            || InputKindCounts is null
            || InputKindCounts.Count != 2
            || !InputKindCounts.TryGetValue(
                "image-pdf",
                out var pdfCount)
            || pdfCount != 5
            || !InputKindCounts.TryGetValue(
                "standalone-raster",
                out var rasterCount)
            || rasterCount != 5
            || SourceFamilyCount < 3
            || CoveredEdgeCaseTags.IsDefault
            || !CoveredEdgeCaseTags.AsSpan().SequenceEqual(
                new[]
                {
                    "amount",
                    "currency-symbol",
                    "date",
                    "identifier",
                })
            || !IsLowerSha256(CandidateSetSha256)
            || !FixedEquals(
                CandidateSetSha256,
                HashCandidates(Candidates))
            || !IsLowerSha256(SampleSha256)
            || !FixedEquals(SampleSha256, HashProof(this)))
        {
            throw InvalidState();
        }
    }

    private static string HashCandidates(
        IReadOnlyList<ReviewCandidate> candidates)
    {
        var ordered = candidates
            .OrderBy(
                static candidate => candidate.DocumentId,
                StringComparer.Ordinal)
            .ToImmutableArray();
        var canonical = WorkbenchJson.Serialize(
            ordered,
            WorkbenchJsonContext.Default
                .ImmutableArrayReviewCandidate);
        return Hash("corpus-review-candidates-v1\n"u8, canonical);
    }

    private static string HashProof(ReviewSampleProof proof)
    {
        var payload = new ReviewSampleProofPayload(
            proof.SchemaVersion,
            proof.CatalogEpoch,
            proof.ContractId,
            proof.MarketId,
            proof.OrderedDocumentIds,
            proof.InputKindCounts,
            proof.SourceFamilyCount,
            proof.CoveredEdgeCaseTags,
            proof.CandidateSetSha256);
        var canonical = WorkbenchJson.Serialize(
            payload,
            WorkbenchJsonContext.Default
                .ReviewSampleProofPayload);
        return Hash("corpus-review-sample-proof-v1\n"u8, canonical);
    }

    private static string Hash(
        ReadOnlySpan<byte> domain,
        byte[] canonical)
    {
        var bytes = new byte[domain.Length + canonical.Length];
        domain.CopyTo(bytes);
        canonical.CopyTo(bytes.AsSpan(domain.Length));
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    private static bool IsLowerSha256(string? value) =>
        value is not null
        && value.Length == 64
        && value.All(static character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static bool FixedEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));

    private static bool CandidatesEqual(
        IReadOnlyList<ReviewCandidate> left,
        IReadOnlyList<ReviewCandidate> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        for (var index = 0; index < left.Count; index++)
        {
            var leftCandidate = left[index];
            var rightCandidate = right[index];
            if (!string.Equals(
                    leftCandidate.DocumentId,
                    rightCandidate.DocumentId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    leftCandidate.ContentSha256,
                    rightCandidate.ContentSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    leftCandidate.SourceFamilyId,
                    rightCandidate.SourceFamilyId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    leftCandidate.InputKind,
                    rightCandidate.InputKind,
                    StringComparison.Ordinal)
                || !leftCandidate.EdgeCaseTags.AsSpan()
                    .SequenceEqual(
                        rightCandidate.EdgeCaseTags.AsSpan()))
            {
                return false;
            }
        }

        return true;
    }

    private static WorkbenchException InvalidState() =>
        new(WorkbenchFailureCode.InvalidCheckpoint);
}

public sealed record ReviewSampleProofPayload(
    string SchemaVersion,
    string CatalogEpoch,
    string ContractId,
    string MarketId,
    ImmutableArray<string> OrderedDocumentIds,
    ImmutableDictionary<string, int> InputKindCounts,
    int SourceFamilyCount,
    ImmutableArray<string> CoveredEdgeCaseTags,
    string CandidateSetSha256);
