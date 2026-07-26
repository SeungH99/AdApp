using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Serialization;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.CorpusWorkbench.Validation;

public sealed class PilotCheckpointStore
{
    private const string CheckpointId = "pilot-validation-v1";
    private const string IdentityDomain =
        "corpus-workbench-checkpoint-v1\n";
    private const string ScopeDomain =
        "corpus-workbench-scope-v1\n";
    private const string DocumentSetDomain =
        "corpus-workbench-document-set-v1\n";
    private const int MaximumDocumentCount = 100_000;
    private const int MaximumCanonicalBytes = 16 * 1024 * 1024;

    private readonly CorpusVault _vault;
    private readonly Action<PilotCheckpointFaultPoint>? _injectFault;

    public PilotCheckpointStore(CorpusVault vault)
        : this(vault, injectFault: null)
    {
    }

    internal PilotCheckpointStore(
        CorpusVault vault,
        Action<PilotCheckpointFaultPoint>? injectFault)
    {
        _vault = vault
            ?? throw new ArgumentNullException(nameof(vault));
        _injectFault = injectFault;
    }

    public Task<PilotValidationCheckpoint> SaveAsync(
        PilotValidationRequest request,
        IEnumerable<string> documentIds,
        CancellationToken cancellationToken)
    {
        var expected = CreateCheckpoint(request, documentIds);
        var canonical = WorkbenchJson.Serialize(
            expected,
            WorkbenchJsonContext.Default
                .PilotValidationCheckpoint);
        if (canonical.Length > MaximumCanonicalBytes)
        {
            throw InvalidCheckpoint();
        }

        return _vault.Store.ExecuteApprovalWriteAsync(
            async (connection, transaction) =>
            {
                var existing = await ReadAsync(
                        connection,
                        transaction,
                        expected)
                    .ConfigureAwait(false);
                if (existing is not null)
                {
                    return existing;
                }

                await using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO checkpoints(
                      checkpoint_id,
                      scope_sha256,
                      canonical_json)
                    VALUES(
                      $checkpoint_id,
                      $scope_sha256,
                      $canonical_json);
                    """;
                insert.Parameters.AddWithValue(
                    "$checkpoint_id",
                    CheckpointId);
                insert.Parameters.AddWithValue(
                    "$scope_sha256",
                    expected.CheckpointIdentitySha256);
                insert.Parameters.Add(
                    "$canonical_json",
                    SqliteType.Blob).Value = canonical;
                if (await insert.ExecuteNonQueryAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false) != 1)
                {
                    throw InvalidCheckpoint();
                }

                _injectFault?.Invoke(
                    PilotCheckpointFaultPoint
                        .AfterInsertBeforeCommit);
                cancellationToken.ThrowIfCancellationRequested();
                return expected;
            },
            cancellationToken);
    }

    public Task<PilotValidationCheckpoint?> LoadAsync(
        PilotValidationRequest request,
        IEnumerable<string> documentIds,
        CancellationToken cancellationToken)
    {
        var expected = CreateCheckpoint(request, documentIds);
        return _vault.Store.ExecuteApprovalReadAsync(
            (connection, transaction) =>
                ReadAsync(connection, transaction, expected),
            cancellationToken);
    }

    public static string ComputeCheckpointIdentitySha256(
        PilotValidationRequest request,
        IEnumerable<string> documentIds)
    {
        PilotValidator.ValidateCheckpointRequest(request);
        var canonicalDocuments =
            CanonicalizeDocumentIds(documentIds);
        using var hash = IncrementalHash.CreateHash(
            HashAlgorithmName.SHA256);
        AppendUtf8(hash, IdentityDomain);
        AppendCanonicalScope(hash, request.Scope);
        AppendUtf8(hash, request.RuleCatalogSha256);
        AppendUtf8(hash, request.WorkerPackageSha256);
        AppendUtf8(hash, request.LedgerHeadSha256);
        AppendCanonicalDocumentSet(hash, canonicalDocuments);
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static PilotValidationCheckpoint CreateCheckpoint(
        PilotValidationRequest request,
        IEnumerable<string> documentIds)
    {
        PilotValidator.ValidateCheckpointRequest(request);
        var canonicalDocuments =
            CanonicalizeDocumentIds(documentIds);
        var canonicalScope = request.Scope with
        {
            MarketIds =
            [
                .. request.Scope.MarketIds
                    .Order(StringComparer.Ordinal),
            ],
        };
        var canonicalRequest = request with
        {
            Scope = canonicalScope,
        };
        return new PilotValidationCheckpoint(
            PilotCatalog.SchemaVersion,
            ComputeCheckpointIdentitySha256(
                canonicalRequest,
                canonicalDocuments),
            canonicalScope,
            request.RuleCatalogSha256,
            request.WorkerPackageSha256,
            request.LedgerHeadSha256,
            canonicalDocuments);
    }

    private static async Task<PilotValidationCheckpoint?> ReadAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        PilotValidationCheckpoint expected)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT checkpoint_id, scope_sha256, canonical_json
            FROM checkpoints
            WHERE checkpoint_id=$checkpoint_id;
            """;
        command.Parameters.AddWithValue(
            "$checkpoint_id",
            CheckpointId);
        await using var reader = await command.ExecuteReaderAsync(
                CancellationToken.None)
            .ConfigureAwait(false);
        if (!await reader.ReadAsync(CancellationToken.None)
                .ConfigureAwait(false))
        {
            return null;
        }

        if (!string.Equals(
                reader.GetString(0),
                CheckpointId,
                StringComparison.Ordinal)
            || reader.GetValue(2) is not byte[] canonical
            || canonical.Length == 0
            || canonical.Length > MaximumCanonicalBytes)
        {
            throw InvalidCheckpoint();
        }

        var persistedIdentity = reader.GetString(1);
        if (await reader.ReadAsync(CancellationToken.None)
                .ConfigureAwait(false))
        {
            throw InvalidCheckpoint();
        }

        PilotValidationCheckpoint checkpoint;
        try
        {
            checkpoint = WorkbenchJson.Parse(
                canonical,
                WorkbenchJsonContext.Default
                    .PilotValidationCheckpoint);
            ValidatePersistedCheckpoint(
                checkpoint,
                persistedIdentity,
                canonical,
                expected);
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is JsonException
                or NotSupportedException
                or FormatException
                or CryptographicException
                or ArgumentException
                or OverflowException)
        {
            throw InvalidCheckpoint(exception);
        }

        return checkpoint;
    }

    private static void ValidatePersistedCheckpoint(
        PilotValidationCheckpoint checkpoint,
        string persistedIdentity,
        byte[] canonical,
        PilotValidationCheckpoint expected)
    {
        if (!string.Equals(
                checkpoint.SchemaVersion,
                PilotCatalog.SchemaVersion,
                StringComparison.Ordinal)
            || !PilotValidator.IsLowerSha256(persistedIdentity)
            || !FixedHashEquals(
                checkpoint.CheckpointIdentitySha256,
                persistedIdentity)
            || !IsCanonicalDocumentSet(checkpoint.DocumentIds)
            || !SameScope(checkpoint.Scope, expected.Scope)
            || !FixedHashEquals(
                checkpoint.RuleCatalogSha256,
                expected.RuleCatalogSha256)
            || !FixedHashEquals(
                checkpoint.WorkerPackageSha256,
                expected.WorkerPackageSha256)
            || !FixedHashEquals(
                checkpoint.LedgerHeadSha256,
                expected.LedgerHeadSha256)
            || !checkpoint.DocumentIds.AsSpan().SequenceEqual(
                expected.DocumentIds.AsSpan())
            || !FixedHashEquals(
                checkpoint.CheckpointIdentitySha256,
                expected.CheckpointIdentitySha256)
            || !FixedHashEquals(
                checkpoint.CheckpointIdentitySha256,
                ComputeCheckpointIdentitySha256(
                    new PilotValidationRequest(
                        checkpoint.Scope,
                        checkpoint.RuleCatalogSha256,
                        checkpoint.WorkerPackageSha256,
                        checkpoint.LedgerHeadSha256),
                    checkpoint.DocumentIds))
            || !CryptographicOperations.FixedTimeEquals(
                canonical,
                WorkbenchJson.Serialize(
                    checkpoint,
                    WorkbenchJsonContext.Default
                        .PilotValidationCheckpoint)))
        {
            throw InvalidCheckpoint();
        }
    }

    private static ImmutableArray<string> CanonicalizeDocumentIds(
        IEnumerable<string> documentIds)
    {
        ArgumentNullException.ThrowIfNull(documentIds);
        var canonical = documentIds
            .Order(StringComparer.Ordinal)
            .ToImmutableArray();
        if (canonical.Length > MaximumDocumentCount
            || canonical.Distinct(StringComparer.Ordinal).Count()
                != canonical.Length
            || canonical.Any(static documentId =>
                documentId is null
                || documentId.Length != "document-".Length + 64
                || !documentId.StartsWith(
                    "document-",
                    StringComparison.Ordinal)
                || !PilotValidator.IsLowerSha256(
                    documentId["document-".Length..])))
        {
            throw InvalidCheckpoint();
        }

        return canonical;
    }

    private static bool IsCanonicalDocumentSet(
        ImmutableArray<string> documentIds) =>
        !documentIds.IsDefault
        && documentIds.Length <= MaximumDocumentCount
        && documentIds.AsSpan().SequenceEqual(
            documentIds
                .Order(StringComparer.Ordinal)
                .ToArray()
                .AsSpan())
        && documentIds.Distinct(StringComparer.Ordinal).Count()
            == documentIds.Length
        && documentIds.All(static documentId =>
            documentId is not null
            && documentId.Length == "document-".Length + 64
            && documentId.StartsWith(
                "document-",
                StringComparison.Ordinal)
            && PilotValidator.IsLowerSha256(
                documentId["document-".Length..]));

    private static bool SameScope(PilotScope left, PilotScope right) =>
        left is not null
        && right is not null
        && string.Equals(
            left.SchemaVersion,
            right.SchemaVersion,
            StringComparison.Ordinal)
        && string.Equals(
            left.CatalogEpoch,
            right.CatalogEpoch,
            StringComparison.Ordinal)
        && string.Equals(
            left.ContractId,
            right.ContractId,
            StringComparison.Ordinal)
        && left.HeldOutTargetPerMarket
            == right.HeldOutTargetPerMarket
        && left.DirectReviewTargetPerMarket
            == right.DirectReviewTargetPerMarket
        && !left.MarketIds.IsDefault
        && !right.MarketIds.IsDefault
        && left.MarketIds.AsSpan().SequenceEqual(
            right.MarketIds.AsSpan());

    private static void AppendCanonicalScope(
        IncrementalHash hash,
        PilotScope scope)
    {
        AppendUtf8(hash, ScopeDomain);
        AppendLengthPrefixed(hash, scope.SchemaVersion);
        AppendLengthPrefixed(hash, scope.CatalogEpoch);
        AppendLengthPrefixed(hash, scope.ContractId);
        var markets = scope.MarketIds
            .Order(StringComparer.Ordinal)
            .ToArray();
        AppendInt32(hash, markets.Length);
        foreach (var market in markets)
        {
            AppendLengthPrefixed(hash, market);
        }

        AppendInt32(hash, scope.HeldOutTargetPerMarket);
        AppendInt32(hash, scope.DirectReviewTargetPerMarket);
    }

    private static void AppendCanonicalDocumentSet(
        IncrementalHash hash,
        ImmutableArray<string> documentIds)
    {
        AppendUtf8(hash, DocumentSetDomain);
        AppendInt32(hash, documentIds.Length);
        foreach (var documentId in documentIds)
        {
            AppendLengthPrefixed(hash, documentId);
        }
    }

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

    private static void AppendUtf8(
        IncrementalHash hash,
        string value) =>
        hash.AppendData(Encoding.UTF8.GetBytes(value));

    private static bool FixedHashEquals(
        string? left,
        string? right) =>
        PilotValidator.IsLowerSha256(left)
        && PilotValidator.IsLowerSha256(right)
        && CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left!),
            Convert.FromHexString(right!));

    private static WorkbenchException InvalidCheckpoint(
        Exception? inner = null) =>
        new(WorkbenchFailureCode.InvalidCheckpoint, inner);
}

internal enum PilotCheckpointFaultPoint
{
    AfterInsertBeforeCommit = 0,
}
