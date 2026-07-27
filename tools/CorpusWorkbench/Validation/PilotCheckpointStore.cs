using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.CorpusWorkbench.Approval;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Serialization;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.CorpusWorkbench.Validation;

public sealed class PilotCheckpointStore
{
    private const string CheckpointId = "pilot-validation-v1";
    private const string AuthenticationCheckpointId =
        "pilot-validation-v1.mac";
    private const string AuthenticationDomain =
        "corpus-workbench-checkpoint-mac-input-v1\n";
    private const string IdentityDomain =
        "corpus-workbench-checkpoint-v1\n";
    private const string ScopeDomain =
        "corpus-workbench-scope-v1\n";
    private const string DocumentSetDomain =
        "corpus-workbench-document-set-v1\n";
    private const int MaximumDocumentCount =
        PilotValidator.MaximumPilotDocumentCount;
    private const int MaximumCanonicalBytes = 64 * 1024;

    private readonly CorpusVault _vault;
    private readonly PilotAuthenticationService _authentication;
    private readonly Func<
        CancellationToken,
        ValueTask<PilotRuntimeTrustState>>? _loadTrustedState;
    private readonly Action<PilotCheckpointFaultPoint>? _injectFault;

    public PilotCheckpointStore(CorpusVault vault)
        : this(
            vault,
            new PilotAuthenticationService(vault),
            loadTrustedState: null,
            injectFault: null)
    {
    }

    public PilotCheckpointStore(
        CorpusVault vault,
        ApprovalLedgerService approvalLedger)
        : this(
            vault,
            new PilotAuthenticationService(vault),
            cancellationToken => LoadTrustedStateAsync(
                approvalLedger,
                cancellationToken),
            injectFault: null)
    {
    }

    internal PilotCheckpointStore(
        CorpusVault vault,
        Action<PilotCheckpointFaultPoint>? injectFault)
        : this(
            vault,
            new PilotAuthenticationService(vault),
            loadTrustedState: null,
            injectFault)
    {
    }

    internal PilotCheckpointStore(
        CorpusVault vault,
        PilotAuthenticationService authentication,
        Func<
            CancellationToken,
            ValueTask<PilotRuntimeTrustState>>? loadTrustedState,
        Action<PilotCheckpointFaultPoint>? injectFault)
    {
        _vault = vault
            ?? throw new ArgumentNullException(nameof(vault));
        _authentication = authentication
            ?? throw new ArgumentNullException(
                nameof(authentication));
        _loadTrustedState = loadTrustedState;
        _injectFault = injectFault;
    }

    public async Task<PilotValidationCheckpoint> SaveAsync(
        PilotValidationRequest request,
        IEnumerable<string> documentIds,
        CancellationToken cancellationToken)
    {
        await RequireTrustedRequestAsync(
                request,
                cancellationToken)
            .ConfigureAwait(false);
        var expected = CreateCheckpoint(
            request,
            documentIds,
            cancellationToken);
        var canonical = WorkbenchJson.Serialize(
            expected,
            WorkbenchJsonContext.Default
                .PilotValidationCheckpoint);
        if (canonical.Length > MaximumCanonicalBytes)
        {
            throw InvalidCheckpoint();
        }

        byte[] authenticationTag;
        try
        {
            authenticationTag =
                await _authentication.SignCheckpointAsync(
                        CreateAuthenticationInput(
                            expected.CheckpointIdentitySha256,
                            expected.CheckpointIdentitySha256,
                            canonical),
                        cancellationToken)
                    .ConfigureAwait(false);
        }
        catch (PilotAuthenticationException exception)
        {
            throw InvalidCheckpoint(exception);
        }

        return await _vault.Store.ExecuteApprovalWriteAsync(
            async (connection, transaction) =>
            {
                var existing = await ReadAsync(
                        connection,
                        transaction,
                        expected,
                        cancellationToken)
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
                    INSERT INTO checkpoints(
                      checkpoint_id,
                      scope_sha256,
                      canonical_json)
                    VALUES(
                      $authentication_checkpoint_id,
                      $scope_sha256,
                      $authentication_tag);
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
                insert.Parameters.AddWithValue(
                    "$authentication_checkpoint_id",
                    AuthenticationCheckpointId);
                insert.Parameters.Add(
                    "$authentication_tag",
                    SqliteType.Blob).Value = authenticationTag;
                if (await insert.ExecuteNonQueryAsync(
                            CancellationToken.None)
                        .ConfigureAwait(false) != 2)
                {
                    throw InvalidCheckpoint();
                }

                _injectFault?.Invoke(
                    PilotCheckpointFaultPoint
                        .AfterInsertBeforeCommit);
                cancellationToken.ThrowIfCancellationRequested();
                return expected;
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<PilotValidationCheckpoint?> LoadAsync(
        PilotValidationRequest request,
        IEnumerable<string> documentIds,
        CancellationToken cancellationToken)
    {
        await RequireTrustedRequestAsync(
                request,
                cancellationToken)
            .ConfigureAwait(false);
        var expected = CreateCheckpoint(
            request,
            documentIds,
            cancellationToken);
        return await _vault.Store.ExecuteApprovalReadAsync(
            (connection, transaction) =>
                ReadAsync(
                    connection,
                    transaction,
                    expected,
                    cancellationToken),
            cancellationToken).ConfigureAwait(false);
    }

    public static string ComputeCheckpointIdentitySha256(
        PilotValidationRequest request,
        IEnumerable<string> documentIds)
    {
        PilotValidator.ValidateCheckpointRequest(request);
        var canonicalDocuments =
            CanonicalizeDocumentIds(
                documentIds,
                CancellationToken.None);
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
        IEnumerable<string> documentIds,
        CancellationToken cancellationToken)
    {
        PilotValidator.ValidateCheckpointRequest(request);
        var canonicalDocuments =
            CanonicalizeDocumentIds(
                documentIds,
                cancellationToken);
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

    private static async ValueTask<PilotRuntimeTrustState>
        LoadTrustedStateAsync(
        ApprovalLedgerService approvalLedger,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(approvalLedger);
        var verification = await approvalLedger.VerifyAsync(
                PilotValidator.MaximumPilotDocumentCount,
                cancellationToken)
            .ConfigureAwait(false);
        return new(
            PilotValidationTrustIdentity.From(approvalLedger),
            verification.IsValid,
            verification.LedgerHeadSha256);
    }

    private async ValueTask RequireTrustedRequestAsync(
        PilotValidationRequest request,
        CancellationToken cancellationToken)
    {
        if (_loadTrustedState is null)
        {
            throw InvalidCheckpoint();
        }

        PilotRuntimeTrustState trusted;
        try
        {
            trusted = await _loadTrustedState(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or CryptographicException
                or JsonException
                or ArgumentException
                or InvalidOperationException)
        {
            throw InvalidCheckpoint(exception);
        }

        PilotValidator.ValidateCheckpointRequest(request);
        if (!trusted.LedgerValid
            || !PilotValidator.SameScope(
                request.Scope,
                trusted.Identity.Scope)
            || !FixedHashEquals(
                request.RuleCatalogSha256,
                trusted.Identity.PilotRuleCatalogSha256)
            || !FixedHashEquals(
                request.WorkerPackageSha256,
                trusted.Identity.WorkerPackageSha256)
            || !FixedHashEquals(
                request.LedgerHeadSha256,
                trusted.LedgerHeadSha256))
        {
            throw InvalidCheckpoint();
        }
    }

    private async Task<PilotValidationCheckpoint?> ReadAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        PilotValidationCheckpoint expected,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT checkpoint_id, scope_sha256, canonical_json
            FROM checkpoints
            WHERE checkpoint_id IN (
              $checkpoint_id,
              $authentication_checkpoint_id)
            ORDER BY checkpoint_id;
            """;
        command.Parameters.AddWithValue(
            "$checkpoint_id",
            CheckpointId);
        command.Parameters.AddWithValue(
            "$authentication_checkpoint_id",
            AuthenticationCheckpointId);
        await using var reader = await command.ExecuteReaderAsync(
                CancellationToken.None)
            .ConfigureAwait(false);
        var rows = new Dictionary<
            string,
            (string Identity, byte[] Payload)>(
            StringComparer.Ordinal);
        while (await reader.ReadAsync(CancellationToken.None)
                   .ConfigureAwait(false))
        {
            if (reader.GetValue(0) is not string checkpointId
                || reader.GetValue(1) is not string identity
                || reader.GetValue(2) is not byte[] payload
                || !rows.TryAdd(
                    checkpointId,
                    (identity, payload)))
            {
                throw InvalidCheckpoint();
            }
        }

        if (rows.Count == 0)
        {
            return null;
        }

        if (rows.Count != 2
            || !rows.TryGetValue(CheckpointId, out var checkpointRow)
            || !rows.TryGetValue(
                AuthenticationCheckpointId,
                out var authenticationRow)
            || checkpointRow.Payload is not { } canonical
            || canonical.Length == 0
            || canonical.Length > MaximumCanonicalBytes
            || authenticationRow.Payload.Length != 32
            || !FixedHashEquals(
                checkpointRow.Identity,
                authenticationRow.Identity))
        {
            throw InvalidCheckpoint();
        }

        try
        {
            if (!await _authentication.VerifyCheckpointAsync(
                        CreateAuthenticationInput(
                            checkpointRow.Identity,
                            authenticationRow.Identity,
                            canonical),
                        authenticationRow.Payload,
                        cancellationToken)
                    .ConfigureAwait(false))
            {
                throw InvalidCheckpoint();
            }
        }
        catch (PilotAuthenticationException exception)
        {
            throw InvalidCheckpoint(exception);
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
                checkpointRow.Identity,
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

    private static byte[] CreateAuthenticationInput(
        string checkpointIdentity,
        string authenticationIdentity,
        byte[] canonical)
    {
        if (canonical.Length > MaximumCanonicalBytes)
        {
            throw InvalidCheckpoint();
        }

        using var stream = new MemoryStream(
            AuthenticationDomain.Length
            + CheckpointId.Length
            + AuthenticationCheckpointId.Length
            + checkpointIdentity.Length
            + authenticationIdentity.Length
            + canonical.Length
            + 5 * sizeof(int));
        WriteLengthPrefixed(stream, AuthenticationDomain);
        WriteLengthPrefixed(stream, CheckpointId);
        WriteLengthPrefixed(stream, AuthenticationCheckpointId);
        WriteLengthPrefixed(stream, checkpointIdentity);
        WriteLengthPrefixed(stream, authenticationIdentity);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(
            length,
            canonical.Length);
        stream.Write(length);
        stream.Write(canonical);
        return stream.ToArray();
    }

    private static void WriteLengthPrefixed(
        Stream stream,
        string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        stream.Write(length);
        stream.Write(bytes);
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
        IEnumerable<string> documentIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(documentIds);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var canonical = new List<string>(
            MaximumDocumentCount);
        foreach (var documentId in documentIds)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (canonical.Count >= MaximumDocumentCount
                || documentId is null
                || documentId.Length
                    != "document-".Length + 64
                || !documentId.StartsWith(
                    "document-",
                    StringComparison.Ordinal)
                || !PilotValidator.IsLowerSha256(
                    documentId["document-".Length..])
                || !seen.Add(documentId))
            {
                throw InvalidCheckpoint();
            }

            canonical.Add(documentId);
        }

        canonical.Sort(StringComparer.Ordinal);
        return [.. canonical];
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

internal sealed record PilotRuntimeTrustState(
    PilotValidationTrustIdentity Identity,
    bool LedgerValid,
    string LedgerHeadSha256);
