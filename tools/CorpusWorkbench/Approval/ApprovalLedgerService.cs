using System.Collections.Immutable;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LocalDocumentOrganizer.CorpusEval;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Labels;
using LocalDocumentOrganizer.CorpusWorkbench.Persistence;
using LocalDocumentOrganizer.CorpusWorkbench.Rules;
using LocalDocumentOrganizer.CorpusWorkbench.Serialization;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.CorpusWorkbench.Approval;

public sealed record ApprovalVerificationResult(
    bool IsValid,
    WorkbenchFailureCode? FailureCode,
    string LedgerHeadSha256,
    ImmutableArray<string> InvalidEntryIds);

public sealed record DirectReviewDecision(
    string DocumentId,
    string LabelRevisionId,
    string ReviewerId,
    DateTimeOffset ApprovedAtUtc);

public sealed record DelegatedLabelDecision(
    string DocumentId,
    string LabelRevisionId,
    string DelegateId,
    DateTimeOffset LabeledAtUtc);

public sealed record BatchApprovalDecision(
    string MarketId,
    string ReviewerId,
    string BatchSummarySha256,
    DateTimeOffset ApprovedAtUtc);

public sealed class ApprovalLedgerService
{
    private const string GenesisSha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    private const string EntryDomain = "corpus-approval-entry-v1\n";
    private const string IdentityDomain =
        "corpus-approval-decision-identity-v1\n";
    private const string BatchSummaryDomain =
        "corpus-approval-batch-summary-v1\n";
    private static readonly TimeSpan FutureTolerance =
        TimeSpan.FromMinutes(5);

    private readonly Action<ApprovalLedgerFaultPoint>? _injectFault;
    private readonly ApprovalLedgerContext _context;
    private readonly TimeProvider _timeProvider;
    private readonly CorpusWorkbenchStore _store;
    private readonly Func<CancellationToken, Task> _verifyWorker;

    public ApprovalLedgerService(
        CorpusVault vault,
        PilotScope scope,
        OfficialRuleCatalogSnapshot rules,
        CorpusWorkerPackageWorkspace workerWorkspace)
        : this(
            vault,
            scope,
            [rules],
            workerWorkspace,
            TimeProvider.System,
            injectFault: null)
    {
    }

    public ApprovalLedgerService(
        CorpusVault vault,
        PilotScope scope,
        IEnumerable<OfficialRuleCatalogSnapshot> rules,
        CorpusWorkerPackageWorkspace workerWorkspace)
        : this(
            vault,
            scope,
            rules,
            workerWorkspace,
            TimeProvider.System,
            injectFault: null)
    {
    }

    private ApprovalLedgerService(
        CorpusVault vault,
        PilotScope scope,
        IEnumerable<OfficialRuleCatalogSnapshot> rules,
        CorpusWorkerPackageWorkspace workerWorkspace,
        TimeProvider timeProvider,
        Action<ApprovalLedgerFaultPoint>? injectFault)
    {
        ArgumentNullException.ThrowIfNull(workerWorkspace);
        _context = ApprovalLedgerContext.Create(
            scope,
            rules,
            workerWorkspace.Identity);
        _store = RequireStore(vault);
        _timeProvider = timeProvider
            ?? throw new ArgumentNullException(nameof(timeProvider));
        _injectFault = injectFault;
        _verifyWorker = workerWorkspace.VerifyAsync;
    }

    internal ApprovalLedgerService(
        CorpusVault vault,
        PilotScope scope,
        IEnumerable<OfficialRuleCatalogSnapshot> rules,
        CorpusWorkerPackageIdentity workerIdentity,
        TimeProvider timeProvider,
        Action<ApprovalLedgerFaultPoint>? injectFault)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(workerIdentity);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _context = ApprovalLedgerContext.Create(
            scope,
            rules,
            workerIdentity);
        _store = vault.Store;
        _timeProvider = timeProvider;
        _injectFault = injectFault;
        _verifyWorker = static _ => Task.CompletedTask;
    }

    public async Task<ApprovalEntry> RecordDirectReviewAsync(
        DirectReviewDecision decision,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ValidateActor(decision.ReviewerId);
        ValidateDecisionTime(decision.ApprovedAtUtc);
        ValidateObjectId(decision.DocumentId, "document-");
        ValidateObjectId(decision.LabelRevisionId, "revision-");
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        return await AppendDocumentDecisionAsync(
                ApprovalMode.DirectReview,
                decision.DocumentId,
                decision.LabelRevisionId,
                decision.ReviewerId.Normalize(),
                decision.ApprovedAtUtc,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ApprovalEntry> RecordDelegatedLabelAsync(
        DelegatedLabelDecision decision,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ValidateActor(decision.DelegateId);
        ValidateDecisionTime(decision.LabeledAtUtc);
        ValidateObjectId(decision.DocumentId, "document-");
        ValidateObjectId(decision.LabelRevisionId, "revision-");
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        return await AppendDocumentDecisionAsync(
                ApprovalMode.DelegatedLabel,
                decision.DocumentId,
                decision.LabelRevisionId,
                decision.DelegateId.Normalize(),
                decision.LabeledAtUtc,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<ApprovalEntry> RecordBatchApprovalAsync(
        BatchApprovalDecision decision,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ValidateActor(decision.ReviewerId);
        ValidateDecisionTime(decision.ApprovedAtUtc);
        if (!_context.RuleCatalogs.ContainsKey(decision.MarketId)
            || !IsLowerSha256(decision.BatchSummarySha256))
        {
            throw InvalidArguments();
        }

        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        decision = decision with
        {
            ReviewerId = decision.ReviewerId.Normalize(),
        };
        return await _store.ExecuteApprovalWriteAsync(
            async (connection, transaction) =>
            {
                var rows = await ReadRowsAsync(
                        connection,
                        transaction)
                    .ConfigureAwait(false);
                RequireValidChain(rows);
                var states =
                    await _store.ReadAllApprovalLabelStatesAsync(
                            connection,
                            transaction)
                        .ConfigureAwait(false);
                var selection = SelectBatchBindings(
                    decision.MarketId,
                    rows,
                    states,
                    requireExactDirectCount: true);
                var actualSummary =
                    ComputeBatchSummarySha256(selection.Delegated);
                if (!FixedEquals(
                        actualSummary,
                        decision.BatchSummarySha256))
                {
                    throw InvalidState();
                }

                var ruleHash =
                    _context.RuleCatalogs[decision.MarketId];
                var payload = ApprovalDecisionPayload.Batch(
                    decision,
                    _context.Scope,
                    ruleHash,
                    _context.WorkerIdentity,
                    selection.Delegated,
                    selection.Direct);
                return await AppendAsync(
                        connection,
                        transaction,
                        rows,
                        payload)
                    .ConfigureAwait(false);
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<ApprovalVerificationResult> VerifyAsync(
        CancellationToken cancellationToken)
    {
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        var result = await _store.ExecuteApprovalReadAsync(
            async connection =>
            {
                var rows = await ReadRowsAsync(
                        connection,
                        transaction: null)
                    .ConfigureAwait(false);
                var invalid = FindChainFailures(rows);
                if (invalid.Count == 0)
                {
                    FindLedgerSemanticFailures(rows, invalid);
                }
                if (invalid.Count == 0)
                {
                    try
                    {
                        var states =
                            await _store.ReadAllApprovalLabelStatesAsync(
                                    connection,
                                    transaction: null)
                                .ConfigureAwait(false);
                        FindCurrentStateFailures(
                            rows,
                            states,
                            invalid);
                    }
                    catch (WorkbenchException)
                    {
                        AddAllEntryIds(rows, invalid);
                    }
                    catch (Exception exception) when (
                        exception is JsonException
                            or FormatException
                            or CryptographicException)
                    {
                        AddAllEntryIds(rows, invalid);
                    }
                }

                var ordered = invalid
                    .OrderBy(
                        entryId => EntrySequence(rows, entryId))
                    .ThenBy(
                        static entryId => entryId,
                        StringComparer.Ordinal)
                    .ToImmutableArray();
                return new ApprovalVerificationResult(
                    ordered.IsEmpty,
                    ordered.IsEmpty
                        ? null
                        : WorkbenchFailureCode.ApprovalChainInvalid,
                    LedgerHead(rows),
                    ordered);
            },
            cancellationToken).ConfigureAwait(false);
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    internal static string ComputeBatchSummarySha256(
        IEnumerable<ApprovalEntryReference> delegatedEntries)
    {
        ArgumentNullException.ThrowIfNull(delegatedEntries);
        var entries = delegatedEntries
            .OrderBy(
                static item => item.DocumentId,
                StringComparer.Ordinal)
            .ThenBy(
                static item => item.EntryId,
                StringComparer.Ordinal)
            .ToArray();
        if (entries.Select(static item => item.DocumentId)
            .Distinct(StringComparer.Ordinal)
            .Count() != entries.Length)
        {
            throw InvalidState();
        }

        using var stream = new MemoryStream();
        stream.Write(Encoding.UTF8.GetBytes(BatchSummaryDomain));
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartArray();
            foreach (var entry in entries)
            {
                WriteReference(writer, entry);
            }

            writer.WriteEndArray();
        }

        return Convert.ToHexStringLower(
            SHA256.HashData(stream.ToArray()));
    }

    private Task<ApprovalEntry> AppendDocumentDecisionAsync(
        ApprovalMode mode,
        string documentId,
        string revisionId,
        string actorId,
        DateTimeOffset decisionTime,
        CancellationToken cancellationToken) =>
        _store.ExecuteApprovalWriteAsync(
            async (connection, transaction) =>
            {
                var rows = await ReadRowsAsync(
                        connection,
                        transaction)
                    .ConfigureAwait(false);
                RequireValidChain(rows);
                var state =
                    await _store.ReadApprovalLabelStateAsync(
                            connection,
                            transaction,
                            documentId)
                        .ConfigureAwait(false);
                var revision = state.PreviousRevision
                    ?? throw InvalidState();
                if (!string.Equals(
                        revision.RevisionId,
                        revisionId,
                        StringComparison.Ordinal))
                {
                    throw InvalidState();
                }

                RequireCurrentBinding(state);
                RequireReviewCoverage(
                    revision,
                    _context.RuleIdsByMarket[
                        state.Document.MarketId]);
                var payload = ApprovalDecisionPayload.Document(
                    mode,
                    actorId,
                    decisionTime,
                    _context.Scope,
                    state.Document,
                    revision);
                return await AppendAsync(
                        connection,
                        transaction,
                        rows,
                        payload)
                    .ConfigureAwait(false);
            },
            cancellationToken);

    private async Task<ApprovalEntry> AppendAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<ApprovalLedgerRow> rows,
        ApprovalDecisionPayload payload)
    {
        var canonical = CanonicalApprovalDecision.Serialize(payload);
        var entryId = CreateEntryId(canonical);
        var exact = rows.SingleOrDefault(
            row => string.Equals(
                row.EntryId,
                entryId,
                StringComparison.Ordinal));
        if (exact is not null)
        {
            if (!exact.CanonicalValid
                || !CryptographicOperations.FixedTimeEquals(
                    exact.Canonical,
                    canonical))
            {
                throw InvalidState();
            }

            await VerifyWorkerAsync(CancellationToken.None)
                .ConfigureAwait(false);
            return exact.ToEntry();
        }

        var previous = rows.Count == 0
            ? GenesisSha256
            : rows[^1].EntrySha256;
        var entrySha256 = HashEntry(previous, canonical);
        var sequence = rows.Count == 0
            ? 1L
            : checked(rows[^1].Sequence + 1);
        _injectFault?.Invoke(
            ApprovalLedgerFaultPoint.BeforeInsert);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO approval_entries(
                  sequence,
                  entry_id,
                  previous_entry_sha256,
                  entry_sha256,
                  canonical_json)
                VALUES(
                  $sequence,
                  $entry_id,
                  $previous_entry_sha256,
                  $entry_sha256,
                  $canonical_json);
                """;
            command.Parameters.AddWithValue("$sequence", sequence);
            command.Parameters.AddWithValue("$entry_id", entryId);
            command.Parameters.AddWithValue(
                "$previous_entry_sha256",
                previous);
            command.Parameters.AddWithValue(
                "$entry_sha256",
                entrySha256);
            var canonicalParameter = command.Parameters.Add(
                "$canonical_json",
                SqliteType.Blob);
            canonicalParameter.Value = canonical;
            if (await command.ExecuteNonQueryAsync(
                    CancellationToken.None)
                .ConfigureAwait(false) != 1)
            {
                throw InvalidState();
            }
        }

        _injectFault?.Invoke(
            ApprovalLedgerFaultPoint.AfterInsertBeforeCommit);
        await VerifyWorkerAsync(CancellationToken.None)
            .ConfigureAwait(false);
        return ApprovalLedgerRow.Valid(
                sequence,
                entryId,
                previous,
                entrySha256,
                canonical,
                payload)
            .ToEntry();
    }

    private void FindCurrentStateFailures(
        IReadOnlyList<ApprovalLedgerRow> rows,
        IReadOnlyList<LabelDraftState> states,
        ISet<string> invalid)
    {
        var currentByDocument = states.ToDictionary(
            static state => state.Document.DocumentId,
            StringComparer.Ordinal);
        var latestDocumentDecisions = rows
            .Where(static row =>
                row.Payload?.Mode is ApprovalMode.DirectReview
                    or ApprovalMode.DelegatedLabel)
            .GroupBy(
                static row => (
                    row.Payload!.Mode,
                    row.Payload.DocumentId),
                EqualityComparer<(ApprovalMode, string?)>.Default)
            .Select(static group =>
                group.OrderByDescending(static row => row.Sequence)
                    .First());
        foreach (var row in latestDocumentDecisions)
        {
            var payload = row.Payload!;
            if (!currentByDocument.TryGetValue(
                    payload.DocumentId!,
                    out var state)
                || !MatchesCurrent(payload, state))
            {
                invalid.Add(row.EntryId);
                continue;
            }

            try
            {
                RequireReviewCoverage(
                    state.PreviousRevision!,
                    _context.RuleIdsByMarket[
                        state.Document.MarketId]);
            }
            catch (WorkbenchException)
            {
                invalid.Add(row.EntryId);
            }
        }

        var latestBatches = rows
            .Where(static row =>
                row.Payload?.Mode == ApprovalMode.BatchApproval)
            .GroupBy(
                static row => row.Payload!.MarketId,
                StringComparer.Ordinal)
            .Select(static group =>
                group.OrderByDescending(static row => row.Sequence)
                    .First());
        foreach (var batch in latestBatches)
        {
            try
            {
                var payload = batch.Payload!;
                var selected = SelectBatchBindings(
                    payload.MarketId,
                    rows,
                    states,
                    requireExactDirectCount: true);
                var summary =
                    ComputeBatchSummarySha256(selected.Delegated);
                if (!FixedEquals(
                        summary,
                        payload.BatchSummarySha256!)
                    || !payload.DelegatedEntries.AsSpan()
                        .SequenceEqual(selected.Delegated.AsSpan())
                    || !payload.DirectReviewEntries.AsSpan()
                        .SequenceEqual(selected.Direct.AsSpan())
                    || !IsCurrentContext(payload))
                {
                    invalid.Add(batch.EntryId);
                }
            }
            catch (WorkbenchException)
            {
                invalid.Add(batch.EntryId);
            }
        }
    }

    private BatchSelection SelectBatchBindings(
        string marketId,
        IReadOnlyList<ApprovalLedgerRow> rows,
        IReadOnlyList<LabelDraftState> states,
        bool requireExactDirectCount)
    {
        if (!_context.RuleCatalogs.ContainsKey(marketId))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.StaleRuleSet);
        }

        var current = states
            .Where(state => string.Equals(
                state.Document.MarketId,
                marketId,
                StringComparison.Ordinal))
            .ToDictionary(
                static state => state.Document.DocumentId,
                StringComparer.Ordinal);
        var directRows = LatestDocumentRows(
            rows,
            ApprovalMode.DirectReview,
            marketId);
        var delegatedRows = LatestDocumentRows(
            rows,
            ApprovalMode.DelegatedLabel,
            marketId);

        var direct = ImmutableArray.CreateBuilder<
            ApprovalEntryReference>();
        foreach (var row in directRows)
        {
            if (!current.TryGetValue(
                    row.Payload!.DocumentId!,
                    out var state)
                || !MatchesCurrent(row.Payload, state))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InsufficientDirectReview);
            }

            RequireReviewCoverage(
                state.PreviousRevision!,
                _context.RuleIdsByMarket[marketId]);
            direct.Add(row.ToReference());
        }

        if (requireExactDirectCount
            && direct.Count
                != _context.Scope.DirectReviewTargetPerMarket)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InsufficientDirectReview);
        }

        var delegated = ImmutableArray.CreateBuilder<
            ApprovalEntryReference>();
        foreach (var row in delegatedRows)
        {
            if (!current.TryGetValue(
                    row.Payload!.DocumentId!,
                    out var state)
                || !MatchesCurrent(row.Payload, state))
            {
                throw InvalidState();
            }

            delegated.Add(row.ToReference());
        }

        return new BatchSelection(
            [
                .. delegated.OrderBy(
                    static item => item.DocumentId,
                    StringComparer.Ordinal),
            ],
            [
                .. direct.OrderBy(
                    static item => item.DocumentId,
                    StringComparer.Ordinal),
            ]);
    }

    private static IReadOnlyList<ApprovalLedgerRow>
        LatestDocumentRows(
        IReadOnlyList<ApprovalLedgerRow> rows,
        ApprovalMode mode,
        string marketId) =>
        rows.Where(row =>
                row.Payload?.Mode == mode
                && string.Equals(
                    row.Payload.MarketId,
                    marketId,
                    StringComparison.Ordinal))
            .GroupBy(
                static row => row.Payload!.DocumentId!,
                StringComparer.Ordinal)
            .Select(static group =>
                group.OrderByDescending(static row => row.Sequence)
                    .First())
            .OrderBy(
                static row => row.Payload!.DocumentId,
                StringComparer.Ordinal)
            .ToArray();

    private void RequireCurrentBinding(LabelDraftState state)
    {
        var revision = state.PreviousRevision
            ?? throw InvalidState();
        if (!string.Equals(
                state.Document.ContractId,
                _context.Scope.ContractId,
                StringComparison.Ordinal)
            || !_context.RuleCatalogs.TryGetValue(
                state.Document.MarketId,
                out var ruleCatalogSha256)
            || !string.Equals(
                revision.RuleCatalogSha256,
                ruleCatalogSha256,
                StringComparison.Ordinal)
            || !MatchesWorker(
                revision,
                _context.WorkerIdentity))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.StaleRuleSet);
        }
    }

    private bool MatchesCurrent(
        ApprovalDecisionPayload payload,
        LabelDraftState state)
    {
        var revision = state.PreviousRevision;
        return revision is not null
            && IsCurrentContext(payload)
            && string.Equals(
                payload.DocumentId,
                state.Document.DocumentId,
                StringComparison.Ordinal)
            && string.Equals(
                payload.DocumentSha256,
                state.Document.ContentSha256,
                StringComparison.Ordinal)
            && string.Equals(
                payload.LabelRevisionId,
                revision.RevisionId,
                StringComparison.Ordinal)
            && string.Equals(
                payload.LabelRevisionSha256,
                revision.RevisionSha256,
                StringComparison.Ordinal)
            && FieldsEqual(payload.Fields, revision.Fields);
    }

    private bool IsCurrentContext(
        ApprovalDecisionPayload payload) =>
        string.Equals(
            payload.PilotEpoch,
            _context.Scope.CatalogEpoch,
            StringComparison.Ordinal)
        && string.Equals(
            payload.ContractId,
            _context.Scope.ContractId,
            StringComparison.Ordinal)
        && _context.RuleCatalogs.TryGetValue(
            payload.MarketId,
            out var rules)
        && string.Equals(
            payload.RuleCatalogSha256,
            rules,
            StringComparison.Ordinal)
        && string.Equals(
            payload.WorkerPackageManifestId,
            _context.WorkerIdentity.ManifestId,
            StringComparison.Ordinal)
        && string.Equals(
            payload.WorkerPackageManifestVersion,
            _context.WorkerIdentity.ManifestVersion,
            StringComparison.Ordinal)
        && string.Equals(
            payload.WorkerPackageSha256,
            _context.WorkerIdentity.Sha256,
            StringComparison.Ordinal)
        && string.Equals(
            payload.WorkerExecutableRelativePath,
            _context.WorkerIdentity.ExecutableRelativePath,
            StringComparison.Ordinal)
        && string.Equals(
            payload.WorkerExecutableSha256,
            _context.WorkerIdentity.ExecutableSha256,
            StringComparison.Ordinal);

    private static bool MatchesWorker(
        LabelRevision revision,
        CorpusWorkerPackageIdentity worker) =>
        string.Equals(
            revision.WorkerPackageManifestId,
            worker.ManifestId,
            StringComparison.Ordinal)
        && string.Equals(
            revision.WorkerPackageManifestVersion,
            worker.ManifestVersion,
            StringComparison.Ordinal)
        && string.Equals(
            revision.WorkerPackageSha256,
            worker.Sha256,
            StringComparison.Ordinal)
        && string.Equals(
            revision.WorkerExecutableRelativePath,
            worker.ExecutableRelativePath,
            StringComparison.Ordinal)
        && string.Equals(
            revision.WorkerExecutableSha256,
            worker.ExecutableSha256,
            StringComparison.Ordinal);

    private static bool FieldsEqual(
        ImmutableArray<LabeledField> left,
        ImmutableArray<LabeledField> right)
    {
        if (left.IsDefault
            || right.IsDefault
            || left.Length != right.Length)
        {
            return false;
        }

        for (var index = 0; index < left.Length; index++)
        {
            var leftField = left[index];
            var rightField = right[index];
            if (!string.Equals(
                    leftField.FieldId,
                    rightField.FieldId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    leftField.NormalizedValue,
                    rightField.NormalizedValue,
                    StringComparison.Ordinal)
                || !string.Equals(
                    leftField.RuleId,
                    rightField.RuleId,
                    StringComparison.Ordinal)
                || !leftField.Evidence.AsSpan()
                    .SequenceEqual(rightField.Evidence.AsSpan()))
            {
                return false;
            }
        }

        return true;
    }

    private static void RequireReviewCoverage(
        LabelRevision revision,
        IReadOnlyDictionary<string, string>? ruleIds = null)
    {
        if (revision.Fields.IsDefault
            || revision.Fields.Length
                != PilotCatalog.RequiredFieldIds.Length
            || !revision.Fields
                .Select(static field => field.FieldId)
                .SequenceEqual(
                    PilotCatalog.RequiredFieldIds,
                    StringComparer.Ordinal))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.ReviewCoverageInsufficient);
        }

        foreach (var field in revision.Fields)
        {
            var absent = string.Equals(
                field.NormalizedValue,
                InvoiceDraftLabeler.AbsentValue,
                StringComparison.Ordinal);
            if (string.IsNullOrWhiteSpace(field.NormalizedValue)
                || string.IsNullOrWhiteSpace(field.RuleId)
                || ruleIds is not null
                && (!ruleIds.TryGetValue(
                        field.FieldId,
                        out var expectedRuleId)
                    || !string.Equals(
                        field.RuleId,
                        expectedRuleId,
                        StringComparison.Ordinal))
                || field.Evidence.IsDefault
                || absent && !field.Evidence.IsEmpty
                || !absent && field.Evidence.IsEmpty
                || field.Evidence.Any(
                    static evidence =>
                        evidence.SourceIndex < 0
                        || !double.IsFinite(evidence.X)
                        || !double.IsFinite(evidence.Y)
                        || !double.IsFinite(evidence.Width)
                        || !double.IsFinite(evidence.Height)
                        || evidence.X < 0
                        || evidence.Y < 0
                        || evidence.Width <= 0
                        || evidence.Height <= 0))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.MissingEvidence);
            }
        }
    }

    private static async Task<IReadOnlyList<ApprovalLedgerRow>>
        ReadRowsAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        var rows = new List<ApprovalLedgerRow>();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT
              sequence,
              entry_id,
              previous_entry_sha256,
              entry_sha256,
              canonical_json
            FROM approval_entries
            ORDER BY sequence;
            """;
        await using var reader =
            await command.ExecuteReaderAsync(CancellationToken.None)
                .ConfigureAwait(false);
        while (await reader.ReadAsync(CancellationToken.None)
                   .ConfigureAwait(false))
        {
            var sequence = reader.GetInt64(0);
            var entryId = reader.GetString(1);
            var previous = reader.GetString(2);
            var entryHash = reader.GetString(3);
            if (reader.GetValue(4) is not byte[] canonical)
            {
                rows.Add(
                    ApprovalLedgerRow.Invalid(
                        sequence,
                        entryId,
                        previous,
                        entryHash,
                        []));
                continue;
            }

            try
            {
                var payload =
                    CanonicalApprovalDecision.Parse(canonical);
                rows.Add(
                    ApprovalLedgerRow.Valid(
                        sequence,
                        entryId,
                        previous,
                        entryHash,
                        canonical,
                        payload));
            }
            catch (Exception exception) when (
                exception is JsonException
                    or NotSupportedException
                    or InvalidOperationException)
            {
                rows.Add(
                    ApprovalLedgerRow.Invalid(
                        sequence,
                        entryId,
                        previous,
                        entryHash,
                        canonical));
            }
        }

        return rows;
    }

    private static HashSet<string> FindChainFailures(
        IReadOnlyList<ApprovalLedgerRow> rows)
    {
        var invalid = new HashSet<string>(StringComparer.Ordinal);
        var expectedPrevious = GenesisSha256;
        long expectedSequence = 1;
        foreach (var row in rows)
        {
            var valid = row.Sequence == expectedSequence
                && row.CanonicalValid
                && IsSafeEntryId(row.EntryId)
                && IsLowerSha256(row.PreviousEntrySha256)
                && IsLowerSha256(row.EntrySha256)
                && FixedEquals(
                    row.PreviousEntrySha256,
                    expectedPrevious);
            if (row.CanonicalValid)
            {
                valid = valid
                    && string.Equals(
                        row.EntryId,
                        CreateEntryId(row.Canonical),
                        StringComparison.Ordinal)
                    && FixedEquals(
                        row.EntrySha256,
                        HashEntry(
                            row.PreviousEntrySha256,
                            row.Canonical))
                    && IsValidPayload(row.Payload!);
            }

            if (!valid)
            {
                invalid.Add(row.EntryId);
            }

            expectedPrevious = row.EntrySha256;
            expectedSequence = row.Sequence == long.MaxValue
                ? long.MinValue
                : row.Sequence + 1;
        }

        return invalid;
    }

    private static void RequireValidChain(
        IReadOnlyList<ApprovalLedgerRow> rows)
    {
        var invalid = FindChainFailures(rows);
        if (invalid.Count == 0)
        {
            FindLedgerSemanticFailures(rows, invalid);
        }
        if (invalid.Count != 0)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.ApprovalChainInvalid);
        }
    }

    private static bool IsValidPayload(
        ApprovalDecisionPayload payload)
    {
        if (payload.SchemaVersion != "1"
            || string.IsNullOrWhiteSpace(payload.ScopeId)
            || string.IsNullOrWhiteSpace(payload.PilotEpoch)
            || payload.PilotEpoch.Length > 128
            || string.IsNullOrWhiteSpace(payload.MarketId)
            || payload.MarketId.Length > 32
            || string.IsNullOrWhiteSpace(payload.ContractId)
            || payload.ContractId.Length > 128
            || !IsLowerSha256(payload.RuleCatalogSha256)
            || !CorpusWorkerPackageManifest
                .IsCanonicalExecutionIdentity(
                    payload.WorkerIdentity)
            || !IsSafeActor(payload.ReviewerId)
            || payload.ApprovedAtUtc.Offset != TimeSpan.Zero
            || payload.Fields.IsDefault
            || payload.DelegatedEntries.IsDefault
            || payload.DirectReviewEntries.IsDefault)
        {
            return false;
        }

        if (payload.Mode == ApprovalMode.BatchApproval)
        {
            return payload.DocumentId is null
                && payload.DocumentSha256 is null
                && payload.LabelRevisionId is null
                && payload.LabelRevisionSha256 is null
                && payload.PreviousRevisionId is null
                && payload.PreviousRevisionSha256 is null
                && payload.LabelRevisionCreatedAtUtc is null
                && payload.Fields.IsEmpty
                && IsLowerSha256(payload.BatchSummarySha256!)
                && string.Equals(
                    payload.ScopeId,
                    payload.MarketId,
                    StringComparison.Ordinal)
                && IsCanonicalReferences(
                    payload.DelegatedEntries)
                && IsCanonicalReferences(
                    payload.DirectReviewEntries)
                && FixedEquals(
                    payload.BatchSummarySha256!,
                    ComputeBatchSummarySha256(
                        payload.DelegatedEntries));
        }

        if (payload.Mode is not (
                ApprovalMode.DirectReview
                or ApprovalMode.DelegatedLabel)
            || payload.BatchSummarySha256 is not null
            || !payload.DelegatedEntries.IsEmpty
            || !payload.DirectReviewEntries.IsEmpty
            || payload.DocumentId is null
            || payload.DocumentSha256 is null
            || payload.LabelRevisionId is null
            || payload.LabelRevisionSha256 is null
            || payload.LabelRevisionCreatedAtUtc is null
            || !string.Equals(
                payload.ScopeId,
                payload.DocumentId,
                StringComparison.Ordinal)
            || !IsLowerSha256(payload.DocumentSha256)
            || !IsLowerSha256(payload.LabelRevisionSha256)
            || payload.LabelRevisionCreatedAtUtc.Value.Offset
                != TimeSpan.Zero)
        {
            return false;
        }

        var revision = payload.ToRevision();
        try
        {
            RequireReviewCoverage(revision);
            return DraftLabelService.HasValidCanonicalHash(revision);
        }
        catch (WorkbenchException)
        {
            return false;
        }
    }

    private static bool IsCanonicalReferences(
        ImmutableArray<ApprovalEntryReference> references)
    {
        var ordered = references
            .OrderBy(
                static item => item.DocumentId,
                StringComparer.Ordinal)
            .ToArray();
        return ordered.AsSpan().SequenceEqual(references.AsSpan())
            && ordered
                .Select(static item => item.DocumentId)
                .Distinct(StringComparer.Ordinal)
                .Count() == ordered.Length
            && ordered.All(
                static item =>
                    IsSafeEntryId(item.EntryId)
                    && IsLowerSha256(item.EntrySha256)
                    && IsLowerSha256(item.DocumentSha256)
                    && IsLowerSha256(item.LabelRevisionSha256)
                    && IsLowerSha256(item.RuleCatalogSha256)
                    && CorpusWorkerPackageManifest
                        .IsCanonicalExecutionIdentity(
                            new CorpusWorkerPackageIdentity(
                                item.WorkerPackageManifestId,
                                item.WorkerPackageManifestVersion,
                                item.WorkerPackageSha256,
                                item.WorkerExecutableRelativePath,
                                item.WorkerExecutableSha256)));
    }

    private static void FindLedgerSemanticFailures(
        IReadOnlyList<ApprovalLedgerRow> rows,
        ISet<string> invalid)
    {
        var byId = rows
            .Where(static row => row.CanonicalValid)
            .ToDictionary(
                static row => row.EntryId,
                StringComparer.Ordinal);
        foreach (var batch in rows.Where(static row =>
                     row.Payload?.Mode
                         == ApprovalMode.BatchApproval))
        {
            var payload = batch.Payload!;
            if (payload.DirectReviewEntries.Length
                    != PilotCatalog.DirectReviewTargetPerMarket
                || !ReferencesEarlierEntries(
                    payload.DirectReviewEntries,
                    ApprovalMode.DirectReview,
                    payload,
                    batch.Sequence,
                    byId)
                || !ReferencesEarlierEntries(
                    payload.DelegatedEntries,
                    ApprovalMode.DelegatedLabel,
                    payload,
                    batch.Sequence,
                    byId))
            {
                invalid.Add(batch.EntryId);
            }
        }
    }

    private static bool ReferencesEarlierEntries(
        ImmutableArray<ApprovalEntryReference> references,
        ApprovalMode expectedMode,
        ApprovalDecisionPayload batch,
        long batchSequence,
        IReadOnlyDictionary<string, ApprovalLedgerRow> byId)
    {
        foreach (var reference in references)
        {
            if (!byId.TryGetValue(reference.EntryId, out var row)
                || row.Sequence >= batchSequence
                || row.Payload?.Mode != expectedMode
                || !string.Equals(
                    row.Payload.MarketId,
                    batch.MarketId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    row.Payload.ContractId,
                    batch.ContractId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    row.Payload.PilotEpoch,
                    batch.PilotEpoch,
                    StringComparison.Ordinal)
                || row.ToReference() != reference)
            {
                return false;
            }
        }

        return true;
    }

    private void ValidateDecisionTime(DateTimeOffset value)
    {
        var now = _timeProvider.GetUtcNow().ToUniversalTime();
        if (value.Offset != TimeSpan.Zero
            || value > now + FutureTolerance)
        {
            throw InvalidArguments();
        }
    }

    private static void ValidateActor(string value)
    {
        if (!IsSafeActor(value))
        {
            throw InvalidArguments();
        }
    }

    private static bool IsSafeActor(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128
        && value.All(
            static character =>
                !char.IsControl(character)
                && !char.IsSurrogate(character));

    private static void ValidateObjectId(
        string value,
        string prefix)
    {
        if (value is null
            || !value.StartsWith(prefix, StringComparison.Ordinal)
            || value.Length != prefix.Length + 64
            || !IsLowerSha256(value[prefix.Length..]))
        {
            throw InvalidArguments();
        }
    }

    private static string CreateEntryId(byte[] canonical) =>
        "approval-" + DomainHash(IdentityDomain, canonical);

    private static string HashEntry(
        string previous,
        byte[] canonical)
    {
        using var hash =
            IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(EntryDomain));
        hash.AppendData(Encoding.UTF8.GetBytes(previous));
        hash.AppendData(canonical);
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static string DomainHash(
        string domain,
        byte[] canonical)
    {
        using var hash =
            IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(domain));
        hash.AppendData(canonical);
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static bool FixedEquals(string left, string right)
    {
        if (!IsLowerSha256(left) || !IsLowerSha256(right))
        {
            return false;
        }

        var leftBytes = Convert.FromHexString(left);
        var rightBytes = Convert.FromHexString(right);
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                leftBytes,
                rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static bool IsLowerSha256(string value) =>
        value is not null
        && value.Length == 64
        && value.All(
            static character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');

    private static bool IsSafeEntryId(string value) =>
        value is not null
        && value.StartsWith("approval-", StringComparison.Ordinal)
        && value.Length == "approval-".Length + 64
        && IsLowerSha256(value["approval-".Length..]);

    private async Task VerifyWorkerAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            await _verifyWorker(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is CorpusWorkerAttestationException
                or ObjectDisposedException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.WorkerAttestationMismatch);
        }
    }

    private static CorpusWorkbenchStore RequireStore(
        CorpusVault vault)
    {
        ArgumentNullException.ThrowIfNull(vault);
        return vault.Store;
    }

    private static string LedgerHead(
        IReadOnlyList<ApprovalLedgerRow> rows) =>
        rows.Count == 0 ? GenesisSha256 : rows[^1].EntrySha256;

    private static long EntrySequence(
        IReadOnlyList<ApprovalLedgerRow> rows,
        string entryId) =>
        rows.FirstOrDefault(row => string.Equals(
                row.EntryId,
                entryId,
                StringComparison.Ordinal))
            ?.Sequence ?? long.MaxValue;

    private static void AddAllEntryIds(
        IEnumerable<ApprovalLedgerRow> rows,
        ISet<string> invalid)
    {
        foreach (var row in rows)
        {
            invalid.Add(row.EntryId);
        }
    }

    private static void WriteReference(
        Utf8JsonWriter writer,
        ApprovalEntryReference value)
    {
        writer.WriteStartObject();
        writer.WriteString("entryId", value.EntryId);
        writer.WriteString("entrySha256", value.EntrySha256);
        writer.WriteString("documentId", value.DocumentId);
        writer.WriteString("documentSha256", value.DocumentSha256);
        writer.WriteString(
            "labelRevisionId",
            value.LabelRevisionId);
        writer.WriteString(
            "labelRevisionSha256",
            value.LabelRevisionSha256);
        writer.WriteString(
            "ruleCatalogSha256",
            value.RuleCatalogSha256);
        writer.WriteString(
            "workerPackageManifestId",
            value.WorkerPackageManifestId);
        writer.WriteString(
            "workerPackageManifestVersion",
            value.WorkerPackageManifestVersion);
        writer.WriteString(
            "workerPackageSha256",
            value.WorkerPackageSha256);
        writer.WriteString(
            "workerExecutableRelativePath",
            value.WorkerExecutableRelativePath);
        writer.WriteString(
            "workerExecutableSha256",
            value.WorkerExecutableSha256);
        writer.WriteEndObject();
    }

    private static WorkbenchException InvalidArguments() =>
        new(WorkbenchFailureCode.InvalidArguments);

    private static WorkbenchException InvalidState() =>
        new(WorkbenchFailureCode.InvalidState);
}

internal sealed record ApprovalDecisionPayload(
    string SchemaVersion,
    ApprovalMode Mode,
    string ScopeId,
    string PilotEpoch,
    string MarketId,
    string ContractId,
    string? DocumentId,
    string? DocumentSha256,
    string? LabelRevisionId,
    string? LabelRevisionSha256,
    string? PreviousRevisionId,
    string? PreviousRevisionSha256,
    DateTimeOffset? LabelRevisionCreatedAtUtc,
    ImmutableArray<LabeledField> Fields,
    string RuleCatalogSha256,
    string WorkerPackageManifestId,
    string WorkerPackageManifestVersion,
    string WorkerPackageSha256,
    string WorkerExecutableRelativePath,
    string WorkerExecutableSha256,
    string ReviewerId,
    DateTimeOffset ApprovedAtUtc,
    string? BatchSummarySha256,
    ImmutableArray<ApprovalEntryReference> DelegatedEntries,
    ImmutableArray<ApprovalEntryReference> DirectReviewEntries)
{
    internal CorpusWorkerPackageIdentity WorkerIdentity =>
        new(
            WorkerPackageManifestId,
            WorkerPackageManifestVersion,
            WorkerPackageSha256,
            WorkerExecutableRelativePath,
            WorkerExecutableSha256);

    internal static ApprovalDecisionPayload Document(
        ApprovalMode mode,
        string actor,
        DateTimeOffset decisionTime,
        PilotScope scope,
        WorkbenchDocument document,
        LabelRevision revision) =>
        new(
            "1",
            mode,
            document.DocumentId,
            scope.CatalogEpoch,
            document.MarketId,
            document.ContractId,
            document.DocumentId,
            document.ContentSha256,
            revision.RevisionId,
            revision.RevisionSha256,
            revision.PreviousRevisionId,
            revision.PreviousRevisionSha256,
            revision.CreatedAtUtc,
            revision.Fields,
            revision.RuleCatalogSha256,
            revision.WorkerPackageManifestId,
            revision.WorkerPackageManifestVersion,
            revision.WorkerPackageSha256,
            revision.WorkerExecutableRelativePath,
            revision.WorkerExecutableSha256,
            actor,
            decisionTime,
            null,
            [],
            []);

    internal static ApprovalDecisionPayload Batch(
        BatchApprovalDecision decision,
        PilotScope scope,
        string ruleCatalogSha256,
        CorpusWorkerPackageIdentity worker,
        ImmutableArray<ApprovalEntryReference> delegated,
        ImmutableArray<ApprovalEntryReference> direct) =>
        new(
            "1",
            ApprovalMode.BatchApproval,
            decision.MarketId,
            scope.CatalogEpoch,
            decision.MarketId,
            scope.ContractId,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            [],
            ruleCatalogSha256,
            worker.ManifestId,
            worker.ManifestVersion,
            worker.Sha256,
            worker.ExecutableRelativePath,
            worker.ExecutableSha256,
            decision.ReviewerId,
            decision.ApprovedAtUtc,
            decision.BatchSummarySha256,
            delegated,
            direct);

    internal LabelRevision ToRevision() =>
        new(
            LabelRevisionId!,
            DocumentId!,
            DocumentSha256!,
            MarketId,
            ContractId,
            PreviousRevisionId,
            PreviousRevisionSha256,
            RuleCatalogSha256,
            WorkerPackageManifestId,
            WorkerPackageManifestVersion,
            WorkerPackageSha256,
            WorkerExecutableRelativePath,
            WorkerExecutableSha256,
            Fields,
            LabelRevisionSha256!,
            LabelRevisionCreatedAtUtc!.Value);
}

internal static class CanonicalApprovalDecision
{
    internal static byte[] Serialize(
        ApprovalDecisionPayload payload) =>
        WorkbenchJson.Serialize(
            payload,
            ApprovalJsonContext.Default.ApprovalDecisionPayload);

    internal static ApprovalDecisionPayload Parse(byte[] canonical)
    {
        var payload = WorkbenchJson.Parse(
            canonical,
            ApprovalJsonContext.Default.ApprovalDecisionPayload);
        var expected = Serialize(payload);
        if (!CryptographicOperations.FixedTimeEquals(
                canonical,
                expected))
        {
            throw new JsonException(
                "Approval payload is not canonical.");
        }

        return payload;
    }
}

internal sealed record ApprovalLedgerRow(
    long Sequence,
    string EntryId,
    string PreviousEntrySha256,
    string EntrySha256,
    byte[] Canonical,
    ApprovalDecisionPayload? Payload,
    bool CanonicalValid)
{
    internal static ApprovalLedgerRow Valid(
        long sequence,
        string entryId,
        string previous,
        string entryHash,
        byte[] canonical,
        ApprovalDecisionPayload payload) =>
        new(
            sequence,
            entryId,
            previous,
            entryHash,
            canonical,
            payload,
            true);

    internal static ApprovalLedgerRow Invalid(
        long sequence,
        string entryId,
        string previous,
        string entryHash,
        byte[] canonical) =>
        new(
            sequence,
            entryId,
            previous,
            entryHash,
            canonical,
            null,
            false);

    internal ApprovalEntry ToEntry()
    {
        var payload = Payload
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.ApprovalChainInvalid);
        return new ApprovalEntry(
            Sequence,
            EntryId,
            payload.Mode,
            payload.ScopeId,
            payload.PilotEpoch,
            payload.MarketId,
            payload.ContractId,
            payload.DocumentId,
            payload.DocumentSha256,
            payload.LabelRevisionId,
            payload.LabelRevisionSha256,
            payload.PreviousRevisionId,
            payload.PreviousRevisionSha256,
            payload.LabelRevisionCreatedAtUtc,
            payload.Fields,
            payload.RuleCatalogSha256,
            payload.WorkerPackageManifestId,
            payload.WorkerPackageManifestVersion,
            payload.WorkerPackageSha256,
            payload.WorkerExecutableRelativePath,
            payload.WorkerExecutableSha256,
            payload.ReviewerId,
            payload.ApprovedAtUtc,
            payload.BatchSummarySha256,
            payload.DelegatedEntries,
            payload.DirectReviewEntries,
            PreviousEntrySha256,
            EntrySha256);
    }

    internal ApprovalEntryReference ToReference()
    {
        var payload = Payload
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.ApprovalChainInvalid);
        return new ApprovalEntryReference(
            EntryId,
            EntrySha256,
            payload.DocumentId!,
            payload.DocumentSha256!,
            payload.LabelRevisionId!,
            payload.LabelRevisionSha256!,
            payload.RuleCatalogSha256,
            payload.WorkerPackageManifestId,
            payload.WorkerPackageManifestVersion,
            payload.WorkerPackageSha256,
            payload.WorkerExecutableRelativePath,
            payload.WorkerExecutableSha256);
    }
}

internal sealed record BatchSelection(
    ImmutableArray<ApprovalEntryReference> Delegated,
    ImmutableArray<ApprovalEntryReference> Direct);

internal sealed record ApprovalLedgerContext(
    PilotScope Scope,
    ImmutableDictionary<string, string> RuleCatalogs,
    ImmutableDictionary<
        string,
        ImmutableDictionary<string, string>> RuleIdsByMarket,
    CorpusWorkerPackageIdentity WorkerIdentity)
{
    internal static ApprovalLedgerContext Create(
        PilotScope scope,
        IEnumerable<OfficialRuleCatalogSnapshot> rules,
        CorpusWorkerPackageIdentity workerIdentity)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(workerIdentity);
        if (scope.SchemaVersion != PilotCatalog.SchemaVersion
            || scope.ContractId != PilotCatalog.ContractId
            || string.IsNullOrWhiteSpace(scope.CatalogEpoch)
            || scope.CatalogEpoch.Length > 128
            || scope.DirectReviewTargetPerMarket
                != PilotCatalog.DirectReviewTargetPerMarket
            || scope.HeldOutTargetPerMarket
                != PilotCatalog.HeldOutTargetPerMarket
            || scope.MarketIds.IsDefaultOrEmpty
            || scope.MarketIds.Distinct(StringComparer.Ordinal).Count()
                != scope.MarketIds.Length
            || scope.MarketIds.Any(marketId =>
                !PilotCatalog.MarketIds.Contains(
                    marketId,
                    StringComparer.Ordinal))
            || !CorpusWorkerPackageManifest
                .IsCanonicalExecutionIdentity(workerIdentity))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }

        var builder =
            ImmutableDictionary.CreateBuilder<string, string>(
                StringComparer.Ordinal);
        var ruleIdsBuilder =
            ImmutableDictionary.CreateBuilder<
                string,
                ImmutableDictionary<string, string>>(
                StringComparer.Ordinal);
        foreach (var rule in rules)
        {
            if (rule is null
                || rule.Document is null
                || !scope.MarketIds.Contains(
                    rule.Document.MarketId,
                    StringComparer.Ordinal)
                || !string.Equals(
                    rule.Document.ContractId,
                    scope.ContractId,
                    StringComparison.Ordinal)
                || rule.Document.SchemaVersion != scope.SchemaVersion
                || !HasValidCatalogHash(rule)
                || !builder.TryAdd(
                    rule.Document.MarketId,
                    rule.CatalogSha256)
                || !ruleIdsBuilder.TryAdd(
                    rule.Document.MarketId,
                    rule.Document.Rules.ToImmutableDictionary(
                        static item => item.FieldId,
                        static item => item.RuleId,
                        StringComparer.Ordinal)))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidArguments);
            }
        }

        if (builder.Count == 0)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.InvalidArguments);
        }

        return new ApprovalLedgerContext(
            scope,
            builder.ToImmutable(),
            ruleIdsBuilder.ToImmutable(),
            workerIdentity);
    }

    private static bool HasValidCatalogHash(
        OfficialRuleCatalogSnapshot snapshot)
    {
        if (!IsLowerSha256(snapshot.CatalogSha256))
        {
            return false;
        }

        try
        {
            OfficialRuleCatalogValidator.Validate(snapshot.Document);
            if (snapshot.RulesByFieldId.Count
                    != snapshot.Document.Rules.Length
                || snapshot.Document.Rules.Any(rule =>
                    !snapshot.RulesByFieldId.TryGetValue(
                        rule.FieldId,
                        out var indexed)
                    || !RuleEquals(rule, indexed)))
            {
                return false;
            }

            var expected = Convert.ToHexStringLower(
                SHA256.HashData(
                    CanonicalRuleCatalog.Serialize(
                        snapshot.Document)));
            var actualBytes = Convert.FromHexString(
                snapshot.CatalogSha256);
            var expectedBytes = Convert.FromHexString(expected);
            try
            {
                return CryptographicOperations.FixedTimeEquals(
                    actualBytes,
                    expectedBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualBytes);
                CryptographicOperations.ZeroMemory(expectedBytes);
            }
        }
        catch (WorkbenchException)
        {
            return false;
        }
    }

    private static bool RuleEquals(
        OfficialFieldRule left,
        OfficialFieldRule right) =>
        string.Equals(
            left.RuleId,
            right.RuleId,
            StringComparison.Ordinal)
        && string.Equals(
            left.FieldId,
            right.FieldId,
            StringComparison.Ordinal)
        && string.Equals(
            left.Normalization,
            right.Normalization,
            StringComparison.Ordinal)
        && left.AcceptedVisibleLabels.AsSpan()
            .SequenceEqual(right.AcceptedVisibleLabels.AsSpan())
        && left.SourceIds.AsSpan()
            .SequenceEqual(right.SourceIds.AsSpan());

    private static bool IsLowerSha256(string value) =>
        value is not null
        && value.Length == 64
        && value.All(
            static character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');
}

internal enum ApprovalLedgerFaultPoint
{
    BeforeInsert,
    AfterInsertBeforeCommit,
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectRequiredConstructorParameters = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    WriteIndented = false)]
[JsonSerializable(typeof(ApprovalDecisionPayload))]
internal sealed partial class ApprovalJsonContext
    : JsonSerializerContext;
