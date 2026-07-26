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

public sealed record OwnerApprovedDocument(
    string DocumentId,
    string LabelRevisionId,
    string ApprovalMode,
    string ApprovalEntryId);

public sealed record OwnerApprovalView(
    string LedgerHeadSha256,
    ImmutableArray<OwnerApprovedDocument> Documents);

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
    private const string AnchorCheckpointId =
        "approval-ledger-anchor-v1";
    private const string AnchorDomainVersion =
        "corpus-approval-ledger-anchor-v1";
    private const string AnchorHashDomain =
        "corpus-approval-ledger-anchor-hash-v1\n";
    // Approval evidence predating the product's supported corpus era is
    // rejected so default/sentinel timestamps cannot enter canonical state.
    private static readonly DateTimeOffset MinimumDecisionTimeUtc =
        new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
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
                var ledger = await ReadLedgerAsync(
                        connection,
                        transaction)
                    .ConfigureAwait(false);
                RequireValidLedger(ledger);
                var states =
                    await _store.ReadAllApprovalLabelStatesAsync(
                            connection,
                            transaction)
                        .ConfigureAwait(false);
                var selection = SelectBatchBindings(
                    decision.MarketId,
                    ledger.Rows,
                    states,
                    requireExactDirectCount: true);
                RequireBatchDecisionTime(
                    decision.ApprovedAtUtc,
                    ledger.Rows,
                    selection);
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
                        ledger,
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
            async (connection, transaction) =>
            {
                var ledger = await ReadLedgerAsync(
                        connection,
                        transaction)
                    .ConfigureAwait(false);
                var rows = ledger.Rows;
                var invalid = FindChainFailures(rows);
                FindLedgerSemanticFailures(rows, invalid);
                FindAnchorFailures(ledger, invalid);
                try
                {
                    var states =
                        await _store.ReadAllApprovalLabelStatesAsync(
                                connection,
                                transaction)
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
                    LedgerHead(ledger),
                    ordered);
            },
            cancellationToken).ConfigureAwait(false);
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    public async Task<OwnerApprovalView> GetOwnerApprovalViewAsync(
        CancellationToken cancellationToken)
    {
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        var result = await _store.ExecuteApprovalReadAsync(
            async (connection, transaction) =>
            {
                var ledger = await ReadLedgerAsync(
                        connection,
                        transaction)
                    .ConfigureAwait(false);
                var rows = ledger.Rows;
                var invalid = FindChainFailures(rows);
                FindLedgerSemanticFailures(rows, invalid);
                FindAnchorFailures(ledger, invalid);
                if (invalid.Count != 0)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.ApprovalChainInvalid);
                }

                var states =
                    await _store.ReadAllApprovalLabelStatesAsync(
                            connection,
                            transaction)
                        .ConfigureAwait(false);
                var currentByDocument = states.ToDictionary(
                    static state => state.Document.DocumentId,
                    StringComparer.Ordinal);

                var approved =
                    new Dictionary<string, OwnerApprovedDocument>(
                        StringComparer.Ordinal);
                foreach (var row in LatestDocumentRows(
                             rows,
                             ApprovalMode.DirectReview))
                {
                    var payload = row.Payload!;
                    if (!IsCurrentDocumentApproval(
                            payload,
                            currentByDocument))
                    {
                        continue;
                    }

                    approved[payload.DocumentId!] =
                        new OwnerApprovedDocument(
                            payload.DocumentId!,
                            payload.LabelRevisionId!,
                            nameof(ApprovalMode.DirectReview),
                            row.EntryId);
                }

                foreach (var batch in rows
                             .Where(static row =>
                                 row.Payload?.Mode
                                     == ApprovalMode.BatchApproval)
                             .GroupBy(
                                 static row =>
                                     row.Payload!.MarketId,
                                 StringComparer.Ordinal)
                             .Select(static group => group
                                 .OrderByDescending(
                                     static row => row.Sequence)
                                 .First()))
                {
                    if (!IsCurrentBatchApproval(
                            batch,
                            rows,
                            states))
                    {
                        continue;
                    }

                    foreach (var delegated in
                             batch.Payload!.DelegatedEntries)
                    {
                        approved.TryAdd(
                            delegated.DocumentId,
                            new OwnerApprovedDocument(
                                delegated.DocumentId,
                                delegated.LabelRevisionId,
                                nameof(ApprovalMode.BatchApproval),
                                batch.EntryId));
                    }
                }

                return new OwnerApprovalView(
                    LedgerHead(ledger),
                    [
                        .. approved.Values.OrderBy(
                            static item => item.DocumentId,
                            StringComparer.Ordinal),
                    ]);
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
                var ledger = await ReadLedgerAsync(
                        connection,
                        transaction)
                    .ConfigureAwait(false);
                RequireValidLedger(ledger);
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
                if (decisionTime < revision.CreatedAtUtc)
                {
                    throw InvalidArguments();
                }

                RequireCurrentBinding(state);
                CurrentRevisionValidator.Validate(
                    state.Document,
                    revision,
                    _context.RuleSnapshots[
                        state.Document.MarketId],
                    _context.WorkerIdentity,
                    pageCount: null);
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
                        ledger,
                        payload)
                    .ConfigureAwait(false);
            },
            cancellationToken);

    private async Task<ApprovalEntry> AppendAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ApprovalLedgerSnapshot ledger,
        ApprovalDecisionPayload payload)
    {
        var rows = ledger.Rows;
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
            ApprovalLedgerFaultPoint.AfterInsertBeforeAnchor);
        await WriteAnchorAsync(
                connection,
                transaction,
                new ApprovalLedgerAnchor(
                    "1",
                    AnchorDomainVersion,
                    sequence,
                    rows.Count + 1L,
                    entryId,
                    entrySha256))
            .ConfigureAwait(false);
        _injectFault?.Invoke(
            ApprovalLedgerFaultPoint.AfterInsertBeforeCommit);
        var appended = await ReadLedgerAsync(
                connection,
                transaction)
            .ConfigureAwait(false);
        RequireValidLedger(appended);
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
                invalid.Add(row.DiagnosticId);
                continue;
            }

            try
            {
                CurrentRevisionValidator.Validate(
                    state.Document,
                    state.PreviousRevision!,
                    _context.RuleSnapshots[
                        state.Document.MarketId],
                    _context.WorkerIdentity,
                    pageCount: null);
            }
            catch (WorkbenchException)
            {
                invalid.Add(row.DiagnosticId);
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
                    invalid.Add(batch.DiagnosticId);
                }
            }
            catch (WorkbenchException)
            {
                invalid.Add(batch.DiagnosticId);
            }
        }
    }

    private bool IsCurrentDocumentApproval(
        ApprovalDecisionPayload payload,
        IReadOnlyDictionary<string, LabelDraftState> currentByDocument)
    {
        if (!currentByDocument.TryGetValue(
                payload.DocumentId!,
                out var state)
            || !MatchesCurrent(payload, state))
        {
            return false;
        }

        try
        {
            CurrentRevisionValidator.Validate(
                state.Document,
                state.PreviousRevision!,
                _context.RuleSnapshots[state.Document.MarketId],
                _context.WorkerIdentity,
                pageCount: null);
            return true;
        }
        catch (WorkbenchException)
        {
            return false;
        }
    }

    // A batch commits one exact direct/delegated selection. Its delegated
    // approvals are therefore atomic: any stale bound entry filters the
    // complete batch instead of deriving a smaller, unapproved selection.
    private bool IsCurrentBatchApproval(
        ApprovalLedgerRow batch,
        IReadOnlyList<ApprovalLedgerRow> rows,
        IReadOnlyList<LabelDraftState> states)
    {
        try
        {
            var payload = batch.Payload!;
            var selected = SelectBatchBindings(
                payload.MarketId,
                rows,
                states,
                requireExactDirectCount: true);
            var summary = ComputeBatchSummarySha256(selected.Delegated);
            return FixedEquals(summary, payload.BatchSummarySha256!)
                && payload.DelegatedEntries.AsSpan()
                    .SequenceEqual(selected.Delegated.AsSpan())
                && payload.DirectReviewEntries.AsSpan()
                    .SequenceEqual(selected.Direct.AsSpan())
                && IsCurrentContext(payload);
        }
        catch (WorkbenchException)
        {
            return false;
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

            CurrentRevisionValidator.Validate(
                state.Document,
                state.PreviousRevision!,
                _context.RuleSnapshots[marketId],
                _context.WorkerIdentity,
                pageCount: null);
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

    private static void RequireBatchDecisionTime(
        DateTimeOffset approvedAtUtc,
        IReadOnlyList<ApprovalLedgerRow> rows,
        BatchSelection selection)
    {
        var referencedIds = selection.Delegated
            .Concat(selection.Direct)
            .Select(static item => item.EntryId)
            .ToHashSet(StringComparer.Ordinal);
        if (rows.Any(row =>
                referencedIds.Contains(row.EntryId)
                && row.Payload is { } payload
                && approvedAtUtc < payload.ApprovedAtUtc))
        {
            throw InvalidArguments();
        }
    }

    private static IReadOnlyList<ApprovalLedgerRow>
        LatestDocumentRows(
        IReadOnlyList<ApprovalLedgerRow> rows,
        ApprovalMode mode) =>
        rows.Where(row => row.Payload?.Mode == mode)
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
        IReadOnlyDictionary<string, string>? ruleIds = null) =>
        CurrentRevisionValidator.ValidateFields(
            revision.Fields,
            ruleIds,
            pageCount: null);

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
            var entryId = reader.GetValue(1) as string
                ?? string.Empty;
            var previous = reader.GetValue(2) as string
                ?? string.Empty;
            var entryHash = reader.GetValue(3) as string
                ?? string.Empty;
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

    private static async Task<ApprovalLedgerSnapshot>
        ReadLedgerAsync(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        var rows = await ReadRowsAsync(connection, transaction)
            .ConfigureAwait(false);
        var anchor = await ReadAnchorAsync(connection, transaction)
            .ConfigureAwait(false);
        var sequence = await ReadSqliteSequenceAsync(
                connection,
                transaction)
            .ConfigureAwait(false);
        return new ApprovalLedgerSnapshot(rows, anchor, sequence);
    }

    private static async Task<ApprovalLedgerAnchorState>
        ReadAnchorAsync(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT scope_sha256, canonical_json
            FROM checkpoints
            WHERE checkpoint_id=$checkpoint_id;
            """;
        command.Parameters.AddWithValue(
            "$checkpoint_id",
            AnchorCheckpointId);
        await using var reader =
            await command.ExecuteReaderAsync(CancellationToken.None)
                .ConfigureAwait(false);
        if (!await reader.ReadAsync(CancellationToken.None)
                .ConfigureAwait(false))
        {
            return ApprovalLedgerAnchorState.Missing;
        }

        var scopeSha256 = reader.GetValue(0) as string ?? string.Empty;
        var canonical = reader.GetValue(1) as byte[] ?? [];
        try
        {
            return new ApprovalLedgerAnchorState(
                true,
                scopeSha256,
                canonical,
                CanonicalApprovalLedgerAnchor.Parse(canonical),
                true);
        }
        catch (Exception exception) when (
            exception is JsonException
                or NotSupportedException
                or InvalidOperationException)
        {
            return new ApprovalLedgerAnchorState(
                true,
                scopeSha256,
                canonical,
                null,
                false);
        }
    }

    private static async Task<SqliteSequenceState>
        ReadSqliteSequenceAsync(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT seq
            FROM sqlite_sequence
            WHERE name='approval_entries';
            """;
        await using var reader =
            await command.ExecuteReaderAsync(CancellationToken.None)
                .ConfigureAwait(false);
        var count = 0;
        long? sequence = null;
        var valuesValid = true;
        while (await reader.ReadAsync(CancellationToken.None)
                   .ConfigureAwait(false))
        {
            count++;
            if (reader.GetValue(0) is long value)
            {
                sequence = value;
            }
            else
            {
                valuesValid = false;
            }
        }

        return new SqliteSequenceState(
            count,
            sequence,
            valuesValid);
    }

    private static async Task WriteAnchorAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ApprovalLedgerAnchor anchor)
    {
        var canonical =
            CanonicalApprovalLedgerAnchor.Serialize(anchor);
        var scopeSha256 = HashAnchor(canonical);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO checkpoints(
              checkpoint_id,
              scope_sha256,
              canonical_json)
            VALUES(
              $checkpoint_id,
              $scope_sha256,
              $canonical_json)
            ON CONFLICT(checkpoint_id) DO UPDATE SET
              scope_sha256=excluded.scope_sha256,
              canonical_json=excluded.canonical_json;
            """;
        command.Parameters.AddWithValue(
            "$checkpoint_id",
            AnchorCheckpointId);
        command.Parameters.AddWithValue(
            "$scope_sha256",
            scopeSha256);
        var canonicalParameter = command.Parameters.Add(
            "$canonical_json",
            SqliteType.Blob);
        canonicalParameter.Value = canonical;
        if (await command.ExecuteNonQueryAsync(CancellationToken.None)
                .ConfigureAwait(false) != 1)
        {
            throw InvalidState();
        }
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
                invalid.Add(row.DiagnosticId);
            }

            expectedPrevious = row.EntrySha256;
            expectedSequence = row.Sequence == long.MaxValue
                ? long.MinValue
                : row.Sequence + 1;
        }

        return invalid;
    }

    private void RequireValidLedger(
        ApprovalLedgerSnapshot ledger)
    {
        var invalid = FindChainFailures(ledger.Rows);
        FindLedgerSemanticFailures(ledger.Rows, invalid);
        FindAnchorFailures(ledger, invalid);
        if (invalid.Count != 0)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.ApprovalChainInvalid);
        }
    }

    private static void FindAnchorFailures(
        ApprovalLedgerSnapshot ledger,
        ISet<string> invalid)
    {
        var rows = ledger.Rows;
        var anchor = ledger.Anchor;
        var sequence = ledger.SqliteSequence;
        if (rows.Count == 0
            && !anchor.Exists
            && sequence.RowCount == 0)
        {
            return;
        }

        var valid = rows.Count != 0
            && anchor.Exists
            && anchor.CanonicalValid
            && anchor.Value is { } value
            && value.SchemaVersion == "1"
            && string.Equals(
                value.DomainVersion,
                AnchorDomainVersion,
                StringComparison.Ordinal)
            && value.TerminalSequence == rows[^1].Sequence
            && value.EntryCount == rows.Count
            && string.Equals(
                value.TerminalEntryId,
                rows[^1].EntryId,
                StringComparison.Ordinal)
            && FixedEquals(
                value.TerminalEntrySha256,
                rows[^1].EntrySha256)
            && IsSafeEntryId(value.TerminalEntryId)
            && FixedEquals(
                anchor.ScopeSha256,
                HashAnchor(anchor.Canonical))
            && sequence.RowCount == 1
            && sequence.ValuesValid
            && sequence.Sequence == rows[^1].Sequence;
        if (valid)
        {
            return;
        }

        invalid.Add(
            rows.Count == 0
                ? ApprovalLedgerDiagnostics.AnchorIdentifier
                : rows[^1].DiagnosticId);
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
            || payload.ApprovedAtUtc < MinimumDecisionTimeUtc
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
                != TimeSpan.Zero
            || payload.ApprovedAtUtc
                < payload.LabelRevisionCreatedAtUtc.Value)
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

    private void FindLedgerSemanticFailures(
        IReadOnlyList<ApprovalLedgerRow> rows,
        ISet<string> invalid)
    {
        var byId = rows
            .Where(static row =>
                row.CanonicalValid
                && IsSafeEntryId(row.EntryId))
            .ToDictionary(
                static row => row.EntryId,
                StringComparer.Ordinal);
        foreach (var row in rows.Where(static row =>
                     row.Payload is not null))
        {
            if (!IsDecisionTimeWithinPolicy(
                    row.Payload!.ApprovedAtUtc))
            {
                invalid.Add(row.DiagnosticId);
            }
        }

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
                invalid.Add(batch.DiagnosticId);
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
                || batch.ApprovedAtUtc
                    < row.Payload.ApprovedAtUtc
                || row.ToReference() != reference)
            {
                return false;
            }
        }

        return true;
    }

    private void ValidateDecisionTime(DateTimeOffset value)
    {
        if (!IsDecisionTimeWithinPolicy(value))
        {
            throw InvalidArguments();
        }
    }

    private bool IsDecisionTimeWithinPolicy(
        DateTimeOffset value)
    {
        var now = _timeProvider.GetUtcNow().ToUniversalTime();
        return value.Offset == TimeSpan.Zero
            && value >= MinimumDecisionTimeUtc
            && value <= now + FutureTolerance;
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

    private static string HashAnchor(byte[] canonical) =>
        DomainHash(AnchorHashDomain, canonical);

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
        ApprovalLedgerSnapshot ledger)
    {
        if (ledger.Anchor.CanonicalValid
            && FixedEquals(
                ledger.Anchor.ScopeSha256,
                HashAnchor(ledger.Anchor.Canonical))
            && ledger.Anchor.Value is { } anchor
            && IsLowerSha256(anchor.TerminalEntrySha256))
        {
            return anchor.TerminalEntrySha256;
        }

        return ledger.Rows.Count != 0
            && IsLowerSha256(ledger.Rows[^1].EntrySha256)
                ? ledger.Rows[^1].EntrySha256
                : GenesisSha256;
    }

    private static long EntrySequence(
        IReadOnlyList<ApprovalLedgerRow> rows,
        string entryId) =>
        string.Equals(
            entryId,
            ApprovalLedgerDiagnostics.AnchorIdentifier,
            StringComparison.Ordinal)
            ? 0
            : rows.FirstOrDefault(row => string.Equals(
                row.DiagnosticId,
                entryId,
                StringComparison.Ordinal))
                ?.Sequence ?? long.MaxValue;

    private static void AddAllEntryIds(
        IEnumerable<ApprovalLedgerRow> rows,
        ISet<string> invalid)
    {
        foreach (var row in rows)
        {
            invalid.Add(row.DiagnosticId);
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

internal sealed record ApprovalLedgerAnchor(
    string SchemaVersion,
    string DomainVersion,
    long TerminalSequence,
    long EntryCount,
    string TerminalEntryId,
    string TerminalEntrySha256);

internal sealed record ApprovalLedgerAnchorState(
    bool Exists,
    string ScopeSha256,
    byte[] Canonical,
    ApprovalLedgerAnchor? Value,
    bool CanonicalValid)
{
    internal static ApprovalLedgerAnchorState Missing { get; } =
        new(false, string.Empty, [], null, false);
}

internal sealed record SqliteSequenceState(
    int RowCount,
    long? Sequence,
    bool ValuesValid);

internal sealed record ApprovalLedgerSnapshot(
    IReadOnlyList<ApprovalLedgerRow> Rows,
    ApprovalLedgerAnchorState Anchor,
    SqliteSequenceState SqliteSequence);

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

internal static class CanonicalApprovalLedgerAnchor
{
    internal static byte[] Serialize(
        ApprovalLedgerAnchor anchor) =>
        WorkbenchJson.Serialize(
            anchor,
            ApprovalJsonContext.Default.ApprovalLedgerAnchor);

    internal static ApprovalLedgerAnchor Parse(byte[] canonical)
    {
        var anchor = WorkbenchJson.Parse(
            canonical,
            ApprovalJsonContext.Default.ApprovalLedgerAnchor);
        var expected = Serialize(anchor);
        if (!CryptographicOperations.FixedTimeEquals(
                canonical,
                expected))
        {
            throw new JsonException(
                "Approval anchor payload is not canonical.");
        }

        return anchor;
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
    internal string DiagnosticId =>
        ApprovalLedgerDiagnostics.Identifier(Sequence, EntryId);

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

internal static class ApprovalLedgerDiagnostics
{
    private const string SurrogateDomain =
        "corpus-approval-invalid-entry-id-v1\n";

    internal static string AnchorIdentifier { get; } =
        Identifier(0, "approval-ledger-anchor");

    internal static string Identifier(
        long sequence,
        string? entryId)
    {
        if (IsSafeEntryId(entryId))
        {
            return entryId!;
        }

        using var hash =
            IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(SurrogateDomain));
        hash.AppendData(
            Encoding.UTF8.GetBytes(
                sequence.ToString(
                    CultureInfo.InvariantCulture)));
        hash.AppendData([0]);
        hash.AppendData(
            Encoding.UTF8.GetBytes(entryId ?? string.Empty));
        var digest = Convert.ToHexStringLower(
            hash.GetHashAndReset());
        return string.Create(
            CultureInfo.InvariantCulture,
            $"invalid-entry-{sequence}-{digest[..16]}");
    }

    private static bool IsSafeEntryId(string? value) =>
        value is not null
        && value.StartsWith("approval-", StringComparison.Ordinal)
        && value.Length == "approval-".Length + 64
        && value["approval-".Length..].All(
            static character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');
}

internal sealed record BatchSelection(
    ImmutableArray<ApprovalEntryReference> Delegated,
    ImmutableArray<ApprovalEntryReference> Direct);

internal sealed record ApprovalLedgerContext(
    PilotScope Scope,
    ImmutableDictionary<string, string> RuleCatalogs,
    ImmutableDictionary<
        string,
        OfficialRuleCatalogSnapshot> RuleSnapshots,
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
        var snapshotBuilder =
            ImmutableDictionary.CreateBuilder<
                string,
                OfficialRuleCatalogSnapshot>(
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
                || !snapshotBuilder.TryAdd(
                    rule.Document.MarketId,
                    rule)
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
            snapshotBuilder.ToImmutable(),
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
    AfterInsertBeforeAnchor,
    AfterInsertBeforeCommit,
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectRequiredConstructorParameters = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    WriteIndented = false)]
[JsonSerializable(typeof(ApprovalDecisionPayload))]
[JsonSerializable(typeof(ApprovalLedgerAnchor))]
internal sealed partial class ApprovalJsonContext
    : JsonSerializerContext;
