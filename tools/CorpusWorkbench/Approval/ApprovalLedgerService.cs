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

internal sealed record PilotApprovalValidationSnapshot(
    IReadOnlyList<LabelDraftState> States,
    ApprovalVerificationResult Verification,
    OwnerApprovalView Approvals);

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
    internal const int MaximumPilotLedgerRowCount = 512;
    private const int MaximumCanonicalBytes = 64 * 1024;
    private const int MaximumAnchorCanonicalBytes = 4 * 1024;
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
    private readonly Action<ApprovalPilotReadPoint>? _observePilotRead;

    internal PilotScope TrustedPilotScope => _context.Scope;

    internal ImmutableDictionary<string, string>
        TrustedRuleCatalogs => _context.RuleCatalogs;

    internal string TrustedPilotRuleCatalogSha256 =>
        OfficialRuleCatalog.ComputePilotCatalogSha256(
            _context.RuleSnapshots.Values);

    internal string TrustedWorkerPackageSha256 =>
        _context.WorkerIdentity.Sha256;

    internal bool IsBoundTo(CorpusVault vault) =>
        vault is not null
        && ReferenceEquals(_store, vault.Store);

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
        _observePilotRead = null;
    }

    internal ApprovalLedgerService(
        CorpusVault vault,
        PilotScope scope,
        IEnumerable<OfficialRuleCatalogSnapshot> rules,
        CorpusWorkerPackageIdentity workerIdentity,
        TimeProvider timeProvider,
        Action<ApprovalLedgerFaultPoint>? injectFault,
        Action<ApprovalPilotReadPoint>? observePilotRead = null)
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
        _observePilotRead = observePilotRead;
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

    internal async Task<ApprovalEntry> RecordBatchApprovalAsync(
        string marketId,
        string reviewerId,
        CancellationToken cancellationToken)
    {
        ValidateActor(reviewerId);
        if (!_context.RuleCatalogs.ContainsKey(marketId))
        {
            throw InvalidArguments();
        }

        var observedAtUtc = _timeProvider.GetUtcNow()
            .ToUniversalTime();
        ValidateDecisionTime(observedAtUtc);
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        reviewerId = reviewerId.Normalize();
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
                var existing = ledger.Rows
                    .Where(row =>
                        row.Payload?.Mode
                            == ApprovalMode.BatchApproval
                        && string.Equals(
                            row.Payload.MarketId,
                            marketId,
                            StringComparison.Ordinal))
                    .OrderByDescending(static row => row.Sequence)
                    .FirstOrDefault();
                if (existing is not null)
                {
                    if (IsCurrentBatchApproval(
                            existing,
                            ledger.Rows,
                            states))
                    {
                        return existing.ToEntry();
                    }

                    throw new WorkbenchException(
                        WorkbenchFailureCode.ApprovalChainInvalid);
                }

                var selection = SelectBatchBindings(
                    marketId,
                    ledger.Rows,
                    states,
                    requireExactDirectCount: true);
                var referencedIds = selection.Delegated
                    .Concat(selection.Direct)
                    .Select(static item => item.EntryId)
                    .ToHashSet(StringComparer.Ordinal);
                var approvedAtUtc = ledger.Rows
                    .Where(row =>
                        referencedIds.Contains(row.EntryId)
                        && row.Payload is not null)
                    .Select(static row =>
                        row.Payload!.ApprovedAtUtc)
                    .Append(observedAtUtc)
                    .Max();
                RequireBatchDecisionTime(
                    approvedAtUtc,
                    ledger.Rows,
                    selection);
                var summary =
                    ComputeBatchSummarySha256(selection.Delegated);
                var decision = new BatchApprovalDecision(
                    marketId,
                    reviewerId,
                    summary,
                    approvedAtUtc);
                var payload = ApprovalDecisionPayload.Batch(
                    decision,
                    _context.Scope,
                    _context.RuleCatalogs[marketId],
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

    public Task<ApprovalVerificationResult> VerifyAsync(
        CancellationToken cancellationToken) =>
        VerifyCoreAsync(
            int.MaxValue,
            maximumLedgerRowCount: null,
            cancellationToken);

    internal Task<ApprovalVerificationResult> VerifyAsync(
        int maximumDocumentCount,
        CancellationToken cancellationToken) =>
        VerifyCoreAsync(
            maximumDocumentCount,
            MaximumPilotLedgerRowCount,
            cancellationToken);

    private async Task<ApprovalVerificationResult> VerifyCoreAsync(
        int maximumDocumentCount,
        int? maximumLedgerRowCount,
        CancellationToken cancellationToken)
    {
        if (maximumDocumentCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumDocumentCount));
        }

        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        var result = await _store.ExecuteApprovalReadAsync(
            async (connection, transaction) =>
            {
                var ledger = await ReadLedgerAsync(
                        connection,
                        transaction,
                        maximumLedgerRowCount,
                        cancellationToken,
                        _observePilotRead)
                    .ConfigureAwait(false);
                var states = Array.Empty<LabelDraftState>();
                try
                {
                    states =
                    [
                        ..
                        await _store.ReadAllApprovalLabelStatesAsync(
                                connection,
                                transaction,
                                maximumDocumentCount,
                                cancellationToken)
                            .ConfigureAwait(false),
                    ];
                }
                catch (WorkbenchException)
                {
                    return InvalidVerification(ledger);
                }
                catch (Exception exception) when (
                    exception is JsonException
                        or FormatException
                        or CryptographicException)
                {
                    return InvalidVerification(ledger);
                }

                return VerifyLedger(
                    ledger,
                    states,
                    cancellationToken,
                    _observePilotRead);
            },
            cancellationToken).ConfigureAwait(false);
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    public Task<OwnerApprovalView> GetOwnerApprovalViewAsync(
        CancellationToken cancellationToken) =>
        GetOwnerApprovalViewCoreAsync(
            int.MaxValue,
            maximumLedgerRowCount: null,
            cancellationToken);

    internal Task<OwnerApprovalView> GetOwnerApprovalViewAsync(
        int maximumDocumentCount,
        CancellationToken cancellationToken) =>
        GetOwnerApprovalViewCoreAsync(
            maximumDocumentCount,
            MaximumPilotLedgerRowCount,
            cancellationToken);

    private async Task<OwnerApprovalView> GetOwnerApprovalViewCoreAsync(
        int maximumDocumentCount,
        int? maximumLedgerRowCount,
        CancellationToken cancellationToken)
    {
        if (maximumDocumentCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumDocumentCount));
        }

        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        var result = await _store.ExecuteApprovalReadAsync(
            async (connection, transaction) =>
            {
                var ledger = await ReadLedgerAsync(
                        connection,
                        transaction,
                        maximumLedgerRowCount,
                        cancellationToken,
                        _observePilotRead)
                    .ConfigureAwait(false);
                var states =
                    await _store.ReadAllApprovalLabelStatesAsync(
                            connection,
                            transaction,
                            maximumDocumentCount,
                            cancellationToken)
                        .ConfigureAwait(false);
                var invalid = FindChainFailures(
                    ledger.Rows,
                    cancellationToken,
                    _observePilotRead);
                FindLedgerSemanticFailures(
                    ledger.Rows,
                    invalid,
                    cancellationToken,
                    _observePilotRead);
                FindAnchorFailures(ledger, invalid);
                if (invalid.Count != 0)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.ApprovalChainInvalid);
                }

                return BuildOwnerApprovalView(
                    ledger,
                    states,
                    cancellationToken,
                    _observePilotRead);
            },
            cancellationToken).ConfigureAwait(false);
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    internal async Task<PilotApprovalValidationSnapshot>
        ReadPilotValidationSnapshotAsync(
        CancellationToken cancellationToken)
    {
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        var result = await _store.ExecuteApprovalReadAsync(
            async (connection, transaction) =>
            {
                var ledger = await ReadLedgerAsync(
                        connection,
                        transaction,
                        MaximumPilotLedgerRowCount,
                        cancellationToken,
                        _observePilotRead)
                    .ConfigureAwait(false);
                _observePilotRead?.Invoke(
                    ApprovalPilotReadPoint.AfterLedgerBeforeStates);
                cancellationToken.ThrowIfCancellationRequested();
                var states =
                    await _store.ReadAllPilotLabelStatesAsync(
                            connection,
                            transaction,
                            PilotCatalog.HeldOutTargetPerMarket * 2,
                            cancellationToken,
                            ObservePilotLabelRead)
                        .ConfigureAwait(false);
                var verification = VerifyLedger(
                    ledger,
                    states,
                    cancellationToken,
                    _observePilotRead);
                var approvals = verification.IsValid
                    ? BuildOwnerApprovalView(
                        ledger,
                        states,
                        cancellationToken,
                        _observePilotRead)
                    : new OwnerApprovalView(
                        verification.LedgerHeadSha256,
                        []);
                cancellationToken.ThrowIfCancellationRequested();
                return new PilotApprovalValidationSnapshot(
                    states,
                    verification,
                    approvals);
            },
            cancellationToken).ConfigureAwait(false);
        await VerifyWorkerAsync(cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    private void ObservePilotLabelRead(PilotLabelReadPoint point)
    {
        if (_observePilotRead is null)
        {
            return;
        }

        _observePilotRead(point switch
        {
            PilotLabelReadPoint.DuringDocumentRowRead =>
                ApprovalPilotReadPoint.DuringDocumentRowRead,
            PilotLabelReadPoint.AfterDocumentShape =>
                ApprovalPilotReadPoint.AfterDocumentShape,
            PilotLabelReadPoint.DuringRevisionRowRead =>
                ApprovalPilotReadPoint.DuringRevisionRowRead,
            PilotLabelReadPoint.AfterRevisionShape =>
                ApprovalPilotReadPoint.AfterRevisionShape,
            PilotLabelReadPoint.DuringRevisionParse =>
                ApprovalPilotReadPoint.DuringRevisionParse,
            _ => throw new WorkbenchException(
                WorkbenchFailureCode.InvalidState),
        });
    }

    private ApprovalVerificationResult VerifyLedger(
        ApprovalLedgerSnapshot ledger,
        IReadOnlyList<LabelDraftState> states,
        CancellationToken cancellationToken,
        Action<ApprovalPilotReadPoint>? observePilotRead)
    {
        var rows = ledger.Rows;
        var invalid = FindChainFailures(
            rows,
            cancellationToken,
            observePilotRead);
        FindLedgerSemanticFailures(
            rows,
            invalid,
            cancellationToken,
            observePilotRead);
        FindAnchorFailures(ledger, invalid);
        FindCurrentStateFailures(
            rows,
            states,
            invalid,
            cancellationToken,
            observePilotRead);
        cancellationToken.ThrowIfCancellationRequested();
        var ordered = invalid
            .OrderBy(entryId => EntrySequence(rows, entryId))
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
    }

    private static ApprovalVerificationResult InvalidVerification(
        ApprovalLedgerSnapshot ledger)
    {
        var invalid = new HashSet<string>(StringComparer.Ordinal);
        AddAllEntryIds(ledger.Rows, invalid);
        return new ApprovalVerificationResult(
            false,
            WorkbenchFailureCode.ApprovalChainInvalid,
            LedgerHead(ledger),
            [
                .. invalid.OrderBy(
                    entryId => EntrySequence(ledger.Rows, entryId)),
            ]);
    }

    private OwnerApprovalView BuildOwnerApprovalView(
        ApprovalLedgerSnapshot ledger,
        IReadOnlyList<LabelDraftState> states,
        CancellationToken cancellationToken,
        Action<ApprovalPilotReadPoint>? observePilotRead)
    {
        var currentByDocument =
            new Dictionary<string, LabelDraftState>(
                states.Count,
                StringComparer.Ordinal);
        foreach (var state in states)
        {
            cancellationToken.ThrowIfCancellationRequested();
            currentByDocument.Add(
                state.Document.DocumentId,
                state);
        }

        var approved =
            new Dictionary<string, OwnerApprovedDocument>(
                StringComparer.Ordinal);
        foreach (var row in LatestDocumentRows(
                     ledger.Rows,
                     ApprovalMode.DirectReview,
                     marketId: null,
                     cancellationToken))
        {
            observePilotRead?.Invoke(
                ApprovalPilotReadPoint.DuringProjection);
            cancellationToken.ThrowIfCancellationRequested();
            var payload = row.Payload!;
            if (!IsCurrentDocumentApproval(
                    payload,
                    currentByDocument,
                    cancellationToken))
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

        var latestBatches =
            new Dictionary<string, ApprovalLedgerRow>(
                StringComparer.Ordinal);
        foreach (var row in ledger.Rows)
        {
            observePilotRead?.Invoke(
                ApprovalPilotReadPoint.DuringProjection);
            cancellationToken.ThrowIfCancellationRequested();
            if (row.Payload?.Mode == ApprovalMode.BatchApproval
                && (!latestBatches.TryGetValue(
                        row.Payload.MarketId,
                        out var current)
                    || row.Sequence > current.Sequence))
            {
                latestBatches[row.Payload.MarketId] = row;
            }
        }

        foreach (var batch in latestBatches.Values)
        {
            observePilotRead?.Invoke(
                ApprovalPilotReadPoint.DuringProjection);
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsCurrentBatchApproval(
                    batch,
                    ledger.Rows,
                    states,
                    cancellationToken))
            {
                continue;
            }

            foreach (var delegated in
                     batch.Payload!.DelegatedEntries)
            {
                cancellationToken.ThrowIfCancellationRequested();
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
    }

    internal static string ComputeBatchSummarySha256(
        IEnumerable<ApprovalEntryReference> delegatedEntries) =>
        ComputeBatchSummarySha256(
            delegatedEntries,
            CancellationToken.None);

    private static string ComputeBatchSummarySha256(
        IEnumerable<ApprovalEntryReference> delegatedEntries,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(delegatedEntries);
        var entries = new List<ApprovalEntryReference>();
        foreach (var entry in delegatedEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            entries.Add(entry);
        }

        entries.Sort(static (left, right) =>
        {
            var documentOrder = string.CompareOrdinal(
                left.DocumentId,
                right.DocumentId);
            return documentOrder != 0
                ? documentOrder
                : string.CompareOrdinal(
                    left.EntryId,
                    right.EntryId);
        });
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!seen.Add(entry.DocumentId))
            {
                throw InvalidState();
            }
        }

        using var stream = new MemoryStream();
        stream.Write(Encoding.UTF8.GetBytes(BatchSummaryDomain));
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartArray();
            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
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
        ISet<string> invalid,
        CancellationToken cancellationToken,
        Action<ApprovalPilotReadPoint>? observePilotRead)
    {
        var currentByDocument =
            new Dictionary<string, LabelDraftState>(
                states.Count,
                StringComparer.Ordinal);
        foreach (var state in states)
        {
            cancellationToken.ThrowIfCancellationRequested();
            currentByDocument.Add(
                state.Document.DocumentId,
                state);
        }

        var latestDocumentDecisions =
            new Dictionary<(ApprovalMode, string), ApprovalLedgerRow>();
        var latestBatches =
            new Dictionary<string, ApprovalLedgerRow>(
                StringComparer.Ordinal);
        foreach (var row in rows)
        {
            observePilotRead?.Invoke(
                ApprovalPilotReadPoint.DuringSemanticVerification);
            cancellationToken.ThrowIfCancellationRequested();
            if (row.Payload?.Mode is ApprovalMode.DirectReview
                    or ApprovalMode.DelegatedLabel
                && row.Payload.DocumentId is { } documentId)
            {
                var key = (row.Payload.Mode, documentId);
                if (!latestDocumentDecisions.TryGetValue(
                        key,
                        out var existing)
                    || row.Sequence > existing.Sequence)
                {
                    latestDocumentDecisions[key] = row;
                }
            }
            else if (row.Payload?.Mode
                         == ApprovalMode.BatchApproval
                     && (!latestBatches.TryGetValue(
                             row.Payload.MarketId,
                             out var existingBatch)
                         || row.Sequence > existingBatch.Sequence))
            {
                latestBatches[row.Payload.MarketId] = row;
            }
        }

        foreach (var row in latestDocumentDecisions.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var payload = row.Payload!;
            if (!currentByDocument.TryGetValue(
                    payload.DocumentId!,
                    out var state)
                || !MatchesCurrent(
                    payload,
                    state,
                    cancellationToken))
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

        foreach (var batch in latestBatches.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var payload = batch.Payload!;
                var selected = SelectBatchBindings(
                    payload.MarketId,
                    rows,
                    states,
                    requireExactDirectCount: true,
                    cancellationToken);
                var summary =
                    ComputeBatchSummarySha256(
                        selected.Delegated,
                        cancellationToken);
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
        IReadOnlyDictionary<string, LabelDraftState> currentByDocument,
        CancellationToken cancellationToken = default)
    {
        if (!currentByDocument.TryGetValue(
                payload.DocumentId!,
                out var state)
            || !MatchesCurrent(
                payload,
                state,
                cancellationToken))
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
        IReadOnlyList<LabelDraftState> states,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var payload = batch.Payload!;
            var selected = SelectBatchBindings(
                payload.MarketId,
                rows,
                states,
                requireExactDirectCount: true,
                cancellationToken);
            var summary = ComputeBatchSummarySha256(
                selected.Delegated,
                cancellationToken);
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
        bool requireExactDirectCount,
        CancellationToken cancellationToken = default)
    {
        if (!_context.RuleCatalogs.ContainsKey(marketId))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.StaleRuleSet);
        }

        var current = new Dictionary<string, LabelDraftState>(
            StringComparer.Ordinal);
        foreach (var state in states)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.Equals(
                    state.Document.MarketId,
                    marketId,
                    StringComparison.Ordinal))
            {
                current.Add(state.Document.DocumentId, state);
            }
        }
        var directRows = LatestDocumentRows(
            rows,
            ApprovalMode.DirectReview,
            marketId,
            cancellationToken);
        var delegatedRows = LatestDocumentRows(
            rows,
            ApprovalMode.DelegatedLabel,
            marketId,
            cancellationToken);

        var direct = ImmutableArray.CreateBuilder<
            ApprovalEntryReference>();
        foreach (var row in directRows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!current.TryGetValue(
                    row.Payload!.DocumentId!,
                    out var state)
                || !MatchesCurrent(
                    row.Payload,
                    state,
                    cancellationToken))
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
            cancellationToken.ThrowIfCancellationRequested();
            if (!current.TryGetValue(
                    row.Payload!.DocumentId!,
                    out var state)
                || !MatchesCurrent(
                    row.Payload,
                    state,
                    cancellationToken))
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
        ApprovalMode mode,
        string? marketId,
        CancellationToken cancellationToken = default)
    {
        var latest = new Dictionary<string, ApprovalLedgerRow>(
            StringComparer.Ordinal);
        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (row.Payload?.Mode != mode
                || row.Payload.DocumentId is not { } documentId
                || marketId is not null
                    && !string.Equals(
                        row.Payload.MarketId,
                        marketId,
                        StringComparison.Ordinal))
            {
                continue;
            }

            if (!latest.TryGetValue(documentId, out var existing)
                || row.Sequence > existing.Sequence)
            {
                latest[documentId] = row;
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        return
        [
            .. latest.Values.OrderBy(
                static row => row.Payload!.DocumentId,
                StringComparer.Ordinal),
        ];
    }

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
        LabelDraftState state,
        CancellationToken cancellationToken = default)
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
            && FieldsEqual(
                payload.Fields,
                revision.Fields,
                cancellationToken);
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
        ImmutableArray<LabeledField> right,
        CancellationToken cancellationToken = default)
    {
        if (left.IsDefault
            || right.IsDefault
            || left.Length != right.Length)
        {
            return false;
        }

        for (var index = 0; index < left.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
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
        SqliteTransaction? transaction,
        int? maximumRowCount,
        CancellationToken cancellationToken,
        Action<ApprovalPilotReadPoint>? observePilotRead)
    {
        if (maximumRowCount is < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumRowCount));
        }

        var rows = new List<ApprovalLedgerRow>();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT
              typeof(sequence),
              sequence,
              typeof(entry_id),
              length(entry_id),
              entry_id,
              typeof(previous_entry_sha256),
              length(previous_entry_sha256),
              previous_entry_sha256,
              typeof(entry_sha256),
              length(entry_sha256),
              entry_sha256,
              typeof(canonical_json),
              length(canonical_json),
              canonical_json
            FROM approval_entries
            ORDER BY sequence
            """;
        if (maximumRowCount is { } maximum)
        {
            command.CommandText += "\nLIMIT $limit;";
            command.Parameters.AddWithValue(
                "$limit",
                checked((long)maximum + 1L));
        }
        else
        {
            command.CommandText += ";";
        }

        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken)
                   .ConfigureAwait(false))
        {
            observePilotRead?.Invoke(
                ApprovalPilotReadPoint.AfterLedgerRowRead);
            cancellationToken.ThrowIfCancellationRequested();
            if (maximumRowCount is { } rowLimit
                && rows.Count >= rowLimit)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.InvalidArguments);
            }

            var sequenceValid =
                IsSqliteType(reader, 0, "integer")
                && reader.GetValue(1) is long;
            var entryIdValid = IsBoundedSqliteText(
                reader,
                2,
                3,
                "approval-".Length + 64,
                "approval-".Length + 64);
            var previousValid = IsBoundedSqliteText(
                reader,
                5,
                6,
                64,
                64);
            var entryHashValid = IsBoundedSqliteText(
                reader,
                8,
                9,
                64,
                64);
            var canonicalValid =
                maximumRowCount is null
                    ? IsSqliteType(reader, 11, "blob")
                    : IsBoundedSqliteBlob(
                        reader,
                        11,
                        12,
                        MaximumCanonicalBytes);
            var sequence = sequenceValid
                ? reader.GetInt64(1)
                : 0;
            var entryId = entryIdValid
                ? reader.GetString(4)
                : string.Empty;
            var previous = previousValid
                ? reader.GetString(7)
                : string.Empty;
            var entryHash = entryHashValid
                ? reader.GetString(10)
                : string.Empty;
            if (!sequenceValid
                || !entryIdValid
                || !previousValid
                || !entryHashValid
                || !canonicalValid)
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

            var canonical = reader.GetFieldValue<byte[]>(13);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
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
        SqliteTransaction transaction) =>
        await ReadLedgerAsync(
                connection,
                transaction,
                maximumRowCount: null,
                CancellationToken.None,
                observePilotRead: null)
            .ConfigureAwait(false);

    private static async Task<ApprovalLedgerSnapshot>
        ReadLedgerAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        int? maximumRowCount,
        CancellationToken cancellationToken,
        Action<ApprovalPilotReadPoint>? observePilotRead)
    {
        var rows = await ReadRowsAsync(
                connection,
                transaction,
                maximumRowCount,
                cancellationToken,
                observePilotRead)
            .ConfigureAwait(false);
        var anchor = await ReadAnchorAsync(
                connection,
                transaction,
                cancellationToken)
            .ConfigureAwait(false);
        var sequence = await ReadSqliteSequenceAsync(
                connection,
                transaction,
                cancellationToken)
            .ConfigureAwait(false);
        return new ApprovalLedgerSnapshot(rows, anchor, sequence);
    }

    private static async Task<ApprovalLedgerAnchorState>
        ReadAnchorAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT
              typeof(scope_sha256),
              length(scope_sha256),
              scope_sha256,
              typeof(canonical_json),
              length(canonical_json),
              canonical_json
            FROM checkpoints
            WHERE checkpoint_id=$checkpoint_id;
            """;
        command.Parameters.AddWithValue(
            "$checkpoint_id",
            AnchorCheckpointId);
        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken)
                .ConfigureAwait(false))
        {
            return ApprovalLedgerAnchorState.Missing;
        }

        if (!IsBoundedSqliteText(reader, 0, 1, 64, 64)
            || !IsBoundedSqliteBlob(
                reader,
                3,
                4,
                MaximumAnchorCanonicalBytes))
        {
            return new ApprovalLedgerAnchorState(
                true,
                string.Empty,
                [],
                null,
                false);
        }

        var scopeSha256 = reader.GetString(2);
        var canonical = reader.GetFieldValue<byte[]>(5);
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
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT seq
            FROM sqlite_sequence
            WHERE name='approval_entries';
            """;
        await using var reader =
            await command.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
        var count = 0;
        long? sequence = null;
        var valuesValid = true;
        while (await reader.ReadAsync(cancellationToken)
                   .ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
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

    private static bool IsBoundedSqliteText(
        SqliteDataReader reader,
        int typeOrdinal,
        int lengthOrdinal,
        int minimumLength,
        int maximumLength) =>
        IsSqliteType(reader, typeOrdinal, "text")
        && reader.GetValue(lengthOrdinal) is long length
        && length >= minimumLength
        && length <= maximumLength;

    private static bool IsBoundedSqliteBlob(
        SqliteDataReader reader,
        int typeOrdinal,
        int lengthOrdinal,
        int maximumLength) =>
        IsSqliteType(reader, typeOrdinal, "blob")
        && reader.GetValue(lengthOrdinal) is long length
        && length > 0
        && length <= maximumLength;

    private static bool IsSqliteType(
        SqliteDataReader reader,
        int ordinal,
        string expected) =>
        reader.GetValue(ordinal) is string actual
        && string.Equals(
            actual,
            expected,
            StringComparison.Ordinal);

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
        IReadOnlyList<ApprovalLedgerRow> rows,
        CancellationToken cancellationToken = default,
        Action<ApprovalPilotReadPoint>? observePilotRead = null)
    {
        var invalid = new HashSet<string>(StringComparer.Ordinal);
        var expectedPrevious = GenesisSha256;
        long expectedSequence = 1;
        foreach (var row in rows)
        {
            observePilotRead?.Invoke(
                ApprovalPilotReadPoint.DuringChainVerification);
            cancellationToken.ThrowIfCancellationRequested();
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
                    && IsValidPayload(
                        row.Payload!,
                        cancellationToken);
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
        ApprovalDecisionPayload payload,
        CancellationToken cancellationToken = default)
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
                    payload.DelegatedEntries,
                    cancellationToken)
                && IsCanonicalReferences(
                    payload.DirectReviewEntries,
                    cancellationToken)
                && FixedEquals(
                    payload.BatchSummarySha256!,
                    ComputeBatchSummarySha256(
                        payload.DelegatedEntries,
                        cancellationToken));
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
        ImmutableArray<ApprovalEntryReference> references,
        CancellationToken cancellationToken = default)
    {
        var ordered = references.ToArray();
        Array.Sort(
            ordered,
            static (left, right) => string.CompareOrdinal(
                left.DocumentId,
                right.DocumentId));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in ordered)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!seen.Add(item.DocumentId)
                || !IsSafeEntryId(item.EntryId)
                || !IsLowerSha256(item.EntrySha256)
                || !IsLowerSha256(item.DocumentSha256)
                || !IsLowerSha256(item.LabelRevisionSha256)
                || !IsLowerSha256(item.RuleCatalogSha256)
                || !CorpusWorkerPackageManifest
                    .IsCanonicalExecutionIdentity(
                        new CorpusWorkerPackageIdentity(
                            item.WorkerPackageManifestId,
                            item.WorkerPackageManifestVersion,
                            item.WorkerPackageSha256,
                            item.WorkerExecutableRelativePath,
                            item.WorkerExecutableSha256)))
            {
                return false;
            }
        }

        return ordered.AsSpan().SequenceEqual(references.AsSpan())
            && seen.Count == ordered.Length;
    }

    private void FindLedgerSemanticFailures(
        IReadOnlyList<ApprovalLedgerRow> rows,
        ISet<string> invalid,
        CancellationToken cancellationToken = default,
        Action<ApprovalPilotReadPoint>? observePilotRead = null)
    {
        var byId = new Dictionary<string, ApprovalLedgerRow>(
            StringComparer.Ordinal);
        foreach (var row in rows)
        {
            observePilotRead?.Invoke(
                ApprovalPilotReadPoint.DuringSemanticVerification);
            cancellationToken.ThrowIfCancellationRequested();
            if (row.CanonicalValid
                && IsSafeEntryId(row.EntryId))
            {
                byId.Add(row.EntryId, row);
            }

            if (row.Payload is null)
            {
                continue;
            }

            if (!IsDecisionTimeWithinPolicy(
                    row.Payload!.ApprovedAtUtc))
            {
                invalid.Add(row.DiagnosticId);
            }
        }

        foreach (var batch in rows)
        {
            observePilotRead?.Invoke(
                ApprovalPilotReadPoint.DuringSemanticVerification);
            cancellationToken.ThrowIfCancellationRequested();
            if (batch.Payload?.Mode
                != ApprovalMode.BatchApproval)
            {
                continue;
            }

            var payload = batch.Payload!;
            if (payload.DirectReviewEntries.Length
                    != PilotCatalog.DirectReviewTargetPerMarket
                || !ReferencesEarlierEntries(
                    payload.DirectReviewEntries,
                    ApprovalMode.DirectReview,
                    payload,
                    batch.Sequence,
                    byId,
                    cancellationToken)
                || !ReferencesEarlierEntries(
                    payload.DelegatedEntries,
                    ApprovalMode.DelegatedLabel,
                    payload,
                    batch.Sequence,
                    byId,
                    cancellationToken))
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
        IReadOnlyDictionary<string, ApprovalLedgerRow> byId,
        CancellationToken cancellationToken = default)
    {
        foreach (var reference in references)
        {
            cancellationToken.ThrowIfCancellationRequested();
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

internal enum ApprovalPilotReadPoint
{
    AfterLedgerRowRead,
    AfterLedgerBeforeStates,
    DuringDocumentRowRead,
    AfterDocumentShape,
    DuringRevisionRowRead,
    AfterRevisionShape,
    DuringRevisionParse,
    DuringChainVerification,
    DuringSemanticVerification,
    DuringProjection,
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
