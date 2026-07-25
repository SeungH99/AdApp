using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Core.Transactions;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public sealed record UndoSameVolumeMoveRequest
{
    private readonly byte[] _approvedProposal;

    public UndoSameVolumeMoveRequest(
        OperationId operationId,
        OperationId originalOperationId,
        ReadOnlyMemory<byte> approvedProposal,
        AppendEventsCommand appendEvents,
        IEnumerable<FileOperationSideEffect> sideEffects,
        FileOperationUsage? usage)
    {
        if (operationId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "An operation ID is required.",
                nameof(operationId));
        }

        if (originalOperationId.Value == Guid.Empty
            || originalOperationId == operationId)
        {
            throw new ArgumentException(
                "A distinct original operation ID is required.",
                nameof(originalOperationId));
        }

        ArgumentNullException.ThrowIfNull(appendEvents);
        ArgumentNullException.ThrowIfNull(sideEffects);
        if (appendEvents.OperationId != operationId)
        {
            throw new ArgumentException(
                "The event append must use the new Undo operation ID.",
                nameof(appendEvents));
        }

        var sideEffectSnapshot = sideEffects.ToArray();
        if (sideEffectSnapshot.Any(sideEffect => sideEffect is null))
        {
            throw new ArgumentException(
                "Side effects cannot contain null entries.",
                nameof(sideEffects));
        }

        OperationId = operationId;
        OriginalOperationId = originalOperationId;
        _approvedProposal = approvedProposal.ToArray();
        AppendEvents = appendEvents;
        SideEffects = Array.AsReadOnly(sideEffectSnapshot);
        Usage = usage;
    }

    public OperationId OperationId { get; }

    public OperationId OriginalOperationId { get; }

    public ReadOnlyMemory<byte> ApprovedProposal =>
        _approvedProposal.ToArray();

    public AppendEventsCommand AppendEvents { get; }

    public IReadOnlyList<FileOperationSideEffect> SideEffects { get; }

    public FileOperationUsage? Usage { get; }
}

public sealed class UndoCoordinator
{
    private readonly IOperationJournalStore _journal;
    private readonly IFileOperationExecutor _executor;
    private readonly OperationRecoveryReadiness _readiness;

    public UndoCoordinator(
        IOperationJournalStore journal,
        FileOperationCoordinator executor)
        : this(journal, (IFileOperationExecutor)executor)
    {
    }

    internal UndoCoordinator(
        IOperationJournalStore journal,
        IFileOperationExecutor executor)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(executor);
        _journal = journal;
        _executor = executor;
        _readiness = executor.Readiness;
    }

    public async Task<FileOperationExecutionResult> ExecuteAsync(
        UndoSameVolumeMoveRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _readiness.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        var original = await _journal.GetAsync(
                request.OriginalOperationId,
                cancellationToken)
            .ConfigureAwait(false);
        if (original is not
            {
                State: OperationJournalState.Completed,
                Identity: not null,
                RecoveryRecipe: not null,
            }
            || original.Kind is not (
                FileOperationKind.SameVolumeMove
                or FileOperationKind.CrossVolumeMove)
            || original.Kind == FileOperationKind.CrossVolumeMove
                && original.AppliedIdentity is null)
        {
            return new FileOperationNotApplied(
                FileOperationFailure.UnexpectedJournalState,
                original?.State);
        }

        var intent = new FileOperationIntent(
            request.OperationId,
            original.Owner,
            original.Kind == FileOperationKind.CrossVolumeMove
                ? FileOperationKind.UndoCrossVolumeMove
                : FileOperationKind.UndoSameVolumeMove,
            original.Intent.DestinationPath,
            original.Intent.SourcePath,
            original.Intent.DestinationRoot,
            original.Intent.SourceRoot,
            request.AppendEvents.StreamId,
            request.AppendEvents.ExpectedVersion,
            request.ApprovedProposal,
            original.OperationId);
        var execution = new FileOperationExecutionRequest(
            intent,
            original.RecoveryRecipe.DataKeyId,
            request.AppendEvents,
            request.SideEffects,
            request.Usage,
            original.Kind == FileOperationKind.CrossVolumeMove
                ? original.AppliedIdentity!
                : original.Identity);
        return await _executor.ExecuteAsync(execution, cancellationToken)
            .ConfigureAwait(false);
    }
}
