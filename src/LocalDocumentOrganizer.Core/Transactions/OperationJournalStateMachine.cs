namespace LocalDocumentOrganizer.Core.Transactions;

public static class OperationJournalStateMachine
{
    private static readonly HashSet<Transition> AllowedTransitions =
    [
        new(FileOperationKind.SameVolumeMove, OperationJournalState.IntentPersisted, OperationJournalState.IdentityLocked),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.IdentityLocked, OperationJournalState.Renaming),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.Renaming, OperationJournalState.FileApplied),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.FileApplied, OperationJournalState.EventAndProjectionCommitted),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.EventAndProjectionCommitted, OperationJournalState.SideEffectsPending),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.SideEffectsPending, OperationJournalState.Completed),

        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.IntentPersisted, OperationJournalState.IdentityLocked),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.IdentityLocked, OperationJournalState.Renaming),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.Renaming, OperationJournalState.FileApplied),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.FileApplied, OperationJournalState.EventAndProjectionCommitted),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.EventAndProjectionCommitted, OperationJournalState.SideEffectsPending),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.SideEffectsPending, OperationJournalState.Completed),

        new(FileOperationKind.CrossVolumeMove, OperationJournalState.IntentPersisted, OperationJournalState.IdentityLocked),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.IdentityLocked, OperationJournalState.Copying),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.Copying, OperationJournalState.Copied),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.Copied, OperationJournalState.Verified),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.Verified, OperationJournalState.DeletingSource),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.DeletingSource, OperationJournalState.FileApplied),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.FileApplied, OperationJournalState.EventAndProjectionCommitted),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.EventAndProjectionCommitted, OperationJournalState.SideEffectsPending),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.SideEffectsPending, OperationJournalState.Completed),

        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.IntentPersisted, OperationJournalState.IdentityLocked),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.IdentityLocked, OperationJournalState.Copying),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.Copying, OperationJournalState.Copied),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.Copied, OperationJournalState.Verified),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.Verified, OperationJournalState.DeletingSource),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.DeletingSource, OperationJournalState.FileApplied),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.FileApplied, OperationJournalState.EventAndProjectionCommitted),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.EventAndProjectionCommitted, OperationJournalState.SideEffectsPending),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.SideEffectsPending, OperationJournalState.Completed),

        new(FileOperationKind.SameVolumeMove, OperationJournalState.IntentPersisted, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.IdentityLocked, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.Renaming, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.Copying, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.Copied, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.Verified, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.DeletingSource, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.FileApplied, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.EventAndProjectionCommitted, OperationJournalState.ManualRecovery),
        new(FileOperationKind.SameVolumeMove, OperationJournalState.SideEffectsPending, OperationJournalState.ManualRecovery),

        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.IntentPersisted, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.IdentityLocked, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.Renaming, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.Copying, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.Copied, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.Verified, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.DeletingSource, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.FileApplied, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.EventAndProjectionCommitted, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoSameVolumeMove, OperationJournalState.SideEffectsPending, OperationJournalState.ManualRecovery),

        new(FileOperationKind.CrossVolumeMove, OperationJournalState.IntentPersisted, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.IdentityLocked, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.Renaming, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.Copying, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.Copied, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.Verified, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.DeletingSource, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.FileApplied, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.EventAndProjectionCommitted, OperationJournalState.ManualRecovery),
        new(FileOperationKind.CrossVolumeMove, OperationJournalState.SideEffectsPending, OperationJournalState.ManualRecovery),

        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.IntentPersisted, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.IdentityLocked, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.Renaming, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.Copying, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.Copied, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.Verified, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.DeletingSource, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.FileApplied, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.EventAndProjectionCommitted, OperationJournalState.ManualRecovery),
        new(FileOperationKind.UndoCrossVolumeMove, OperationJournalState.SideEffectsPending, OperationJournalState.ManualRecovery),
    ];

    public static OperationRecoveryDecision DecideSameVolumeRecovery(
        RecoveryPathObservation source,
        RecoveryPathObservation destination)
    {
        if (!Enum.IsDefined(source))
        {
            throw new ArgumentOutOfRangeException(
                nameof(source),
                "The source observation is not defined.");
        }

        if (!Enum.IsDefined(destination))
        {
            throw new ArgumentOutOfRangeException(
                nameof(destination),
                "The destination observation is not defined.");
        }

        return (source, destination) switch
        {
            (RecoveryPathObservation.Exact, RecoveryPathObservation.Missing) =>
                OperationRecoveryDecision.ResumeRename,
            (RecoveryPathObservation.Missing, RecoveryPathObservation.Exact) =>
                OperationRecoveryDecision.FinalizeDatabaseCommit,
            _ => OperationRecoveryDecision.ManualRecovery,
        };
    }

    public static bool CanTransition(
        FileOperationKind kind,
        OperationJournalState current,
        OperationJournalState next) =>
        Enum.IsDefined(kind)
        && Enum.IsDefined(current)
        && Enum.IsDefined(next)
        && AllowedTransitions.Contains(new Transition(kind, current, next));

    public static void EnsureCanTransition(
        FileOperationKind kind,
        OperationJournalState current,
        OperationJournalState next)
    {
        if (!CanTransition(kind, current, next))
        {
            throw new InvalidOperationException(
                $"Operation kind '{kind}' cannot transition from '{current}' to '{next}'.");
        }
    }

    private readonly record struct Transition(
        FileOperationKind Kind,
        OperationJournalState Current,
        OperationJournalState Next);
}
