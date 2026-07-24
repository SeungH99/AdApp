namespace LocalDocumentOrganizer.Core.Transactions;

public enum OperationJournalState
{
    IntentPersisted = 0,
    IdentityLocked = 1,
    Renaming = 2,
    Copying = 3,
    Copied = 4,
    Verified = 5,
    DeletingSource = 6,
    FileApplied = 7,
    EventAndProjectionCommitted = 8,
    SideEffectsPending = 9,
    Completed = 10,
    ManualRecovery = 11,
}

public enum OperationSourceHealth
{
    Healthy = 0,
    Missing = 1,
    Changed = 2,
    Replaced = 3,
    AccessDenied = 4,
    UnsupportedReparsePoint = 5,
    ManualRecovery = 6,
}

public enum RecoveryPathObservation
{
    Exact = 0,
    Missing = 1,
    Mismatch = 2,
    InaccessibleOrUnknown = 3,
}

public enum OperationRecoveryDecision
{
    ResumeRename = 0,
    FinalizeDatabaseCommit = 1,
    ManualRecovery = 2,
}

public enum OperationManualRecoveryReason
{
    MissingRecoveryRecipe = 0,
    AmbiguousPathObservations = 1,
    ObservationFailed = 2,
    JournalStateMismatch = 3,
    ExactCommitConflict = 4,
    UnspecifiedRecoveryBoundary = 5,
}

public enum OperationManualRecoveryAction
{
    InspectBothPathsWithoutMutation = 0,
    RestoreAuthenticatedRecipeOrEscalate = 1,
    InspectAtomicCommitContributions = 2,
}

public sealed record OperationManualRecoveryEvidence
{
    public OperationManualRecoveryEvidence(
        OperationJournalState observedState,
        RecoveryPathObservation sourceObservation,
        RecoveryPathObservation destinationObservation,
        OperationManualRecoveryReason reason,
        OperationManualRecoveryAction recommendedAction)
    {
        if (!Enum.IsDefined(observedState))
        {
            throw new ArgumentOutOfRangeException(
                nameof(observedState),
                "The observed Journal state is not defined.");
        }

        if (!Enum.IsDefined(sourceObservation))
        {
            throw new ArgumentOutOfRangeException(
                nameof(sourceObservation),
                "The source observation is not defined.");
        }

        if (!Enum.IsDefined(destinationObservation))
        {
            throw new ArgumentOutOfRangeException(
                nameof(destinationObservation),
                "The destination observation is not defined.");
        }

        if (!Enum.IsDefined(reason))
        {
            throw new ArgumentOutOfRangeException(
                nameof(reason),
                "The manual-recovery reason is not defined.");
        }

        if (!Enum.IsDefined(recommendedAction))
        {
            throw new ArgumentOutOfRangeException(
                nameof(recommendedAction),
                "The manual-recovery action is not defined.");
        }

        ObservedState = observedState;
        SourceObservation = sourceObservation;
        DestinationObservation = destinationObservation;
        Reason = reason;
        RecommendedAction = recommendedAction;
    }

    public OperationJournalState ObservedState { get; }

    public RecoveryPathObservation SourceObservation { get; }

    public RecoveryPathObservation DestinationObservation { get; }

    public OperationManualRecoveryReason Reason { get; }

    public OperationManualRecoveryAction RecommendedAction { get; }
}
