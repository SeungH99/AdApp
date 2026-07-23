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
