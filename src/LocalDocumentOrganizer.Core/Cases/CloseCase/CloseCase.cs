namespace LocalDocumentOrganizer.Core.Cases.CloseCase;

public sealed record ExplicitApproval(DateTimeOffset ApprovedAtUtc);

public sealed record CloseCaseCommand(
    CaseId CaseId,
    DocumentId? ProofDocumentId,
    string? ManualReason,
    ExplicitApproval? Approval);

public enum CloseCaseFailureCode
{
    ApprovalRequired = 1,
    ClosureEvidenceRequired = 2,
    ProofDocumentNotLinked = 3,
    CaseAlreadyClosed = 4,
    CaseIdentityMismatch = 5,
}

public sealed record CaseClosed(
    CaseId CaseId,
    DocumentId? ProofDocumentId,
    string? ManualReason,
    DateTimeOffset OccurredAtUtc)
    : CaseEvent(CaseId, OccurredAtUtc);

public sealed record CloseCaseDecision(CaseClosed? Event, CloseCaseFailureCode? Failure)
{
    public bool IsAccepted => Event is not null && Failure is null;

    public static CloseCaseDecision Rejected(CloseCaseFailureCode failure) => new(null, failure);
}

public static class CloseCaseDecider
{
    public static CloseCaseDecision Decide(CaseState state, CloseCaseCommand command)
    {
        if (state.Id != command.CaseId)
        {
            return CloseCaseDecision.Rejected(CloseCaseFailureCode.CaseIdentityMismatch);
        }

        if (command.Approval is null)
        {
            return CloseCaseDecision.Rejected(CloseCaseFailureCode.ApprovalRequired);
        }

        if (state.Status is CaseStatus.Closed)
        {
            return CloseCaseDecision.Rejected(CloseCaseFailureCode.CaseAlreadyClosed);
        }

        var hasManualConfirmation = !string.IsNullOrWhiteSpace(command.ManualReason);
        if (command.ProofDocumentId is null && !hasManualConfirmation)
        {
            return CloseCaseDecision.Rejected(CloseCaseFailureCode.ClosureEvidenceRequired);
        }

        if (command.ProofDocumentId is { } proofDocumentId &&
            !state.LinkedDocuments.Contains(proofDocumentId))
        {
            return CloseCaseDecision.Rejected(CloseCaseFailureCode.ProofDocumentNotLinked);
        }

        return new CloseCaseDecision(
            new CaseClosed(
                command.CaseId,
                command.ProofDocumentId,
                command.ManualReason,
                command.Approval.ApprovedAtUtc),
            null);
    }
}
