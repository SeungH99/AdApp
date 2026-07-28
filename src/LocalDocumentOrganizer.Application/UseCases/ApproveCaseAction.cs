using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Cases.CloseCase;

namespace LocalDocumentOrganizer.Application.UseCases;

public static class ApproveCaseAction
{
    public static bool TryApprove(
        DateTimeOffset approvedAtUtc,
        out string? failure)
    {
        var caseId = new CaseId(
            Guid.Parse("20CDA91C-D41E-4F19-A6DB-4B35A24F9968"));
        var proofDocumentId = new DocumentId(
            Guid.Parse("2C8B4E54-E38A-4269-A8C3-34EFD790AF2E"));
        var state = new CaseState(
            caseId,
            CaseStatus.Open,
            [proofDocumentId],
            []);
        var decision = CloseCaseDecider.Decide(
            state,
            new CloseCaseCommand(
                caseId,
                proofDocumentId,
                null,
                new ExplicitApproval(approvedAtUtc)));

        failure = decision.Failure?.ToString();
        return decision.IsAccepted;
    }
}
