using System.Collections.Immutable;

namespace LocalDocumentOrganizer.Core.Cases;

public readonly record struct CaseId(Guid Value);

public readonly record struct DocumentId(Guid Value);

public enum CaseStatus
{
    Open = 0,
    Closed = 1,
}

public abstract record CaseEvent(CaseId CaseId, DateTimeOffset OccurredAtUtc);

public sealed record CaseCreated(CaseId CaseId, DateTimeOffset OccurredAtUtc)
    : CaseEvent(CaseId, OccurredAtUtc);

public sealed record EvidenceLinked(
    CaseId CaseId,
    DocumentId DocumentId,
    DateTimeOffset OccurredAtUtc)
    : CaseEvent(CaseId, OccurredAtUtc);

public sealed record CaseState(
    CaseId Id,
    CaseStatus Status,
    ImmutableHashSet<DocumentId> LinkedDocuments,
    ImmutableArray<CaseEvent> Timeline);

public static class CaseProjector
{
    public static CaseState Replay(IEnumerable<CaseEvent> events)
    {
        var timeline = events.ToImmutableArray();
        var id = timeline.IsEmpty ? default : timeline[0].CaseId;
        var status = CaseStatus.Open;
        var linkedDocuments = ImmutableHashSet.CreateBuilder<DocumentId>();

        foreach (var @event in timeline)
        {
            switch (@event)
            {
                case EvidenceLinked evidenceLinked:
                    linkedDocuments.Add(evidenceLinked.DocumentId);
                    break;
                case CloseCase.CaseClosed:
                    status = CaseStatus.Closed;
                    break;
            }
        }

        return new CaseState(id, status, linkedDocuments.ToImmutable(), timeline);
    }
}
