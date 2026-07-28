using System.Collections.Immutable;
using System.Runtime.InteropServices;
using LocalDocumentOrganizer.Application.Products;

namespace LocalDocumentOrganizer.Application.Intake;

public enum DocumentIntakeOrigin
{
    Picker = 0,
    Drop = 1,
}

public enum DocumentIntakeOutcome
{
    Imported = 0,
    AlreadyImported = 1,
    Rejected = 2,
    RetryRequired = 3,
    ManualRecoveryRequired = 4,
}

public enum DocumentIntakeFailureCode
{
    None = 0,
    UnsupportedExtension = 1,
    ContainerMagicMismatch = 2,
    InputTooLarge = 3,
    PdfPageLimitExceeded = 4,
    RasterDimensionLimitExceeded = 5,
    DecodedPixelLimitExceeded = 6,
    SourceLocked = 7,
    SourceChanged = 8,
    SourceReplaced = 9,
    UnsupportedReparsePoint = 10,
    MultipleHardLinks = 11,
    NonRegularFile = 12,
    SourceAccessDenied = 13,
    InvalidDisplayName = 14,
    StorageUnavailable = 15,
    ProductCommitConflict = 16,
    RecoveryEvidenceInvalid = 17,
}

public sealed record DocumentIntakeRequest
{
    public DocumentIntakeRequest(
        string sourcePath,
        DocumentIntakeOrigin origin)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        if (!Enum.IsDefined(origin))
        {
            throw new ArgumentOutOfRangeException(nameof(origin));
        }

        SourcePath = sourcePath;
        Origin = origin;
    }

    public string SourcePath { get; }

    public DocumentIntakeOrigin Origin { get; }
}

public sealed record DocumentIntakeResult
{
    private DocumentIntakeResult(
        DocumentIntakeOutcome outcome,
        InboxId? inboxId,
        DocumentIntakeFailureCode failureCode)
    {
        Outcome = outcome;
        InboxId = inboxId;
        FailureCode = failureCode;
    }

    public DocumentIntakeOutcome Outcome { get; }

    public InboxId? InboxId { get; }

    public DocumentIntakeFailureCode FailureCode { get; }

    public static DocumentIntakeResult Imported(InboxId inboxId) =>
        new(DocumentIntakeOutcome.Imported, inboxId, DocumentIntakeFailureCode.None);

    public static DocumentIntakeResult AlreadyImported(InboxId inboxId) =>
        new(
            DocumentIntakeOutcome.AlreadyImported,
            inboxId,
            DocumentIntakeFailureCode.None);

    public static DocumentIntakeResult Rejected(
        DocumentIntakeFailureCode failureCode) =>
        Failure(DocumentIntakeOutcome.Rejected, failureCode);

    public static DocumentIntakeResult RetryRequired(
        DocumentIntakeFailureCode failureCode) =>
        Failure(DocumentIntakeOutcome.RetryRequired, failureCode);

    public static DocumentIntakeResult ManualRecoveryRequired(
        DocumentIntakeFailureCode failureCode) =>
        Failure(DocumentIntakeOutcome.ManualRecoveryRequired, failureCode);

    private static DocumentIntakeResult Failure(
        DocumentIntakeOutcome outcome,
        DocumentIntakeFailureCode failureCode)
    {
        if (failureCode == DocumentIntakeFailureCode.None
            || !Enum.IsDefined(failureCode))
        {
            throw new ArgumentOutOfRangeException(nameof(failureCode));
        }

        return new DocumentIntakeResult(outcome, inboxId: null, failureCode);
    }
}

public sealed record DocumentIntakeReceipt(
    Guid SubmissionId,
    Task<DocumentIntakeResult> Completion);

public sealed record DocumentIntakeQueueState(
    int Capacity,
    int QueuedCount,
    int ActiveCount,
    long AcceptedCount,
    long CompletedCount);

public interface IDocumentIntakeProcessor
{
    Task<DocumentIntakeResult> ProcessAsync(
        DocumentIntakeRequest request,
        CancellationToken cancellationToken);
}

public interface IDocumentIntakeQueueReader
{
    DocumentIntakeQueueState GetQueueState();
}

public interface IDocumentIntakeService : IDocumentIntakeQueueReader
{
    ValueTask<DocumentIntakeReceipt> EnqueuePickerAsync(
        string sourcePath,
        CancellationToken cancellationToken);

    ValueTask<DocumentIntakeReceipt> EnqueueDropAsync(
        string sourcePath,
        CancellationToken cancellationToken);
}

public interface IDocumentIntakeRecovery
{
    Task RecoverPendingAsync(CancellationToken cancellationToken);
}

public enum DocumentAdmissionInspectionOutcome
{
    Inspected = 1,
    ContentUnreadable = 2,
    SourceChanged = 3,
    Unavailable = 4,
}

public sealed record DocumentAdmissionInspectionResult
{
    private DocumentAdmissionInspectionResult(
        DocumentAdmissionInspectionOutcome outcome,
        int pdfPageCount)
    {
        Outcome = outcome;
        PdfPageCount = pdfPageCount;
    }

    public DocumentAdmissionInspectionOutcome Outcome { get; }

    public int PdfPageCount { get; }

    public static DocumentAdmissionInspectionResult Inspected(
        int pdfPageCount)
    {
        if (pdfPageCount <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pdfPageCount));
        }

        return new(
            DocumentAdmissionInspectionOutcome.Inspected,
            pdfPageCount);
    }

    public static DocumentAdmissionInspectionResult ContentUnreadable() =>
        new(DocumentAdmissionInspectionOutcome.ContentUnreadable, 0);

    public static DocumentAdmissionInspectionResult SourceChanged() =>
        new(DocumentAdmissionInspectionOutcome.SourceChanged, 0);

    public static DocumentAdmissionInspectionResult Unavailable() =>
        new(DocumentAdmissionInspectionOutcome.Unavailable, 0);
}

public interface IDocumentAdmissionInspector
{
    Task<DocumentAdmissionInspectionResult> InspectPdfAsync(
        SafeHandle sourceHandle,
        long verifiedLength,
        ImmutableArray<byte> sha256,
        CancellationToken cancellationToken);
}
