using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Core.Events;

namespace LocalDocumentOrganizer.Application.Processing;

public sealed class DocumentProcessingService
{
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);
    private readonly IExtractionOutboxStore _outbox;
    private readonly IDocumentProcessingDispatcher _dispatcher;
    private readonly TimeProvider _clock;

    public DocumentProcessingService(
        IExtractionOutboxStore outbox,
        IDocumentProcessingDispatcher dispatcher,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(outbox);
        ArgumentNullException.ThrowIfNull(dispatcher);
        _outbox = outbox;
        _dispatcher = dispatcher;
        _clock = clock ?? TimeProvider.System;
    }

    public async Task<DocumentProcessingResult> ProcessNextAsync(
        CancellationToken cancellationToken)
    {
        var claim = await _outbox.ClaimNextAsync(
            Guid.NewGuid(),
            _clock.GetUtcNow(),
            LeaseDuration,
            cancellationToken).ConfigureAwait(false);
        if (claim is null)
        {
            return DocumentProcessingResult.NoWork();
        }

        var request = ToRequest(claim.Work);
        DocumentProcessingDispatchResult result;
        try
        {
            result = await _dispatcher.DispatchAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            result = DocumentProcessingDispatchResult.TransientFailure(
                DocumentProcessingFailureCode.WorkerUnavailable);
        }

        return result switch
        {
            DocumentProcessingDispatchResult.Successful success =>
                await CompleteSuccessAsync(claim, request, success, cancellationToken).ConfigureAwait(false),
            DocumentProcessingDispatchResult.Failed failure =>
                await CompleteFailureAsync(claim, failure.FailureCode, cancellationToken).ConfigureAwait(false),
            _ => await CompleteFailureAsync(
                claim,
                DocumentProcessingFailureCode.ResponseInvalid,
                cancellationToken).ConfigureAwait(false),
        };
    }

    public Task<ExplicitReprocessResult> RequestReprocessAsync(
        ExplicitReprocessCommand command,
        CancellationToken cancellationToken) =>
        _outbox.ScheduleReprocessAsync(command, cancellationToken);

    private async Task<DocumentProcessingResult> CompleteSuccessAsync(
        ExtractionOutboxClaim claim,
        DocumentProcessingRequest request,
        DocumentProcessingDispatchResult.Successful success,
        CancellationToken cancellationToken)
    {
        if (!IsBound(request, success.Binding)
            || string.IsNullOrWhiteSpace(success.AuthenticatedDraft)
            || success.AuthenticatedDraft.Length > DocumentExtractionLimits.MaxSerializedResponseBytes)
        {
            return await CompleteFailureAsync(
                claim,
                DocumentProcessingFailureCode.ResponseBindingInvalid,
                cancellationToken).ConfigureAwait(false);
        }

        var responseValidation = ValidateResponse(request, success.Response);
        if (responseValidation != DocumentProcessingFailureCode.None)
        {
            return await CompleteFailureAsync(claim, responseValidation, cancellationToken)
                .ConfigureAwait(false);
        }

        var commit = new CommitExtractionCommand(
            request.CommitOperationId,
            new EventId(request.CommitOperationId.Value),
            request.DocumentId,
            new StreamVersion(request.TargetRevision - 1),
            _clock.GetUtcNow(),
            success.AuthenticatedDraft,
            success.IsComplete
                ? ProductInboxStatus.ReadyForReview
                : ProductInboxStatus.NeedsReview,
            new ExtractionClaimBinding(
                claim.OwnerId,
                claim.Work.AttemptId.Value,
                claim.Work.TargetRevision,
                claim.Work.LeaseExpiresAtUtc ?? throw new InvalidOperationException()));
        await _outbox.CompleteAsync(
            new ExtractionOutboxCompletionCommand(
                claim,
                ExtractionOutboxState.Succeeded,
                claim.Work.AutomaticFailureCount,
                DocumentProcessingFailureCode.None,
                commit),
            cancellationToken).ConfigureAwait(false);
        return new DocumentProcessingResult(
            DocumentProcessingOutcome.Completed,
            DocumentProcessingFailureCode.None);
    }

    private async Task<DocumentProcessingResult> CompleteFailureAsync(
        ExtractionOutboxClaim claim,
        DocumentProcessingFailureCode failureCode,
        CancellationToken cancellationToken)
    {
        var transient = failureCode is DocumentProcessingFailureCode.WorkerUnavailable
            or DocumentProcessingFailureCode.WorkerTimedOut
            or DocumentProcessingFailureCode.StorageUnavailable;
        var retry = transient && claim.Work.AutomaticFailureCount == 0;
        await _outbox.CompleteAsync(
            new ExtractionOutboxCompletionCommand(
                claim,
                retry ? ExtractionOutboxState.RetryPending : ExtractionOutboxState.TerminalFailure,
                retry ? 1 : claim.Work.AutomaticFailureCount,
                failureCode,
                null),
            cancellationToken).ConfigureAwait(false);
        return new DocumentProcessingResult(
            retry ? DocumentProcessingOutcome.RetryScheduled : DocumentProcessingOutcome.TerminalFailure,
            failureCode);
    }

    private static DocumentProcessingRequest ToRequest(ExtractionOutboxWorkItem work) =>
        new(
            work.DocumentId,
            work.InboxId,
            work.AttemptId,
            work.TargetRevision,
            work.CommitOperationId,
            work.ContentSha256,
            work.RequestedLanguages,
            work.RequestedCapabilities);

    private static bool IsBound(
        DocumentProcessingRequest request,
        DocumentProcessingResponseBinding binding) =>
        binding.AttemptId == request.AttemptId.Value
        && binding.DocumentId == request.DocumentId
        && binding.ContentSha256.Equals(request.ContentSha256)
        && binding.SourceLength >= 0;

    private static DocumentProcessingFailureCode ValidateResponse(
        DocumentProcessingRequest request,
        DocumentExtractionResponse response)
    {
        if (response.JobId != request.AttemptId.Value)
        {
            return DocumentProcessingFailureCode.ResponseBindingInvalid;
        }

        if (response.ProtocolVersion != DocumentExtractionProtocol.CurrentVersion
            || !Enum.IsDefined(response.Outcome)
            || !Enum.IsDefined(response.FailureCode)
            || response.ElapsedMilliseconds < 0
            || response.Fragments.IsDefault
            || response.SourcePages.IsDefault)
        {
            return DocumentProcessingFailureCode.ResponseInvalid;
        }

        return DocumentProcessingFailureCode.None;
    }
}
