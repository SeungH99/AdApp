using System.Collections.Immutable;
using System.Diagnostics;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Source;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public sealed class DocumentExtractionProcessor
{
    private static readonly ExtractionRuntimeMetadata WorkerRuntimeMetadata =
        new("worker", "1", string.Empty, null);

    private readonly ImmutableArray<IDocumentExtractionAdapter> adapters;

    public DocumentExtractionProcessor(IEnumerable<IDocumentExtractionAdapter> adapters)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        this.adapters = [.. adapters];
        if (this.adapters.Any(static adapter => adapter is null))
        {
            throw new ArgumentException(
                "The adapter collection cannot contain null.",
                nameof(adapters));
        }
    }

    public Task<DocumentExtractionResponse> ProcessAsync(
        DocumentExtractionRequest request,
        CancellationToken cancellationToken) =>
        ProcessAsync(
            request,
            cancellationToken,
            cancellationToken,
            CancellationToken.None);

    internal async Task<DocumentExtractionResponse> ProcessAsync(
        DocumentExtractionRequest request,
        CancellationToken cancellationToken,
        CancellationToken callerCancellationToken,
        CancellationToken deadlineCancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var stopwatch = Stopwatch.StartNew();

        var requestValidation = DocumentExtractionValidator.ValidateRequest(request);
        if (!requestValidation.IsValid)
        {
            return Failure(request, requestValidation.FailureCode, stopwatch.ElapsedMilliseconds);
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            IDocumentExtractionAdapter? selectedAdapter = null;
            foreach (var adapter in adapters)
            {
                if (adapter.CanHandle(request.Source))
                {
                    selectedAdapter = adapter;
                    break;
                }
            }

            if (selectedAdapter is null)
            {
                return Failure(
                    request,
                    DocumentExtractionFailureCode.NoAdapterAvailable,
                    stopwatch.ElapsedMilliseconds);
            }

            await using var source = await InheritedSourceDocument.OpenAndVerifyAsync(
                    request.Source,
                    cancellationToken)
                .ConfigureAwait(false);
            var response = await selectedAdapter.ExtractAsync(
                    source,
                    request,
                    cancellationToken)
                .ConfigureAwait(false);

            if (response is null)
            {
                return Failure(
                    request,
                    DocumentExtractionFailureCode.InternalFailure,
                    stopwatch.ElapsedMilliseconds);
            }

            var responseValidation = DocumentExtractionValidator.ValidateResponse(
                request,
                response);
            if (!responseValidation.IsValid)
            {
                return Failure(
                    request,
                    responseValidation.FailureCode,
                    stopwatch.ElapsedMilliseconds);
            }

            return response;
        }
        catch (Exception exception)
        {
            return Failure(
                request,
                ExtractionFailureMapper.Map(
                    exception,
                    cancellationToken,
                    callerCancellationToken,
                    deadlineCancellationToken),
                stopwatch.ElapsedMilliseconds);
        }
    }

    private static DocumentExtractionResponse Failure(
        DocumentExtractionRequest request,
        DocumentExtractionFailureCode failureCode,
        long elapsedMilliseconds) =>
        new(
            DocumentExtractionProtocol.CurrentVersion,
            request.JobId,
            DocumentExtractionOutcome.Failure,
            [],
            [],
            WorkerRuntimeMetadata,
            elapsedMilliseconds,
            failureCode);
}
