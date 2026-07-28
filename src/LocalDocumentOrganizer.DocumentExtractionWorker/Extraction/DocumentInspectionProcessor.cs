using System.Collections.Immutable;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Source;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public sealed class DocumentInspectionProcessor
{
    private readonly ImmutableArray<IDocumentInspectionAdapter> _adapters;

    public DocumentInspectionProcessor(
        IEnumerable<IDocumentExtractionAdapter> adapters)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        _adapters =
        [
            .. adapters.OfType<IDocumentInspectionAdapter>(),
        ];
    }

    public async Task<DocumentInspectionResponse> ProcessAsync(
        DocumentInspectionRequest request,
        CancellationToken cancellationToken,
        CancellationToken callerCancellationToken,
        CancellationToken deadlineCancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var validation =
            DocumentInspectionValidator.ValidateRequest(request);
        if (!validation.IsValid)
        {
            return Failure(request, validation.FailureCode);
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var adapter = _adapters.FirstOrDefault(
                candidate => candidate.CanInspect(request.Source));
            if (adapter is null)
            {
                return Failure(
                    request,
                    DocumentExtractionFailureCode.NoAdapterAvailable);
            }

            await using var source =
                await InheritedSourceDocument.OpenAndVerifyAsync(
                        request.Source,
                        cancellationToken)
                    .ConfigureAwait(false);
            var pageCount = await adapter.InspectPdfPageCountAsync(
                    source,
                    request,
                    cancellationToken)
                .ConfigureAwait(false);
            if (pageCount <= 0)
            {
                return Failure(
                    request,
                    DocumentExtractionFailureCode.CorruptDocument);
            }

            return new DocumentInspectionResponse(
                DocumentExtractionProtocol.CurrentVersion,
                request.RequestId,
                Binding(request),
                DocumentInspectionOutcome.Success,
                pageCount,
                DocumentExtractionFailureCode.None);
        }
        catch (Exception exception)
        {
            return Failure(
                request,
                ExtractionFailureMapper.Map(
                    exception,
                    cancellationToken,
                    callerCancellationToken,
                    deadlineCancellationToken));
        }
    }

    internal static DocumentInspectionResponse Failure(
        DocumentInspectionRequest request,
        DocumentExtractionFailureCode failureCode) =>
        new(
            DocumentExtractionProtocol.CurrentVersion,
            request.RequestId,
            Binding(request),
            DocumentInspectionOutcome.Failure,
            PdfPageCount: 0,
            failureCode);

    private static DocumentSourceBinding Binding(
        DocumentInspectionRequest request) =>
        new(
            request.Source?.DeclaredLength ?? -1,
            request.Source?.Sha256 ?? ImmutableArray<byte>.Empty);
}
