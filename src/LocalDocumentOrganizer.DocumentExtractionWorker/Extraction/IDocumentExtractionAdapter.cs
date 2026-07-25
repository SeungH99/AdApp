using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Source;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public interface IDocumentExtractionAdapter
{
    bool CanHandle(DocumentSourceDescriptor source);

    Task<DocumentExtractionResponse> ExtractAsync(
        InheritedSourceDocument source,
        DocumentExtractionRequest request,
        CancellationToken cancellationToken);
}
