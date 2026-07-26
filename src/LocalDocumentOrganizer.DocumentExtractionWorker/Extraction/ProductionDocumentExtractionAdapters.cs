using System.Collections.Immutable;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public static class ProductionDocumentExtractionAdapters
{
    public static ImmutableArray<IDocumentExtractionAdapter> Create() =>
        [
            new WindowsNativePdfAdapter(),
            new WindowsRasterOcrAdapter(),
        ];
}
