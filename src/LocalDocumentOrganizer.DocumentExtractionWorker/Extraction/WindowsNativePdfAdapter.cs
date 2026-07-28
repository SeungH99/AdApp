using System.Collections.Immutable;
using System.Diagnostics;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Source;
using Windows.Data.Pdf;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;
using Windows.Storage.Streams;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public sealed class WindowsNativePdfAdapter :
    IDocumentExtractionAdapter,
    IDocumentInspectionAdapter
{
    internal const string AdapterIdentifier = "windows-native-pdf-ocr";
    internal const string AdapterApiVersion = "1";
    internal const string DecoderApiVersion =
        "windows-data-pdf-universal-api-contract-v1";
    private const double PointsPerDip = 72d / 96d;
    private const double RenderScale = 2d;
    private const int WrongPasswordHResult = unchecked((int)0x8007052B);

    public bool CanHandle(DocumentSourceDescriptor source) =>
        source is not null
        && source.ContainerKind == DocumentContainerKind.Pdf
        && source.DeclaredMimeType == "application/pdf";

    public bool CanInspect(DocumentSourceDescriptor source) =>
        CanHandle(source);

    public async Task<int> InspectPdfPageCountAsync(
        InheritedSourceDocument source,
        DocumentInspectionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        _ = DocumentMagicClassifier.Classify(
            source.Content,
            source.DeclaredMimeType,
            source.ContainerKind);
        var opened = await OpenPdfAsync(
                source,
                cancellationToken)
            .ConfigureAwait(false);
        using (opened.Stream)
        {
            return checked((int)opened.Document.PageCount);
        }
    }

    public Task<DocumentExtractionResponse> ExtractAsync(
        InheritedSourceDocument source,
        DocumentExtractionRequest request,
        CancellationToken cancellationToken) =>
        ExtractPagesAsync(
            source,
            request,
            pageIndexes: null,
            new ExtractionResponseBudget(),
            cancellationToken);

    public async Task<DocumentExtractionResponse> ExtractPagesAsync(
        InheritedSourceDocument source,
        DocumentExtractionRequest request,
        IReadOnlySet<int>? pageIndexes,
        ExtractionResponseBudget responseBudget,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(responseBudget);
        cancellationToken.ThrowIfCancellationRequested();
        if ((request.RequestedCapabilities & ExtractionCapability.Ocr) == 0)
        {
            throw new UnsupportedDocumentException(
                "The native PDF adapter requires the OCR capability.");
        }

        _ = DocumentMagicClassifier.Classify(
            source.Content,
            source.DeclaredMimeType,
            source.ContainerKind);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            var opened = await OpenPdfAsync(
                    source,
                    cancellationToken)
                .ConfigureAwait(false);
            using var randomAccess = opened.Stream;
            var document = opened.Document;
            DocumentMagicClassifier.ValidatePdfPageCount(document.PageCount);
            if (document.IsPasswordProtected)
            {
                throw new EncryptedDocumentException(
                    "Password-protected PDFs are not supported.");
            }

            var ocrEngine = WindowsExtractionSupport.CreateOcrEngine(
                request.RequestedLanguages);
            var fragments = ImmutableArray.CreateBuilder<TextFragment>();
            var pages = ImmutableArray.CreateBuilder<DocumentSourcePage>();
            for (uint pageIndex = 0; pageIndex < document.PageCount; pageIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var page = document.GetPage(pageIndex);
                var pdfWidth = page.Size.Width * PointsPerDip;
                var pdfHeight = page.Size.Height * PointsPerDip;
                pages.Add(
                    new DocumentSourcePage(
                        checked((int)pageIndex),
                        pdfWidth,
                        pdfHeight,
                        EvidenceCoordinateSystem.PdfPagePoints));
                if (pageIndexes is not null
                    && !pageIndexes.Contains(checked((int)pageIndex)))
                {
                    continue;
                }

                var renderWidth = Math.Max(
                    1u,
                    checked((uint)Math.Min(
                        OcrEngine.MaxImageDimension,
                        Math.Ceiling(page.Size.Width * RenderScale))));
                var renderHeight = Math.Max(
                    1u,
                    checked((uint)Math.Min(
                        OcrEngine.MaxImageDimension,
                        Math.Ceiling(page.Size.Height * RenderScale))));
                using var rendered = new InMemoryRandomAccessStream();
                var options = new PdfPageRenderOptions
                {
                    BitmapEncoderId = BitmapEncoder.PngEncoderId,
                    DestinationWidth = renderWidth,
                    DestinationHeight = renderHeight,
                    IsIgnoringHighContrast = true,
                };
                await page.RenderToStreamAsync(rendered, options)
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
                rendered.Seek(0);
                var decoder = await BitmapDecoder.CreateAsync(rendered)
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
                using var bitmap = await decoder.GetSoftwareBitmapAsync(
                        BitmapPixelFormat.Bgra8,
                        BitmapAlphaMode.Premultiplied)
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
                var result = await ocrEngine.RecognizeAsync(bitmap)
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
                fragments.AddRange(
                    WindowsExtractionSupport.CreateOcrFragments(
                        result,
                        checked((int)pageIndex),
                        EvidenceCoordinateSystem.PdfPagePoints,
                        pdfWidth,
                        pdfHeight,
                        new OrientationTransform(1, 0, 0, 1, 0, 0),
                        DecoderApiVersion,
                        WindowsRasterOcrAdapter.OcrApiVersion,
                        rectangle =>
                            EvidenceCoordinateMapper.MapPdfRenderRectangle(
                                rectangle,
                                decoder.OrientedPixelWidth,
                                decoder.OrientedPixelHeight,
                                pdfWidth,
                                pdfHeight),
                        responseBudget));
            }

            if (fragments.Count == 0)
            {
                throw new UnsupportedDocumentException(
                    "The PDF contains no usable OCR text.");
            }

            return new DocumentExtractionResponse(
                DocumentExtractionProtocol.CurrentVersion,
                request.JobId,
                DocumentExtractionOutcome.Success,
                fragments.ToImmutable(),
                pages.ToImmutable(),
                new ExtractionRuntimeMetadata(
                    AdapterIdentifier,
                    AdapterApiVersion,
                    DecoderApiVersion,
                    WindowsRasterOcrAdapter.OcrApiVersion),
                stopwatch.ElapsedMilliseconds,
                DocumentExtractionFailureCode.None);
        }
        catch (DocumentExtractionAdapterException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception.HResult == WrongPasswordHResult)
        {
            throw new EncryptedDocumentException(
                "Password-protected PDFs are not supported.",
                exception);
        }
        catch (Exception exception)
        {
            throw new DecoderFailureException(
                "Windows PDF rendering or OCR failed.",
                exception);
        }
    }

    private static async Task<OpenedPdf> OpenPdfAsync(
        InheritedSourceDocument source,
        CancellationToken cancellationToken)
    {
        var randomAccess = await WindowsExtractionSupport
            .CopyToRandomAccessStreamAsync(
                source.Content,
                source.VerifiedLength,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            PdfDocument document;
            try
            {
                document = await PdfDocument
                    .LoadFromStreamAsync(randomAccess)
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (
                exception.HResult == WrongPasswordHResult)
            {
                throw new EncryptedDocumentException(
                    "Password-protected PDFs are not supported.",
                    exception);
            }
            catch (Exception exception)
            {
                throw new CorruptDocumentException(
                    "Windows could not parse the PDF document.",
                    exception);
            }

            return new OpenedPdf(randomAccess, document);
        }
        catch
        {
            randomAccess.Dispose();
            throw;
        }
    }

    private sealed record OpenedPdf(
        InMemoryRandomAccessStream Stream,
        PdfDocument Document);
}
