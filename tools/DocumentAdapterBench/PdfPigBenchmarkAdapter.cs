using System.Collections.Immutable;
using System.Diagnostics;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;
using LocalDocumentOrganizer.DocumentExtractionWorker.Source;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Exceptions;

namespace LocalDocumentOrganizer.DocumentAdapterBench;

public sealed class PdfPigBenchmarkAdapter : IDocumentExtractionAdapter
{
    internal const string AdapterIdentifier = "pdfpig-embedded-text";
    internal const string AdapterApiVersion = "1";
    internal const string DecoderApiVersion = "PdfPig/0.1.15";
    private readonly WindowsNativePdfAdapter fallback;

    public PdfPigBenchmarkAdapter()
        : this(new WindowsNativePdfAdapter())
    {
    }

    internal PdfPigBenchmarkAdapter(WindowsNativePdfAdapter fallback)
    {
        this.fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
    }

    public bool CanHandle(DocumentSourceDescriptor source) =>
        source is not null
        && source.ContainerKind == DocumentContainerKind.Pdf
        && source.DeclaredMimeType == "application/pdf";

    public async Task<DocumentExtractionResponse> ExtractAsync(
        InheritedSourceDocument source,
        DocumentExtractionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        _ = DocumentMagicClassifier.Classify(
            source.Content,
            source.DeclaredMimeType,
            source.ContainerKind);
        if ((request.RequestedCapabilities & ExtractionCapability.EmbeddedText) == 0)
        {
            return await fallback.ExtractPagesAsync(
                    source,
                    request,
                    pageIndexes: null,
                    new ExtractionResponseBudget(),
                    cancellationToken)
                .ConfigureAwait(false);
        }

        var stopwatch = Stopwatch.StartNew();
        var responseBudget = new ExtractionResponseBudget();
        try
        {
            source.Content.Position = 0;
            var parsed = ParseDocument(source.Content, responseBudget);
            var fragments = parsed.Fragments.ToBuilder();
            if (parsed.MissingPages.Count > 0
                && (request.RequestedCapabilities & ExtractionCapability.Ocr) != 0)
            {
                var fallbackResponse = await fallback.ExtractPagesAsync(
                        source,
                        request,
                        parsed.MissingPages,
                        responseBudget,
                        cancellationToken)
                    .ConfigureAwait(false);
                var compositeDecoder =
                    $"{DecoderApiVersion}+"
                    + fallbackResponse.RuntimeMetadata.DecoderVersion;
                for (var index = 0; index < fragments.Count; index++)
                {
                    fragments[index] = fragments[index] with
                    {
                        DecoderVersion = compositeDecoder,
                    };
                }

                fragments.AddRange(
                    fallbackResponse.Fragments.Select(
                        fragment => fragment with
                        {
                            DecoderVersion = compositeDecoder,
                        }));
                if (fragments.Count == 0)
                {
                    throw new UnsupportedDocumentException(
                        "The PDF contains no usable embedded or OCR text.");
                }

                return new DocumentExtractionResponse(
                    DocumentExtractionProtocol.CurrentVersion,
                    request.JobId,
                    DocumentExtractionOutcome.Success,
                    fragments.ToImmutable(),
                    parsed.Pages,
                    new ExtractionRuntimeMetadata(
                        AdapterIdentifier,
                        AdapterApiVersion,
                        compositeDecoder,
                        fallbackResponse.RuntimeMetadata.OcrVersion),
                    stopwatch.ElapsedMilliseconds,
                    DocumentExtractionFailureCode.None);
            }

            if (fragments.Count == 0)
            {
                throw new UnsupportedDocumentException(
                    "The PDF contains no usable embedded text and OCR is off.");
            }

            return new DocumentExtractionResponse(
                DocumentExtractionProtocol.CurrentVersion,
                request.JobId,
                DocumentExtractionOutcome.Success,
                fragments.ToImmutable(),
                parsed.Pages,
                new ExtractionRuntimeMetadata(
                    AdapterIdentifier,
                    AdapterApiVersion,
                    DecoderApiVersion,
                    null),
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
        catch (PdfDocumentEncryptedException exception)
        {
            throw new EncryptedDocumentException(
                "Password-protected PDFs are not supported.",
                exception);
        }
        catch (Exception exception)
        {
            throw new CorruptDocumentException(
                "PdfPig could not parse the PDF document.",
                exception);
        }
        finally
        {
            source.Content.Position = 0;
        }
    }

    private static ParsedPdf ParseDocument(
        Stream content,
        ExtractionResponseBudget responseBudget)
    {
        using var document = PdfDocument.Open(
            content,
            new ParsingOptions { UseLenientParsing = false });
        DocumentMagicClassifier.ValidatePdfPageCount(
            checked((uint)document.NumberOfPages));
        if (document.IsEncrypted)
        {
            throw new EncryptedDocumentException(
                "Password-protected PDFs are not supported.");
        }

        var fragments = ImmutableArray.CreateBuilder<TextFragment>();
        var pages = ImmutableArray.CreateBuilder<DocumentSourcePage>();
        var missingPages = new HashSet<int>();
        for (var pageNumber = 1;
             pageNumber <= document.NumberOfPages;
             pageNumber++)
        {
            var page = document.GetPage(pageNumber);
            var sourceIndex = pageNumber - 1;
            pages.Add(
                new DocumentSourcePage(
                    sourceIndex,
                    page.Width,
                    page.Height,
                    EvidenceCoordinateSystem.PdfPagePoints));
            var pageFragmentStart = fragments.Count;
            foreach (var word in page.GetWords())
            {
                var text = word.Text?.Trim();
                if (string.IsNullOrWhiteSpace(text))
                {
                    continue;
                }

                var bounds = word.BoundingBox;
                var left = new[]
                {
                    bounds.BottomLeft.X,
                    bounds.TopLeft.X,
                    bounds.BottomRight.X,
                    bounds.TopRight.X,
                }.Min();
                var bottom = new[]
                {
                    bounds.BottomLeft.Y,
                    bounds.TopLeft.Y,
                    bounds.BottomRight.Y,
                    bounds.TopRight.Y,
                }.Min();
                var right = new[]
                {
                    bounds.BottomLeft.X,
                    bounds.TopLeft.X,
                    bounds.BottomRight.X,
                    bounds.TopRight.X,
                }.Max();
                var top = new[]
                {
                    bounds.BottomLeft.Y,
                    bounds.TopLeft.Y,
                    bounds.BottomRight.Y,
                    bounds.TopRight.Y,
                }.Max();
                if (right <= left || top <= bottom)
                {
                    continue;
                }

                responseBudget.AddText(text);
                fragments.Add(
                    new TextFragment(
                        text,
                        sourceIndex,
                        EvidenceCoordinateSystem.PdfPagePoints,
                        new EvidenceRectangle(
                            left,
                            bottom,
                            right - left,
                            top - bottom),
                        new OrientationTransform(1, 0, 0, 1, 0, 0),
                        ExtractionCapability.EmbeddedText,
                        DecoderApiVersion,
                        null));
            }

            if (fragments.Count == pageFragmentStart)
            {
                missingPages.Add(sourceIndex);
            }
        }

        return new ParsedPdf(
            fragments.ToImmutable(),
            pages.ToImmutable(),
            missingPages);
    }

    private sealed record ParsedPdf(
        ImmutableArray<TextFragment> Fragments,
        ImmutableArray<DocumentSourcePage> Pages,
        IReadOnlySet<int> MissingPages);
}
