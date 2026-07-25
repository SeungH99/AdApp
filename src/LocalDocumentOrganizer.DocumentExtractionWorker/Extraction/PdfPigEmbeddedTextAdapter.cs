using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Source;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Exceptions;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public sealed class PdfPigEmbeddedTextAdapter : IDocumentExtractionAdapter
{
    internal const string AdapterIdentifier = "pdfpig-embedded-text";
    internal const string AdapterApiVersion = "1";
    internal const string DecoderApiVersion = "PdfPig/0.1.15";
    private const int MaximumAccumulatedTextBytes =
        DocumentExtractionLimits.MaxSerializedResponseBytes - (64 * 1024);
    private readonly WindowsNativePdfAdapter fallback;

    public PdfPigEmbeddedTextAdapter()
        : this(new WindowsNativePdfAdapter())
    {
    }

    internal PdfPigEmbeddedTextAdapter(WindowsNativePdfAdapter fallback)
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

        var stopwatch = Stopwatch.StartNew();
        var fragments = ImmutableArray.CreateBuilder<TextFragment>();
        var pages = ImmutableArray.CreateBuilder<DocumentSourcePage>();
        var missingPages = new HashSet<int>();
        var textBytes = 0;
        try
        {
            source.Content.Position = 0;
            using (var document = PdfDocument.Open(
                       source.Content,
                       new ParsingOptions { UseLenientParsing = false }))
            {
                DocumentMagicClassifier.ValidatePdfPageCount(
                    checked((uint)document.NumberOfPages));
                if (document.IsEncrypted)
                {
                    throw new EncryptedDocumentException(
                        "Password-protected PDFs are not supported.");
                }

                for (var pageNumber = 1;
                     pageNumber <= document.NumberOfPages;
                     pageNumber++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
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
                        cancellationToken.ThrowIfCancellationRequested();
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

                        textBytes = checked(
                            textBytes + Encoding.UTF8.GetByteCount(text));
                        if (textBytes > MaximumAccumulatedTextBytes)
                        {
                            throw new ResponseTooLargeAdapterException();
                        }

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
            }

            if (missingPages.Count > 0
                && (request.RequestedCapabilities & ExtractionCapability.Ocr) != 0)
            {
                var fallbackResponse = await fallback.ExtractPagesAsync(
                        source,
                        request,
                        missingPages,
                        cancellationToken)
                    .ConfigureAwait(false);
                var compositeDecoder =
                    $"{DecoderApiVersion}+{WindowsNativePdfAdapter.DecoderApiVersion}";
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
                    pages.ToImmutable(),
                    new ExtractionRuntimeMetadata(
                        AdapterIdentifier,
                        AdapterApiVersion,
                        compositeDecoder,
                        WindowsRasterOcrAdapter.OcrApiVersion),
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
                pages.ToImmutable(),
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
}
