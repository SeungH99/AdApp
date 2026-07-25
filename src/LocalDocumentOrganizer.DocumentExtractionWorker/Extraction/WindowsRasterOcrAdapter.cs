using System.Collections.Immutable;
using System.Diagnostics;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Source;
using Windows.Globalization;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;
using Windows.Storage.Streams;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public sealed class WindowsRasterOcrAdapter : IDocumentExtractionAdapter
{
    internal const string AdapterIdentifier = "windows-raster-ocr";
    internal const string AdapterApiVersion = "1";
    internal const string OcrApiVersion =
        "Windows.Media.Ocr/UniversalApiContract-v1";

    public bool CanHandle(DocumentSourceDescriptor source) =>
        source is not null
        && source.ContainerKind == DocumentContainerKind.RasterImage
        && source.DeclaredMimeType is
            "image/jpeg" or "image/png" or "image/tiff" or "image/bmp";

    public async Task<DocumentExtractionResponse> ExtractAsync(
        InheritedSourceDocument source,
        DocumentExtractionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if ((request.RequestedCapabilities & ExtractionCapability.Ocr) == 0)
        {
            throw new UnsupportedDocumentException(
                "Raster extraction requires the OCR capability.");
        }

        _ = DocumentMagicClassifier.Classify(
            source.Content,
            source.DeclaredMimeType,
            source.ContainerKind);
        var stopwatch = Stopwatch.StartNew();

        try
        {
            using var randomAccess = await WindowsExtractionSupport
                .CopyToRandomAccessStreamAsync(
                    source.Content,
                    source.VerifiedLength,
                    cancellationToken)
                .ConfigureAwait(false);
            var decoder = await BitmapDecoder.CreateAsync(randomAccess)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
            var ocrEngine = WindowsExtractionSupport.CreateOcrEngine(
                request.RequestedLanguages);
            DocumentMagicClassifier.ValidateRasterMetadata(
                decoder.OrientedPixelWidth,
                decoder.OrientedPixelHeight,
                decoder.FrameCount,
                OcrEngine.MaxImageDimension);

            var orientation = await WindowsExtractionSupport
                .ReadOrientationTransformAsync(decoder, cancellationToken)
                .ConfigureAwait(false);
            using var bitmap = await decoder.GetSoftwareBitmapAsync(
                    BitmapPixelFormat.Bgra8,
                    BitmapAlphaMode.Premultiplied,
                    new BitmapTransform(),
                    ExifOrientationMode.RespectExifOrientation,
                    ColorManagementMode.ColorManageToSRgb)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
            var ocrResult = await ocrEngine.RecognizeAsync(bitmap)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
            var decoderVersion =
                $"Windows.Graphics.Imaging/{decoder.DecoderInformation.CodecId:D}";
            var fragments = WindowsExtractionSupport.CreateOcrFragments(
                ocrResult,
                0,
                EvidenceCoordinateSystem.OrientedRasterPixels,
                decoder.OrientedPixelWidth,
                decoder.OrientedPixelHeight,
                orientation,
                decoderVersion,
                OcrApiVersion,
                mapEvidence: null,
                new ExtractionResponseBudget());
            if (fragments.IsEmpty)
            {
                throw new UnsupportedDocumentException(
                    "The raster image contains no usable OCR text.");
            }

            return new DocumentExtractionResponse(
                DocumentExtractionProtocol.CurrentVersion,
                request.JobId,
                DocumentExtractionOutcome.Success,
                fragments,
                [
                    new DocumentSourcePage(
                        0,
                        decoder.OrientedPixelWidth,
                        decoder.OrientedPixelHeight,
                        EvidenceCoordinateSystem.OrientedRasterPixels),
                ],
                new ExtractionRuntimeMetadata(
                    AdapterIdentifier,
                    AdapterApiVersion,
                    decoderVersion,
                    OcrApiVersion),
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
        catch (Exception exception)
        {
            throw new DecoderFailureException(
                "Windows raster decoding or OCR failed.",
                exception);
        }
    }
}

internal static class WindowsExtractionSupport
{
    private const int CopyBufferBytes = 81_920;
    private const string JpegOrientationQuery = "/app1/ifd/{ushort=274}";
    private const string TiffOrientationQuery = "/ifd/{ushort=274}";

    public static async Task<InMemoryRandomAccessStream>
        CopyToRandomAccessStreamAsync(
            Stream source,
            long verifiedLength,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (verifiedLength < 0
            || verifiedLength > DocumentExtractionLimits.MaxEncodedInputBytes)
        {
            throw new UnsupportedDocumentException(
                "The encoded input exceeds the in-memory stream boundary.");
        }

        var originalPosition = source.Position;
        var randomAccess = new InMemoryRandomAccessStream();
        try
        {
            source.Position = 0;
            using var writer = new DataWriter(randomAccess);
            var buffer = new byte[CopyBufferBytes];
            var remaining = verifiedLength;
            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = (int)Math.Min(buffer.Length, remaining);
                var read = await source.ReadAsync(
                        buffer.AsMemory(0, count),
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    throw new CorruptDocumentException(
                        "The verified source ended during its bounded copy.");
                }

                writer.WriteBytes(buffer.AsSpan(0, read).ToArray());
                await writer.StoreAsync()
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
                remaining -= read;
            }

            await writer.FlushAsync()
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
            writer.DetachStream();
            randomAccess.Seek(0);
            return randomAccess;
        }
        catch
        {
            randomAccess.Dispose();
            throw;
        }
        finally
        {
            source.Position = originalPosition;
        }
    }

    public static OcrEngine CreateOcrEngine(
        ImmutableArray<string> requestedLanguages)
    {
        if (requestedLanguages.IsDefaultOrEmpty)
        {
            throw new UnsupportedLanguageException(
                "At least one OCR language is required.");
        }

        foreach (var languageTag in requestedLanguages)
        {
            try
            {
                var language = new Language(languageTag);
                if (!OcrEngine.IsLanguageSupported(language))
                {
                    continue;
                }

                var engine = OcrEngine.TryCreateFromLanguage(language);
                if (engine is not null)
                {
                    return engine;
                }
            }
            catch (Exception exception) when (
                exception is not OutOfMemoryException)
            {
                // Invalid or unavailable language profiles are tried in order.
            }
        }

        throw new UnsupportedLanguageException(
            "None of the requested OCR languages is installed.");
    }

    public static ImmutableArray<TextFragment> CreateOcrFragments(
        OcrResult result,
        int sourceIndex,
        EvidenceCoordinateSystem coordinateSystem,
        double outputWidth,
        double outputHeight,
        OrientationTransform orientation,
        string decoderVersion,
        string ocrVersion,
        Func<EvidenceRectangle, EvidenceRectangle>? mapEvidence,
        ExtractionResponseBudget responseBudget)
    {
        ArgumentNullException.ThrowIfNull(responseBudget);
        var fragments = ImmutableArray.CreateBuilder<TextFragment>();
        foreach (var line in result.Lines)
        {
            foreach (var word in line.Words)
            {
                var text = word.Text?.Trim();
                if (string.IsNullOrWhiteSpace(text))
                {
                    continue;
                }

                responseBudget.AddText(text);

                var bounds = word.BoundingRect;
                var evidence = new EvidenceRectangle(
                    bounds.X,
                    bounds.Y,
                    bounds.Width,
                    bounds.Height);
                evidence = mapEvidence is null
                    ? EvidenceCoordinateMapper.MapRectangle(
                        evidence,
                        new OrientationTransform(1, 0, 0, 1, 0, 0),
                        outputWidth,
                        outputHeight)
                    : mapEvidence(evidence);
                fragments.Add(
                    new TextFragment(
                        text,
                        sourceIndex,
                        coordinateSystem,
                        evidence,
                        orientation,
                        ExtractionCapability.Ocr,
                        decoderVersion,
                        ocrVersion));
            }
        }

        return fragments.ToImmutable();
    }

    public static async Task<OrientationTransform> ReadOrientationTransformAsync(
        BitmapDecoder decoder,
        CancellationToken cancellationToken)
    {
        ushort orientation = 1;
        foreach (var query in new[] { JpegOrientationQuery, TiffOrientationQuery })
        {
            try
            {
                var properties = await decoder.BitmapProperties
                    .GetPropertiesAsync([query])
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
                if (properties.TryGetValue(query, out var typed)
                    && typed.Value is ushort value)
                {
                    orientation = value;
                    break;
                }
            }
            catch (Exception exception) when (
                exception is not OperationCanceledException)
            {
                // Absence of optional EXIF orientation is normal.
            }
        }

        var width = (double)decoder.PixelWidth;
        var height = (double)decoder.PixelHeight;
        return orientation switch
        {
            1 => new OrientationTransform(1, 0, 0, 1, 0, 0),
            2 => new OrientationTransform(-1, 0, 0, 1, width, 0),
            3 => new OrientationTransform(-1, 0, 0, -1, width, height),
            4 => new OrientationTransform(1, 0, 0, -1, 0, height),
            5 => new OrientationTransform(0, 1, 1, 0, 0, 0),
            6 => new OrientationTransform(0, 1, -1, 0, height, 0),
            7 => new OrientationTransform(0, -1, -1, 0, height, width),
            8 => new OrientationTransform(0, -1, 1, 0, 0, width),
            _ => throw new CorruptDocumentException(
                "The raster EXIF orientation is invalid."),
        };
    }
}
