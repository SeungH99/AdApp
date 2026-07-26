using System.Diagnostics;
using LocalDocumentOrganizer.Core.Documents;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;

public enum DocumentMagicKind
{
    Pdf = 1,
    Jpeg = 2,
    Png = 3,
    Tiff = 4,
    Bmp = 5,
}

public readonly record struct DocumentMagicClassification(
    DocumentMagicKind Kind,
    string MimeType);

public static class DocumentMagicClassifier
{
    private const int MaximumMagicPrefixBytes = 64;
    private static ReadOnlySpan<byte> JpegMagic => [0xff, 0xd8, 0xff];
    private static ReadOnlySpan<byte> PngMagic =>
        [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    private static ReadOnlySpan<byte> LittleEndianTiffMagic =>
        [0x49, 0x49, 0x2a, 0x00];
    private static ReadOnlySpan<byte> BigEndianTiffMagic =>
        [0x4d, 0x4d, 0x00, 0x2a];
    private static ReadOnlySpan<byte> ZipMagic => [0x50, 0x4b, 0x03, 0x04];

    public static DocumentMagicClassification Classify(
        Stream source,
        string declaredMimeType,
        DocumentContainerKind declaredContainer)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(declaredMimeType);
        if (!source.CanRead || !source.CanSeek)
        {
            throw new CorruptDocumentException("The document stream must be seekable.");
        }

        var originalPosition = source.Position;
        Span<byte> prefix = stackalloc byte[MaximumMagicPrefixBytes];
        var length = 0;
        try
        {
            source.Position = 0;
            while (length < prefix.Length)
            {
                var read = source.Read(prefix[length..]);
                if (read == 0)
                {
                    break;
                }

                length += read;
            }
        }
        finally
        {
            source.Position = originalPosition;
        }

        var bytes = prefix[..length];
        var kind = ClassifyMagic(bytes);
        var expected = kind switch
        {
            DocumentMagicKind.Pdf =>
                ("application/pdf", DocumentContainerKind.Pdf),
            DocumentMagicKind.Jpeg =>
                ("image/jpeg", DocumentContainerKind.RasterImage),
            DocumentMagicKind.Png =>
                ("image/png", DocumentContainerKind.RasterImage),
            DocumentMagicKind.Tiff =>
                ("image/tiff", DocumentContainerKind.RasterImage),
            DocumentMagicKind.Bmp =>
                ("image/bmp", DocumentContainerKind.RasterImage),
            _ => throw new UnreachableException(),
        };

        if (!string.Equals(
                declaredMimeType,
                expected.Item1,
                StringComparison.Ordinal)
            || declaredContainer != expected.Item2)
        {
            throw new CorruptDocumentException(
                "The declared MIME type or container does not match the document header.");
        }

        if (ContainsConflictingMagic(bytes, kind))
        {
            throw new CorruptDocumentException(
                "The document prefix contains conflicting container signatures.");
        }

        return new DocumentMagicClassification(kind, expected.Item1);
    }

    public static void ValidatePdfPageCount(uint pageCount)
    {
        if (pageCount == 0)
        {
            throw new CorruptDocumentException("The PDF contains no pages.");
        }

        if (pageCount > DocumentExtractionLimits.MaxPdfPages)
        {
            throw new UnsupportedDocumentException(
                "The PDF exceeds the supported page count.");
        }
    }

    public static void ValidateRasterMetadata(
        uint orientedWidth,
        uint orientedHeight,
        uint frameCount,
        uint ocrMaximumDimension)
    {
        if (orientedWidth == 0 || orientedHeight == 0 || frameCount == 0)
        {
            throw new CorruptDocumentException(
                "The raster metadata contains an empty dimension or frame set.");
        }

        if (frameCount != 1)
        {
            throw new UnsupportedDocumentException(
                "Multi-frame raster images are not supported.");
        }

        var maximumDimension = Math.Min(
            (uint)DocumentExtractionLimits.MaxRasterDimensionPixels,
            ocrMaximumDimension);
        if (orientedWidth > maximumDimension || orientedHeight > maximumDimension)
        {
            throw new UnsupportedDocumentException(
                "The raster dimensions exceed the supported OCR boundary.");
        }

        if ((ulong)orientedWidth * orientedHeight
            > (ulong)DocumentExtractionLimits.MaxDecodedPixels)
        {
            throw new UnsupportedDocumentException(
                "The decoded raster pixel count exceeds the supported boundary.");
        }
    }

    private static DocumentMagicKind ClassifyMagic(ReadOnlySpan<byte> bytes)
    {
        if (bytes.StartsWith("%PDF-"u8))
        {
            return DocumentMagicKind.Pdf;
        }

        if (bytes.StartsWith(JpegMagic))
        {
            return DocumentMagicKind.Jpeg;
        }

        if (bytes.StartsWith(PngMagic))
        {
            return DocumentMagicKind.Png;
        }

        if (bytes.StartsWith(LittleEndianTiffMagic)
            || bytes.StartsWith(BigEndianTiffMagic))
        {
            return DocumentMagicKind.Tiff;
        }

        if (bytes.StartsWith("BM"u8))
        {
            return DocumentMagicKind.Bmp;
        }

        throw new UnsupportedDocumentException(
            "The document signature is not allowlisted.");
    }

    private static bool ContainsConflictingMagic(
        ReadOnlySpan<byte> bytes,
        DocumentMagicKind primaryKind)
    {
        ReadOnlySpan<byte> remainder = bytes.Length > 1 ? bytes[1..] : [];
        if (remainder.IndexOf(ZipMagic) >= 0
            || remainder.IndexOf("GIF87a"u8) >= 0
            || remainder.IndexOf("GIF89a"u8) >= 0
            || remainder.IndexOf("WEBP"u8) >= 0)
        {
            return true;
        }

        return (primaryKind != DocumentMagicKind.Pdf
                && remainder.IndexOf("%PDF-"u8) >= 0)
            || (primaryKind != DocumentMagicKind.Png
                && remainder.IndexOf(PngMagic) >= 0)
            || (primaryKind != DocumentMagicKind.Jpeg
                && remainder.IndexOf(JpegMagic) >= 0);
    }
}
