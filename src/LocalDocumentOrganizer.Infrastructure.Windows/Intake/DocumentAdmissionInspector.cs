using System.Buffers.Binary;
using System.Collections.Immutable;
using LocalDocumentOrganizer.Application.Intake;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Intake;

internal enum AdmittedContainer
{
    Pdf,
    Jpeg,
    Png,
    Tiff,
}

internal sealed record DocumentAdmission(
    AdmittedContainer Container,
    string CanonicalExtension);

internal static class DocumentAdmissionInspector
{
    internal static async Task<(DocumentAdmission? Admission, DocumentIntakeFailureCode Failure)>
        InspectAsync(
            VerifiedStableSource source,
            string extension,
            byte[] sha256,
            IDocumentAdmissionInspector admissionInspector,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentNullException.ThrowIfNull(admissionInspector);
        if (!TryExpectedContainer(extension, out var expected))
        {
            return (null, DocumentIntakeFailureCode.UnsupportedExtension);
        }

        if (source.Length > DocumentExtractionLimits.MaxEncodedInputBytes)
        {
            return (null, DocumentIntakeFailureCode.InputTooLarge);
        }

        var bytes = new byte[checked((int)source.Length)];
        try
        {
            long offset = 0;
            while (offset < source.Length)
            {
                var read = await RandomAccess.ReadAsync(
                        source.Handle,
                        bytes.AsMemory(
                            checked((int)offset),
                            checked((int)(source.Length - offset))),
                        offset,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    throw new FileSystemBoundaryException(
                        "The stable source changed while it was inspected.");
                }

                offset += read;
            }

            source.Revalidate();
            if (!TryMagic(bytes, out var actual)
                || actual != expected)
            {
                return (null, DocumentIntakeFailureCode.ContainerMagicMismatch);
            }

            if (actual == AdmittedContainer.Pdf)
            {
                var inspection =
                    await admissionInspector.InspectPdfAsync(
                            source.Handle,
                            source.Length,
                            ImmutableArray.Create(sha256),
                            cancellationToken)
                        .ConfigureAwait(false);
                if (inspection.Outcome
                        == DocumentAdmissionInspectionOutcome.Inspected
                    && inspection.PdfPageCount
                        > DocumentExtractionLimits.MaxPdfPages)
                {
                    return (null, DocumentIntakeFailureCode.PdfPageLimitExceeded);
                }

                if (inspection.Outcome
                    == DocumentAdmissionInspectionOutcome.SourceChanged)
                {
                    return (
                        null,
                        DocumentIntakeFailureCode.SourceChanged);
                }

                if (inspection.Outcome
                    == DocumentAdmissionInspectionOutcome.Unavailable)
                {
                    return (
                        null,
                        DocumentIntakeFailureCode.StorageUnavailable);
                }
            }
            else if (TryReadRasterDimensions(
                         actual,
                         bytes,
                         out var width,
                         out var height,
                         out var decodedPixels))
            {
                if (width > DocumentExtractionLimits.MaxRasterDimensionPixels
                    || height > DocumentExtractionLimits.MaxRasterDimensionPixels)
                {
                    return (
                        null,
                        DocumentIntakeFailureCode.RasterDimensionLimitExceeded);
                }

                if (decodedPixels
                    > DocumentExtractionLimits.MaxDecodedPixels)
                {
                    return (
                        null,
                        DocumentIntakeFailureCode.DecodedPixelLimitExceeded);
                }
            }

            return (
                new DocumentAdmission(actual, CanonicalExtension(actual)),
                DocumentIntakeFailureCode.None);
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    private static bool TryExpectedContainer(
        string extension,
        out AdmittedContainer container)
    {
        container = extension.ToLowerInvariant() switch
        {
            ".pdf" => AdmittedContainer.Pdf,
            ".jpg" or ".jpeg" => AdmittedContainer.Jpeg,
            ".png" => AdmittedContainer.Png,
            ".tif" or ".tiff" => AdmittedContainer.Tiff,
            _ => default,
        };
        return extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".jpg", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".jpeg", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".png", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".tif", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".tiff", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryMagic(
        ReadOnlySpan<byte> bytes,
        out AdmittedContainer container)
    {
        if (bytes.StartsWith("%PDF-"u8))
        {
            container = AdmittedContainer.Pdf;
            return true;
        }

        if (bytes.Length >= 3
            && bytes[0] == 0xff
            && bytes[1] == 0xd8
            && bytes[2] == 0xff)
        {
            container = AdmittedContainer.Jpeg;
            return true;
        }

        if (bytes.StartsWith(
                new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
        {
            container = AdmittedContainer.Png;
            return true;
        }

        if (bytes.StartsWith("II*\0"u8)
            || bytes.StartsWith("MM\0*"u8))
        {
            container = AdmittedContainer.Tiff;
            return true;
        }

        container = default;
        return false;
    }

    private static bool TryReadRasterDimensions(
        AdmittedContainer container,
        ReadOnlySpan<byte> bytes,
        out long width,
        out long height,
        out long decodedPixels) =>
        container switch
        {
            AdmittedContainer.Png => TryReadPng(
                bytes,
                out width,
                out height,
                out decodedPixels),
            AdmittedContainer.Jpeg => TryReadJpeg(
                bytes,
                out width,
                out height,
                out decodedPixels),
            AdmittedContainer.Tiff => TryReadTiff(
                bytes,
                out width,
                out height,
                out decodedPixels),
            _ => SetMissing(
                out width,
                out height,
                out decodedPixels),
        };

    private static bool TryReadPng(
        ReadOnlySpan<byte> bytes,
        out long width,
        out long height,
        out long decodedPixels)
    {
        if (bytes.Length < 24
            || !bytes.Slice(12, 4).SequenceEqual("IHDR"u8))
        {
            return SetMissing(
                out width,
                out height,
                out decodedPixels);
        }

        width = BinaryPrimitives.ReadUInt32BigEndian(bytes[16..]);
        height = BinaryPrimitives.ReadUInt32BigEndian(bytes[20..]);
        decodedPixels = SaturatingProduct(width, height);
        return width > 0 && height > 0;
    }

    private static bool TryReadJpeg(
        ReadOnlySpan<byte> bytes,
        out long width,
        out long height,
        out long decodedPixels)
    {
        var offset = 2;
        while (offset + 3 < bytes.Length)
        {
            if (bytes[offset] != 0xff)
            {
                offset++;
                continue;
            }

            while (offset < bytes.Length && bytes[offset] == 0xff)
            {
                offset++;
            }

            if (offset >= bytes.Length)
            {
                break;
            }

            var marker = bytes[offset++];
            if (marker is 0xd8 or 0xd9
                || marker is >= 0xd0 and <= 0xd7)
            {
                continue;
            }

            if (offset + 2 > bytes.Length)
            {
                break;
            }

            var segmentLength =
                BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]);
            if (segmentLength < 2
                || offset + segmentLength > bytes.Length)
            {
                break;
            }

            if (IsStartOfFrame(marker) && segmentLength >= 7)
            {
                height =
                    BinaryPrimitives.ReadUInt16BigEndian(bytes[(offset + 3)..]);
                width =
                    BinaryPrimitives.ReadUInt16BigEndian(bytes[(offset + 5)..]);
                decodedPixels = SaturatingProduct(width, height);
                return width > 0 && height > 0;
            }

            offset += segmentLength;
        }

        return SetMissing(
            out width,
            out height,
            out decodedPixels);
    }

    private static bool IsStartOfFrame(byte marker) =>
        marker is >= 0xc0 and <= 0xc3
            or >= 0xc5 and <= 0xc7
            or >= 0xc9 and <= 0xcb
            or >= 0xcd and <= 0xcf;

    private static bool TryReadTiff(
        ReadOnlySpan<byte> bytes,
        out long width,
        out long height,
        out long decodedPixels)
    {
        width = 0;
        height = 0;
        decodedPixels = 0;
        if (bytes.Length < 10)
        {
            return false;
        }

        var littleEndian = bytes[0] == (byte)'I';
        var ifdOffset = ReadUInt32(bytes[4..], littleEndian);
        if (ifdOffset > int.MaxValue
            || ifdOffset + 2 > (uint)bytes.Length)
        {
            return false;
        }

        var visited = new HashSet<uint>();
        while (ifdOffset != 0)
        {
            if (!visited.Add(ifdOffset)
                || visited.Count > 100_000
                || ifdOffset > int.MaxValue
                || ifdOffset + 2 > (uint)bytes.Length)
            {
                return false;
            }

            var cursor = checked((int)ifdOffset);
            var entries = ReadUInt16(bytes[cursor..], littleEndian);
            cursor += 2;
            long frameWidth = 0;
            long frameHeight = 0;
            for (var index = 0; index < entries; index++)
            {
                if (cursor + 12 > bytes.Length)
                {
                    return false;
                }

                var tag = ReadUInt16(bytes[cursor..], littleEndian);
                var type = ReadUInt16(bytes[(cursor + 2)..], littleEndian);
                var count = ReadUInt32(bytes[(cursor + 4)..], littleEndian);
                if (count == 1 && type is 3 or 4)
                {
                    var value = type == 3
                        ? ReadUInt16(
                            bytes[(cursor + 8)..],
                            littleEndian)
                        : ReadUInt32(
                            bytes[(cursor + 8)..],
                            littleEndian);
                    if (tag == 256)
                    {
                        frameWidth = value;
                    }
                    else if (tag == 257)
                    {
                        frameHeight = value;
                    }
                }

                cursor += 12;
            }

            if (frameWidth <= 0
                || frameHeight <= 0
                || cursor + 4 > bytes.Length)
            {
                return false;
            }

            width = Math.Max(width, frameWidth);
            height = Math.Max(height, frameHeight);
            var framePixels =
                SaturatingProduct(frameWidth, frameHeight);
            decodedPixels =
                decodedPixels > long.MaxValue - framePixels
                    ? long.MaxValue
                    : decodedPixels + framePixels;
            ifdOffset = ReadUInt32(bytes[cursor..], littleEndian);
        }

        return width > 0 && height > 0 && decodedPixels > 0;
    }

    private static ushort ReadUInt16(
        ReadOnlySpan<byte> bytes,
        bool littleEndian) =>
        littleEndian
            ? BinaryPrimitives.ReadUInt16LittleEndian(bytes)
            : BinaryPrimitives.ReadUInt16BigEndian(bytes);

    private static uint ReadUInt32(
        ReadOnlySpan<byte> bytes,
        bool littleEndian) =>
        littleEndian
            ? BinaryPrimitives.ReadUInt32LittleEndian(bytes)
            : BinaryPrimitives.ReadUInt32BigEndian(bytes);

    private static bool SetMissing(
        out long width,
        out long height,
        out long decodedPixels)
    {
        width = 0;
        height = 0;
        decodedPixels = 0;
        return false;
    }

    private static long SaturatingProduct(long left, long right) =>
        left <= 0 || right <= 0
            ? 0
            : left > long.MaxValue / right
                ? long.MaxValue
                : left * right;

    private static string CanonicalExtension(AdmittedContainer container) =>
        container switch
        {
            AdmittedContainer.Pdf => ".pdf",
            AdmittedContainer.Jpeg => ".jpg",
            AdmittedContainer.Png => ".png",
            AdmittedContainer.Tiff => ".tiff",
            _ => throw new ArgumentOutOfRangeException(nameof(container)),
        };
}
