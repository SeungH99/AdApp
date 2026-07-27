using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Ingestion;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using Microsoft.Win32.SafeHandles;
using Windows.Data.Pdf;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

namespace LocalDocumentOrganizer.CorpusWorkbench.Review;

public sealed record DocumentPreview(
    byte[] PngBytes,
    int PageCount);

public sealed class DocumentPreviewService
{
    private const string PdfRenderer =
        "windows-data-pdf-png-v1";
    private const string RasterRenderer =
        "windows-graphics-imaging-png-v1";
    private const string NormalizedOrientation =
        "upright-normalized-v1";
    private const string CacheDomain =
        "corpus-preview-cache-v1\n";
    private const int MaximumPageIndex = 255;
    private const uint MaximumDimension = 4096;
    private const ulong MaximumPixels = 16_777_216;
    private const int MaximumPngBytes = 16 * 1024 * 1024;
    private static readonly TimeSpan RenderBudget =
        TimeSpan.FromSeconds(15);
    private static readonly byte[] PngSignature =
        [137, 80, 78, 71, 13, 10, 26, 10];

    private readonly CorpusVault _vault;

    public DocumentPreviewService(CorpusVault vault) =>
        _vault = vault
        ?? throw new ArgumentNullException(nameof(vault));

    public async Task<DocumentPreview> RenderAsync(
        string documentId,
        int pageIndex,
        CancellationToken cancellationToken)
    {
        ValidateRequest(documentId, pageIndex);
        using var timeout = new CancellationTokenSource(RenderBudget);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeout.Token);
        try
        {
            var state = await _vault.Store.LoadLabelStateAsync(
                    documentId,
                    linked.Token)
                .ConfigureAwait(false);
            RequireDocumentIdentity(state.Document, documentId);
            var encoded = await ReadVerifiedObjectAsync(
                    state.Document,
                    linked.Token)
                .ConfigureAwait(false);
            try
            {
                var rendered = state.Document.InputKind switch
                {
                    CorpusIngestionService.ImagePdfInputKind =>
                        await RenderPdfAsync(
                                encoded,
                                pageIndex,
                                linked.Token)
                            .ConfigureAwait(false),
                    CorpusIngestionService.StandaloneRasterInputKind =>
                        await RenderRasterAsync(
                                encoded,
                                pageIndex,
                                linked.Token)
                            .ConfigureAwait(false),
                    _ => throw InvalidRequest(),
                };
                ValidatePng(rendered.PngBytes);
                var renderer = state.Document.InputKind
                    == CorpusIngestionService.ImagePdfInputKind
                        ? PdfRenderer
                        : RasterRenderer;
                var cacheKey = CreateCacheKey(
                    state.Document.ContentSha256,
                    pageIndex,
                    renderer,
                    NormalizedOrientation);
                await VerifyOrPopulateCacheAsync(
                        cacheKey,
                        rendered.PngBytes,
                        linked.Token)
                    .ConfigureAwait(false);
                return rendered;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (WorkbenchException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or CryptographicException
                or FileSystemBoundaryException
                or StableSourceBoundaryException
                or ArgumentException
                or OverflowException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }
        catch (OperationCanceledException)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.UnsupportedInput);
        }
        catch
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.UnsupportedInput);
        }
    }

    internal async Task<int> GetPageCountAsync(
        string documentId,
        CancellationToken cancellationToken)
    {
        ValidateRequest(documentId, 0);
        var state = await _vault.Store.LoadLabelStateAsync(
                documentId,
                cancellationToken)
            .ConfigureAwait(false);
        RequireDocumentIdentity(state.Document, documentId);
        var encoded = await ReadVerifiedObjectAsync(
                state.Document,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            using var randomAccess = await CopyToRandomAccessAsync(
                    encoded,
                    cancellationToken)
                .ConfigureAwait(false);
            if (state.Document.InputKind
                == CorpusIngestionService.ImagePdfInputKind)
            {
                var document = await PdfDocument
                    .LoadFromStreamAsync(randomAccess)
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
                return RequirePageCount(document.PageCount);
            }

            if (state.Document.InputKind
                != CorpusIngestionService.StandaloneRasterInputKind)
            {
                throw InvalidRequest();
            }

            var decoder = await BitmapDecoder.CreateAsync(randomAccess)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
            RequireRasterBounds(decoder);
            return 1;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    internal static void ValidateRequest(
        string documentId,
        int pageIndex)
    {
        if (documentId is null
            || !documentId.StartsWith(
                "document-",
                StringComparison.Ordinal)
            || documentId.Length is < 10 or > 128
            || documentId.Any(static character =>
                character is not (>= 'a' and <= 'z')
                    and not (>= '0' and <= '9')
                    and not '-')
            || pageIndex is < 0 or > MaximumPageIndex)
        {
            throw InvalidRequest();
        }
    }

    internal static string CreateCacheKey(
        string contentSha256,
        int pageIndex,
        string renderer,
        string orientation)
    {
        CorpusVault.ValidateContentSha256(contentSha256);
        if (pageIndex is < 0 or > MaximumPageIndex
            || !IsCacheComponent(renderer)
            || !IsCacheComponent(orientation))
        {
            throw InvalidRequest();
        }

        var canonical = Encoding.UTF8.GetBytes(
            CacheDomain
            + contentSha256
            + "\n"
            + pageIndex.ToString(
                System.Globalization.CultureInfo.InvariantCulture)
            + "\n"
            + renderer
            + "\n"
            + orientation
            + "\n");
        return Convert.ToHexStringLower(SHA256.HashData(canonical));
    }

    private async Task<byte[]> ReadVerifiedObjectAsync(
        WorkbenchDocument document,
        CancellationToken cancellationToken)
    {
        using var verified = _vault.TryOpenObject(
            document.ContentSha256)
            ?? throw new WorkbenchException(
                WorkbenchFailureCode.ContentHashMismatch);
        if (verified.Length is <= 0
            or > DocumentExtractionLimits.MaxEncodedInputBytes)
        {
            throw InvalidRequest();
        }

        verified.Revalidate();
        var path = _vault.GetObjectPathForExtraction(document);
        var bytes = new byte[checked((int)verified.Length)];
        await using (var stream = new FileStream(
                         path,
                         FileMode.Open,
                         FileAccess.Read,
                         FileShare.Read,
                         bufferSize: 81_920,
                         FileOptions.Asynchronous
                             | FileOptions.SequentialScan))
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken)
                .ConfigureAwait(false);
            if (stream.ReadByte() != -1)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.ContentHashMismatch);
            }
        }

        verified.Revalidate();
        var actual = SHA256.HashData(bytes);
        var expected = Convert.FromHexString(
            document.ContentSha256);
        if (!CryptographicOperations.FixedTimeEquals(
                actual,
                expected))
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new WorkbenchException(
                WorkbenchFailureCode.ContentHashMismatch);
        }

        return bytes;
    }

    private static async Task<DocumentPreview> RenderPdfAsync(
        byte[] encoded,
        int pageIndex,
        CancellationToken cancellationToken)
    {
        using var randomAccess = await CopyToRandomAccessAsync(
                encoded,
                cancellationToken)
            .ConfigureAwait(false);
        var document = await PdfDocument
            .LoadFromStreamAsync(randomAccess)
            .AsTask(cancellationToken)
            .ConfigureAwait(false);
        var pageCount = RequirePageCount(document.PageCount);
        if (pageIndex >= pageCount || document.IsPasswordProtected)
        {
            throw InvalidRequest();
        }

        using var page = document.GetPage(checked((uint)pageIndex));
        var dimensions = FitDimensions(
            page.Size.Width,
            page.Size.Height);
        using var output = new InMemoryRandomAccessStream();
        var options = new PdfPageRenderOptions
        {
            BitmapEncoderId = BitmapEncoder.PngEncoderId,
            DestinationWidth = dimensions.Width,
            DestinationHeight = dimensions.Height,
            IsIgnoringHighContrast = true,
        };
        await page.RenderToStreamAsync(output, options)
            .AsTask(cancellationToken)
            .ConfigureAwait(false);
        return new DocumentPreview(
            await ReadOutputAsync(output, cancellationToken)
                .ConfigureAwait(false),
            pageCount);
    }

    private static async Task<DocumentPreview> RenderRasterAsync(
        byte[] encoded,
        int pageIndex,
        CancellationToken cancellationToken)
    {
        if (pageIndex != 0)
        {
            throw InvalidRequest();
        }

        using var randomAccess = await CopyToRandomAccessAsync(
                encoded,
                cancellationToken)
            .ConfigureAwait(false);
        var decoder = await BitmapDecoder.CreateAsync(randomAccess)
            .AsTask(cancellationToken)
            .ConfigureAwait(false);
        RequireRasterBounds(decoder);
        using var bitmap = await decoder.GetSoftwareBitmapAsync(
                BitmapPixelFormat.Bgra8,
                BitmapAlphaMode.Premultiplied,
                new BitmapTransform(),
                ExifOrientationMode.RespectExifOrientation,
                ColorManagementMode.ColorManageToSRgb)
            .AsTask(cancellationToken)
            .ConfigureAwait(false);
        using var output = new InMemoryRandomAccessStream();
        var encoder = await BitmapEncoder.CreateAsync(
                BitmapEncoder.PngEncoderId,
                output)
            .AsTask(cancellationToken)
            .ConfigureAwait(false);
        encoder.SetSoftwareBitmap(bitmap);
        encoder.IsThumbnailGenerated = false;
        await encoder.FlushAsync()
            .AsTask(cancellationToken)
            .ConfigureAwait(false);
        return new DocumentPreview(
            await ReadOutputAsync(output, cancellationToken)
                .ConfigureAwait(false),
            1);
    }

    private async Task VerifyOrPopulateCacheAsync(
        string cacheKey,
        byte[] png,
        CancellationToken cancellationToken)
    {
        var fileStore = _vault.PreviewFileStore;
        var relative = Path.Combine(
            "previews",
            "preview-" + cacheKey + ".png");
        using (var existing =
               fileStore.TryOpenExistingOwnedVerified(relative))
        {
            if (existing is not null)
            {
                var cached = await ReadVerifiedCacheAsync(
                        fileStore,
                        existing,
                        relative,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (!CryptographicOperations.FixedTimeEquals(
                        cached,
                        png))
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.VaultBoundaryViolation);
                }

                return;
            }
        }

        var staging = Path.Combine(
            "previews",
            ".staging",
            "preview-" + Guid.NewGuid().ToString("N") + ".tmp");
        using var handle = fileStore.CreateNewPromotableVerified(
            staging,
            png.Length);
        var promoted = false;
        try
        {
            await WriteAllAsync(handle, png, cancellationToken)
                .ConfigureAwait(false);
            RandomAccess.FlushToDisk(handle);
            fileStore.RevalidateCreated(
                handle,
                staging,
                png.Length);
            var ownership = new FilePromotionOwnership();
            promoted = fileStore.PromoteCreatedNoReplace(
                handle,
                staging,
                relative,
                png.Length,
                ownership);
            if (promoted)
            {
                fileStore.RevalidateCreated(
                    handle,
                    relative,
                    png.Length);
                return;
            }

            using var winner =
                fileStore.TryOpenExistingOwnedVerified(relative)
                ?? throw new WorkbenchException(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            var cached = await ReadVerifiedCacheAsync(
                    fileStore,
                    winner,
                    relative,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                    cached,
                    png))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }
        }
        finally
        {
            if (!promoted)
            {
                fileStore.DeleteOwnedOnClose(
                    handle,
                    staging,
                    png.Length);
            }
        }
    }

    private static async Task<byte[]> ReadVerifiedCacheAsync(
        ApprovedRootFileStore fileStore,
        VerifiedStableSource source,
        string relative,
        CancellationToken cancellationToken)
    {
        if (source.Length is < 24 or > MaximumPngBytes)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        source.Revalidate();
        var bytes = new byte[checked((int)source.Length)];
        var path = Path.Combine(fileStore.ApprovedRoot, relative);
        await using (var stream = new FileStream(
                         path,
                         FileMode.Open,
                         FileAccess.Read,
                         FileShare.Read,
                         bufferSize: 81_920,
                         FileOptions.Asynchronous
                             | FileOptions.SequentialScan))
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken)
                .ConfigureAwait(false);
        }

        source.Revalidate();
        fileStore.RevalidateExisting(source, relative);
        ValidatePng(bytes);
        return bytes;
    }

    private static async Task<InMemoryRandomAccessStream>
        CopyToRandomAccessAsync(
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        var stream = new InMemoryRandomAccessStream();
        try
        {
            using var writer = new DataWriter(stream);
            const int chunkSize = 81_920;
            for (var offset = 0; offset < bytes.Length;)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = Math.Min(chunkSize, bytes.Length - offset);
                writer.WriteBytes(bytes.AsSpan(offset, count).ToArray());
                await writer.StoreAsync()
                    .AsTask(cancellationToken)
                    .ConfigureAwait(false);
                offset += count;
            }

            await writer.FlushAsync()
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
            writer.DetachStream();
            stream.Seek(0);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static async Task<byte[]> ReadOutputAsync(
        InMemoryRandomAccessStream output,
        CancellationToken cancellationToken)
    {
        if (output.Size is < 24 or > MaximumPngBytes)
        {
            throw InvalidRequest();
        }

        output.Seek(0);
        using var reader = new DataReader(output);
        var length = checked((uint)output.Size);
        await reader.LoadAsync(length)
            .AsTask(cancellationToken)
            .ConfigureAwait(false);
        var bytes = new byte[checked((int)length)];
        reader.ReadBytes(bytes);
        return bytes;
    }

    private static async Task WriteAllAsync(
        SafeFileHandle handle,
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        const int chunkSize = 81_920;
        for (var offset = 0; offset < bytes.Length;)
        {
            var count = Math.Min(chunkSize, bytes.Length - offset);
            await RandomAccess.WriteAsync(
                    handle,
                    bytes.AsMemory(offset, count),
                    offset,
                    cancellationToken)
                .ConfigureAwait(false);
            offset += count;
        }
    }

    private static int RequirePageCount(uint count)
    {
        if (count is 0 or > MaximumPageIndex + 1u)
        {
            throw InvalidRequest();
        }

        return checked((int)count);
    }

    private static void RequireRasterBounds(BitmapDecoder decoder)
    {
        if (decoder.FrameCount != 1
            || decoder.OrientedPixelWidth is 0 or > MaximumDimension
            || decoder.OrientedPixelHeight is 0 or > MaximumDimension
            || checked(
                (ulong)decoder.OrientedPixelWidth
                * decoder.OrientedPixelHeight) > MaximumPixels)
        {
            throw InvalidRequest();
        }
    }

    private static (uint Width, uint Height) FitDimensions(
        double width,
        double height)
    {
        if (!double.IsFinite(width)
            || !double.IsFinite(height)
            || width <= 0
            || height <= 0)
        {
            throw InvalidRequest();
        }

        var scale = Math.Min(
            2d,
            Math.Min(
                MaximumDimension / width,
                MaximumDimension / height));
        var outputWidth = checked(
            (uint)Math.Max(1, Math.Floor(width * scale)));
        var outputHeight = checked(
            (uint)Math.Max(1, Math.Floor(height * scale)));
        if (checked((ulong)outputWidth * outputHeight)
            > MaximumPixels)
        {
            throw InvalidRequest();
        }

        return (outputWidth, outputHeight);
    }

    private static void ValidatePng(byte[] png)
    {
        if (png.Length is < 24 or > MaximumPngBytes
            || !png.AsSpan(0, PngSignature.Length)
                .SequenceEqual(PngSignature)
            || !png.AsSpan(12, 4).SequenceEqual("IHDR"u8))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        var width = BinaryPrimitives.ReadUInt32BigEndian(
            png.AsSpan(16, 4));
        var height = BinaryPrimitives.ReadUInt32BigEndian(
            png.AsSpan(20, 4));
        if (width is 0 or > MaximumDimension
            || height is 0 or > MaximumDimension
            || checked((ulong)width * height) > MaximumPixels)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }
    }

    private static void RequireDocumentIdentity(
        WorkbenchDocument document,
        string requestedId)
    {
        if (!string.Equals(
                document.DocumentId,
                requestedId,
                StringComparison.Ordinal)
            || !string.Equals(
                document.DocumentId,
                "document-" + document.ContentSha256,
                StringComparison.Ordinal))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.ContentHashMismatch);
        }
    }

    private static bool IsCacheComponent(string value) =>
        value is not null
        && value.Length is > 0 and <= 64
        && value.All(static character =>
            character is >= 'a' and <= 'z'
                or >= '0' and <= '9'
                or '-');

    private static WorkbenchException InvalidRequest() =>
        new(WorkbenchFailureCode.InvalidArguments);
}
