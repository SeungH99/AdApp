using System.Globalization;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Persistence;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.CorpusWorkbench.Ingestion;

public sealed record ImportResult(
    string DocumentId,
    string ContentSha256,
    bool WasExisting);

public sealed class CorpusIngestionService
{
    private const int ExistingObjectOpenRetryLimit = 40;
    private static readonly TimeSpan ExistingObjectOpenRetryDeadline =
        TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ExistingObjectOpenRetryDelay =
        TimeSpan.FromMilliseconds(25);

    public const long MaxInputLength = 64L * 1024 * 1024;
    public const string VerifiedReusableStatus =
        "verified-reusable";
    public const string ImagePdfInputKind = "image-pdf";
    public const string StandaloneRasterInputKind =
        "standalone-raster";
    public const string JpegCodecId = "jpeg";
    public const string PngCodecId = "png";
    public const string TiffCodecId = "tiff";
    public const string BmpCodecId = "bmp";

    private static readonly string[] ApprovedReuseStatuses =
    [
        VerifiedReusableStatus,
        "owner-approved",
        "public-domain",
        "licensed",
    ];

    private static readonly string[] ApprovedRasterCodecIds =
    [
        JpegCodecId,
        PngCodecId,
        TiffCodecId,
        BmpCodecId,
    ];

    private readonly CorpusVault _vault;
    private readonly NtfsFileIdentityProvider _identityProvider;

    public CorpusIngestionService(
        CorpusVault vault,
        NtfsFileIdentityProvider identityProvider)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(identityProvider);
        _vault = vault;
        _identityProvider = identityProvider;
    }

    public Task<ImportResult> ImportAsync(
        string sourcePath,
        SourceReceipt receipt,
        CancellationToken cancellationToken) =>
        ImportCoreAsync(
            sourcePath,
            receipt,
            declaredInput: null,
            cancellationToken);

    public Task<ImportResult> ImportAsync(
        string sourcePath,
        SourceReceipt receipt,
        string inputKind,
        string? codecId,
        CancellationToken cancellationToken) =>
        ImportCoreAsync(
            sourcePath,
            receipt,
            ValidateDeclaredInput(inputKind, codecId),
            cancellationToken);

    private async Task<ImportResult> ImportCoreAsync(
        string sourcePath,
        SourceReceipt receipt,
        ClassifiedInput? declaredInput,
        CancellationToken cancellationToken)
    {
        ValidateReceipt(receipt);
        ArgumentException.ThrowIfNullOrWhiteSpace(
            sourcePath,
            nameof(sourcePath));
        cancellationToken.ThrowIfCancellationRequested();

        var canonicalReceipt =
            CanonicalSourceReceipt.Serialize(receipt);
        var receiptSha256 = Convert.ToHexStringLower(
            SHA256.HashData(canonicalReceipt));

        await using var source =
            _identityProvider.OpenVerifiedSourceFromApprovedRoot(
                sourcePath);
        if (source.Length <= 0
            || source.Length > MaxInputLength)
        {
            throw UnsupportedInput();
        }

        byte[]? firstPassHash = null;
        byte[]? expectedHash = null;
        try
        {
            using var probe = new ProbeSink();
            await source.CopyToAsync(probe, cancellationToken)
                .ConfigureAwait(false);
            var probeResult = probe.Complete();
            firstPassHash = probeResult.Sha256;
            expectedHash = Convert.FromHexString(
                receipt.ExpectedContentSha256);
            if (probeResult.Length != source.Length
                || !CryptographicOperations.FixedTimeEquals(
                    firstPassHash,
                    expectedHash))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.ContentHashMismatch);
            }

            ClassifiedInput classified;
            try
            {
                classified = Classify(probeResult.MagicBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    probeResult.MagicBytes);
            }
            if (declaredInput is not null
                && declaredInput != classified)
            {
                throw UnsupportedInput();
            }

            using var importLease =
                await _vault.AcquireImportLeaseAsync(
                        receipt.ExpectedContentSha256,
                        cancellationToken)
                    .ConfigureAwait(false);

            var existing = await _vault.Store.FindImportAsync(
                    receipt,
                    canonicalReceipt,
                    receiptSha256,
                    classified.InputKind,
                    classified.CodecId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (existing is not null)
            {
                var opened = await OpenExistingObjectAfterHandoffAsync(
                        existing,
                        receipt,
                        canonicalReceipt,
                        receiptSha256,
                        classified,
                        cancellationToken)
                    .ConfigureAwait(false);
                var existingObject = opened.Object;
                await using (existingObject)
                {
                    await VerifyExistingObjectAsync(
                            existingObject,
                            source.Length,
                            expectedHash,
                            cancellationToken)
                        .ConfigureAwait(false);
                    source.Revalidate();
                    _vault.RevalidateObject(
                        existingObject,
                        receipt.ExpectedContentSha256);
                }

                return new ImportResult(
                    opened.Document.DocumentId,
                    opened.Document.ContentSha256,
                    WasExisting: true);
            }

            StagedCorpusObject? staged = null;
            VerifiedStableSource? storedObject = null;
            var ownsFinalObject = false;
            var ownership = new ImportCommitOwnership();
            try
            {
                try
                {
                    storedObject = _vault.TryOpenObject(
                        receipt.ExpectedContentSha256);
                }
                catch (FileSystemTransientShareOrLockException)
                {
                    // A competing importer can hold a newly promoted
                    // object exclusively until its durable boundary.
                    storedObject = null;
                }
                if (storedObject is not null
                    && !await IsCompleteValidObjectAsync(
                            storedObject,
                            source.Length,
                            expectedHash,
                            cancellationToken)
                        .ConfigureAwait(false))
                {
                    await storedObject.DisposeAsync();
                    storedObject = null;
                    if (!await TryReclaimInvalidOrphanAsync(
                            receipt.ExpectedContentSha256,
                            source.Length,
                            expectedHash)
                        .ConfigureAwait(false))
                    {
                        throw new WorkbenchException(
                            WorkbenchFailureCode
                                .VaultBoundaryViolation);
                    }
                }

                if (storedObject is null)
                {
                    staged = _vault.CreateStagingObject(
                        source.Length);
                    using (var destination = new ObjectWriteSink(
                               staged.Handle,
                               source.Length))
                    {
                        await source.CopyToAsync(
                                destination,
                                cancellationToken)
                            .ConfigureAwait(false);
                        var secondPassHash = destination.Complete();
                        try
                        {
                            if (destination.Length != source.Length
                                || !CryptographicOperations
                                    .FixedTimeEquals(
                                        secondPassHash,
                                        expectedHash)
                                || !CryptographicOperations
                                    .FixedTimeEquals(
                                        secondPassHash,
                                        firstPassHash))
                            {
                                throw new WorkbenchException(
                                    WorkbenchFailureCode
                                        .ContentHashMismatch);
                            }
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(
                                secondPassHash);
                        }
                    }

                    RandomAccess.FlushToDisk(staged.Handle);
                    _vault.RevalidateStagingObject(staged);
                    _vault.InjectFault(
                        CorpusImportFaultPoint
                            .AfterStagingObjectFlushed);

                    for (var attempt = 0;
                         attempt < 600;
                         attempt++)
                    {
                        cancellationToken
                            .ThrowIfCancellationRequested();
                        if (_vault.PromoteStagingObject(
                                staged!,
                                receipt.ExpectedContentSha256))
                        {
                            ownsFinalObject = true;
                            storedObject =
                                _vault.AdoptPromotedObject(staged!);
                            staged!.Dispose();
                            staged = null;
                            _vault.InjectFault(
                                CorpusImportFaultPoint
                                    .AfterObjectPromoted);
                            break;
                        }

                        try
                        {
                            var collision = _vault.TryOpenObject(
                                receipt.ExpectedContentSha256);
                            if (collision is not null)
                            {
                                if (await IsCompleteValidObjectAsync(
                                        collision,
                                        source.Length,
                                        expectedHash,
                                        cancellationToken)
                                    .ConfigureAwait(false))
                                {
                                    storedObject = collision;
                                    _vault.DeleteOwnedStagingOnClose(
                                        staged!);
                                    staged!.Dispose();
                                    staged = null;
                                    break;
                                }

                                await collision.DisposeAsync();
                                if (await TryReclaimInvalidOrphanAsync(
                                        receipt.ExpectedContentSha256,
                                        source.Length,
                                        expectedHash)
                                    .ConfigureAwait(false))
                                {
                                    continue;
                                }
                            }
                        }
                        catch (FileSystemTransientShareOrLockException)
                        {
                            // Another importer can hold its promoted
                            // handle until its database transaction ends.
                        }

                        await Task.Delay(
                                TimeSpan.FromMilliseconds(50),
                                cancellationToken)
                            .ConfigureAwait(false);
                    }

                    if (storedObject is null)
                    {
                        throw new WorkbenchException(
                            WorkbenchFailureCode
                                .VaultBoundaryViolation);
                    }
                }

                var acceptedObject = storedObject;
                var persisted =
                    await _vault.Store.PersistImportAsync(
                            receipt,
                            canonicalReceipt,
                            receiptSha256,
                            classified.InputKind,
                            classified.CodecId,
                            () =>
                            {
                                _vault.InjectFault(
                                    CorpusImportFaultPoint
                                        .BeforeAcceptanceRevalidation);
                                source.Revalidate();
                                acceptedObject.Revalidate();
                                _vault.RevalidateObject(
                                    acceptedObject,
                                    receipt
                                        .ExpectedContentSha256);
                            },
                            ownership,
                            cancellationToken)
                        .ConfigureAwait(false);
                if (ownership.IsTransferred)
                {
                    ownsFinalObject = false;
                }

                return ToResult(persisted);
            }
            catch (Exception exception)
            {
                var primary = ExceptionDispatchInfo.Capture(
                    exception);
                Exception? cleanupFailure = null;
                if (staged is { IsPromoted: false })
                {
                    try
                    {
                        _vault.DeleteOwnedStagingOnClose(staged);
                    }
                    catch (Exception cleanupException)
                    {
                        cleanupFailure = cleanupException;
                    }
                }

                if (staged is { IsPromoted: true }
                    && ownsFinalObject
                    && !ownership.IsTransferred)
                {
                    try
                    {
                        var promotedStaging = staged;
                        await _vault.Store.DeleteIfDocumentMissingAsync(
                                receipt.ExpectedContentSha256,
                                () =>
                                {
                                    _vault.DeleteOwnedStagingOnClose(
                                        promotedStaging);
                                    promotedStaging.Dispose();
                                })
                            .ConfigureAwait(false);
                    }
                    catch (Exception cleanupException)
                    {
                        cleanupFailure = cleanupFailure is null
                            ? cleanupException
                            : new AggregateException(
                                cleanupFailure,
                                cleanupException);
                    }
                }

                if (ownsFinalObject
                    && storedObject is not null
                    && !ownership.IsTransferred)
                {
                    try
                    {
                        var ownedObject = storedObject;
                        await _vault.Store.DeleteIfDocumentMissingAsync(
                                receipt.ExpectedContentSha256,
                                () =>
                                {
                                    _vault.DeleteOwnedObjectOnClose(
                                        ownedObject,
                                        receipt
                                            .ExpectedContentSha256,
                                        source.Length);
                                    ownedObject.Dispose();
                                })
                            .ConfigureAwait(false);
                    }
                    catch (Exception cleanupException)
                    {
                        cleanupFailure = cleanupFailure is null
                            ? cleanupException
                            : new AggregateException(
                                cleanupFailure,
                                cleanupException);
                    }
                }

                if (cleanupFailure is not null)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode
                            .VaultBoundaryViolation,
                        new AggregateException(
                            exception,
                            cleanupFailure));
                }

                primary.Throw();
                throw;
            }
            finally
            {
                staged?.Dispose();
                if (storedObject is not null)
                {
                    await storedObject.DisposeAsync()
                        .ConfigureAwait(false);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                canonicalReceipt);
            if (firstPassHash is not null)
            {
                CryptographicOperations.ZeroMemory(
                    firstPassHash);
            }

            if (expectedHash is not null)
            {
                CryptographicOperations.ZeroMemory(expectedHash);
            }
        }
    }

    private async Task<OpenedExistingObject>
        OpenExistingObjectAfterHandoffAsync(
            WorkbenchDocument expectedDocument,
            SourceReceipt receipt,
            byte[] canonicalReceipt,
            string receiptSha256,
            ClassifiedInput classified,
            CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        using var deadlineCancellation = new CancellationTokenSource(
            ExistingObjectOpenRetryDeadline);
        using var retryCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                deadlineCancellation.Token);
        for (var attempt = 0;
             attempt < ExistingObjectOpenRetryLimit;
             attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (stopwatch.Elapsed >= ExistingObjectOpenRetryDeadline)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }

            WorkbenchDocument? current;
            try
            {
                current = await _vault.Store.FindImportAsync(
                        receipt,
                        canonicalReceipt,
                        receiptSha256,
                        classified.InputKind,
                        classified.CodecId,
                        retryCancellation.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (deadlineCancellation.IsCancellationRequested
                    && !cancellationToken.IsCancellationRequested)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }
            if (current is null
                || !string.Equals(
                    current.DocumentId,
                    expectedDocument.DocumentId,
                    StringComparison.Ordinal)
                || !string.Equals(
                    current.ContentSha256,
                    expectedDocument.ContentSha256,
                    StringComparison.Ordinal))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }

            try
            {
                var opened = _vault.TryOpenObject(
                    receipt.ExpectedContentSha256);
                if (opened is null)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.VaultBoundaryViolation);
                }

                if (stopwatch.Elapsed >= ExistingObjectOpenRetryDeadline)
                {
                    opened.Dispose();
                    throw new WorkbenchException(
                        WorkbenchFailureCode.VaultBoundaryViolation);
                }

                return new OpenedExistingObject(current, opened);
            }
            catch (FileSystemTransientShareOrLockException)
            {
                _vault.InjectFault(
                    CorpusImportFaultPoint
                        .ExistingObjectOpenTransientShareOrLock);
                var remaining = ExistingObjectOpenRetryDeadline
                    - stopwatch.Elapsed;
                if (attempt + 1 >= ExistingObjectOpenRetryLimit
                    || remaining <= TimeSpan.Zero)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.VaultBoundaryViolation);
                }

                try
                {
                    await Task.Delay(
                            remaining < ExistingObjectOpenRetryDelay
                                ? remaining
                                : ExistingObjectOpenRetryDelay,
                            retryCancellation.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                    when (deadlineCancellation.IsCancellationRequested
                        && !cancellationToken.IsCancellationRequested)
                {
                    throw new WorkbenchException(
                        WorkbenchFailureCode.VaultBoundaryViolation);
                }
            }
        }

        throw new WorkbenchException(
            WorkbenchFailureCode.VaultBoundaryViolation);
    }


    private static async Task VerifyExistingObjectAsync(
        VerifiedStableSource existingObject,
        long expectedLength,
        byte[] expectedHash,
        CancellationToken cancellationToken)
    {
        if (existingObject.Length != expectedLength)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        var actual = await existingObject
            .ComputeSha256Async(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    actual,
                    expectedHash))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode
                        .VaultBoundaryViolation);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static async Task<bool> IsCompleteValidObjectAsync(
        VerifiedStableSource existingObject,
        long expectedLength,
        byte[] expectedHash,
        CancellationToken cancellationToken)
    {
        if (existingObject.Length != expectedLength)
        {
            existingObject.Revalidate();
            return false;
        }

        var actual = await existingObject
            .ComputeSha256Async(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            existingObject.Revalidate();
            return CryptographicOperations.FixedTimeEquals(
                actual,
                expectedHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private async Task<bool> TryReclaimInvalidOrphanAsync(
        string contentSha256,
        long expectedLength,
        byte[] expectedHash)
    {
        var owned = _vault.TryOpenOwnedObject(contentSha256);
        if (owned is null)
        {
            return false;
        }

        var disposed = false;
        try
        {
            if (await IsCompleteValidObjectAsync(
                    owned,
                    expectedLength,
                    expectedHash,
                    CancellationToken.None)
                .ConfigureAwait(false))
            {
                return false;
            }

            return await _vault.Store.DeleteIfDocumentMissingAsync(
                    contentSha256,
                    () =>
                    {
                        _vault.DeleteOwnedObjectOnClose(
                            owned,
                            contentSha256,
                            owned.Length);
                        owned.Dispose();
                        disposed = true;
                    })
                .ConfigureAwait(false);
        }
        finally
        {
            if (!disposed)
            {
                await owned.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static void ValidateReceipt(SourceReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (receipt.SchemaVersion != PilotCatalog.SchemaVersion
            || receipt.ContractId != PilotCatalog.ContractId
            || !PilotCatalog.MarketIds.Contains(
                receipt.MarketId,
                StringComparer.Ordinal)
            || !IsIdentifier(receipt.ReceiptId)
            || !IsIdentifier(receipt.SourceFamilyId)
            || !IsSafeText(receipt.Publisher, 256)
            || !ApprovedReuseStatuses.Contains(
                receipt.ReuseStatus,
                StringComparer.Ordinal)
            || receipt.RetrievedAtUtc.Offset != TimeSpan.Zero
            || receipt.RetrievedAtUtc
                < DateTimeOffset.UnixEpoch
            || receipt.RetrievedAtUtc
                > DateTimeOffset.UtcNow.AddMinutes(5)
            || !IsSecureSourceUri(receipt.SourceUri))
        {
            throw new WorkbenchException(
                receipt is { ReuseStatus: not null }
                && !ApprovedReuseStatuses.Contains(
                    receipt.ReuseStatus,
                    StringComparer.Ordinal)
                    ? WorkbenchFailureCode.ReuseStatusUnknown
                    : WorkbenchFailureCode.InvalidState);
        }

        CorpusVault.ValidateContentSha256(
            receipt.ExpectedContentSha256);
    }

    private static bool IsIdentifier(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= 128
        && value.All(
            static character =>
                character is >= 'a' and <= 'z'
                    or >= 'A' and <= 'Z'
                    or >= '0' and <= '9'
                    or '-'
                    or '_'
                    or '.'
                    or ':')
        && char.IsLetterOrDigit(value[0]);

    private static bool IsSafeText(string value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= maximumLength
        && value.All(
            static character =>
                !char.IsControl(character)
                && !char.IsSurrogate(character));

    private static bool IsSecureSourceUri(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 2_048
            || !Uri.TryCreate(
                value,
                UriKind.Absolute,
                out var uri))
        {
            return false;
        }

        return uri.Scheme.Equals(
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Fragment)
            && uri.IsDefaultPort
            && !string.IsNullOrWhiteSpace(uri.Host);
    }

    private static ClassifiedInput ValidateDeclaredInput(
        string inputKind,
        string? codecId)
    {
        if (inputKind == ImagePdfInputKind && codecId is null)
        {
            return new ClassifiedInput(
                ImagePdfInputKind,
                CodecId: null);
        }

        if (inputKind == StandaloneRasterInputKind
            && codecId is not null
            && ApprovedRasterCodecIds.Contains(
                codecId,
                StringComparer.Ordinal))
        {
            return new ClassifiedInput(inputKind, codecId);
        }

        throw UnsupportedInput();
    }

    private static ClassifiedInput Classify(
        ReadOnlySpan<byte> magic)
    {
        if (magic.StartsWith("%PDF-"u8))
        {
            return new ClassifiedInput(
                ImagePdfInputKind,
                CodecId: null);
        }

        if (magic.Length >= 3
            && magic[0] == 0xff
            && magic[1] == 0xd8
            && magic[2] == 0xff)
        {
            return new ClassifiedInput(
                StandaloneRasterInputKind,
                JpegCodecId);
        }

        if (magic.StartsWith(
                new byte[]
                {
                    0x89,
                    0x50,
                    0x4e,
                    0x47,
                    0x0d,
                    0x0a,
                    0x1a,
                    0x0a,
                }))
        {
            return new ClassifiedInput(
                StandaloneRasterInputKind,
                PngCodecId);
        }

        if (magic.StartsWith(
                new byte[] { 0x49, 0x49, 0x2a, 0x00 })
            || magic.StartsWith(
                new byte[] { 0x4d, 0x4d, 0x00, 0x2a }))
        {
            return new ClassifiedInput(
                StandaloneRasterInputKind,
                TiffCodecId);
        }

        if (magic.StartsWith("BM"u8))
        {
            return new ClassifiedInput(
                StandaloneRasterInputKind,
                BmpCodecId);
        }

        throw UnsupportedInput();
    }

    private static ImportResult ToResult(PersistedImport persisted) =>
        new(
            persisted.Document.DocumentId,
            persisted.Document.ContentSha256,
            persisted.WasExisting);

    private static WorkbenchException UnsupportedInput() =>
        new(WorkbenchFailureCode.UnsupportedInput);

    private sealed record ClassifiedInput(
        string InputKind,
        string? CodecId);

    private sealed record OpenedExistingObject(
        WorkbenchDocument Document,
        VerifiedStableSource Object);

    private sealed class ProbeSink : Stream
    {
        private const int MagicLength = 16;
        private readonly IncrementalHash _hash =
            IncrementalHash.CreateHash(
                HashAlgorithmName.SHA256);
        private readonly byte[] _magic = new byte[MagicLength];
        private int _magicCount;
        private bool _completed;
        private long _length;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => _length;

        public override long Position
        {
            get => _length;
            set => throw new NotSupportedException();
        }

        internal ProbeResult Complete()
        {
            ObjectDisposedException.ThrowIf(_completed, this);
            _completed = true;
            return new ProbeResult(
                _hash.GetHashAndReset(),
                _magic.AsSpan(0, _magicCount).ToArray(),
                _length);
        }

        public override void Flush()
        {
        }

        public override void Write(
            byte[] buffer,
            int offset,
            int count) =>
            Consume(buffer.AsSpan(offset, count));

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Consume(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count) =>
            throw new NotSupportedException();

        public override long Seek(
            long offset,
            SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hash.Dispose();
                CryptographicOperations.ZeroMemory(_magic);
            }

            base.Dispose(disposing);
        }

        private void Consume(ReadOnlySpan<byte> bytes)
        {
            ObjectDisposedException.ThrowIf(_completed, this);
            var magicBytes = Math.Min(
                bytes.Length,
                MagicLength - _magicCount);
            bytes[..magicBytes].CopyTo(
                _magic.AsSpan(_magicCount));
            _magicCount += magicBytes;
            _hash.AppendData(bytes);
            _length = checked(_length + bytes.Length);
        }
    }

    private sealed record ProbeResult(
        byte[] Sha256,
        byte[] MagicBytes,
        long Length);

    private sealed class ObjectWriteSink : Stream
    {
        private readonly SafeFileHandle _handle;
        private readonly long _expectedLength;
        private readonly IncrementalHash _hash =
            IncrementalHash.CreateHash(
                HashAlgorithmName.SHA256);
        private bool _completed;
        private long _length;

        internal ObjectWriteSink(
            SafeFileHandle handle,
            long expectedLength)
        {
            ArgumentNullException.ThrowIfNull(handle);
            _handle = handle;
            _expectedLength = expectedLength;
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => _length;

        public override long Position
        {
            get => _length;
            set => throw new NotSupportedException();
        }

        internal byte[] Complete()
        {
            ObjectDisposedException.ThrowIf(_completed, this);
            if (_length != _expectedLength)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode
                        .ContentHashMismatch);
            }

            _completed = true;
            return _hash.GetHashAndReset();
        }

        public override void Flush() =>
            RandomAccess.FlushToDisk(_handle);

        public override void Write(
            byte[] buffer,
            int offset,
            int count)
        {
            var memory = buffer.AsMemory(offset, count);
            WriteAsync(memory).AsTask().GetAwaiter().GetResult();
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_completed, this);
            if (buffer.Length > _expectedLength - _length)
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode
                        .ContentHashMismatch);
            }

            _hash.AppendData(buffer.Span);
            await RandomAccess.WriteAsync(
                    _handle,
                    buffer,
                    _length,
                    cancellationToken)
                .ConfigureAwait(false);
            _length = checked(_length + buffer.Length);
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count) =>
            throw new NotSupportedException();

        public override long Seek(
            long offset,
            SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hash.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

internal static class CanonicalSourceReceipt
{
    internal static byte[] Serialize(SourceReceipt receipt)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString(
                "schemaVersion",
                receipt.SchemaVersion);
            writer.WriteString("receiptId", receipt.ReceiptId);
            writer.WriteString("sourceUri", receipt.SourceUri);
            writer.WriteString("publisher", receipt.Publisher);
            writer.WriteString(
                "retrievedAtUtc",
                receipt.RetrievedAtUtc.ToString(
                    "O",
                    CultureInfo.InvariantCulture));
            writer.WriteString(
                "reuseStatus",
                receipt.ReuseStatus);
            writer.WriteString("marketId", receipt.MarketId);
            writer.WriteString(
                "contractId",
                receipt.ContractId);
            writer.WriteString(
                "sourceFamilyId",
                receipt.SourceFamilyId);
            writer.WriteString(
                "expectedContentSha256",
                receipt.ExpectedContentSha256);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}
