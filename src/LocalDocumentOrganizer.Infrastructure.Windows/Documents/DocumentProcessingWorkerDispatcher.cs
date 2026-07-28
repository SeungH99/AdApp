using System.Collections.Immutable;
using System.Security.Cryptography;
using LocalDocumentOrganizer.Application.Processing;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Documents;

/// <summary>
/// Resolves an immutable Vault object only for the duration of a Worker request.
/// Implementations derive the path from the content address under an approved Vault root;
/// they do not persist or return source-file paths to the Application layer.
/// </summary>
public interface IImmutableVaultExtractionSourceResolver
{
    Task<ImmutableVaultExtractionSource> OpenAsync(
        DocumentProcessingRequest request,
        CancellationToken cancellationToken);
}

public sealed class ContentAddressedVaultExtractionSourceResolver(
    ApprovedRootPathGuard vaultRoot) : IImmutableVaultExtractionSourceResolver
{
    public ContentAddressedVaultExtractionSourceResolver(
        ApprovedRootPathGuard vaultRoot,
        string ignoredWorkerPackageIdentity) : this(vaultRoot)
    {
    }
    public async Task<ImmutableVaultExtractionSource> OpenAsync(
        DocumentProcessingRequest request,
        CancellationToken cancellationToken)
    {
        var binding = request.SourceBinding
            ?? throw new DocumentExtractionException(DocumentExtractionFailureCode.InvalidSourceHandle);
        if (!binding.IsValid)
            throw new DocumentExtractionException(DocumentExtractionFailureCode.InvalidSourceHandle);
        var path = Path.Combine(vaultRoot.ApprovedRoot, "objects",
            request.ContentSha256.Hex[..2], request.ContentSha256.Hex + binding.CanonicalExtension);
        try
        {
            await using var source = vaultRoot.OpenVerifiedSourceFromApprovedRoot(path);
            if (source.Length != binding.DeclaredLength
                || !await HasExpectedMagicAsync(source, binding.Format, cancellationToken).ConfigureAwait(false)
                || !CryptographicOperations.FixedTimeEquals(
                    await ComputeSha256Async(source, cancellationToken).ConfigureAwait(false),
                    request.ContentSha256.Bytes.Span))
                throw new DocumentExtractionException(DocumentExtractionFailureCode.InvalidSourceFingerprint);
            return new ImmutableVaultExtractionSource(path,
                new DocumentSourceDescriptor(0, ToContainer(binding.Format), binding.CanonicalMimeType,
                    binding.DeclaredLength, ImmutableArray.CreateRange(request.ContentSha256.Bytes.ToArray())));
        }
        catch (FileSystemBoundaryException exception)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle,
                exception);
        }
    }

    private static async Task<byte[]> ComputeSha256Async(
        VerifiedStableSource source,
        CancellationToken cancellationToken)
    {
        source.RequireSingleLink();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        long offset = 0;
        while (offset < source.Length)
        {
            var count = await RandomAccess.ReadAsync(
                source.Handle,
                buffer.AsMemory(0, (int)Math.Min(buffer.Length, source.Length - offset)),
                offset,
                cancellationToken).ConfigureAwait(false);
            if (count == 0)
                throw new DocumentExtractionException(DocumentExtractionFailureCode.InvalidSourceLength);
            hash.AppendData(buffer, 0, count);
            offset += count;
        }
        source.RequireSingleLink();
        return hash.GetHashAndReset();
    }

    private static async Task<bool> HasExpectedMagicAsync(VerifiedStableSource source, ProductDocumentSourceFormat format, CancellationToken cancellationToken)
    {
        var bytes = new byte[8];
        var read = await RandomAccess.ReadAsync(source.Handle, bytes, 0, cancellationToken).ConfigureAwait(false);
        return format switch
        {
            ProductDocumentSourceFormat.Pdf => read >= 5 && bytes.AsSpan(0, 5).SequenceEqual("%PDF-"u8),
            ProductDocumentSourceFormat.Jpeg => read >= 3 && bytes.AsSpan(0, 3).SequenceEqual(new byte[] { 0xFF, 0xD8, 0xFF }),
            ProductDocumentSourceFormat.Png => read >= 8 && bytes.AsSpan().SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }),
            ProductDocumentSourceFormat.Tiff => read >= 4 && (bytes.AsSpan(0, 4).SequenceEqual(new byte[] { 73, 73, 42, 0 }) || bytes.AsSpan(0, 4).SequenceEqual(new byte[] { 77, 77, 0, 42 })),
            _ => false,
        };
    }

    private static DocumentContainerKind ToContainer(ProductDocumentSourceFormat format) =>
        format == ProductDocumentSourceFormat.Pdf ? DocumentContainerKind.Pdf : DocumentContainerKind.RasterImage;
}

public sealed record ImmutableVaultExtractionSource(
    string FullyQualifiedVaultPath,
    DocumentSourceDescriptor Descriptor)
{
    public string WorkerPackageIdentity => string.Empty;

    public ImmutableVaultExtractionSource(
        string fullyQualifiedVaultPath,
        DocumentSourceDescriptor descriptor,
        string ignoredWorkerPackageIdentity) : this(fullyQualifiedVaultPath, descriptor)
    {
    }
}

/// <summary>Application port adapter for the existing attested AppContainer Worker.</summary>
public sealed class DocumentProcessingWorkerDispatcher : IDocumentProcessingDispatcher
{
    private readonly IImmutableVaultExtractionSourceResolver _sources;
    private readonly DocumentExtractionClient _client;
    private readonly string _expectedWorkerPackageIdentity;
    private readonly IExtractionMarketSuggester _marketSuggester;

    public DocumentProcessingWorkerDispatcher(
        IImmutableVaultExtractionSourceResolver sources,
        DocumentExtractionClient client,
        string expectedWorkerPackageIdentity,
        IExtractionMarketSuggester marketSuggester)
    {
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedWorkerPackageIdentity);
        ArgumentNullException.ThrowIfNull(marketSuggester);
        _sources = sources;
        _client = client;
        _expectedWorkerPackageIdentity = expectedWorkerPackageIdentity;
        _marketSuggester = marketSuggester;
    }

    public async Task<DocumentProcessingDispatchResult> DispatchAsync(
        DocumentProcessingRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.SourceBinding is null)
                return DocumentProcessingDispatchResult.TransientFailure(DocumentProcessingFailureCode.ResponseBindingInvalid);
            var source = await _sources.OpenAsync(request, cancellationToken).ConfigureAwait(false);
            if (source.Descriptor.DeclaredLength != request.SourceBinding.DeclaredLength
                || source.Descriptor.DeclaredMimeType != request.SourceBinding.CanonicalMimeType
                || !CryptographicOperations.FixedTimeEquals(
                    source.Descriptor.Sha256.AsSpan(), request.ContentSha256.Bytes.Span))
            {
                return DocumentProcessingDispatchResult.TransientFailure(
                    DocumentProcessingFailureCode.ResponseBindingInvalid);
            }

            var evaluation = await _client.ExtractForEvaluationAsync(
                source.FullyQualifiedVaultPath,
                source.Descriptor,
                request.AttemptId.Value,
                request.RequestedCapabilities,
                request.RequestedLanguages,
                cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                    evaluation.SourceSha256.AsSpan(), request.ContentSha256.Bytes.Span))
            {
                return DocumentProcessingDispatchResult.TransientFailure(
                    DocumentProcessingFailureCode.ResponseBindingInvalid);
            }
            if (!string.Equals(
                    evaluation.WorkerPackageIdentity,
                    _expectedWorkerPackageIdentity,
                    StringComparison.Ordinal))
            {
                return DocumentProcessingDispatchResult.TransientFailure(
                    DocumentProcessingFailureCode.WorkerAttestationInvalid);
            }

            if (evaluation.Response.Outcome == DocumentExtractionOutcome.Failure)
            {
                return DocumentProcessingDispatchResult.TransientFailure(
                    MapWorkerFailure(evaluation.Response.FailureCode));
            }

            var marketSuggestion = _marketSuggester.Suggest(evaluation.Response);
            var protectedDraft = AuthenticatedExtractionDraftSerializer.Serialize(
                evaluation.Response,
                marketSuggestion,
                IsComplete(evaluation.Response));
            return new DocumentProcessingDispatchResult.Successful(
                evaluation.Response,
                new DocumentProcessingResponseBinding(
                    request.AttemptId.Value,
                    request.DocumentId,
                    source.Descriptor.DeclaredLength,
                    request.ContentSha256,
                    evaluation.WorkerPackageIdentity),
                protectedDraft,
                IsComplete(evaluation.Response),
                marketSuggestion.MarketId);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DocumentExtractionException exception)
        {
            return DocumentProcessingDispatchResult.TransientFailure(MapWorkerFailure(exception.FailureCode));
        }
        catch (ExtractionDraftSerializationException)
        {
            return DocumentProcessingDispatchResult.TransientFailure(
                DocumentProcessingFailureCode.ResponseInvalid);
        }
        catch (Exception)
        {
            return DocumentProcessingDispatchResult.TransientFailure(
                DocumentProcessingFailureCode.WorkerUnavailable);
        }
    }

    private static bool IsComplete(DocumentExtractionResponse response) =>
        // Extraction never invents required invoice fields; Task 5 performs user confirmation.
        response.Fragments.Length >= 6;

    public static DocumentProcessingFailureCode MapWorkerFailure(
        DocumentExtractionFailureCode failureCode) => failureCode switch
    {
        DocumentExtractionFailureCode.UnsupportedDocument
            or DocumentExtractionFailureCode.UnsupportedMimeType
            or DocumentExtractionFailureCode.NoAdapterAvailable =>
            DocumentProcessingFailureCode.UnsupportedDocument,
        DocumentExtractionFailureCode.CorruptDocument
            or DocumentExtractionFailureCode.EncryptedDocument =>
            DocumentProcessingFailureCode.CorruptDocument,
        DocumentExtractionFailureCode.ExtractionTimedOut
            or DocumentExtractionFailureCode.WorkerMemoryLimitExceeded =>
            DocumentProcessingFailureCode.WorkerTimedOut,
        DocumentExtractionFailureCode.InvalidSourceFingerprint
            or DocumentExtractionFailureCode.InvalidSourceLength
            or DocumentExtractionFailureCode.ResponseJobMismatch
            or DocumentExtractionFailureCode.ResponseProtocolVersionMismatch =>
            DocumentProcessingFailureCode.ResponseBindingInvalid,
        DocumentExtractionFailureCode.InvalidFraming
            or DocumentExtractionFailureCode.ResponseTooLarge =>
            DocumentProcessingFailureCode.ResponseInvalid,
        DocumentExtractionFailureCode.WorkerTerminated
            or DocumentExtractionFailureCode.InternalFailure =>
            DocumentProcessingFailureCode.WorkerUnavailable,
        _ => DocumentProcessingFailureCode.WorkerUnavailable,
    };
}
