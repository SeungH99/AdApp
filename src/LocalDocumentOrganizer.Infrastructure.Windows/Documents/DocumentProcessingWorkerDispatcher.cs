using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Processing;
using LocalDocumentOrganizer.Core.Documents;

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

public sealed record ImmutableVaultExtractionSource(
    string FullyQualifiedVaultPath,
    DocumentSourceDescriptor Descriptor,
    string WorkerPackageIdentity);

/// <summary>Application port adapter for the existing attested AppContainer Worker.</summary>
public sealed class DocumentProcessingWorkerDispatcher : IDocumentProcessingDispatcher
{
    private readonly IImmutableVaultExtractionSourceResolver _sources;
    private readonly DocumentExtractionClient _client;

    public DocumentProcessingWorkerDispatcher(
        IImmutableVaultExtractionSourceResolver sources,
        DocumentExtractionClient client)
    {
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(client);
        _sources = sources;
        _client = client;
    }

    public async Task<DocumentProcessingDispatchResult> DispatchAsync(
        DocumentProcessingRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var source = await _sources.OpenAsync(request, cancellationToken).ConfigureAwait(false);
            if (source.Descriptor.DeclaredLength < 0
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

            if (evaluation.Response.Outcome == DocumentExtractionOutcome.Failure)
            {
                return DocumentProcessingDispatchResult.TransientFailure(
                    MapWorkerFailure(evaluation.Response.FailureCode));
            }

            var protectedDraft = JsonSerializer.Serialize(
                evaluation.Response,
                DocumentExtractionJsonContext.Default.DocumentExtractionResponse);
            return new DocumentProcessingDispatchResult.Successful(
                evaluation.Response,
                new DocumentProcessingResponseBinding(
                    request.AttemptId.Value,
                    request.DocumentId,
                    source.Descriptor.DeclaredLength,
                    request.ContentSha256,
                    source.WorkerPackageIdentity),
                protectedDraft,
                IsComplete(evaluation.Response),
                SuggestMarket(request.RequestedLanguages));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DocumentExtractionException exception)
        {
            return DocumentProcessingDispatchResult.TransientFailure(MapWorkerFailure(exception.FailureCode));
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

    private static string SuggestMarket(ImmutableArray<string> languages) =>
        languages.Any(language => language.StartsWith("ko", StringComparison.OrdinalIgnoreCase))
            ? "ko-KR"
            : "en-US";

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
