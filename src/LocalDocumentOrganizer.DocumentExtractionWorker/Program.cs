using System.Collections.Immutable;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;
using LocalDocumentOrganizer.DocumentExtractionWorker.Protocol;

namespace LocalDocumentOrganizer.DocumentExtractionWorker;

public static class Program
{
    public static Task<int> Main() =>
        RunAsync(
            Console.OpenStandardInput(),
            Console.OpenStandardOutput(),
            Console.Error,
            [],
            CancellationToken.None);

    public static async Task<int> RunAsync(
        Stream input,
        Stream output,
        TextWriter error,
        IEnumerable<IDocumentExtractionAdapter> adapters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(adapters);

        DocumentExtractionRequest request;
        try
        {
            request = await FramedJsonTransport.ReadRequestAsync(input, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is InvalidDataException
                or EndOfStreamException
                or JsonException
                or IOException)
        {
            error.WriteLine("worker:protocol-error");
            return 64;
        }
        catch (Exception)
        {
            error.WriteLine("worker:internal-error");
            return 70;
        }

        using var timeout = new CancellationTokenSource(
            DocumentExtractionLimits.ExtractionTimeoutMilliseconds);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeout.Token);

        try
        {
            var processor = new DocumentExtractionProcessor(adapters);
            var response = await processor.ProcessAsync(request, linked.Token)
                .ConfigureAwait(false);
            using var responseWriteTimeout =
                new CancellationTokenSource(TimeSpan.FromSeconds(1));
            await FramedJsonTransport.WriteResponseAsync(
                    output,
                    response,
                    responseWriteTimeout.Token)
                .ConfigureAwait(false);
            return 0;
        }
        catch (Exception)
        {
            error.WriteLine("worker:internal-error");
            var response = new DocumentExtractionResponse(
                DocumentExtractionProtocol.CurrentVersion,
                request.JobId,
                DocumentExtractionOutcome.Failure,
                ImmutableArray<TextFragment>.Empty,
                ImmutableArray<DocumentSourcePage>.Empty,
                new ExtractionRuntimeMetadata("worker", "1", string.Empty, null),
                0,
                DocumentExtractionFailureCode.InternalFailure);

            try
            {
                using var bestEffortTimeout =
                    new CancellationTokenSource(TimeSpan.FromSeconds(1));
                await FramedJsonTransport.WriteResponseAsync(
                        output,
                        response,
                        bestEffortTimeout.Token)
                    .ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The exit code and fixed diagnostic remain the only reliable channel.
            }

            return 70;
        }
    }
}
