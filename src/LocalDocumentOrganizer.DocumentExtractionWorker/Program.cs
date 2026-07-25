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
            TimeSpan.FromMilliseconds(
                DocumentExtractionLimits.ExtractionTimeoutMilliseconds),
            CancellationToken.None);

    public static Task<int> RunAsync(
        Stream input,
        Stream output,
        TextWriter error,
        IEnumerable<IDocumentExtractionAdapter> adapters,
        CancellationToken cancellationToken) =>
        RunAsync(
            input,
            output,
            error,
            adapters,
            TimeSpan.FromMilliseconds(
                DocumentExtractionLimits.ExtractionTimeoutMilliseconds),
            cancellationToken);

    public static async Task<int> RunAsync(
        Stream input,
        Stream output,
        TextWriter error,
        IEnumerable<IDocumentExtractionAdapter> adapters,
        TimeSpan workerLifetime,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(adapters);

        using var deadline = new CancellationTokenSource(workerLifetime);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            deadline.Token);

        DocumentExtractionRequest request;
        try
        {
            request = await FramedJsonTransport.ReadRequestAsync(input, linked.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            deadline.IsCancellationRequested
            && !cancellationToken.IsCancellationRequested)
        {
            error.WriteLine("worker:timeout");
            return 70;
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

        try
        {
            var processor = new DocumentExtractionProcessor(adapters);
            var response = await processor.ProcessAsync(
                    request,
                    linked.Token,
                    cancellationToken,
                    deadline.Token)
                .ConfigureAwait(false);

            var responseWriteToken = linked.Token;
            CancellationTokenSource? terminalResponseTimeout = null;
            if (linked.IsCancellationRequested
                && response.FailureCode is (
                    DocumentExtractionFailureCode.ExtractionCancelled
                    or DocumentExtractionFailureCode.ExtractionTimedOut))
            {
                terminalResponseTimeout =
                    new CancellationTokenSource(TimeSpan.FromSeconds(1));
                responseWriteToken = terminalResponseTimeout.Token;
            }

            using (terminalResponseTimeout)
            {
                await FramedJsonTransport.WriteResponseAsync(
                        output,
                        response,
                        responseWriteToken)
                    .ConfigureAwait(false);
            }

            return 0;
        }
        catch (OperationCanceledException) when (
            deadline.IsCancellationRequested
            && !cancellationToken.IsCancellationRequested)
        {
            error.WriteLine("worker:timeout");
            return 70;
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
