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
            ProductionDocumentExtractionAdapters.Create(),
            TimeSpan.FromMilliseconds(
                DocumentExtractionLimits.ExtractionTimeoutMilliseconds),
            TimeProvider.System,
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
            TimeProvider.System,
            cancellationToken);

    public static Task<int> RunAsync(
        Stream input,
        Stream output,
        TextWriter error,
        IEnumerable<IDocumentExtractionAdapter> adapters,
        TimeSpan workerLifetime,
        CancellationToken cancellationToken) =>
        RunAsync(
            input,
            output,
            error,
            adapters,
            workerLifetime,
            TimeProvider.System,
            cancellationToken);

    public static async Task<int> RunAsync(
        Stream input,
        Stream output,
        TextWriter error,
        IEnumerable<IDocumentExtractionAdapter> adapters,
        TimeSpan workerLifetime,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (workerLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(workerLifetime),
                "The worker lifetime must be positive.");
        }

        var terminalResponseReserve = GetTerminalResponseReserve(workerLifetime);
        var operationLifetime = workerLifetime - terminalResponseReserve;
        using var hardDeadline = new CancellationTokenSource(
            workerLifetime,
            timeProvider);
        using var operationDeadline = new CancellationTokenSource(
            operationLifetime,
            timeProvider);
        using var operationLinked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            operationDeadline.Token);

        DocumentExtractionRequest request;
        try
        {
            request = await FramedJsonTransport.ReadRequestAsync(
                    input,
                    operationLinked.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            operationDeadline.IsCancellationRequested
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
                    operationLinked.Token,
                    cancellationToken,
                    operationDeadline.Token)
                .ConfigureAwait(false);

            CancellationTokenSource? normalResponseLinked = null;
            var responseWriteToken = hardDeadline.Token;
            if (!operationLinked.IsCancellationRequested
                || response.FailureCode is not (
                    DocumentExtractionFailureCode.ExtractionCancelled
                    or DocumentExtractionFailureCode.ExtractionTimedOut))
            {
                normalResponseLinked =
                    CancellationTokenSource.CreateLinkedTokenSource(
                        cancellationToken,
                        hardDeadline.Token);
                responseWriteToken = normalResponseLinked.Token;
            }

            using (normalResponseLinked)
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
            hardDeadline.IsCancellationRequested
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
                await FramedJsonTransport.WriteResponseAsync(
                        output,
                        response,
                        hardDeadline.Token)
                    .ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The hard deadline and fixed diagnostic remain the reliable channels.
            }

            return 70;
        }
    }

    private static TimeSpan GetTerminalResponseReserve(TimeSpan workerLifetime)
    {
        var maximumReserve = TimeSpan.FromSeconds(1);
        if (workerLifetime > maximumReserve)
        {
            return maximumReserve;
        }

        var reserveTicks = Math.Max(1, workerLifetime.Ticks / 5);
        if (reserveTicks >= workerLifetime.Ticks)
        {
            reserveTicks = workerLifetime.Ticks / 2;
        }

        return TimeSpan.FromTicks(reserveTicks);
    }
}
