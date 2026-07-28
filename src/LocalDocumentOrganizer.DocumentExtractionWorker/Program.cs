using System.Collections.Immutable;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.DocumentExtractionWorker.Extraction;
using LocalDocumentOrganizer.DocumentExtractionWorker.Protocol;

namespace LocalDocumentOrganizer.DocumentExtractionWorker;

public static class Program
{
    public static async Task<int> Main()
    {
        var adapters = ProductionDocumentExtractionAdapters.Create();
        var output = Console.OpenStandardOutput();
        output.Write(DocumentExtractionProtocol.WorkerReadinessPreamble);
        await output.FlushAsync(CancellationToken.None).ConfigureAwait(false);

        return await RunAsync(
                Console.OpenStandardInput(),
                output,
                Console.Error,
                adapters,
                TimeSpan.FromMilliseconds(
                    DocumentExtractionLimits.ExtractionTimeoutMilliseconds),
                TimeProvider.System,
                CancellationToken.None)
            .ConfigureAwait(false);
    }

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

        DocumentWorkerRequestEnvelope request;
        try
        {
            request = await FramedJsonTransport.ReadOperationAsync(
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
            object response;
            if (request.Operation
                    == DocumentWorkerOperation.ExtractDocument
                && request.ExtractionRequest is { } extractionRequest)
            {
                var processor =
                    new DocumentExtractionProcessor(adapters);
                response = await processor.ProcessAsync(
                        extractionRequest,
                        operationLinked.Token,
                        cancellationToken,
                        operationDeadline.Token)
                    .ConfigureAwait(false);
            }
            else if (request.Operation
                         == DocumentWorkerOperation.InspectDocument
                     && request.InspectionRequest
                         is { } inspectionRequest)
            {
                var processor =
                    new DocumentInspectionProcessor(adapters);
                response = await processor.ProcessAsync(
                        inspectionRequest,
                        operationLinked.Token,
                        cancellationToken,
                        operationDeadline.Token)
                    .ConfigureAwait(false);
            }
            else
            {
                throw new InvalidDataException(
                    "The Worker operation is invalid.");
            }

            CancellationTokenSource? normalResponseLinked = null;
            var responseWriteToken = hardDeadline.Token;
            if (!operationLinked.IsCancellationRequested
                || !IsCancellationFailure(response))
            {
                normalResponseLinked =
                    CancellationTokenSource.CreateLinkedTokenSource(
                        cancellationToken,
                        hardDeadline.Token);
                responseWriteToken = normalResponseLinked.Token;
            }

            using (normalResponseLinked)
            {
                await WriteResponseAsync(
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
            var response = CreateInternalFailure(request);

            try
            {
                await WriteResponseAsync(
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

    private static bool IsCancellationFailure(object response) =>
        response switch
        {
            DocumentExtractionResponse extraction =>
                extraction.FailureCode is
                    DocumentExtractionFailureCode.ExtractionCancelled
                    or DocumentExtractionFailureCode.ExtractionTimedOut,
            DocumentInspectionResponse inspection =>
                inspection.FailureCode is
                    DocumentExtractionFailureCode.ExtractionCancelled
                    or DocumentExtractionFailureCode.ExtractionTimedOut,
            _ => false,
        };

    private static Task WriteResponseAsync(
        Stream output,
        object response,
        CancellationToken cancellationToken) =>
        response switch
        {
            DocumentExtractionResponse extraction =>
                FramedJsonTransport.WriteResponseAsync(
                    output,
                    extraction,
                    cancellationToken),
            DocumentInspectionResponse inspection =>
                FramedJsonTransport.WriteInspectionResponseAsync(
                    output,
                    inspection,
                    cancellationToken),
            _ => throw new InvalidDataException(
                "The Worker response type is invalid."),
        };

    private static object CreateInternalFailure(
        DocumentWorkerRequestEnvelope request)
    {
        if (request.InspectionRequest is { } inspection)
        {
            return DocumentInspectionProcessor.Failure(
                inspection,
                DocumentExtractionFailureCode.InternalFailure);
        }

        var extraction = request.ExtractionRequest
            ?? throw new InvalidDataException(
                "The Worker request type is invalid.");
        return new DocumentExtractionResponse(
            DocumentExtractionProtocol.CurrentVersion,
            extraction.JobId,
            DocumentExtractionOutcome.Failure,
            ImmutableArray<TextFragment>.Empty,
            ImmutableArray<DocumentSourcePage>.Empty,
            new ExtractionRuntimeMetadata(
                "worker",
                "1",
                string.Empty,
                null),
            0,
            DocumentExtractionFailureCode.InternalFailure);
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
