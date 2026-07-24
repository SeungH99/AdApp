using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Core.Transactions;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public sealed record FileOperationBatchItemResult(
    OperationId OperationId,
    FileOperationExecutionResult Result);

public sealed record FileOperationBatchExecutionResult
{
    public FileOperationBatchExecutionResult(
        IEnumerable<FileOperationBatchItemResult> items,
        bool stoppedByCancellation)
    {
        ArgumentNullException.ThrowIfNull(items);
        var snapshot = items.ToArray();
        if (snapshot.Any(item => item is null))
            throw new ArgumentException(
                "Batch results cannot contain null items.",
                nameof(items));
        Items = Array.AsReadOnly(snapshot);
        StoppedByCancellation = stoppedByCancellation;
    }

    public IReadOnlyList<FileOperationBatchItemResult> Items { get; }

    public bool StoppedByCancellation { get; }
}

public sealed class FileOperationBatchCoordinator
{
    private readonly IFileOperationExecutor _executor;

    public FileOperationBatchCoordinator(IFileOperationExecutor executor)
    {
        ArgumentNullException.ThrowIfNull(executor);
        _executor = executor;
    }

    public async Task<FileOperationBatchExecutionResult> ExecuteAsync(
        IEnumerable<FileOperationExecutionRequest> requests,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requests);
        var snapshot = requests.ToArray();
        if (snapshot.Length is < 1 or > FileOperationBatch.MaximumIntentCount)
        {
            throw new ArgumentException(
                "A batch must contain between one and 100 requests.",
                nameof(requests));
        }

        if (snapshot.Any(request => request is null))
            throw new ArgumentException(
                "A batch cannot contain a null request.",
                nameof(requests));
        if (snapshot
                .Select(request => request.Intent.OperationId)
                .Distinct()
                .Count() != snapshot.Length)
        {
            throw new ArgumentException(
                "A batch must contain independent operation IDs.",
                nameof(requests));
        }

        var results = new List<FileOperationBatchItemResult>(snapshot.Length);
        foreach (var request in snapshot)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return new FileOperationBatchExecutionResult(
                    results,
                    stoppedByCancellation: true);
            }

            try
            {
                var result = await _executor
                    .ExecuteAsync(request, cancellationToken)
                    .ConfigureAwait(false);
                results.Add(new FileOperationBatchItemResult(
                    request.Intent.OperationId,
                    result));
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return new FileOperationBatchExecutionResult(
                    results,
                    stoppedByCancellation: true);
            }
            catch (Exception exception) when (
                exception is not OutOfMemoryException
                and not AccessViolationException)
            {
                results.Add(new FileOperationBatchItemResult(
                    request.Intent.OperationId,
                    new FileOperationUnexpectedFailure()));
            }
        }

        return new FileOperationBatchExecutionResult(
            results,
            stoppedByCancellation: false);
    }
}
