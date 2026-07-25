namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public sealed class FileMutationGate
{
    private static readonly SemaphoreSlim ProcessGate = new(1, 1);

    public async ValueTask<FileMutationLease> AcquireAsync(
        CancellationToken cancellationToken)
    {
        await ProcessGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new FileMutationLease();
    }

    public sealed class FileMutationLease : IDisposable, IAsyncDisposable
    {
        private int _disposed;

        internal FileMutationLease()
        {
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                ProcessGate.Release();
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
