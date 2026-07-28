using System.Threading.Channels;

namespace LocalDocumentOrganizer.Application.Intake;

public sealed class DocumentIntakeService :
    IDocumentIntakeService,
    IAsyncDisposable
{
    private readonly IDocumentIntakeProcessor _processor;
    private readonly Channel<QueuedIntake> _channel;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _consumer;
    private readonly int _capacity;
    private int _queued;
    private int _waiting;
    private int _active;
    private long _accepted;
    private long _completed;
    private int _disposeStarted;

    public DocumentIntakeService(
        IDocumentIntakeProcessor processor,
        int capacity)
    {
        ArgumentNullException.ThrowIfNull(processor);
        if (capacity < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        _processor = processor;
        _capacity = capacity;
        _channel = Channel.CreateBounded<QueuedIntake>(
            new BoundedChannelOptions(capacity)
            {
                AllowSynchronousContinuations = false,
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false,
            });
        _consumer = ConsumeAsync();
    }

    public ValueTask<DocumentIntakeReceipt> EnqueuePickerAsync(
        string sourcePath,
        CancellationToken cancellationToken) =>
        EnqueueAsync(
            new DocumentIntakeRequest(
                sourcePath,
                DocumentIntakeOrigin.Picker),
            cancellationToken);

    public ValueTask<DocumentIntakeReceipt> EnqueueDropAsync(
        string sourcePath,
        CancellationToken cancellationToken) =>
        EnqueueAsync(
            new DocumentIntakeRequest(
                sourcePath,
                DocumentIntakeOrigin.Drop),
            cancellationToken);

    public DocumentIntakeQueueState GetQueueState() =>
        new(
            _capacity,
            Volatile.Read(ref _queued),
            Volatile.Read(ref _waiting),
            Volatile.Read(ref _active),
            Interlocked.Read(ref _accepted),
            Interlocked.Read(ref _completed));

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0)
        {
            await _consumer.ConfigureAwait(false);
            return;
        }

        _channel.Writer.TryComplete();
        _shutdown.Cancel();
        try
        {
            await _consumer.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }
        finally
        {
            _shutdown.Dispose();
        }
    }

    private async ValueTask<DocumentIntakeReceipt> EnqueueAsync(
        DocumentIntakeRequest request,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposeStarted) != 0,
            this);
        var queued = new QueuedIntake(
            Guid.NewGuid(),
            request,
            cancellationToken);
        var written = false;
        Interlocked.Increment(ref _waiting);
        try
        {
            while (await _channel.Writer.WaitToWriteAsync(
                       cancellationToken).ConfigureAwait(false))
            {
                Interlocked.Increment(ref _queued);
                if (_channel.Writer.TryWrite(queued))
                {
                    written = true;
                    break;
                }

                Interlocked.Decrement(ref _queued);
            }
        }
        finally
        {
            Interlocked.Decrement(ref _waiting);
        }

        ObjectDisposedException.ThrowIf(!written, this);
        Interlocked.Increment(ref _accepted);
        return new DocumentIntakeReceipt(
            queued.SubmissionId,
            queued.Completion.Task);
    }

    private async Task ConsumeAsync()
    {
        try
        {
            await foreach (var item in _channel.Reader.ReadAllAsync(
                               _shutdown.Token).ConfigureAwait(false))
            {
                Interlocked.Decrement(ref _queued);
                Interlocked.Increment(ref _active);
                try
                {
                    using var processingCancellation =
                        CancellationTokenSource.CreateLinkedTokenSource(
                            item.CancellationToken,
                            _shutdown.Token);
                    var result = await _processor.ProcessAsync(
                            item.Request,
                            processingCancellation.Token)
                        .ConfigureAwait(false);
                    item.Completion.TrySetResult(result);
                }
                catch (OperationCanceledException exception)
                {
                    item.Completion.TrySetCanceled(
                        exception.CancellationToken);
                }
                catch (Exception)
                {
                    item.Completion.TrySetResult(
                        DocumentIntakeResult.RetryRequired(
                            DocumentIntakeFailureCode.StorageUnavailable));
                }
                finally
                {
                    Interlocked.Decrement(ref _active);
                    Interlocked.Increment(ref _completed);
                }
            }
        }
        finally
        {
            while (_channel.Reader.TryRead(out var pending))
            {
                Interlocked.Decrement(ref _queued);
                Interlocked.Increment(ref _completed);
                pending.Completion.TrySetCanceled(_shutdown.Token);
            }
        }
    }

    private sealed class QueuedIntake
    {
        internal QueuedIntake(
            Guid submissionId,
            DocumentIntakeRequest request,
            CancellationToken cancellationToken)
        {
            SubmissionId = submissionId;
            Request = request;
            CancellationToken = cancellationToken;
        }

        internal Guid SubmissionId { get; }

        internal DocumentIntakeRequest Request { get; }

        internal CancellationToken CancellationToken { get; }

        internal TaskCompletionSource<DocumentIntakeResult> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
