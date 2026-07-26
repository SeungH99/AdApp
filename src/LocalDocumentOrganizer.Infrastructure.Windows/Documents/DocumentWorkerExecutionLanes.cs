using System.Collections.Concurrent;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Documents;

internal readonly struct DocumentWorkerDeadlineStamp
{
    private readonly TimeProvider _timeProvider;
    private readonly long _startedAt;
    private readonly TimeSpan _budget;

    private DocumentWorkerDeadlineStamp(
        TimeProvider timeProvider,
        long startedAt,
        TimeSpan budget,
        CancellationToken cancellationToken)
    {
        _timeProvider = timeProvider;
        _startedAt = startedAt;
        _budget = budget;
        CancellationToken = cancellationToken;
    }

    internal CancellationToken CancellationToken { get; }

    internal TimeSpan Remaining
    {
        get
        {
            var remaining = _budget - _timeProvider.GetElapsedTime(
                _startedAt,
                _timeProvider.GetTimestamp());
            return remaining > TimeSpan.Zero
                ? remaining
                : TimeSpan.Zero;
        }
    }

    internal bool IsExpired =>
        CancellationToken.IsCancellationRequested
        || Remaining <= TimeSpan.Zero;

    internal static DocumentWorkerDeadlineStamp FromNow(
        TimeSpan budget,
        CancellationToken cancellationToken,
        TimeProvider? timeProvider = null)
    {
        if (budget <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(budget));
        }

        var effectiveTimeProvider = timeProvider ?? TimeProvider.System;
        return new DocumentWorkerDeadlineStamp(
            effectiveTimeProvider,
            effectiveTimeProvider.GetTimestamp(),
            budget,
            cancellationToken);
    }

    internal void ThrowIfExpired()
    {
        CancellationToken.ThrowIfCancellationRequested();
        if (Remaining <= TimeSpan.Zero)
        {
            throw new OperationCanceledException(CancellationToken);
        }
    }
}

internal enum DedicatedDeadlineSignal
{
    Expired,
    Shutdown,
}

internal interface IDedicatedDeadlineRegistration : IDisposable;

internal sealed class DedicatedMonotonicDeadlineScheduler : IDisposable
{
    private readonly object _gate = new();
    private readonly PriorityQueue<ScheduledDeadline, long> _scheduled = new();
    private readonly Thread _thread;
    private readonly int _capacity;
    private int _activeCount;
    private bool _disposed;

    internal DedicatedMonotonicDeadlineScheduler(int capacity)
    {
        if (capacity <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }

        _capacity = capacity;
        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = "LDO document deadline scheduler",
        };
        _thread.Start();
    }

    internal static DedicatedMonotonicDeadlineScheduler Shared { get; } =
        new(256);

    internal IDedicatedDeadlineRegistration Schedule(
        DocumentWorkerDeadlineStamp deadline,
        Action<DedicatedDeadlineSignal> callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        ScheduledDeadline? scheduled = null;
        DedicatedDeadlineSignal? rejection = null;
        lock (_gate)
        {
            if (!_disposed && _activeCount < _capacity)
            {
                scheduled = new ScheduledDeadline(this, deadline, callback);
                _scheduled.Enqueue(
                    scheduled,
                    CalculateDueTimestamp(deadline));
                _activeCount++;
                Monitor.Pulse(_gate);
            }
            else
            {
                rejection = _disposed
                    ? DedicatedDeadlineSignal.Shutdown
                    : DedicatedDeadlineSignal.Expired;
            }
        }

        if (scheduled is not null)
        {
            return scheduled;
        }

        callback(rejection!.Value);
        return EmptyDeadlineRegistration.Instance;
    }

    public void Dispose()
    {
        List<ScheduledDeadline> pending = [];
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            while (_scheduled.TryDequeue(out var scheduled, out _))
            {
                if (scheduled.TrySignal())
                {
                    pending.Add(scheduled);
                }
            }

            _activeCount = 0;
            Monitor.PulseAll(_gate);
        }

        foreach (var scheduled in pending)
        {
            scheduled.Invoke(DedicatedDeadlineSignal.Shutdown);
        }
    }

    private void Run()
    {
        while (true)
        {
            ScheduledDeadline? due = null;
            lock (_gate)
            {
                ScheduledDeadline? candidate;
                while (due is null)
                {
                    if (_disposed)
                    {
                        return;
                    }

                    while (_scheduled.TryPeek(out candidate, out _)
                           && !candidate.IsActive)
                    {
                        _scheduled.Dequeue();
                    }

                    if (!_scheduled.TryPeek(out candidate, out _))
                    {
                        Monitor.Wait(_gate);
                        continue;
                    }

                    var remaining = candidate.Deadline.Remaining;
                    if (remaining > TimeSpan.Zero)
                    {
                        Monitor.Wait(
                            _gate,
                            Math.Max(
                                1,
                                (int)Math.Min(
                                    int.MaxValue,
                                    Math.Ceiling(
                                        remaining.TotalMilliseconds))));
                        continue;
                    }

                    _scheduled.Dequeue();
                    if (candidate.TrySignal())
                    {
                        _activeCount--;
                        due = candidate;
                    }
                }
            }

            due.Invoke(DedicatedDeadlineSignal.Expired);
        }
    }

    private void Cancel(ScheduledDeadline scheduled)
    {
        lock (_gate)
        {
            if (scheduled.TrySignal())
            {
                _activeCount--;
                Monitor.Pulse(_gate);
            }
        }
    }

    private static long CalculateDueTimestamp(
        DocumentWorkerDeadlineStamp deadline)
    {
        var now = TimeProvider.System.GetTimestamp();
        var remaining = deadline.Remaining;
        var delta = remaining.TotalSeconds
                    * TimeProvider.System.TimestampFrequency;
        if (delta >= long.MaxValue - now)
        {
            return long.MaxValue;
        }

        return now + (long)Math.Ceiling(Math.Max(0, delta));
    }

    private sealed class ScheduledDeadline(
        DedicatedMonotonicDeadlineScheduler owner,
        DocumentWorkerDeadlineStamp deadline,
        Action<DedicatedDeadlineSignal> callback)
        : IDedicatedDeadlineRegistration
    {
        private int _state;

        internal DocumentWorkerDeadlineStamp Deadline { get; } = deadline;

        internal bool IsActive => Volatile.Read(ref _state) == 0;

        internal bool TrySignal() =>
            Interlocked.CompareExchange(ref _state, 1, 0) == 0;

        internal void Invoke(DedicatedDeadlineSignal signal) =>
            callback(signal);

        public void Dispose() => owner.Cancel(this);
    }

    private sealed class EmptyDeadlineRegistration
        : IDedicatedDeadlineRegistration
    {
        internal static EmptyDeadlineRegistration Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}

internal sealed class DocumentWorkerExecutionLanes : IDisposable
{
    private readonly object _gate = new();
    private readonly object _cleanupGate = new();
    private readonly BlockingCollection<ILaunchWorkItem> _launchQueue;
    private readonly BlockingCollection<CleanupWorkItem> _cleanupQueue;
    private readonly HashSet<ILaunchWorkItem> _pending = [];
    private readonly DedicatedMonotonicDeadlineScheduler _scheduler;
    private readonly bool _ownsScheduler;
    private readonly Thread _launchThread;
    private readonly Thread _cleanupThread;
    private bool _cleanupReserved;
    private bool _disposed;

    internal DocumentWorkerExecutionLanes(
        int launchQueueCapacity,
        int schedulerCapacity)
        : this(
            launchQueueCapacity,
            new DedicatedMonotonicDeadlineScheduler(schedulerCapacity),
            ownsScheduler: true)
    {
    }

    private DocumentWorkerExecutionLanes(
        int launchQueueCapacity,
        DedicatedMonotonicDeadlineScheduler scheduler,
        bool ownsScheduler)
    {
        if (launchQueueCapacity <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(launchQueueCapacity));
        }

        _scheduler = scheduler;
        _ownsScheduler = ownsScheduler;
        _launchQueue = new BlockingCollection<ILaunchWorkItem>(
            new ConcurrentQueue<ILaunchWorkItem>(),
            launchQueueCapacity);
        _cleanupQueue = new BlockingCollection<CleanupWorkItem>(
            new ConcurrentQueue<CleanupWorkItem>(),
            boundedCapacity: 1);
        _launchThread = new Thread(RunLaunchLane)
        {
            IsBackground = true,
            Name = "LDO document native launch lane",
        };
        _cleanupThread = new Thread(RunCleanupLane)
        {
            IsBackground = true,
            Name = "LDO document cleanup lane",
        };
        _launchThread.Start();
        _cleanupThread.Start();
    }

    internal static DocumentWorkerExecutionLanes Shared { get; } =
        new(
            launchQueueCapacity: 1,
            DedicatedMonotonicDeadlineScheduler.Shared,
            ownsScheduler: false);

    internal Task<T> LaunchAsync<T>(
        DocumentWorkerDeadlineStamp deadline,
        SafeFileHandle source,
        Func<SafeFileHandle, DocumentWorkerCleanupReservation, T> launch)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(launch);
        var work = new LaunchWorkItem<T>(
            this,
            deadline,
            source,
            launch);
        lock (_gate)
        {
            if (_disposed)
            {
                work.Shutdown();
                return work.Task;
            }

            _pending.Add(work);
            work.Monitor(_scheduler);
            _launchQueue.TryAdd(work);
        }

        return work.Task;
    }

    public void Dispose()
    {
        ILaunchWorkItem[] pending;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            pending = [.. _pending];
            _launchQueue.CompleteAdding();
        }

        foreach (var work in pending)
        {
            work.Shutdown();
        }

        CleanupWorkItem[] cleanup;
        lock (_cleanupGate)
        {
            _cleanupQueue.CompleteAdding();
            cleanup = _cleanupQueue.ToArray();
            Monitor.PulseAll(_cleanupGate);
        }

        foreach (var work in cleanup)
        {
            work.Shutdown();
        }

        if (_ownsScheduler)
        {
            _scheduler.Dispose();
        }
    }

    private void RunLaunchLane()
    {
        foreach (var work in _launchQueue.GetConsumingEnumerable())
        {
            work.Execute();
        }
    }

    private void RunCleanupLane()
    {
        foreach (var work in _cleanupQueue.GetConsumingEnumerable())
        {
            work.Execute();
        }
    }

    private DocumentWorkerCleanupReservation AcquireCleanup(
        DocumentWorkerDeadlineStamp deadline)
    {
        lock (_cleanupGate)
        {
            while (_cleanupReserved && !_disposed)
            {
                deadline.ThrowIfExpired();
                var remaining = deadline.Remaining;
                Monitor.Wait(
                    _cleanupGate,
                    Math.Max(
                        1,
                        (int)Math.Min(
                            25,
                            Math.Ceiling(remaining.TotalMilliseconds))));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(
                    nameof(DocumentWorkerExecutionLanes));
            }

            deadline.ThrowIfExpired();
            _cleanupReserved = true;
            return new DocumentWorkerCleanupReservation(this);
        }
    }

    private Task SubmitCleanupAsync(
        DocumentWorkerCleanupReservation reservation,
        Action cleanup)
    {
        var work = new CleanupWorkItem(reservation, cleanup);
        lock (_cleanupGate)
        {
            if (_disposed || !_cleanupQueue.TryAdd(work))
            {
                work.Shutdown();
            }
        }

        return work.Task;
    }

    private void ReleaseCleanup(
        DocumentWorkerCleanupReservation reservation)
    {
        lock (_cleanupGate)
        {
            if (_cleanupReserved)
            {
                _cleanupReserved = false;
                Monitor.PulseAll(_cleanupGate);
            }
        }
    }

    private void Remove(ILaunchWorkItem work)
    {
        lock (_gate)
        {
            _pending.Remove(work);
        }
    }

    internal sealed class LaunchWorkItem<T> : ILaunchWorkItem
    {
        private readonly DocumentWorkerExecutionLanes _owner;
        private readonly DocumentWorkerDeadlineStamp _deadline;
        private readonly SafeFileHandle _source;
        private readonly Func<
            SafeFileHandle,
            DocumentWorkerCleanupReservation,
            T> _launch;
        // Inline completion keeps deadline delivery independent of the shared
        // ThreadPool. Terminal paths release their state before signaling.
        private readonly TaskCompletionSource<T> _completion = new();
        private IDedicatedDeadlineRegistration? _deadlineRegistration;
        private CancellationTokenRegistration _cancellationRegistration;
        private int _state;

        internal LaunchWorkItem(
            DocumentWorkerExecutionLanes owner,
            DocumentWorkerDeadlineStamp deadline,
            SafeFileHandle source,
            Func<
                SafeFileHandle,
                DocumentWorkerCleanupReservation,
                T> launch)
        {
            _owner = owner;
            _deadline = deadline;
            _source = source;
            _launch = launch;
        }

        internal Task<T> Task => _completion.Task;

        public void Monitor(
            DedicatedMonotonicDeadlineScheduler scheduler)
        {
            var deadlineRegistration = scheduler.Schedule(
                _deadline,
                signal =>
                {
                    if (signal == DedicatedDeadlineSignal.Shutdown)
                    {
                        Shutdown();
                    }
                    else
                    {
                        Cancel();
                    }
                });
            var cancellationRegistration =
                _deadline.CancellationToken.Register(Cancel);
            _deadlineRegistration = deadlineRegistration;
            _cancellationRegistration = cancellationRegistration;
            if (Volatile.Read(ref _state) == 2)
            {
                deadlineRegistration.Dispose();
                cancellationRegistration.Dispose();
            }
        }

        public void Execute()
        {
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
            {
                return;
            }

            DocumentWorkerCleanupReservation? cleanup = null;
            try
            {
                _deadline.ThrowIfExpired();
                cleanup = _owner.AcquireCleanup(_deadline);
                _deadline.ThrowIfExpired();
                using var nativeSource =
                    DocumentExtractionClient.DuplicateReadOnly(_source);
                _deadline.ThrowIfExpired();
                var result = _launch(nativeSource, cleanup);
                cleanup = null;
                Complete(result);
            }
            catch (Exception exception)
            {
                cleanup?.Dispose();
                CompleteException(exception);
            }
        }

        public void Shutdown()
        {
            if (Interlocked.CompareExchange(ref _state, 2, 0) == 0)
            {
                Finish();
                _completion.TrySetException(
                    new ObjectDisposedException(
                        nameof(DocumentWorkerExecutionLanes)));
            }
        }

        private void Cancel()
        {
            if (Interlocked.CompareExchange(ref _state, 2, 0) == 0)
            {
                Finish();
                _completion.TrySetException(
                    new OperationCanceledException(
                        _deadline.CancellationToken));
            }
        }

        private void Complete(T result)
        {
            Interlocked.Exchange(ref _state, 2);
            Finish();
            _completion.TrySetResult(result);
        }

        private void CompleteException(Exception exception)
        {
            Interlocked.Exchange(ref _state, 2);
            Finish();
            _completion.TrySetException(exception);
        }

        private void Finish()
        {
            _deadlineRegistration?.Dispose();
            _cancellationRegistration.Unregister();
            _owner.Remove(this);
        }
    }

    private interface ILaunchWorkItem
    {
        void Monitor(DedicatedMonotonicDeadlineScheduler scheduler);

        void Execute();

        void Shutdown();
    }

    private sealed class CleanupWorkItem(
        DocumentWorkerCleanupReservation reservation,
        Action cleanup)
    {
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _state;

        internal Task Task => _completion.Task;

        internal void Execute()
        {
            if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
            {
                return;
            }

            Exception? failure = null;
            try
            {
                cleanup();
            }
            catch (Exception exception)
            {
                failure = exception;
            }
            finally
            {
                Interlocked.Exchange(ref _state, 2);
                reservation.Release();
            }

            if (failure is null)
            {
                _completion.TrySetResult();
            }
            else
            {
                _completion.TrySetException(failure);
            }
        }

        internal void Shutdown()
        {
            if (Interlocked.CompareExchange(ref _state, 2, 0) == 0)
            {
                _completion.TrySetException(
                    new ObjectDisposedException(
                        nameof(DocumentWorkerExecutionLanes)));
                reservation.Release();
            }
        }
    }

    internal sealed class CleanupReservationBridge
    {
        internal static Task Submit(
            DocumentWorkerExecutionLanes owner,
            DocumentWorkerCleanupReservation reservation,
            Action cleanup) =>
            owner.SubmitCleanupAsync(reservation, cleanup);

        internal static void Release(
            DocumentWorkerExecutionLanes owner,
            DocumentWorkerCleanupReservation reservation) =>
            owner.ReleaseCleanup(reservation);
    }
}

internal sealed class DocumentWorkerCleanupReservation : IDisposable
{
    private readonly DocumentWorkerExecutionLanes _owner;
    private int _state;

    internal DocumentWorkerCleanupReservation(
        DocumentWorkerExecutionLanes owner)
    {
        _owner = owner;
    }

    internal ValueTask ExecuteAsync(Action cleanup)
    {
        ArgumentNullException.ThrowIfNull(cleanup);
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
        {
            throw new InvalidOperationException(
                "The cleanup reservation was already consumed.");
        }

        return new ValueTask(
            DocumentWorkerExecutionLanes.CleanupReservationBridge.Submit(
                _owner,
                this,
                cleanup));
    }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _state, 2, 0) == 0)
        {
            DocumentWorkerExecutionLanes.CleanupReservationBridge.Release(
                _owner,
                this);
        }
    }

    internal void Release()
    {
        Interlocked.Exchange(ref _state, 2);
        DocumentWorkerExecutionLanes.CleanupReservationBridge.Release(
            _owner,
            this);
    }
}
