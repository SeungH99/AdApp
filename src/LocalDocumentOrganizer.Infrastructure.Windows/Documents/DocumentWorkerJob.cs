using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Documents;

public readonly record struct DocumentWorkerJobLimits(
    bool KillOnJobClose,
    uint ActiveProcessLimit,
    long ProcessMemoryLimit);

public sealed class DocumentWorkerJob : IDisposable
{
    private const uint JobObjectLimitActiveProcess = 0x00000008;
    private const uint JobObjectLimitProcessMemory = 0x00000100;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const long RequiredMemoryLimit = 512L * 1024 * 1024;
    private const uint JobObjectMessageProcessMemoryLimit = 9;

    private SafeKernelHandle? _handle;
    private SafeKernelHandle? _completionPort;
    private int _processMemoryLimitReached;

    public DocumentWorkerJob()
    {
        var handle = WorkerNativeMethods.CreateJobObjectW(IntPtr.Zero, null);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new AppContainerLaunchException(
                "Job Object creation failed.",
                new Win32Exception(error));
        }

        try
        {
            var information =
                new WorkerNativeMethods.JobObjectExtendedLimitInformation
                {
                    BasicLimitInformation =
                    {
                        LimitFlags = JobObjectLimitKillOnJobClose
                            | JobObjectLimitActiveProcess
                            | JobObjectLimitProcessMemory,
                        ActiveProcessLimit = 1,
                    },
                    ProcessMemoryLimit = (UIntPtr)RequiredMemoryLimit,
                };
            if (!WorkerNativeMethods.SetInformationJobObject(
                    handle,
                    WorkerNativeMethods.JobObjectInformationClass
                        .ExtendedLimitInformation,
                    ref information,
                    checked((uint)Marshal.SizeOf(information))))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            var completionPort = WorkerNativeMethods.CreateIoCompletionPort(
                new IntPtr(-1),
                IntPtr.Zero,
                UIntPtr.Zero,
                1);
            if (completionPort.IsInvalid)
            {
                var error = Marshal.GetLastPInvokeError();
                completionPort.Dispose();
                throw new Win32Exception(error);
            }

            try
            {
                var association =
                    new WorkerNativeMethods.JobObjectAssociateCompletionPort
                    {
                        CompletionKey = new IntPtr(1),
                        CompletionPort =
                            completionPort.DangerousGetHandle(),
                    };
                if (!WorkerNativeMethods.SetInformationJobObjectCompletionPort(
                        handle,
                        WorkerNativeMethods.JobObjectInformationClass
                            .AssociateCompletionPortInformation,
                        ref association,
                        checked((uint)Marshal.SizeOf(association))))
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError());
                }

                _completionPort = completionPort;
            }
            catch
            {
                completionPort.Dispose();
                throw;
            }

            _handle = handle;
        }
        catch (Exception exception)
        {
            handle.Dispose();
            throw new AppContainerLaunchException(
                "Job Object limit configuration failed.",
                exception);
        }
    }

    public DocumentWorkerJobLimits QueryLimits()
    {
        var handle = GetHandle();
        if (!WorkerNativeMethods.QueryInformationJobObject(
                handle,
                WorkerNativeMethods.JobObjectInformationClass
                    .ExtendedLimitInformation,
                out var information,
                checked((uint)Marshal.SizeOf<
                    WorkerNativeMethods.JobObjectExtendedLimitInformation>()),
                out _))
        {
            throw new AppContainerLaunchException(
                "Job Object limit query failed.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        var flags = information.BasicLimitInformation.LimitFlags;
        return new DocumentWorkerJobLimits(
            (flags & JobObjectLimitKillOnJobClose) != 0,
            information.BasicLimitInformation.ActiveProcessLimit,
            checked((long)information.ProcessMemoryLimit.ToUInt64()));
    }

    internal void Assign(SafeKernelHandle process)
    {
        if (!WorkerNativeMethods.AssignProcessToJobObject(GetHandle(), process))
        {
            throw new AppContainerLaunchException(
                "The suspended worker could not be assigned to its Job Object.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }
    }

    internal void Terminate(uint exitCode)
    {
        var handle = _handle;
        if (handle is null || handle.IsClosed || handle.IsInvalid)
        {
            return;
        }

        if (!WorkerNativeMethods.TerminateJobObject(handle, exitCode))
        {
            var error = Marshal.GetLastPInvokeError();
            const int errorAccessDenied = 5;
            if (error != errorAccessDenied)
            {
                throw new AppContainerLaunchException(
                    "The worker Job Object could not be terminated.",
                    new Win32Exception(error));
            }
        }
    }

    internal bool WasProcessMemoryLimitReached()
    {
        if (Volatile.Read(ref _processMemoryLimitReached) != 0)
        {
            return true;
        }

        var completionPort = _completionPort;
        if (completionPort is not null
            && !completionPort.IsClosed
            && !completionPort.IsInvalid)
        {
            var deadline = Environment.TickCount64 + 500;
            while (Environment.TickCount64 < deadline)
            {
                if (WorkerNativeMethods.GetQueuedCompletionStatus(
                        completionPort,
                        out var message,
                        out _,
                        out _,
                        50)
                    && message == JobObjectMessageProcessMemoryLimit)
                {
                    Volatile.Write(ref _processMemoryLimitReached, 1);
                    return true;
                }
            }
        }

        var handle = GetHandle();
        if (!WorkerNativeMethods.QueryInformationJobObject(
                handle,
                WorkerNativeMethods.JobObjectInformationClass
                    .ExtendedLimitInformation,
                out var information,
                checked((uint)Marshal.SizeOf<
                    WorkerNativeMethods.JobObjectExtendedLimitInformation>()),
                out _))
        {
            return false;
        }

        var limit = information.ProcessMemoryLimit.ToUInt64();
        var peak = information.PeakProcessMemoryUsed.ToUInt64();
        return limit != 0 && peak >= limit;
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _handle, null)?.Dispose();
        Interlocked.Exchange(ref _completionPort, null)?.Dispose();
    }

    private SafeKernelHandle GetHandle() =>
        _handle is { IsClosed: false, IsInvalid: false } handle
            ? handle
            : throw new ObjectDisposedException(nameof(DocumentWorkerJob));
}
