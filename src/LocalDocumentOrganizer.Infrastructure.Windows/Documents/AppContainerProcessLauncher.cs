using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

[assembly: InternalsVisibleTo(
    "LocalDocumentOrganizer.WorkerSecurity.Tests")]

namespace LocalDocumentOrganizer.Infrastructure.Windows.Documents;

internal enum WorkerLaunchFaultPoint
{
    BeforeJobAssignment,
    BeforeThreadResume,
    BeforeOutputStreamConstruction,
    BeforeTerminationWait,
}

internal interface IWorkerLaunchFaultInjector
{
    void ThrowIfRequested(
        WorkerLaunchFaultPoint point,
        uint processId);
}

internal sealed class NoOpWorkerLaunchFaultInjector
    : IWorkerLaunchFaultInjector
{
    internal static NoOpWorkerLaunchFaultInjector Instance { get; } = new();

    private NoOpWorkerLaunchFaultInjector()
    {
    }

    public void ThrowIfRequested(
        WorkerLaunchFaultPoint point,
        uint processId)
    {
    }
}

public sealed class AppContainerLaunchException : Exception
{
    public AppContainerLaunchException(
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
    }

    internal static AppContainerLaunchException FromHResult(
        string operation,
        int result) =>
        new(
            $"{operation} failed.",
            Marshal.GetExceptionForHR(result));
}

public sealed class AppContainerProcessLauncher
{
    private readonly AppContainerProfile _profile;
    private readonly IWorkerLaunchFaultInjector _faultInjector;

    public AppContainerProcessLauncher(AppContainerProfile profile)
        : this(profile, NoOpWorkerLaunchFaultInjector.Instance)
    {
    }

    internal AppContainerProcessLauncher(
        AppContainerProfile profile,
        IWorkerLaunchFaultInjector faultInjector)
    {
        _profile = profile ?? throw new ArgumentNullException(nameof(profile));
        _faultInjector = faultInjector
            ?? throw new ArgumentNullException(nameof(faultInjector));
    }

    public LaunchedAppContainerProcess Start(
        string executablePath,
        IReadOnlyList<string> arguments,
        SafeFileHandle source)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(source);
        if (!Path.IsPathFullyQualified(executablePath) || !File.Exists(executablePath))
        {
            throw new AppContainerLaunchException(
                "The configured document worker executable is unavailable.");
        }

        if (source.IsClosed || source.IsInvalid)
        {
            throw new AppContainerLaunchException(
                "The pinned source handle is unavailable.");
        }

        SafeFileHandle? childInput = null;
        SafeFileHandle? parentInput = null;
        SafeFileHandle? parentOutput = null;
        SafeFileHandle? childOutput = null;
        SafeFileHandle? inheritedSource = null;
        SafeKernelHandle? process = null;
        SafeKernelHandle? thread = null;
        DocumentWorkerJob? job = null;
        FileStream? inputStream = null;
        FileStream? outputStream = null;
        SafeSidHandle? profileSid = null;
        var profileSidAddedRef = false;
        IntPtr attributeList = IntPtr.Zero;
        var attributeListInitialized = false;
        IntPtr capabilitiesPointer = IntPtr.Zero;
        IntPtr handlesPointer = IntPtr.Zero;
        IntPtr environmentPointer = IntPtr.Zero;
        uint processId = 0;
        try
        {
            CreateProtocolPipes(
                out childInput,
                out parentInput,
                out parentOutput,
                out childOutput);
            inheritedSource = DuplicateReadOnlyInheritable(source);

            var handles = new[]
            {
                childInput.DangerousGetHandle(),
                childOutput.DangerousGetHandle(),
                inheritedSource.DangerousGetHandle(),
            };
            handlesPointer = Marshal.AllocHGlobal(
                checked(handles.Length * IntPtr.Size));
            Marshal.Copy(handles, 0, handlesPointer, handles.Length);

            profileSid = _profile.GetSidHandle();
            profileSid.DangerousAddRef(ref profileSidAddedRef);
            var capabilities = new WorkerNativeMethods.SecurityCapabilities
            {
                AppContainerSid = profileSid.DangerousGetHandle(),
                Capabilities = IntPtr.Zero,
                CapabilityCount = 0,
                Reserved = 0,
            };
            capabilitiesPointer = Marshal.AllocHGlobal(
                Marshal.SizeOf(capabilities));
            Marshal.StructureToPtr(
                capabilities,
                capabilitiesPointer,
                fDeleteOld: false);

            UIntPtr attributeListSize = UIntPtr.Zero;
            _ = WorkerNativeMethods.InitializeProcThreadAttributeList(
                IntPtr.Zero,
                2,
                0,
                ref attributeListSize);
            if (attributeListSize == UIntPtr.Zero
                || Marshal.GetLastPInvokeError()
                    != WorkerNativeMethods.ErrorInsufficientBuffer)
            {
                ThrowLastWin32("Process attribute-list sizing");
            }

            attributeList = Marshal.AllocHGlobal(
                checked((int)attributeListSize.ToUInt64()));
            if (!WorkerNativeMethods.InitializeProcThreadAttributeList(
                    attributeList,
                    2,
                    0,
                    ref attributeListSize))
            {
                ThrowLastWin32("Process attribute-list initialization");
            }

            attributeListInitialized = true;
            UpdateAttribute(
                attributeList,
                WorkerNativeMethods.ProcThreadAttributeHandleList,
                handlesPointer,
                checked((nuint)(handles.Length * IntPtr.Size)),
                "exact inherited-handle list");
            UpdateAttribute(
                attributeList,
                WorkerNativeMethods.ProcThreadAttributeSecurityCapabilities,
                capabilitiesPointer,
                checked((nuint)Marshal.SizeOf(capabilities)),
                "zero-capability AppContainer");

            var startupInfo = new WorkerNativeMethods.StartupInfoEx
            {
                StartupInfo =
                {
                    Size = checked((uint)Marshal.SizeOf<
                        WorkerNativeMethods.StartupInfoEx>()),
                    Flags = WorkerNativeMethods.StartfUseStdHandles,
                    StandardInput = childInput.DangerousGetHandle(),
                    StandardOutput = childOutput.DangerousGetHandle(),
                    StandardError = childOutput.DangerousGetHandle(),
                },
                AttributeList = attributeList,
            };
            var commandLine = new StringBuilder(
                BuildCommandLine(executablePath, arguments));
            environmentPointer = CreateMinimalEnvironmentBlock();
            job = new DocumentWorkerJob();
            if (!WorkerNativeMethods.CreateProcessW(
                    executablePath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    inheritHandles: true,
                    WorkerNativeMethods.CreateSuspended
                        | WorkerNativeMethods.CreateUnicodeEnvironment
                        | WorkerNativeMethods.ExtendedStartupInfoPresent,
                    environmentPointer,
                    _profile.FolderPath,
                    ref startupInfo,
                    out var processInformation))
            {
                ThrowLastWin32("Capability-free AppContainer process creation");
            }

            process = new SafeKernelHandle(processInformation.Process);
            thread = new SafeKernelHandle(processInformation.Thread);
            processId = processInformation.ProcessId;
            _faultInjector.ThrowIfRequested(
                WorkerLaunchFaultPoint.BeforeJobAssignment,
                processId);
            job.Assign(process);
            _faultInjector.ThrowIfRequested(
                WorkerLaunchFaultPoint.BeforeThreadResume,
                processId);
            var previousSuspendCount = WorkerNativeMethods.ResumeThread(thread);
            if (previousSuspendCount == uint.MaxValue)
            {
                ThrowLastWin32("Suspended worker resume");
            }

            if (previousSuspendCount != 1)
            {
                throw new AppContainerLaunchException(
                    "The worker primary thread had an unexpected suspend count.");
            }

            thread.Dispose();
            thread = null;
            childInput.Dispose();
            childInput = null;
            childOutput.Dispose();
            childOutput = null;
            inheritedSource.Dispose();
            inheritedSource = null;

            inputStream = new FileStream(
                parentInput,
                FileAccess.Write,
                bufferSize: 4096,
                isAsync: false);
            parentInput = null;
            _faultInjector.ThrowIfRequested(
                WorkerLaunchFaultPoint.BeforeOutputStreamConstruction,
                processId);
            outputStream = new FileStream(
                parentOutput,
                FileAccess.Read,
                bufferSize: 4096,
                isAsync: false);
            parentOutput = null;
            var launched = new LaunchedAppContainerProcess(
                process,
                job,
                inputStream,
                outputStream,
                processInformation.ProcessId,
                unchecked((ulong)handles[2].ToInt64()),
                _profile,
                _faultInjector);
            inputStream = null;
            outputStream = null;
            process = null;
            job = null;
            return launched;
        }
        catch (Exception exception)
        {
            if (process is not null)
            {
                try
                {
                    WorkerProcessTermination.TerminateAndWait(
                        process,
                        job,
                        _faultInjector,
                        processId,
                        0xE0000001,
                        0xE0000002);
                }
                catch (Exception cleanupException)
                {
                    _profile.MarkCleanupUnsafe();
                    TryAttachCleanupFailure(exception, cleanupException);
                }
            }

            if (exception is AppContainerLaunchException)
            {
                ExceptionDispatchInfo.Capture(exception).Throw();
            }

            throw new AppContainerLaunchException(
                "Capability-free document worker launch failed.",
                exception);
        }
        finally
        {
            thread?.Dispose();
            process?.Dispose();
            job?.Dispose();
            childInput?.Dispose();
            parentInput?.Dispose();
            parentOutput?.Dispose();
            childOutput?.Dispose();
            inheritedSource?.Dispose();
            inputStream?.Dispose();
            outputStream?.Dispose();
            if (attributeListInitialized)
            {
                WorkerNativeMethods.DeleteProcThreadAttributeList(attributeList);
            }

            if (attributeList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(attributeList);
            }

            if (capabilitiesPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(capabilitiesPointer);
            }

            if (handlesPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(handlesPointer);
            }

            if (environmentPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(environmentPointer);
            }

            if (profileSidAddedRef)
            {
                profileSid!.DangerousRelease();
            }
        }
    }

    private static void TryAttachCleanupFailure(
        Exception primaryException,
        Exception cleanupException)
    {
        try
        {
            primaryException.Data["AppContainerLaunchCleanup"] =
                cleanupException.Message;
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException)
        {
        }
    }

    private static void CreateProtocolPipes(
        out SafeFileHandle childInput,
        out SafeFileHandle parentInput,
        out SafeFileHandle parentOutput,
        out SafeFileHandle childOutput)
    {
        childInput = new SafeFileHandle(IntPtr.Zero, ownsHandle: true);
        parentInput = new SafeFileHandle(IntPtr.Zero, ownsHandle: true);
        parentOutput = new SafeFileHandle(IntPtr.Zero, ownsHandle: true);
        childOutput = new SafeFileHandle(IntPtr.Zero, ownsHandle: true);
        var attributes = new WorkerNativeMethods.SecurityAttributes
        {
            Length = checked((uint)Marshal.SizeOf<
                WorkerNativeMethods.SecurityAttributes>()),
            InheritHandle = true,
        };
        if (!WorkerNativeMethods.CreatePipe(
                out var childInputPointer,
                out var parentInputPointer,
                ref attributes,
                0))
        {
            ThrowLastWin32("Worker input-pipe creation");
        }

        childInput.Dispose();
        parentInput.Dispose();
        childInput = new SafeFileHandle(childInputPointer, ownsHandle: true);
        parentInput = new SafeFileHandle(parentInputPointer, ownsHandle: true);
        try
        {
            if (!WorkerNativeMethods.CreatePipe(
                    out var parentOutputPointer,
                    out var childOutputPointer,
                    ref attributes,
                    0))
            {
                ThrowLastWin32("Worker output-pipe creation");
            }

            parentOutput.Dispose();
            childOutput.Dispose();
            parentOutput =
                new SafeFileHandle(parentOutputPointer, ownsHandle: true);
            childOutput =
                new SafeFileHandle(childOutputPointer, ownsHandle: true);
            if (!WorkerNativeMethods.SetHandleInformation(
                    parentInput,
                    WorkerNativeMethods.HandleFlagInherit,
                    0)
                || !WorkerNativeMethods.SetHandleInformation(
                    parentOutput,
                    WorkerNativeMethods.HandleFlagInherit,
                    0))
            {
                ThrowLastWin32("Parent pipe inheritance removal");
            }
        }
        catch
        {
            childInput.Dispose();
            parentInput.Dispose();
            parentOutput.Dispose();
            childOutput.Dispose();
            throw;
        }
    }

    private static SafeFileHandle DuplicateReadOnlyInheritable(
        SafeFileHandle source)
    {
        var currentProcess = WorkerNativeMethods.GetCurrentProcess();
        if (!WorkerNativeMethods.DuplicateHandle(
                currentProcess,
                source,
                currentProcess,
                out var duplicate,
                WorkerNativeMethods.FileGenericRead,
                inheritHandle: true,
                options: 0))
        {
            ThrowLastWin32("Read-only source-handle duplication");
        }

        return new SafeFileHandle(duplicate, ownsHandle: true);
    }

    private static void UpdateAttribute(
        IntPtr attributeList,
        UIntPtr attribute,
        IntPtr value,
        nuint size,
        string operation)
    {
        if (!WorkerNativeMethods.UpdateProcThreadAttribute(
                attributeList,
                0,
                attribute,
                value,
                (UIntPtr)size,
                IntPtr.Zero,
                IntPtr.Zero))
        {
            ThrowLastWin32($"Process {operation} configuration");
        }
    }

    private static string BuildCommandLine(
        string executablePath,
        IReadOnlyList<string> arguments)
    {
        var builder = new StringBuilder(QuoteArgument(executablePath));
        foreach (var argument in arguments)
        {
            builder.Append(' ');
            builder.Append(QuoteArgument(argument));
        }

        return builder.ToString();
    }

    private IntPtr CreateMinimalEnvironmentBlock()
    {
        var windowsDirectory = Environment.GetFolderPath(
            Environment.SpecialFolder.Windows);
        if (!Path.IsPathFullyQualified(windowsDirectory))
        {
            throw new AppContainerLaunchException(
                "The Windows runtime directory is unavailable.");
        }

        var temporaryDirectory = Path.Combine(
            _profile.FolderPath,
            "Temp");
        Directory.CreateDirectory(temporaryDirectory);
        var entries = new[]
        {
            $"APPDATA={_profile.FolderPath}",
            $"COMPlus_EnableDiagnostics=0",
            $"DOTNET_CLI_TELEMETRY_OPTOUT=1",
            $"DOTNET_EnableDiagnostics=0",
            $"DOTNET_NOLOGO=1",
            $"LOCALAPPDATA={_profile.FolderPath}",
            $"SystemRoot={windowsDirectory}",
            $"TEMP={temporaryDirectory}",
            $"TMP={temporaryDirectory}",
            $"USERPROFILE={_profile.FolderPath}",
            $"windir={windowsDirectory}",
        };
        Array.Sort(entries, StringComparer.OrdinalIgnoreCase);
        var block = string.Join('\0', entries) + "\0\0";
        var characters = block.ToCharArray();
        var pointer = Marshal.AllocHGlobal(
            checked(characters.Length * sizeof(char)));
        Marshal.Copy(characters, 0, pointer, characters.Length);
        return pointer;
    }

    private static string QuoteArgument(string argument)
    {
        ArgumentNullException.ThrowIfNull(argument);
        if (argument.Length > 0
            && argument.IndexOfAny([' ', '\t', '"']) < 0)
        {
            return argument;
        }

        var builder = new StringBuilder(argument.Length + 2);
        builder.Append('"');
        var backslashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                builder.Append('\\', checked(backslashes * 2 + 1));
                builder.Append('"');
                backslashes = 0;
                continue;
            }

            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }

        builder.Append('\\', checked(backslashes * 2));
        builder.Append('"');
        return builder.ToString();
    }

    private static void ThrowLastWin32(string operation)
    {
        throw new AppContainerLaunchException(
            $"{operation} failed.",
            new Win32Exception(Marshal.GetLastPInvokeError()));
    }
}

public sealed class LaunchedAppContainerProcess : IAsyncDisposable, IDisposable
{
    private SafeKernelHandle? _process;
    private DocumentWorkerJob? _job;
    private readonly AppContainerProfile _profile;
    private readonly IWorkerLaunchFaultInjector _faultInjector;
    private int _disposed;

    internal LaunchedAppContainerProcess(
        SafeKernelHandle process,
        DocumentWorkerJob job,
        Stream standardInput,
        Stream standardOutput,
        uint processId,
        ulong inheritedSourceHandle,
        AppContainerProfile profile,
        IWorkerLaunchFaultInjector faultInjector)
    {
        _process = process;
        _job = job;
        _profile = profile;
        _faultInjector = faultInjector;
        StandardInput = standardInput;
        StandardOutput = standardOutput;
        ProcessId = processId;
        InheritedSourceHandle = inheritedSourceHandle;
    }

    public Stream StandardInput { get; }

    public Stream StandardOutput { get; }

    public uint ProcessId { get; }

    public ulong InheritedSourceHandle { get; }

    public uint ExitCode
    {
        get
        {
            if (!WorkerNativeMethods.GetExitCodeProcess(GetProcess(), out var code))
            {
                throw new AppContainerLaunchException(
                    "Worker exit-code query failed.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }

            return code;
        }
    }

    public async Task WaitForExitAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = WorkerNativeMethods.WaitForSingleObject(
                GetProcess(),
                50);
            if (result == WorkerNativeMethods.WaitObject0)
            {
                return;
            }

            if (result != WorkerNativeMethods.WaitTimeout)
            {
                throw new AppContainerLaunchException(
                    "Worker wait failed.",
                    new Win32Exception(Marshal.GetLastPInvokeError()));
            }

            await Task.Delay(25, cancellationToken).ConfigureAwait(false);
        }
    }

    public void Kill()
    {
        _job?.Terminate(0xE0000002);
    }

    internal bool WasProcessMemoryLimitReached() =>
        _job?.WasProcessMemoryLimitReached() == true;

    public void Dispose()
    {
        DisposeCore();
    }

    public ValueTask DisposeAsync()
    {
        DisposeCore();
        return ValueTask.CompletedTask;
    }

    private void DisposeCore()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Exception? cleanupFailure = null;
        try
        {
            try
            {
                WorkerProcessTermination.TerminateAndWait(
                    GetProcess(),
                    _job,
                    _faultInjector,
                    ProcessId,
                    0xE0000003,
                    0xE0000004);
            }
            catch (Exception exception)
            {
                _profile.MarkCleanupUnsafe();
                cleanupFailure = exception;
            }
        }
        finally
        {
            try
            {
                StandardInput.Dispose();
            }
            catch (Exception exception)
            {
                cleanupFailure ??= exception;
            }

            try
            {
                StandardOutput.Dispose();
            }
            catch (Exception exception)
            {
                cleanupFailure ??= exception;
            }

            try
            {
                Interlocked.Exchange(ref _job, null)?.Dispose();
            }
            finally
            {
                Interlocked.Exchange(ref _process, null)?.Dispose();
            }
        }

        if (cleanupFailure is not null)
        {
            ExceptionDispatchInfo.Capture(cleanupFailure).Throw();
        }
    }

    private SafeKernelHandle GetProcess() =>
        _process is { IsClosed: false, IsInvalid: false } process
            ? process
            : throw new ObjectDisposedException(
                nameof(LaunchedAppContainerProcess));

}

internal static class WorkerProcessTermination
{
    private const uint GracefulTerminationWaitMilliseconds = 5_000;
    private const uint ForcedTerminationWaitMilliseconds = 1_000;

    internal static void TerminateAndWait(
        SafeKernelHandle process,
        DocumentWorkerJob? job,
        IWorkerLaunchFaultInjector faultInjector,
        uint processId,
        uint jobExitCode,
        uint processExitCode)
    {
        try
        {
            job?.Terminate(jobExitCode);
        }
        catch (AppContainerLaunchException)
        {
        }

        _ = WorkerNativeMethods.TerminateProcess(process, processExitCode);
        faultInjector.ThrowIfRequested(
            WorkerLaunchFaultPoint.BeforeTerminationWait,
            processId);
        var result = WorkerNativeMethods.WaitForSingleObject(
            process,
            GracefulTerminationWaitMilliseconds);
        if (result == WorkerNativeMethods.WaitObject0)
        {
            return;
        }

        if (result == WorkerNativeMethods.WaitFailed)
        {
            throw new AppContainerLaunchException(
                "Worker termination wait failed.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        if (result != WorkerNativeMethods.WaitTimeout)
        {
            throw new AppContainerLaunchException(
                "Worker termination wait returned an invalid result.");
        }

        _ = WorkerNativeMethods.TerminateProcess(
            process,
            processExitCode);
        result = WorkerNativeMethods.WaitForSingleObject(
            process,
            ForcedTerminationWaitMilliseconds);
        if (result == WorkerNativeMethods.WaitObject0)
        {
            return;
        }

        if (result == WorkerNativeMethods.WaitFailed)
        {
            throw new AppContainerLaunchException(
                "Forced worker termination wait failed.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        throw new AppContainerLaunchException(
            "The isolated worker did not terminate within the cleanup deadline.");
    }
}
