using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Documents;

public sealed class DocumentExtractionException : Exception
{
    public DocumentExtractionException(
        DocumentExtractionFailureCode failureCode,
        Exception? innerException = null)
        : base(CreateMessage(failureCode), innerException)
    {
        FailureCode = failureCode;
    }

    public DocumentExtractionFailureCode FailureCode { get; }

    private static string CreateMessage(
        DocumentExtractionFailureCode failureCode) =>
        failureCode switch
        {
            DocumentExtractionFailureCode.ExtractionCancelled =>
                "Document extraction was cancelled.",
            DocumentExtractionFailureCode.ExtractionTimedOut =>
                "The isolated document worker timed out.",
            DocumentExtractionFailureCode.WorkerMemoryLimitExceeded =>
                "The isolated document worker exceeded its memory limit.",
            DocumentExtractionFailureCode.InvalidFraming
                or DocumentExtractionFailureCode.ResponseTooLarge =>
                "The isolated document worker returned an invalid response.",
            DocumentExtractionFailureCode.InvalidSourceHandle
                or DocumentExtractionFailureCode.InvalidSourceLength
                or DocumentExtractionFailureCode.InvalidSourceFingerprint =>
                "The pinned source document is invalid.",
            _ => "The isolated document worker failed.",
        };
}

public sealed class DocumentExtractionClient
{
    private const int DiagnosticDrainLimit = 4096;
    private readonly string _workerExecutablePath;
    private readonly IReadOnlyList<string> _workerArguments;
    private readonly ApprovedRootPathGuard? _approvedRoot;

    public DocumentExtractionClient(string workerExecutablePath)
        : this(workerExecutablePath, approvedRoot: null, workerArguments: [])
    {
    }

    public DocumentExtractionClient(
        string workerExecutablePath,
        ApprovedRootPathGuard? approvedRoot)
        : this(workerExecutablePath, approvedRoot, workerArguments: [])
    {
    }

    public DocumentExtractionClient(
        string workerExecutablePath,
        ApprovedRootPathGuard? approvedRoot,
        IReadOnlyList<string> workerArguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerExecutablePath);
        ArgumentNullException.ThrowIfNull(workerArguments);
        if (!Path.IsPathFullyQualified(workerExecutablePath))
        {
            throw new ArgumentException(
                "An absolute worker executable path is required.",
                nameof(workerExecutablePath));
        }

        _workerExecutablePath = workerExecutablePath;
        _workerArguments = workerArguments.ToArray();
        _approvedRoot = approvedRoot;
    }

    public async Task<DocumentExtractionResponse> ExtractAsync(
        SafeFileHandle source,
        DocumentSourceDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(descriptor);
        if (cancellationToken.IsCancellationRequested)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.ExtractionCancelled);
        }

        if (source.IsClosed || source.IsInvalid)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }

        SafeFileHandle? verificationHandle = null;
        try
        {
            verificationHandle = DuplicateReadOnly(source);
            await using var verified = VerifiedStableSource.Create(
                verificationHandle);
            verificationHandle = null;
            return await ExtractVerifiedAsync(
                    verified,
                    descriptor,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is StableSourceBoundaryException
                or FileSystemBoundaryException)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }
        finally
        {
            verificationHandle?.Dispose();
        }
    }

    public async Task<DocumentExtractionResponse> ExtractAsync(
        string sourcePath,
        DocumentSourceDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        if (_approvedRoot is null)
        {
            throw new InvalidOperationException(
                "An approved-root guard is required for path-based extraction.");
        }

        if (cancellationToken.IsCancellationRequested)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.ExtractionCancelled);
        }

        VerifiedStableSource verified;
        try
        {
            verified = _approvedRoot.OpenVerifiedSource(sourcePath);
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or StableSourceBoundaryException
                or ArgumentException
                or NotSupportedException
                or PathTooLongException
                or UnauthorizedAccessException)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }

        await using (verified)
        {
            return await ExtractVerifiedAsync(
                    verified,
                    descriptor,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task<DocumentExtractionResponse> ExtractVerifiedAsync(
        VerifiedStableSource source,
        DocumentSourceDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        byte[]? initialHash = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(_workerExecutablePath))
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.WorkerTerminated);
            }

            source.RequireSingleLink();
            initialHash = await ComputeSha256Async(
                    source.Handle,
                    source.Length,
                    cancellationToken)
                .ConfigureAwait(false);
            var profile = AppContainerProfile.OpenOrCreate();
            LaunchedAppContainerProcess? worker = null;
            Exception? primaryException = null;
            try
            {
                var launcher = new AppContainerProcessLauncher(profile);
                var activeWorker = launcher.Start(
                    _workerExecutablePath,
                    _workerArguments,
                    source.Handle);
                worker = activeWorker;
                var request = new DocumentExtractionRequest(
                    DocumentExtractionProtocol.CurrentVersion,
                    Guid.NewGuid(),
                    new DocumentSourceDescriptor(
                        activeWorker.InheritedSourceHandle,
                        descriptor.ContainerKind,
                        descriptor.DeclaredMimeType,
                        source.Length,
                        ImmutableArray.Create(initialHash)),
                    ExtractionCapability.EmbeddedText | ExtractionCapability.Ocr,
                    ImmutableArray<string>.Empty);
                var requestValidation =
                    DocumentExtractionValidator.ValidateRequest(request);
                if (!requestValidation.IsValid)
                {
                    activeWorker.Kill();
                    throw new DocumentExtractionException(
                        requestValidation.FailureCode);
                }

                using var timeout = new CancellationTokenSource(
                    TimeSpan.FromMilliseconds(
                        DocumentExtractionLimits.ExtractionTimeoutMilliseconds));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken,
                    timeout.Token);
                try
                {
                    await WriteRequestFrameAsync(
                            activeWorker.StandardInput,
                            request,
                            linked.Token)
                        .ConfigureAwait(false);
                    activeWorker.StandardInput.Dispose();

                    var response = await ReadResponseFrameAsync(
                            activeWorker.StandardOutput,
                            linked.Token)
                        .ConfigureAwait(false);
                    await activeWorker.WaitForExitAsync(linked.Token)
                        .ConfigureAwait(false);
                    if (activeWorker.ExitCode != 0)
                    {
                        throw CreateTerminationFailure(activeWorker);
                    }

                    var responseValidation =
                        DocumentExtractionValidator.ValidateResponse(
                            request,
                            response);
                    if (!responseValidation.IsValid)
                    {
                        throw new DocumentExtractionException(
                            responseValidation.FailureCode);
                    }

                    source.RequireSingleLink();
                    if (WindowsFileSystemNative
                            .GetStableSourceSnapshot(source.Handle)
                            .Length
                        != source.Length)
                    {
                        throw new DocumentExtractionException(
                            DocumentExtractionFailureCode.InvalidSourceLength);
                    }

                    var finalHash = await ComputeSha256Async(
                            source.Handle,
                            source.Length,
                            linked.Token)
                        .ConfigureAwait(false);
                    try
                    {
                        if (!CryptographicOperations.FixedTimeEquals(
                                initialHash,
                                finalHash))
                        {
                            throw new DocumentExtractionException(
                                DocumentExtractionFailureCode
                                    .InvalidSourceFingerprint);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(finalHash);
                    }

                    return response;
                }
                catch (OperationCanceledException exception)
                {
                    await RescueAsync(activeWorker).ConfigureAwait(false);
                    throw new DocumentExtractionException(
                        cancellationToken.IsCancellationRequested
                            ? DocumentExtractionFailureCode.ExtractionCancelled
                            : DocumentExtractionFailureCode.ExtractionTimedOut,
                        exception);
                }
                catch (FrameException exception)
                {
                    var failureCode = activeWorker.WasProcessMemoryLimitReached()
                        ? DocumentExtractionFailureCode.WorkerMemoryLimitExceeded
                        : exception.FailureCode;
                    await RescueAsync(activeWorker).ConfigureAwait(false);
                    throw new DocumentExtractionException(
                        failureCode,
                        exception);
                }
                catch (DocumentExtractionException)
                {
                    await RescueAsync(activeWorker).ConfigureAwait(false);
                    throw;
                }
                catch (Exception exception) when (
                    exception is IOException
                        or JsonException
                        or AppContainerLaunchException)
                {
                    await RescueAsync(activeWorker).ConfigureAwait(false);
                    throw CreateTerminationFailure(activeWorker, exception);
                }
            }
            catch (Exception exception)
            {
                primaryException = exception;
                throw;
            }
            finally
            {
                await CleanupWorkerAndProfileAsync(
                        worker,
                        profile,
                        primaryException)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException exception)
            when (cancellationToken.IsCancellationRequested)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.ExtractionCancelled,
                exception);
        }
        catch (Exception exception) when (
            exception is StableSourceBoundaryException
                or FileSystemBoundaryException)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }
        catch (AppContainerLaunchException exception)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.WorkerTerminated,
                exception);
        }
        finally
        {
            if (initialHash is not null)
            {
                CryptographicOperations.ZeroMemory(initialHash);
            }
        }
    }

    private static async ValueTask CleanupWorkerAndProfileAsync(
        LaunchedAppContainerProcess? worker,
        AppContainerProfile profile,
        Exception? primaryException)
    {
        var cleanupFailed = false;
        var workerTerminationUnconfirmed = false;
        if (worker is not null)
        {
            try
            {
                await worker.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is AppContainerLaunchException
                    or IOException
                    or ObjectDisposedException
                    or UnauthorizedAccessException)
            {
                cleanupFailed = true;
                workerTerminationUnconfirmed = true;
            }
        }

        if (workerTerminationUnconfirmed)
        {
            try
            {
                profile.ReleaseWithoutProfileDeletion();
            }
            catch (Exception exception) when (
                exception is IOException
                    or ObjectDisposedException
                    or UnauthorizedAccessException)
            {
                cleanupFailed = true;
            }
        }
        else
        {
            try
            {
                profile.Dispose();
            }
            catch (Exception exception) when (
                exception is AppContainerLaunchException
                    or IOException
                    or ObjectDisposedException
                    or UnauthorizedAccessException)
            {
                cleanupFailed = true;
            }
        }

        if (!cleanupFailed)
        {
            return;
        }

        if (primaryException is not null)
        {
            try
            {
                primaryException.Data["DocumentExtractionCleanup"] =
                    "One or more isolated worker cleanup steps failed.";
            }
            catch (Exception exception) when (
                exception is ArgumentException
                    or InvalidOperationException
                    or NotSupportedException)
            {
            }

            return;
        }

        throw new AppContainerLaunchException(
            "The isolated worker cleanup did not complete.");
    }

    private static SafeFileHandle DuplicateReadOnly(SafeFileHandle source)
    {
        var process = WorkerNativeMethods.GetCurrentProcess();
        if (!WorkerNativeMethods.DuplicateHandle(
                process,
                source,
                process,
                out var duplicate,
                WorkerNativeMethods.FileGenericRead,
                inheritHandle: false,
                options: 0))
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }

        return new SafeFileHandle(duplicate, ownsHandle: true);
    }

    private static async Task<byte[]> ComputeSha256Async(
        SafeFileHandle source,
        long length,
        CancellationToken cancellationToken)
    {
        if (length < 0
            || length > DocumentExtractionLimits.MaxEncodedInputBytes)
        {
            throw new DocumentExtractionException(
                length < 0
                    ? DocumentExtractionFailureCode.InvalidSourceLength
                    : DocumentExtractionFailureCode.InputTooLarge);
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        try
        {
            long offset = 0;
            while (offset < length)
            {
                var count = (int)Math.Min(buffer.Length, length - offset);
                var read = await RandomAccess.ReadAsync(
                        source,
                        buffer.AsMemory(0, count),
                        offset,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    throw new DocumentExtractionException(
                        DocumentExtractionFailureCode.InvalidSourceLength);
                }

                hash.AppendData(buffer, 0, read);
                offset += read;
            }

            return hash.GetHashAndReset();
        }
        catch (Exception exception) when (
            exception is IOException
                or ObjectDisposedException
                or ArgumentException)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static async Task WriteRequestFrameAsync(
        Stream output,
        DocumentExtractionRequest request,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            request,
            DocumentExtractionJsonContext.Default.DocumentExtractionRequest);
        try
        {
            if (payload.Length == 0
                || payload.Length
                    > DocumentExtractionLimits.MaxSerializedResponseBytes)
            {
                throw new FrameException(
                    DocumentExtractionFailureCode.InvalidFraming);
            }

            var prefix = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
            await output.WriteAsync(prefix, cancellationToken)
                .ConfigureAwait(false);
            await output.WriteAsync(payload, cancellationToken)
                .ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    private static async Task<DocumentExtractionResponse> ReadResponseFrameAsync(
        Stream input,
        CancellationToken cancellationToken)
    {
        var prefix = new byte[sizeof(int)];
        await ReadExactlyAsync(input, prefix, cancellationToken)
            .ConfigureAwait(false);
        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (payloadLength <= 0)
        {
            throw new FrameException(
                DocumentExtractionFailureCode.InvalidFraming);
        }

        if (payloadLength
            > DocumentExtractionLimits.MaxSerializedResponseBytes)
        {
            throw new FrameException(
                DocumentExtractionFailureCode.ResponseTooLarge);
        }

        var payload = new byte[payloadLength];
        try
        {
            await ReadExactlyAsync(input, payload, cancellationToken)
                .ConfigureAwait(false);
            var trailing = new byte[1];
            if (await input.ReadAsync(trailing, cancellationToken)
                    .ConfigureAwait(false)
                != 0)
            {
                throw new FrameException(
                    DocumentExtractionFailureCode.InvalidFraming);
            }

            return JsonSerializer.Deserialize(
                    payload,
                    DocumentExtractionJsonContext.Default
                        .DocumentExtractionResponse)
                ?? throw new FrameException(
                    DocumentExtractionFailureCode.InvalidFraming);
        }
        catch (JsonException exception)
        {
            throw new FrameException(
                DocumentExtractionFailureCode.InvalidFraming,
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    private static async Task ReadExactlyAsync(
        Stream input,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await input.ReadAsync(
                    destination[offset..],
                    cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new FrameException(
                    DocumentExtractionFailureCode.InvalidFraming);
            }

            offset += read;
        }
    }

    private static async Task RescueAsync(
        LaunchedAppContainerProcess worker)
    {
        try
        {
            worker.Kill();
        }
        catch (AppContainerLaunchException)
        {
            // Kill-on-close remains the final process-tree rescue.
        }

        try
        {
            worker.StandardInput.Dispose();
        }
        catch (IOException)
        {
        }

        using var drainTimeout = new CancellationTokenSource(
            TimeSpan.FromMilliseconds(250));
        var buffer = new byte[DiagnosticDrainLimit];
        try
        {
            var total = 0;
            while (total < buffer.Length)
            {
                var read = await worker.StandardOutput.ReadAsync(
                        buffer.AsMemory(total),
                        drainTimeout.Token)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }
        }
        catch (Exception exception) when (
            exception is IOException or OperationCanceledException)
        {
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static DocumentExtractionException CreateTerminationFailure(
        LaunchedAppContainerProcess worker,
        Exception? innerException = null) =>
        new(
            worker.WasProcessMemoryLimitReached()
                ? DocumentExtractionFailureCode.WorkerMemoryLimitExceeded
                : DocumentExtractionFailureCode.WorkerTerminated,
            innerException);

    private sealed class FrameException : Exception
    {
        internal FrameException(
            DocumentExtractionFailureCode failureCode,
            Exception? innerException = null)
            : base("The worker frame is invalid.", innerException)
        {
            FailureCode = failureCode;
        }

        internal DocumentExtractionFailureCode FailureCode { get; }
    }
}
