using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Documents;
using LocalDocumentOrganizer.Application.Intake;
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

public sealed record DocumentExtractionEvaluationResult(
    DocumentExtractionResponse Response,
    ImmutableArray<byte> SourceSha256);

public sealed class DocumentExtractionClient :
    IDocumentAdmissionInspector
{
    private const int DiagnosticDrainLimit = 4096;
    private readonly string _workerExecutablePath;
    private readonly IReadOnlyList<string> _workerArguments;
    private readonly ApprovedRootPathGuard? _approvedRoot;
    private readonly ImmutableArray<string> _defaultOcrLanguages;
    private readonly IDocumentExtractionDeadlineFactory _deadlineFactory;
    private readonly IDocumentSourceHasher _sourceHasher;
    private readonly IDocumentWorkerSessionLauncher _workerLauncher;
    private readonly IDocumentWorkerCleanupDiagnostics _cleanupDiagnostics;

    public DocumentExtractionClient(
        string workerExecutablePath,
        IReadOnlyList<string> defaultOcrLanguages,
        ApprovedRootPathGuard? approvedRoot = null,
        IReadOnlyList<string>? workerArguments = null)
        : this(
            workerExecutablePath,
            approvedRoot,
            workerArguments ?? [],
            defaultOcrLanguages,
            NoOpWorkerLaunchFaultInjector.Instance)
    {
    }

    internal DocumentExtractionClient(
        string workerExecutablePath,
        ApprovedRootPathGuard? approvedRoot,
        IReadOnlyList<string> workerArguments,
        IReadOnlyList<string> defaultOcrLanguages,
        IWorkerLaunchFaultInjector? faultInjector)
        : this(
            workerExecutablePath,
            approvedRoot,
            workerArguments,
            defaultOcrLanguages,
            faultInjector,
            deadlineFactory: null,
            sourceHasher: null,
            workerLauncher: null,
            cleanupDiagnostics: null)
    {
    }

    internal DocumentExtractionClient(
        string workerExecutablePath,
        ApprovedRootPathGuard? approvedRoot,
        IReadOnlyList<string> workerArguments,
        IReadOnlyList<string> defaultOcrLanguages,
        IWorkerLaunchFaultInjector? faultInjector,
        IDocumentExtractionDeadlineFactory? deadlineFactory,
        IDocumentSourceHasher? sourceHasher,
        IDocumentWorkerSessionLauncher? workerLauncher,
        IDocumentWorkerCleanupDiagnostics? cleanupDiagnostics = null)
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
        _defaultOcrLanguages =
            CopyAndValidateDefaultOcrLanguages(defaultOcrLanguages);
        _approvedRoot = approvedRoot;
        var effectiveFaultInjector = faultInjector
            ?? NoOpWorkerLaunchFaultInjector.Instance;
        _deadlineFactory = deadlineFactory
            ?? new MonotonicDocumentExtractionDeadlineFactory(
                TimeSpan.FromMilliseconds(
                    DocumentExtractionLimits.ExtractionTimeoutMilliseconds),
                TimeProvider.System);
        _sourceHasher = sourceHasher
            ?? DefaultDocumentSourceHasher.Instance;
        _cleanupDiagnostics = cleanupDiagnostics
            ?? NullDocumentWorkerCleanupDiagnostics.Instance;
        _workerLauncher = workerLauncher
            ?? new AppContainerDocumentWorkerSessionLauncher(
                effectiveFaultInjector,
                _cleanupDiagnostics);
    }

    public async Task<DocumentExtractionResponse> ExtractAsync(
        SafeFileHandle source,
        DocumentSourceDescriptor descriptor,
        CancellationToken cancellationToken) =>
        await ExtractAsync(
                source,
                descriptor,
                ExtractionCapability.EmbeddedText | ExtractionCapability.Ocr,
                _defaultOcrLanguages,
                cancellationToken)
            .ConfigureAwait(false);

    public async Task<DocumentExtractionResponse> ExtractAsync(
        SafeFileHandle source,
        DocumentSourceDescriptor descriptor,
        ExtractionCapability requestedCapabilities,
        ImmutableArray<string> requestedLanguages,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(descriptor);
        try
        {
            return await RunWithDeadlineAsync(
                    cancellationToken,
                    async deadline =>
                    {
                        deadline.ThrowIfCancellationRequested();
                        if (source.IsClosed || source.IsInvalid)
                        {
                            throw new DocumentExtractionException(
                                DocumentExtractionFailureCode
                                    .InvalidSourceHandle);
                        }

                        SafeFileHandle? verificationHandle = null;
                        try
                        {
                            verificationHandle = DuplicateReadOnly(source);
                            deadline.ThrowIfCancellationRequested();
                            await using var verified =
                                VerifiedStableSource.Create(
                                    verificationHandle);
                            verificationHandle = null;
                            deadline.ThrowIfCancellationRequested();
                            return (await ExtractVerifiedAsync(
                                    verified,
                                    descriptor,
                                    deadline,
                                    requestedCapabilities,
                                    requestedLanguages)
                                .ConfigureAwait(false)).Response;
                        }
                        finally
                        {
                            verificationHandle?.Dispose();
                        }
                    })
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is StableSourceBoundaryException
                or FileSystemBoundaryException)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }
    }

    public async Task<DocumentInspectionResponse> InspectDocumentAsync(
        SafeFileHandle source,
        DocumentSourceDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(descriptor);
        try
        {
            return await RunWithDeadlineAsync(
                    cancellationToken,
                    async deadline =>
                    {
                        deadline.ThrowIfCancellationRequested();
                        if (source.IsClosed || source.IsInvalid)
                        {
                            throw new DocumentExtractionException(
                                DocumentExtractionFailureCode
                                    .InvalidSourceHandle);
                        }

                        SafeFileHandle? verificationHandle = null;
                        try
                        {
                            verificationHandle =
                                DuplicateReadOnly(source);
                            deadline.ThrowIfCancellationRequested();
                            await using var verified =
                                VerifiedStableSource.Create(
                                    verificationHandle);
                            verificationHandle = null;
                            return await InspectVerifiedAsync(
                                    verified,
                                    descriptor,
                                    deadline)
                                .ConfigureAwait(false);
                        }
                        finally
                        {
                            verificationHandle?.Dispose();
                        }
                    })
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is StableSourceBoundaryException
                or FileSystemBoundaryException)
        {
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }
    }

    async Task<DocumentAdmissionInspectionResult>
        IDocumentAdmissionInspector.InspectPdfAsync(
            SafeHandle sourceHandle,
            long verifiedLength,
            ImmutableArray<byte> sha256,
            CancellationToken cancellationToken)
    {
        if (sourceHandle is not SafeFileHandle source)
        {
            return DocumentAdmissionInspectionResult.SourceChanged();
        }

        try
        {
            var response = await InspectDocumentAsync(
                    source,
                    new DocumentSourceDescriptor(
                        InheritedHandle: 1,
                        DocumentContainerKind.Pdf,
                        "application/pdf",
                        verifiedLength,
                        sha256),
                    cancellationToken)
                .ConfigureAwait(false);
            if (response.Outcome
                == DocumentInspectionOutcome.Success)
            {
                return DocumentAdmissionInspectionResult.Inspected(
                    response.PdfPageCount);
            }

            return response.FailureCode is
                DocumentExtractionFailureCode.CorruptDocument
                or DocumentExtractionFailureCode.EncryptedDocument
                or DocumentExtractionFailureCode.UnsupportedDocument
                or DocumentExtractionFailureCode.DecoderFailure
                ? DocumentAdmissionInspectionResult.ContentUnreadable()
                : response.FailureCode is
                    DocumentExtractionFailureCode.InvalidSourceHandle
                    or DocumentExtractionFailureCode
                        .InvalidSourceFingerprint
                    or DocumentExtractionFailureCode.InvalidSourceLength
                    ? DocumentAdmissionInspectionResult.SourceChanged()
                    : DocumentAdmissionInspectionResult.Unavailable();
        }
        catch (DocumentExtractionException exception)
            when (exception.FailureCode
                  == DocumentExtractionFailureCode.ExtractionCancelled
                  && cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (DocumentExtractionException exception)
            when (exception.FailureCode is
                DocumentExtractionFailureCode.InvalidSourceHandle
                or DocumentExtractionFailureCode
                    .InvalidSourceFingerprint
                or DocumentExtractionFailureCode.InvalidSourceLength)
        {
            return DocumentAdmissionInspectionResult.SourceChanged();
        }
        catch (DocumentExtractionException)
        {
            return DocumentAdmissionInspectionResult.Unavailable();
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

        try
        {
            return await RunWithDeadlineAsync(
                    cancellationToken,
                    async deadline =>
                    {
                        deadline.ThrowIfCancellationRequested();
                        var verified =
                            _approvedRoot.OpenVerifiedSource(sourcePath);
                        await using (verified)
                        {
                            deadline.ThrowIfCancellationRequested();
                            return (await ExtractVerifiedAsync(
                                    verified,
                                    descriptor,
                                    deadline,
                                    ExtractionCapability.EmbeddedText
                                        | ExtractionCapability.Ocr,
                                    _defaultOcrLanguages)
                                .ConfigureAwait(false)).Response;
                        }
                    })
                .ConfigureAwait(false);
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
    }

    public async Task<DocumentExtractionEvaluationResult>
        ExtractForEvaluationAsync(
            string sourcePath,
            DocumentSourceDescriptor descriptor,
            ImmutableArray<string> requestedLanguages,
            CancellationToken cancellationToken)
    {
        if (_approvedRoot is null)
        {
            throw new InvalidOperationException(
                "A path extraction requires an approved root.");
        }

        if (requestedLanguages.IsDefaultOrEmpty)
        {
            throw new ArgumentException(
                "At least one requested language is required.",
                nameof(requestedLanguages));
        }

        try
        {
            return await RunWithDeadlineAsync(
                    cancellationToken,
                    async deadline =>
                    {
                        deadline.ThrowIfCancellationRequested();
                        var verified =
                            _approvedRoot.OpenVerifiedSource(sourcePath);
                        await using (verified)
                        {
                            deadline.ThrowIfCancellationRequested();
                            return await ExtractVerifiedAsync(
                                    verified,
                                    descriptor,
                                    deadline,
                                    ExtractionCapability.EmbeddedText
                                        | ExtractionCapability.Ocr,
                                    requestedLanguages)
                                .ConfigureAwait(false);
                        }
                    })
                .ConfigureAwait(false);
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
    }

    private async Task<DocumentInspectionResponse>
        InspectVerifiedAsync(
        VerifiedStableSource source,
        DocumentSourceDescriptor descriptor,
        IDocumentExtractionDeadline deadline)
    {
        byte[]? initialHash = null;
        try
        {
            deadline.ThrowIfCancellationRequested();
            if (!File.Exists(_workerExecutablePath))
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.WorkerTerminated);
            }

            source.RequireSingleLink();
            if (descriptor.DeclaredLength != source.Length)
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.InvalidSourceLength);
            }

            if (descriptor.ContainerKind != DocumentContainerKind.Pdf
                || descriptor.DeclaredMimeType != "application/pdf")
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode
                        .ContainerMimeTypeMismatch);
            }

            if (descriptor.Sha256.IsDefault
                || descriptor.Sha256.Length
                    != SHA256.HashSizeInBytes)
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode
                        .InvalidSourceFingerprint);
            }

            initialHash = await _sourceHasher.ComputeSha256Async(
                    source.Handle,
                    source.Length,
                    deadline.Token)
                .ConfigureAwait(false);
            if (initialHash.Length != SHA256.HashSizeInBytes
                || !CryptographicOperations.FixedTimeEquals(
                    initialHash,
                    descriptor.Sha256.AsSpan()))
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode
                        .InvalidSourceFingerprint);
            }

            DocumentWorkerSessionLease? worker = null;
            Exception? primaryException = null;
            try
            {
                IDocumentWorkerSession activeWorker;
                Task<IDocumentWorkerSession> launch;
                using (var launchSource =
                       DuplicateReadOnly(source.Handle))
                {
                    deadline.ThrowIfCancellationRequested();
                    launch = _workerLauncher.LaunchAsync(
                        _workerExecutablePath,
                        _workerArguments,
                        launchSource,
                        deadline.Capture());
                    try
                    {
                        activeWorker = await launch
                            .WaitAsync(deadline.Token)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        ObserveLateLaunch(launch);
                        throw;
                    }
                }

                worker = new DocumentWorkerSessionLease(
                    activeWorker,
                    _cleanupDiagnostics);
                deadline.ThrowIfCancellationRequested();
                var request = new DocumentInspectionRequest(
                    DocumentExtractionProtocol.CurrentVersion,
                    Guid.NewGuid(),
                    new DocumentSourceDescriptor(
                        activeWorker.InheritedSourceHandle,
                        DocumentContainerKind.Pdf,
                        "application/pdf",
                        source.Length,
                        ImmutableArray.Create(initialHash)));
                var requestValidation =
                    DocumentInspectionValidator.ValidateRequest(request);
                if (!requestValidation.IsValid)
                {
                    worker.Abort();
                    throw new DocumentExtractionException(
                        requestValidation.FailureCode);
                }

                try
                {
                    await ReadWorkerReadinessAsync(
                            activeWorker.StandardOutput,
                            deadline.Token)
                        .ConfigureAwait(false);
                    await WriteInspectionRequestFrameAsync(
                            activeWorker.StandardInput,
                            request,
                            deadline.Token)
                        .ConfigureAwait(false);
                    activeWorker.StandardInput.Dispose();

                    var response =
                        await ReadInspectionResponseFrameAsync(
                                activeWorker.StandardOutput,
                                deadline.Token)
                            .ConfigureAwait(false);
                    await activeWorker.WaitForExitAsync(deadline.Token)
                        .ConfigureAwait(false);
                    if (activeWorker.ExitCode != 0)
                    {
                        throw CreateTerminationFailure(activeWorker);
                    }

                    var responseValidation =
                        DocumentInspectionValidator.ValidateResponse(
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
                            DocumentExtractionFailureCode
                                .InvalidSourceLength);
                    }

                    var finalHash =
                        await _sourceHasher.ComputeSha256Async(
                                source.Handle,
                                source.Length,
                                deadline.Token)
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
                catch (OperationCanceledException)
                {
                    worker.Abort();
                    throw;
                }
                catch (FrameException exception)
                {
                    var failureCode =
                        activeWorker.WasProcessMemoryLimitReached()
                            ? DocumentExtractionFailureCode
                                .WorkerMemoryLimitExceeded
                            : exception.FailureCode;
                    worker.Abort();
                    await DrainDiagnosticsAsync(
                            activeWorker,
                            deadline.Token)
                        .ConfigureAwait(false);
                    throw new DocumentExtractionException(
                        failureCode,
                        exception);
                }
                catch (DocumentExtractionException)
                {
                    worker.Abort();
                    await DrainDiagnosticsAsync(
                            activeWorker,
                            deadline.Token)
                        .ConfigureAwait(false);
                    throw;
                }
                catch (Exception exception) when (
                    exception is IOException
                        or JsonException
                        or AppContainerLaunchException)
                {
                    worker.Abort();
                    await DrainDiagnosticsAsync(
                            activeWorker,
                            deadline.Token)
                        .ConfigureAwait(false);
                    throw CreateTerminationFailure(
                        activeWorker,
                        exception);
                }
            }
            catch (Exception exception)
            {
                primaryException = exception;
                throw;
            }
            finally
            {
                if (worker is not null)
                {
                    await CleanupWorkerWithinDeadlineAsync(
                            worker,
                            primaryException,
                            deadline)
                        .ConfigureAwait(false);
                }
            }
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

    private async Task<DocumentExtractionEvaluationResult>
        ExtractVerifiedAsync(
        VerifiedStableSource source,
        DocumentSourceDescriptor descriptor,
        IDocumentExtractionDeadline deadline,
        ExtractionCapability requestedCapabilities,
        ImmutableArray<string> requestedLanguages)
    {
        byte[]? initialHash = null;
        try
        {
            deadline.ThrowIfCancellationRequested();
            if (!File.Exists(_workerExecutablePath))
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.WorkerTerminated);
            }

            deadline.ThrowIfCancellationRequested();
            source.RequireSingleLink();
            if (descriptor.DeclaredLength != source.Length)
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.InvalidSourceLength);
            }

            if (descriptor.Sha256.IsDefault
                || descriptor.Sha256.Length != SHA256.HashSizeInBytes)
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.InvalidSourceFingerprint);
            }

            initialHash = await _sourceHasher.ComputeSha256Async(
                    source.Handle,
                    source.Length,
                    deadline.Token)
                .ConfigureAwait(false);
            deadline.ThrowIfCancellationRequested();
            if (initialHash.Length != SHA256.HashSizeInBytes
                || !CryptographicOperations.FixedTimeEquals(
                    initialHash,
                    descriptor.Sha256.AsSpan()))
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.InvalidSourceFingerprint);
            }

            DocumentWorkerSessionLease? worker = null;
            Exception? primaryException = null;
            try
            {
                IDocumentWorkerSession activeWorker;
                Task<IDocumentWorkerSession> launch;
                using (var launchSource = DuplicateReadOnly(source.Handle))
                {
                    deadline.ThrowIfCancellationRequested();
                    launch = _workerLauncher.LaunchAsync(
                        _workerExecutablePath,
                        _workerArguments,
                        launchSource,
                        deadline.Capture());
                    try
                    {
                        activeWorker = await launch
                            .WaitAsync(deadline.Token)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        ObserveLateLaunch(launch);
                        throw;
                    }
                }

                worker = new DocumentWorkerSessionLease(
                    activeWorker,
                    _cleanupDiagnostics);
                deadline.ThrowIfCancellationRequested();
                var request = new DocumentExtractionRequest(
                    DocumentExtractionProtocol.CurrentVersion,
                    Guid.NewGuid(),
                    new DocumentSourceDescriptor(
                        activeWorker.InheritedSourceHandle,
                        descriptor.ContainerKind,
                        descriptor.DeclaredMimeType,
                        source.Length,
                        ImmutableArray.Create(initialHash)),
                    requestedCapabilities,
                    requestedLanguages);
                var requestValidation =
                    DocumentExtractionValidator.ValidateRequest(request);
                if (!requestValidation.IsValid)
                {
                    worker.Abort();
                    throw new DocumentExtractionException(
                        requestValidation.FailureCode);
                }

                try
                {
                    await ReadWorkerReadinessAsync(
                            activeWorker.StandardOutput,
                            deadline.Token)
                        .ConfigureAwait(false);
                    await WriteRequestFrameAsync(
                            activeWorker.StandardInput,
                            request,
                            deadline.Token)
                        .ConfigureAwait(false);
                    activeWorker.StandardInput.Dispose();

                    var response = await ReadResponseFrameAsync(
                            activeWorker.StandardOutput,
                            deadline.Token)
                        .ConfigureAwait(false);
                    await activeWorker.WaitForExitAsync(deadline.Token)
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

                    var finalHash = await _sourceHasher.ComputeSha256Async(
                            source.Handle,
                            source.Length,
                            deadline.Token)
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

                    return new DocumentExtractionEvaluationResult(
                        response,
                        ImmutableArray.CreateRange(initialHash));
                }
                catch (OperationCanceledException)
                {
                    worker.Abort();
                    throw;
                }
                catch (FrameException exception)
                {
                    var failureCode = activeWorker.WasProcessMemoryLimitReached()
                        ? DocumentExtractionFailureCode.WorkerMemoryLimitExceeded
                        : exception.FailureCode;
                    worker.Abort();
                    await DrainDiagnosticsAsync(
                            activeWorker,
                            deadline.Token)
                        .ConfigureAwait(false);
                    throw new DocumentExtractionException(
                        failureCode,
                        exception);
                }
                catch (DocumentExtractionException)
                {
                    worker.Abort();
                    await DrainDiagnosticsAsync(
                            activeWorker,
                            deadline.Token)
                        .ConfigureAwait(false);
                    throw;
                }
                catch (Exception exception) when (
                    exception is IOException
                        or JsonException
                        or AppContainerLaunchException)
                {
                    worker.Abort();
                    await DrainDiagnosticsAsync(
                            activeWorker,
                            deadline.Token)
                        .ConfigureAwait(false);
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
                if (worker is not null)
                {
                    await CleanupWorkerWithinDeadlineAsync(
                            worker,
                            primaryException,
                            deadline)
                        .ConfigureAwait(false);
                }
            }
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

    private async Task<T> RunWithDeadlineAsync<T>(
        CancellationToken callerCancellation,
        Func<IDocumentExtractionDeadline, Task<T>> operation)
    {
        using var deadline = _deadlineFactory.Start(callerCancellation);
        try
        {
            deadline.ThrowIfCancellationRequested();
            return await operation(deadline).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
        {
            throw new DocumentExtractionException(
                callerCancellation.IsCancellationRequested
                    ? DocumentExtractionFailureCode.ExtractionCancelled
                    : DocumentExtractionFailureCode.ExtractionTimedOut,
                exception);
        }
    }

    private void ObserveLateLaunch(
        Task<IDocumentWorkerSession> launch)
    {
        _ = AbortAndCleanupLateLaunchAsync(launch);
    }

    private async Task AbortAndCleanupLateLaunchAsync(
        Task<IDocumentWorkerSession> launch)
    {
        try
        {
            var worker = new DocumentWorkerSessionLease(
                await launch.ConfigureAwait(false),
                _cleanupDiagnostics);
            worker.Abort();
            await worker.CleanupAsync(
                    new OperationCanceledException(
                        "The launch completed after its deadline."))
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            DocumentWorkerCleanupDiagnostics.ReportSafely(
                _cleanupDiagnostics,
                DocumentWorkerCleanupFailureKind.LateLaunch);
        }
    }

    private async Task CleanupWorkerWithinDeadlineAsync(
        DocumentWorkerSessionLease worker,
        Exception? primaryException,
        IDocumentExtractionDeadline deadline)
    {
        if (primaryException is not null
            || deadline.Token.IsCancellationRequested
            || deadline.Remaining <= TimeSpan.Zero)
        {
            worker.Abort();
        }

        var cleanup = worker.CleanupAsync(primaryException).AsTask();
        try
        {
            deadline.ThrowIfCancellationRequested();
            await cleanup.WaitAsync(deadline.Token).ConfigureAwait(false);
            deadline.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException)
        {
            worker.Abort();
            ObserveBackgroundCleanup(cleanup);
            throw;
        }
    }

    private void ObserveBackgroundCleanup(Task cleanup)
    {
        _ = ObserveBackgroundCleanupAsync(cleanup);
    }

    private async Task ObserveBackgroundCleanupAsync(Task cleanup)
    {
        try
        {
            await cleanup.ConfigureAwait(false);
        }
        catch (Exception)
        {
            DocumentWorkerCleanupDiagnostics.ReportSafely(
                _cleanupDiagnostics,
                DocumentWorkerCleanupFailureKind.BackgroundCleanup);
        }
    }

    internal static SafeFileHandle DuplicateReadOnly(SafeFileHandle source)
    {
        if (source.IsAsync)
        {
            if (!WorkerNativeMethods.TryGetFileMode(source, out var mode)
                || (mode & WorkerNativeMethods.FileNoIntermediateBuffering)
                    != 0)
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.InvalidSourceHandle);
            }

            var reopened = WorkerNativeMethods.ReOpenFile(
                source,
                WorkerNativeMethods.FileGenericRead,
                WorkerNativeMethods.FileShareRead
                    | WorkerNativeMethods.FileShareDelete,
                WorkerNativeMethods.FileFlagSequentialScan);
            if (!reopened.IsInvalid)
            {
                return reopened;
            }

            reopened.Dispose();
            throw new DocumentExtractionException(
                DocumentExtractionFailureCode.InvalidSourceHandle);
        }

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

    private static ImmutableArray<string> CopyAndValidateDefaultOcrLanguages(
        IReadOnlyList<string> defaultOcrLanguages)
    {
        ArgumentNullException.ThrowIfNull(defaultOcrLanguages);
        var copy = ImmutableArray.CreateRange(defaultOcrLanguages);
        if (copy.IsEmpty)
        {
            throw new ArgumentException(
                "At least one default OCR language is required.",
                nameof(defaultOcrLanguages));
        }

        var validation =
            DocumentExtractionValidator.ValidateRequestedLanguages(copy);
        if (!validation.IsValid)
        {
            throw new ArgumentException(
                "Default OCR languages must be normalized BCP-47 tags "
                    + $"without duplicates ({validation.FailureCode}).",
                nameof(defaultOcrLanguages));
        }

        return copy;
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

    private static async Task WriteInspectionRequestFrameAsync(
        Stream output,
        DocumentInspectionRequest request,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            request,
            DocumentExtractionJsonContext.Default
                .DocumentInspectionRequest);
        try
        {
            if (payload.Length == 0
                || payload.Length
                    > DocumentExtractionLimits
                        .MaxSerializedResponseBytes)
            {
                throw new FrameException(
                    DocumentExtractionFailureCode.InvalidFraming);
            }

            var prefix = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(
                prefix,
                payload.Length);
            await output.WriteAsync(prefix, cancellationToken)
                .ConfigureAwait(false);
            await output.WriteAsync(payload, cancellationToken)
                .ConfigureAwait(false);
            await output.FlushAsync(cancellationToken)
                .ConfigureAwait(false);
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

    private static async Task<DocumentInspectionResponse>
        ReadInspectionResponseFrameAsync(
            Stream input,
            CancellationToken cancellationToken)
    {
        var prefix = new byte[sizeof(int)];
        await ReadExactlyAsync(input, prefix, cancellationToken)
            .ConfigureAwait(false);
        var payloadLength =
            BinaryPrimitives.ReadInt32LittleEndian(prefix);
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
            await ReadExactlyAsync(
                    input,
                    payload,
                    cancellationToken)
                .ConfigureAwait(false);
            var trailing = new byte[1];
            if (await input.ReadAsync(
                        trailing,
                        cancellationToken)
                    .ConfigureAwait(false)
                != 0)
            {
                throw new FrameException(
                    DocumentExtractionFailureCode.InvalidFraming);
            }

            return JsonSerializer.Deserialize(
                    payload,
                    DocumentExtractionJsonContext.Default
                        .DocumentInspectionResponse)
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

    private static async Task ReadWorkerReadinessAsync(
        Stream input,
        CancellationToken cancellationToken)
    {
        var expected =
            DocumentExtractionProtocol.WorkerReadinessPreamble.ToArray();
        var actual = new byte[expected.Length];
        try
        {
            try
            {
                await ReadExactlyAsync(input, actual, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (FrameException exception)
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.WorkerTerminated,
                    exception);
            }

            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            {
                throw new DocumentExtractionException(
                    DocumentExtractionFailureCode.WorkerTerminated);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(actual);
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

    private static async Task DrainDiagnosticsAsync(
        IDocumentWorkerSession worker,
        CancellationToken deadlineCancellation)
    {
        try
        {
            worker.StandardInput.Dispose();
        }
        catch (IOException)
        {
        }

        using var drainTimeout = new CancellationTokenSource(
            TimeSpan.FromMilliseconds(250),
            TimeProvider.System);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            deadlineCancellation,
            drainTimeout.Token);
        var buffer = new byte[DiagnosticDrainLimit];
        try
        {
            var total = 0;
            while (total < buffer.Length)
            {
                    var read = await worker.StandardOutput.ReadAsync(
                            buffer.AsMemory(total),
                            linked.Token)
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
        IDocumentWorkerSession worker,
        Exception? innerException = null) =>
        new(
            worker.WasProcessMemoryLimitReached()
                ? DocumentExtractionFailureCode.WorkerMemoryLimitExceeded
                : DocumentExtractionFailureCode.WorkerTerminated,
            innerException);

    private sealed class DefaultDocumentSourceHasher
        : IDocumentSourceHasher
    {
        internal static DefaultDocumentSourceHasher Instance { get; } = new();

        private DefaultDocumentSourceHasher()
        {
        }

        public Task<byte[]> ComputeSha256Async(
            SafeFileHandle source,
            long length,
            CancellationToken cancellationToken) =>
            DocumentExtractionClient.ComputeSha256Async(
                source,
                length,
                cancellationToken);
    }

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
