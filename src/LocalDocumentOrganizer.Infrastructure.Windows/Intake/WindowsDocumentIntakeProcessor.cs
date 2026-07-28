using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Intake;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Core.Transactions;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using LocalDocumentOrganizer.Infrastructure.Windows.Storage;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Intake;

public sealed class WindowsDocumentIntakeProcessor :
    IDocumentIntakeProcessor,
    IDocumentIntakeRecovery,
    IAsyncDisposable
{
    private const int SourceAttemptLimit = 3;
    private static readonly TimeSpan SourceRetryDelay =
        TimeSpan.FromMilliseconds(75);
    private static readonly ConcurrentDictionary<string, SemaphoreSlim>
        ImportGates = new(StringComparer.OrdinalIgnoreCase);

    private readonly IOperationJournalStore _journal;
    private readonly IProductCommitStore _products;
    private readonly IDocumentAdmissionInspector _admissionInspector;
    private readonly TimeProvider _timeProvider;
    private readonly ApprovedRootFileStore _vault;
    private readonly IVaultImportFaultInjector _faultInjector;
    private readonly SemaphoreSlim _importGate;

    public WindowsDocumentIntakeProcessor(
        string vaultRoot,
        IOperationJournalStore journal,
        IProductCommitStore products,
        IDocumentAdmissionInspector admissionInspector,
        TimeProvider? timeProvider = null)
        : this(
            vaultRoot,
            journal,
            products,
            admissionInspector,
            timeProvider,
            NoOpVaultImportFaultInjector.Instance)
    {
    }

    internal WindowsDocumentIntakeProcessor(
        string vaultRoot,
        IOperationJournalStore journal,
        IProductCommitStore products,
        IDocumentAdmissionInspector admissionInspector,
        TimeProvider? timeProvider,
        IVaultImportFaultInjector faultInjector)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultRoot);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(products);
        ArgumentNullException.ThrowIfNull(admissionInspector);
        ArgumentNullException.ThrowIfNull(faultInjector);
        _journal = journal;
        _products = products;
        _admissionInspector = admissionInspector;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _faultInjector = faultInjector;
        _vault = new ApprovedRootFileStore(
            new ApprovedRootPathGuard(vaultRoot));
        _importGate = ImportGates.GetOrAdd(
            _vault.ApprovedRoot,
            static _ => new SemaphoreSlim(1, 1));
    }

    public async Task<DocumentIntakeResult> ProcessAsync(
        DocumentIntakeRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        await _importGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return await ProcessExclusiveAsync(request, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InjectedVaultImportFaultException)
        {
            throw;
        }
        catch (OperationJournalRecoveryRequiredException)
        {
            return DocumentIntakeResult.ManualRecoveryRequired(
                DocumentIntakeFailureCode.RecoveryEvidenceInvalid);
        }
        catch (Exception)
        {
            return DocumentIntakeResult.RetryRequired(
                DocumentIntakeFailureCode.StorageUnavailable);
        }
        finally
        {
            _importGate.Release();
        }
    }

    private async Task<DocumentIntakeResult> ProcessExclusiveAsync(
        DocumentIntakeRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var leaf = Path.GetFileName(request.SourcePath);
        if (string.IsNullOrWhiteSpace(leaf)
            || leaf.Length > 255
            || leaf.Contains('/')
            || leaf.Contains('\\'))
        {
            return DocumentIntakeResult.Rejected(
                DocumentIntakeFailureCode.InvalidDisplayName);
        }

        var extension = Path.GetExtension(leaf);
        if (!IsSupportedExtension(extension))
        {
            return DocumentIntakeResult.Rejected(
                DocumentIntakeFailureCode.UnsupportedExtension);
        }

        var sourceResult = await OpenSourceAsync(
                request.SourcePath,
                cancellationToken)
            .ConfigureAwait(false);
        if (sourceResult.Source is null)
        {
            return sourceResult.Failure;
        }

        await using var source = sourceResult.Source;
        _faultInjector.OnFaultPoint(
            VaultImportFaultPoint.SourceHashing);
        var shaBytes = await source.ComputeSha256Async(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var inspection =
                await DocumentAdmissionInspector.InspectAsync(
                        source,
                        extension,
                        shaBytes,
                        _admissionInspector,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (inspection.Admission is null)
            {
                return inspection.Failure is
                    DocumentIntakeFailureCode.SourceChanged
                    or DocumentIntakeFailureCode.StorageUnavailable
                    ? DocumentIntakeResult.RetryRequired(
                        inspection.Failure)
                    : DocumentIntakeResult.Rejected(
                        inspection.Failure);
            }

            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.AdmissionRevalidated);
            source.Revalidate();
            var sha = new ContentSha256(shaBytes);
            var operationId = new OperationId(Guid.NewGuid());
            var eventId = new EventId(Guid.NewGuid());
            var documentId = new DocumentId(Guid.NewGuid());
            var inboxId = new InboxId(Guid.NewGuid());
            var receivedAtUtc =
                _timeProvider.GetUtcNow().ToUniversalTime();
            var temporaryRelativePath = Path.Combine(
                ".staging",
                operationId.Value.ToString("N") + ".tmp");
            var destinationRelativePath = Path.Combine(
                "objects",
                sha.Hex[..2],
                sha.Hex + inspection.Admission.CanonicalExtension);
            const string authenticatedMetadata =
                """{"schemaVersion":1,"storage":"content-addressed"}""";
            var sourceBinding = inspection.Admission.Container switch
            {
                AdmittedContainer.Pdf => new ProductDocumentSourceBinding(
                    ProductDocumentSourceFormat.Pdf, "application/pdf", ".pdf", source.Length),
                AdmittedContainer.Jpeg => new ProductDocumentSourceBinding(
                    ProductDocumentSourceFormat.Jpeg, "image/jpeg", ".jpg", source.Length),
                AdmittedContainer.Png => new ProductDocumentSourceBinding(
                    ProductDocumentSourceFormat.Png, "image/png", ".png", source.Length),
                AdmittedContainer.Tiff => new ProductDocumentSourceBinding(
                    ProductDocumentSourceFormat.Tiff, "image/tiff", ".tiff", source.Length),
                _ => throw new InvalidOperationException(),
            };
            var payload = VaultImportJournalPayload.Create(
                eventId,
                documentId,
                inboxId,
                sha,
                source.Length,
                sourceBinding,
                receivedAtUtc,
                leaf,
                authenticatedMetadata,
                temporaryRelativePath,
                destinationRelativePath);
            var serializedPayload = payload.Serialize();
            var sourceRoot = Path.GetDirectoryName(
                Path.GetFullPath(request.SourcePath))
                ?? throw new InvalidOperationException();
            var intent = new FileOperationIntent(
                operationId,
                new SensitiveObjectRef(
                    SensitiveObjectKind.DocumentEvidence,
                    new SensitiveObjectId(documentId.Value)),
                FileOperationKind.VaultImport,
                request.SourcePath,
                Path.Combine(_vault.ApprovedRoot, destinationRelativePath),
                sourceRoot,
                _vault.ApprovedRoot,
                new StreamId(documentId.Value),
                StreamVersion.NoStream,
                serializedPayload);
            var persisted = await _journal.PersistIntentAsync(
                    intent,
                    cancellationToken)
                .ConfigureAwait(false);
            if (persisted.Status == PersistOperationIntentStatus.Conflict
                || persisted.Entry is null)
            {
                return DocumentIntakeResult.ManualRecoveryRequired(
                    DocumentIntakeFailureCode.RecoveryEvidenceInvalid);
            }

            var entry = persisted.Entry;
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.IntentPersisted);
            entry = await AdvanceAsync(
                    entry,
                    OperationJournalState.IdentityLocked,
                    sourceHealth: OperationSourceHealth.Healthy,
                    identity: source.CreateIdentity(shaBytes),
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.IdentityLocked);

            _vault.EnsureDirectoryVerified(".staging");
            _vault.EnsureDirectoryVerified(
                Path.Combine("objects", sha.Hex[..2]));
            using var temporaryHandle = _vault.CreateNewPromotableVerified(
                temporaryRelativePath,
                source.Length);
            using var temporaryProof =
                VerifiedStableSource.Create(temporaryHandle);
            var temporaryIdentity =
                temporaryProof.CreateIdentity(shaBytes);
            entry = await AdvanceAsync(
                    entry,
                    OperationJournalState.Copying,
                    OperationSourceHealth.Healthy,
                    appliedIdentity: temporaryIdentity,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.Copying);
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.TemporaryCreated);
            using (var destination =
                   new RandomAccessDestinationStream(temporaryProof.Handle))
            {
                await source.CopyToAsync(destination, cancellationToken)
                    .ConfigureAwait(false);
                destination.Flush();
            }

            source.Revalidate();
            using var verifiedTemporary =
                VerifiedStableSource.Create(temporaryHandle);
            entry = await AdvanceAsync(
                    entry,
                    OperationJournalState.Copied,
                    OperationSourceHealth.Healthy,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(VaultImportFaultPoint.Copied);
            var temporarySha = await ComputeShaAsync(
                    verifiedTemporary.Handle,
                    source.Length,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                    shaBytes,
                    temporarySha)
                || !temporaryIdentity.IdentifiesSameFileObject(
                    verifiedTemporary.CreateIdentity(shaBytes)))
            {
                throw new FileSystemBoundaryException(
                    "The immutable Vault copy failed verification.");
            }

            entry = await AdvanceAsync(
                    entry,
                    OperationJournalState.Verified,
                    OperationSourceHealth.Healthy,
                    appliedIdentity: temporaryIdentity,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(VaultImportFaultPoint.Verified);
            entry = await AdvanceAsync(
                    entry,
                    OperationJournalState.Publishing,
                    OperationSourceHealth.Healthy,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.Publishing);

            var ownership = new FilePromotionOwnership();
            var published = _vault.PromoteCreatedNoReplace(
                verifiedTemporary.Handle,
                temporaryRelativePath,
                destinationRelativePath,
                source.Length,
                ownership);
            if (!published)
            {
                await VerifyExistingDestinationAsync(
                        destinationRelativePath,
                        source.Length,
                        shaBytes,
                        cancellationToken)
                    .ConfigureAwait(false);
                _vault.DeleteOwnedOnClose(
                    verifiedTemporary,
                    temporaryRelativePath,
                    source.Length);
            }

            entry = await AdvanceAsync(
                    entry,
                    OperationJournalState.FileApplied,
                    OperationSourceHealth.Healthy,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.FileApplied);
            var commit = await _products.CommitImportAsync(
                    payload.ToCommand(operationId),
                    cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.ProductCommitted);
            var result = commit switch
            {
                ImportCommitted committed =>
                    DocumentIntakeResult.Imported(committed.InboxId),
                ImportAlreadyCommitted committed =>
                    DocumentIntakeResult.Imported(committed.InboxId),
                AlreadyImported duplicate =>
                    DocumentIntakeResult.AlreadyImported(
                        duplicate.ExistingInboxId),
                ImportConflict =>
                    DocumentIntakeResult.ManualRecoveryRequired(
                        DocumentIntakeFailureCode.ProductCommitConflict),
                ProductRecoveryRequired =>
                    DocumentIntakeResult.RetryRequired(
                        DocumentIntakeFailureCode.StorageUnavailable),
                _ => DocumentIntakeResult.ManualRecoveryRequired(
                    DocumentIntakeFailureCode.RecoveryEvidenceInvalid),
            };
            if (commit is ImportConflict or ProductRecoveryRequired)
            {
                return result;
            }

            entry = await AdvanceAsync(
                    entry,
                    OperationJournalState.EventAndProjectionCommitted,
                    OperationSourceHealth.Healthy,
                    commitFingerprint:
                        payload.ComputeCommitFingerprint(operationId),
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.EventAndProjectionCommitted);
            entry = await AdvanceAsync(
                    entry,
                    OperationJournalState.SideEffectsPending,
                    OperationSourceHealth.Healthy,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            _faultInjector.OnFaultPoint(
                VaultImportFaultPoint.SideEffectsPending);
            _ = await AdvanceAsync(
                    entry,
                    OperationJournalState.Completed,
                    OperationSourceHealth.Healthy,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shaBytes);
        }
    }

    public async Task RecoverPendingAsync(
        CancellationToken cancellationToken)
    {
        await _importGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            await RecoverPendingExclusiveAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _importGate.Release();
        }
    }

    private async Task RecoverPendingExclusiveAsync(
        CancellationToken cancellationToken)
    {
        var entries = await _journal.GetNonTerminalAsync(cancellationToken)
            .ConfigureAwait(false);
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.Kind != FileOperationKind.VaultImport)
            {
                continue;
            }

            await RecoverEntryAsync(entry, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    public ValueTask DisposeAsync()
    {
        _vault.Dispose();
        return ValueTask.CompletedTask;
    }

    private static bool IsSupportedExtension(string extension) =>
        extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase)
        || extension.Equals(".jpg", StringComparison.OrdinalIgnoreCase)
        || extension.Equals(".jpeg", StringComparison.OrdinalIgnoreCase)
        || extension.Equals(".png", StringComparison.OrdinalIgnoreCase)
        || extension.Equals(".tif", StringComparison.OrdinalIgnoreCase)
        || extension.Equals(".tiff", StringComparison.OrdinalIgnoreCase);

    private async Task RecoverEntryAsync(
        OperationJournalEntry original,
        CancellationToken cancellationToken)
    {
        VaultImportJournalPayload payload;
        byte[] expectedSha;
        try
        {
            payload = VaultImportJournalPayload.Deserialize(
                original.Intent.ApprovedProposal);
            expectedSha = Convert.FromHexString(payload.ContentSha256);
            if (expectedSha.Length != ContentSha256.Size
                || payload.DocumentId != original.Owner.Id.Value
                || payload.DocumentId != original.Intent.StreamId.Value
                || payload.Length < 0
                || !string.Equals(
                    Path.GetFullPath(original.Intent.DestinationRoot),
                    _vault.ApprovedRoot,
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    Path.GetFullPath(original.Intent.DestinationPath),
                    Path.GetFullPath(
                        Path.Combine(
                            _vault.ApprovedRoot,
                            payload.DestinationRelativePath)),
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException();
            }
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or FormatException
                or InvalidDataException
                or JsonException)
        {
            await MarkManualAsync(
                    original,
                    OperationManualRecoveryReason
                        .VaultImportEvidenceInvalid,
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        try
        {
            var entry = original;
            for (var step = 0; step < 12; step++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                switch (entry.State)
                {
                    case OperationJournalState.IntentPersisted:
                    {
                        var source = await OpenVerifiedRecoverySourceAsync(
                                entry,
                                payload,
                                expectedSha,
                                requireJournalIdentity: false,
                                cancellationToken)
                            .ConfigureAwait(false);
                        if (source is null)
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportSourceChanged,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        await using (source)
                        {
                            entry = await AdvanceAsync(
                                    entry,
                                    OperationJournalState.IdentityLocked,
                                    OperationSourceHealth.Healthy,
                                    identity:
                                        source.CreateIdentity(expectedSha),
                                    cancellationToken: cancellationToken)
                                .ConfigureAwait(false);
                        }

                        break;
                    }
                    case OperationJournalState.IdentityLocked:
                    {
                        var source = await OpenVerifiedRecoverySourceAsync(
                                entry,
                                payload,
                                expectedSha,
                                requireJournalIdentity: true,
                                cancellationToken)
                            .ConfigureAwait(false);
                        if (source is null)
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportSourceChanged,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        await source.DisposeAsync().ConfigureAwait(false);
                        EnsureVaultDirectories(payload);
                        StableFileIdentity temporaryIdentity;
                        try
                        {
                            using var handle =
                                _vault.CreateNewPromotableVerified(
                                    payload.TemporaryRelativePath,
                                    payload.Length);
                            using var temporary =
                                VerifiedStableSource.Create(handle);
                            temporaryIdentity =
                                temporary.CreateIdentity(expectedSha);
                        }
                        catch (Exception exception) when (
                            exception is FileSystemBoundaryException
                                or FileStoreEntryAlreadyExistsException)
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportTemporaryOwnershipAmbiguous,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        entry = await AdvanceAsync(
                                entry,
                                OperationJournalState.Copying,
                                OperationSourceHealth.Healthy,
                                appliedIdentity: temporaryIdentity,
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }
                    case OperationJournalState.Copying:
                    {
                        await using var temporary =
                            await OpenOwnedTemporaryForCopyAsync(
                                entry,
                                payload,
                                cancellationToken)
                            .ConfigureAwait(false);
                        if (temporary is null)
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportTemporaryOwnershipAmbiguous,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        var source = await OpenVerifiedRecoverySourceAsync(
                                entry,
                                payload,
                                expectedSha,
                                requireJournalIdentity: true,
                                cancellationToken)
                            .ConfigureAwait(false);
                        if (source is null)
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportSourceChanged,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        await using (source)
                        using (var destination =
                               new RandomAccessDestinationStream(
                                   temporary.Handle))
                        {
                            await source.CopyToAsync(
                                    destination,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            destination.Flush();
                            source.Revalidate();
                        }

                        entry = await AdvanceAsync(
                                entry,
                                OperationJournalState.Copied,
                                OperationSourceHealth.Healthy,
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }
                    case OperationJournalState.Copied:
                    {
                        await using var temporary =
                            _vault.TryOpenExistingOwnedVerified(
                                payload.TemporaryRelativePath);
                        if (!await VerifyTemporaryAsync(
                                temporary,
                                payload,
                                expectedSha,
                                entry.AppliedIdentity,
                                cancellationToken).ConfigureAwait(false))
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportTemporaryOwnershipAmbiguous,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        entry = await AdvanceAsync(
                                entry,
                                OperationJournalState.Verified,
                                OperationSourceHealth.Healthy,
                                appliedIdentity: entry.AppliedIdentity,
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }
                    case OperationJournalState.Verified:
                    {
                        await using var temporary =
                            _vault.TryOpenExistingOwnedVerified(
                                payload.TemporaryRelativePath);
                        if (!await VerifyTemporaryAsync(
                                temporary,
                                payload,
                                expectedSha,
                                entry.AppliedIdentity,
                                cancellationToken).ConfigureAwait(false))
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportTemporaryOwnershipAmbiguous,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        entry = await AdvanceAsync(
                                entry,
                                OperationJournalState.Publishing,
                                OperationSourceHealth.Healthy,
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }
                    case OperationJournalState.Publishing:
                    {
                        if (!await PublishDuringRecoveryAsync(
                                entry,
                                payload,
                                expectedSha,
                                cancellationToken).ConfigureAwait(false))
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportPublishedObjectMismatch,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        entry = await AdvanceAsync(
                                entry,
                                OperationJournalState.FileApplied,
                                OperationSourceHealth.Healthy,
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }
                    case OperationJournalState.FileApplied:
                    {
                        if (!await DestinationMatchesAsync(
                                payload,
                                expectedSha,
                                cancellationToken).ConfigureAwait(false))
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportPublishedObjectMismatch,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        var commit = await _products.CommitImportAsync(
                                payload.ToCommand(entry.OperationId),
                                cancellationToken)
                            .ConfigureAwait(false);
                        if (commit is ImportConflict)
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportProductCommitConflict,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        if (commit is ProductRecoveryRequired)
                        {
                            return;
                        }

                        if (commit is not (
                                ImportCommitted
                                or ImportAlreadyCommitted
                                or AlreadyImported))
                        {
                            await MarkManualAsync(
                                    entry,
                                    OperationManualRecoveryReason
                                        .VaultImportProductCommitConflict,
                                    cancellationToken)
                                .ConfigureAwait(false);
                            return;
                        }

                        entry = await AdvanceAsync(
                                entry,
                                OperationJournalState
                                    .EventAndProjectionCommitted,
                                OperationSourceHealth.Healthy,
                                commitFingerprint:
                                    payload.ComputeCommitFingerprint(
                                        entry.OperationId),
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    }
                    case OperationJournalState.EventAndProjectionCommitted:
                        entry = await AdvanceAsync(
                                entry,
                                OperationJournalState.SideEffectsPending,
                                OperationSourceHealth.Healthy,
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    case OperationJournalState.SideEffectsPending:
                        _ = await AdvanceAsync(
                                entry,
                                OperationJournalState.Completed,
                                OperationSourceHealth.Healthy,
                                cancellationToken: cancellationToken)
                            .ConfigureAwait(false);
                        return;
                    case OperationJournalState.Completed:
                    case OperationJournalState.ManualRecovery:
                        return;
                    default:
                        await MarkManualAsync(
                                entry,
                                OperationManualRecoveryReason
                                    .VaultImportEvidenceInvalid,
                                cancellationToken)
                            .ConfigureAwait(false);
                        return;
                }
            }

            await MarkManualAsync(
                    entry,
                    OperationManualRecoveryReason.VaultImportEvidenceInvalid,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedSha);
        }
    }

    private static async Task<(VerifiedStableSource? Source, DocumentIntakeResult Failure)>
        OpenSourceAsync(
            string sourcePath,
            CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < SourceAttemptLimit; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var fullPath = Path.GetFullPath(sourcePath);
                var sourceRoot = Path.GetDirectoryName(fullPath)
                    ?? throw new FileSystemBoundaryException(
                        "The selected source has no approved parent.");
                var provider = new NtfsFileIdentityProvider(
                    new ApprovedRootPathGuard(sourceRoot));
                return (
                    provider.OpenVerifiedSource(fullPath),
                    DocumentIntakeResult.RetryRequired(
                        DocumentIntakeFailureCode.SourceLocked));
            }
            catch (FileSystemTransientShareOrLockException)
                when (attempt + 1 < SourceAttemptLimit)
            {
                await Task.Delay(
                        SourceRetryDelay,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (FileSystemTransientShareOrLockException)
            {
                return (
                    null,
                    DocumentIntakeResult.RetryRequired(
                        DocumentIntakeFailureCode.SourceLocked));
            }
            catch (StableSourceBoundaryException exception)
                when (exception.Failure
                    == StableSourceBoundaryFailure.MultipleHardLinks)
            {
                return (
                    null,
                    DocumentIntakeResult.Rejected(
                        DocumentIntakeFailureCode.MultipleHardLinks));
            }
            catch (FileSystemBoundaryException)
            {
                return (
                    null,
                    DocumentIntakeResult.Rejected(
                        ContainsReparsePoint(sourcePath)
                            ? DocumentIntakeFailureCode
                                .UnsupportedReparsePoint
                            : DocumentIntakeFailureCode.NonRegularFile));
            }
            catch (UnauthorizedAccessException)
            {
                return (
                    null,
                    DocumentIntakeResult.RetryRequired(
                        DocumentIntakeFailureCode.SourceAccessDenied));
            }
        }

        return (
            null,
            DocumentIntakeResult.RetryRequired(
                DocumentIntakeFailureCode.SourceLocked));
    }

    private static bool ContainsReparsePoint(string sourcePath)
    {
        try
        {
            var fullPath = Path.GetFullPath(sourcePath);
            var root = Path.GetPathRoot(fullPath);
            if (string.IsNullOrWhiteSpace(root))
            {
                return false;
            }

            var current = root;
            var relative = fullPath[root.Length..];
            foreach (var component in relative.Split(
                         [
                             Path.DirectorySeparatorChar,
                             Path.AltDirectorySeparatorChar,
                         ],
                         StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, component);
                if ((File.GetAttributes(current)
                        & FileAttributes.ReparsePoint) != 0)
                {
                    return true;
                }
            }
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IOException
                or UnauthorizedAccessException
                or NotSupportedException)
        {
        }

        return false;
    }

    private async Task<VerifiedStableSource?> OpenVerifiedRecoverySourceAsync(
        OperationJournalEntry entry,
        VaultImportJournalPayload payload,
        byte[] expectedSha,
        bool requireJournalIdentity,
        CancellationToken cancellationToken)
    {
        var opened = await OpenSourceAsync(
                entry.Intent.SourcePath,
                cancellationToken)
            .ConfigureAwait(false);
        if (opened.Source is null)
        {
            return null;
        }

        var source = opened.Source;
        try
        {
            if (source.Length != payload.Length)
            {
                source.Dispose();
                return null;
            }

            var actualSha = await source.ComputeSha256Async(
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(
                        actualSha,
                        expectedSha)
                    || requireJournalIdentity
                    && (entry.Identity is null
                        || !entry.Identity.FixedTimeEquals(
                            source.CreateIdentity(actualSha))))
                {
                    source.Dispose();
                    return null;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualSha);
            }

            return source;
        }
        catch
        {
            source.Dispose();
            throw;
        }
    }

    private void EnsureVaultDirectories(
        VaultImportJournalPayload payload)
    {
        _vault.EnsureDirectoryVerified(".staging");
        var destinationParent =
            Path.GetDirectoryName(payload.DestinationRelativePath);
        if (string.IsNullOrWhiteSpace(destinationParent))
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        _vault.EnsureDirectoryVerified(destinationParent);
    }

    private Task<VerifiedStableSource?> OpenOwnedTemporaryForCopyAsync(
        OperationJournalEntry entry,
        VaultImportJournalPayload payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureVaultDirectories(payload);
        VerifiedStableSource? temporary = null;
        try
        {
            temporary = _vault.OpenExistingPromotableVerified(
                payload.TemporaryRelativePath);
            if (entry.AppliedIdentity is null
                || temporary.Length != payload.Length
                || !entry.AppliedIdentity.IdentifiesSameFileObject(
                    temporary.CreateIdentity(
                        entry.AppliedIdentity.KeyedFingerprint)))
            {
                temporary.Dispose();
                return Task.FromResult<VerifiedStableSource?>(null);
            }

            return Task.FromResult<VerifiedStableSource?>(temporary);
        }
        catch (FileSystemBoundaryException)
        {
            temporary?.Dispose();
            return Task.FromResult<VerifiedStableSource?>(null);
        }
    }

    private static async Task<bool> VerifyTemporaryAsync(
        VerifiedStableSource? temporary,
        VaultImportJournalPayload payload,
        byte[] expectedSha,
        StableFileIdentity? expectedIdentity,
        CancellationToken cancellationToken)
    {
        if (temporary is null || temporary.Length != payload.Length)
        {
            return false;
        }

        var actual = await temporary.ComputeSha256Async(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                    actual,
                    expectedSha)
                && (expectedIdentity is null
                    || expectedIdentity.IdentifiesSameFileObject(
                        temporary.CreateIdentity(actual)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private async Task<bool> PublishDuringRecoveryAsync(
        OperationJournalEntry entry,
        VaultImportJournalPayload payload,
        byte[] expectedSha,
        CancellationToken cancellationToken)
    {
        VerifiedStableSource? temporary = null;
        try
        {
            try
            {
                temporary = _vault.OpenExistingPromotableVerified(
                    payload.TemporaryRelativePath);
            }
            catch (FileSystemBoundaryException)
            {
                temporary = null;
            }
            if (temporary is null)
            {
                return await DestinationMatchesAsync(
                        payload,
                        expectedSha,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (!await VerifyTemporaryAsync(
                    temporary,
                    payload,
                    expectedSha,
                    entry.AppliedIdentity,
                    cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            var ownership = new FilePromotionOwnership();
            if (_vault.PromoteCreatedNoReplace(
                    temporary.Handle,
                    payload.TemporaryRelativePath,
                    payload.DestinationRelativePath,
                    payload.Length,
                    ownership))
            {
                return true;
            }

            if (!await DestinationMatchesAsync(
                    payload,
                    expectedSha,
                    cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            _vault.DeleteOwnedOnClose(
                temporary,
                payload.TemporaryRelativePath,
                payload.Length);
            return true;
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or OperationJournalRecoveryRequiredException)
        {
            return false;
        }
        finally
        {
            if (temporary is not null)
            {
                await temporary.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task<bool> DestinationMatchesAsync(
        VaultImportJournalPayload payload,
        byte[] expectedSha,
        CancellationToken cancellationToken)
    {
        try
        {
            await VerifyExistingDestinationAsync(
                    payload.DestinationRelativePath,
                    payload.Length,
                    expectedSha,
                    cancellationToken)
                .ConfigureAwait(false);
            return true;
        }
        catch (Exception exception) when (
            exception is FileSystemBoundaryException
                or OperationJournalRecoveryRequiredException)
        {
            return false;
        }
    }

    private async Task MarkManualAsync(
        OperationJournalEntry entry,
        OperationManualRecoveryReason reason,
        CancellationToken cancellationToken)
    {
        var evidence = new OperationManualRecoveryEvidence(
            entry.State,
            RecoveryPathObservation.InaccessibleOrUnknown,
            RecoveryPathObservation.InaccessibleOrUnknown,
            reason,
            OperationManualRecoveryAction
                .InspectVaultImportEvidenceWithoutMutation);
        var transitioned = await _journal.TransitionAsync(
                new TransitionOperationCommand(
                    entry.OperationId,
                    entry.Revision,
                    OperationJournalState.ManualRecovery,
                    OperationSourceHealth.ManualRecovery,
                    manualRecoveryEvidence: evidence),
                cancellationToken)
            .ConfigureAwait(false);
        if (transitioned.Status is not (
                TransitionOperationStatus.Transitioned
                or TransitionOperationStatus.AlreadyApplied))
        {
            throw new OperationJournalRecoveryRequiredException();
        }
    }

    private async Task<OperationJournalEntry> AdvanceAsync(
        OperationJournalEntry entry,
        OperationJournalState state,
        OperationSourceHealth sourceHealth,
        StableFileIdentity? identity = null,
        StableFileIdentity? appliedIdentity = null,
        byte[]? commitFingerprint = null,
        CancellationToken cancellationToken = default)
    {
        var transitioned = await _journal.TransitionAsync(
                new TransitionOperationCommand(
                    entry.OperationId,
                    entry.Revision,
                    state,
                    sourceHealth,
                    identity,
                    manualRecoveryEvidence: null,
                    appliedIdentity,
                    commitFingerprint),
                cancellationToken)
            .ConfigureAwait(false);
        if (transitioned.Status is not (
                TransitionOperationStatus.Transitioned
                or TransitionOperationStatus.AlreadyApplied)
            || transitioned.Entry is null)
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        return transitioned.Entry;
    }

    private async Task VerifyExistingDestinationAsync(
        string relativePath,
        long expectedLength,
        byte[] expectedSha,
        CancellationToken cancellationToken)
    {
        await using var existing = _vault.OpenExistingVerified(relativePath);
        if (existing.Length != expectedLength)
        {
            throw new OperationJournalRecoveryRequiredException();
        }

        var actual = await existing.ComputeSha256Async(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    actual,
                    expectedSha))
            {
                throw new OperationJournalRecoveryRequiredException();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static async Task<byte[]> ComputeShaAsync(
        SafeFileHandle handle,
        long length,
        CancellationToken cancellationToken)
    {
        using var hash =
            IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81_920];
        try
        {
            long offset = 0;
            while (offset < length)
            {
                var count = (int)Math.Min(buffer.Length, length - offset);
                var read = await RandomAccess.ReadAsync(
                        handle,
                        buffer.AsMemory(0, count),
                        offset,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                hash.AppendData(buffer, 0, read);
                offset += read;
            }

            return hash.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private sealed class RandomAccessDestinationStream : Stream
    {
        private readonly SafeFileHandle _handle;
        private long _position;

        internal RandomAccessDestinationStream(SafeFileHandle handle)
        {
            _handle = handle;
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length =>
            throw new NotSupportedException();

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override void Flush() =>
            WindowsFileSystemNative.FlushFileData(_handle);

        public override Task FlushAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Flush();
            return Task.CompletedTask;
        }

        public override void Write(
            byte[] buffer,
            int offset,
            int count) =>
            Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            RandomAccess.Write(_handle, buffer, _position);
            _position = checked(_position + buffer.Length);
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await RandomAccess.WriteAsync(
                    _handle,
                    buffer,
                    _position,
                    cancellationToken)
                .ConfigureAwait(false);
            _position = checked(_position + buffer.Length);
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();
    }
}
