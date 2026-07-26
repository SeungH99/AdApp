using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Persistence;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using Microsoft.Win32.SafeHandles;

[assembly: InternalsVisibleTo(
    "LocalDocumentOrganizer.CorpusWorkbench.Tests")]

namespace LocalDocumentOrganizer.CorpusWorkbench.Vault;

public sealed class CorpusVault : IDisposable, IAsyncDisposable
{
    private const string DatabaseRelativePath = "workbench.db";
    private const string ObjectRootRelativePath =
        "objects\\sha256";
    private const string StagingRootRelativePath =
        "objects\\.staging";

    private readonly ConcurrentDictionary<string, SemaphoreSlim>
        _importGates = new(StringComparer.Ordinal);
    private readonly Action<CorpusImportFaultPoint>? _injectFault;
    private ApprovedRootFileStore? _fileStore;
    private CorpusWorkbenchStore? _store;

    private CorpusVault(
        ApprovedRootFileStore fileStore,
        CorpusWorkbenchStore store,
        Action<CorpusImportFaultPoint>? injectFault)
    {
        _fileStore = fileStore;
        _store = store;
        _injectFault = injectFault;
    }

    internal CorpusWorkbenchStore Store =>
        _store
        ?? throw new ObjectDisposedException(nameof(CorpusVault));

    public static CorpusVault OpenExisting(string vaultRoot)
        => OpenExisting(vaultRoot, injectFault: null);

    internal static CorpusVault OpenExisting(
        string vaultRoot,
        Action<CorpusImportFaultPoint>? injectFault)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultRoot);
        var guard = new ApprovedRootPathGuard(vaultRoot);
        var fileStore = new ApprovedRootFileStore(guard);
        try
        {
            fileStore.EnsureDirectoryVerified("objects");
            fileStore.EnsureDirectoryVerified(ObjectRootRelativePath);
            fileStore.EnsureDirectoryVerified(
                StagingRootRelativePath);
            fileStore.EnsureDirectoryVerified("previews");
            fileStore.EnsureDirectoryVerified("checkpoints");

            try
            {
                using var created = fileStore.CreateNewVerified(
                    DatabaseRelativePath,
                    expectedLength: 0);
            }
            catch (FileStoreEntryAlreadyExistsException)
            {
            }

            using (fileStore.OpenExistingVerified(
                       DatabaseRelativePath))
            {
            }

            var store = new CorpusWorkbenchStore(
                fileStore,
                Path.Combine(
                    fileStore.ApprovedRoot,
                    DatabaseRelativePath),
                injectFault);
            var vault = new CorpusVault(
                fileStore,
                store,
                injectFault);
            vault.RecoverStagingOrphans();
            return vault;
        }
        catch
        {
            fileStore.Dispose();
            throw;
        }
    }

    internal async ValueTask<ImportLease> AcquireImportLeaseAsync(
        string contentSha256,
        CancellationToken cancellationToken)
    {
        ValidateContentSha256(contentSha256);
        ThrowIfDisposed();
        var gate = _importGates.GetOrAdd(
            contentSha256,
            static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (_fileStore is null)
        {
            gate.Release();
            throw new ObjectDisposedException(nameof(CorpusVault));
        }

        return new ImportLease(gate);
    }

    internal string GetObjectRelativePath(string contentSha256)
    {
        ValidateContentSha256(contentSha256);
        return Path.Combine(
            ObjectRootRelativePath,
            contentSha256[..2],
            contentSha256.Substring(2, 2),
            contentSha256);
    }

    internal StagedCorpusObject CreateStagingObject(
        long expectedLength)
    {
        var fileStore = GetFileStore();
        for (var attempt = 0; attempt < 16; attempt++)
        {
            var relativePath = Path.Combine(
                StagingRootRelativePath,
                "import-"
                + Guid.NewGuid().ToString("N")
                + ".tmp");
            try
            {
                return new StagedCorpusObject(
                    fileStore.CreateNewPromotableVerified(
                        relativePath,
                        expectedLength),
                    relativePath,
                    expectedLength);
            }
            catch (FileStoreEntryAlreadyExistsException)
            {
            }
        }

        throw new WorkbenchException(
            WorkbenchFailureCode.VaultBoundaryViolation);
    }

    internal bool PromoteStagingObject(
        StagedCorpusObject staged,
        string contentSha256)
    {
        ArgumentNullException.ThrowIfNull(staged);
        var fileStore = GetFileStore();
        var firstPrefix = Path.Combine(
            ObjectRootRelativePath,
            contentSha256[..2]);
        fileStore.EnsureDirectoryVerified(firstPrefix);
        fileStore.EnsureDirectoryVerified(
            Path.Combine(
                firstPrefix,
                contentSha256.Substring(2, 2)));
        var destination = GetObjectRelativePath(contentSha256);
        var ownership = new FilePromotionOwnership();
        try
        {
            return fileStore.PromoteCreatedNoReplace(
                staged.Handle,
                staged.RelativePath,
                destination,
                staged.ExpectedLength,
                ownership);
        }
        finally
        {
            if (ownership.IsTransferred)
            {
                staged.MarkPromoted(destination);
            }
        }
    }

    internal VerifiedStableSource AdoptPromotedObject(
        StagedCorpusObject staged)
    {
        ArgumentNullException.ThrowIfNull(staged);
        if (!staged.IsPromoted)
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.VaultBoundaryViolation);
        }

        var handle = staged.TakeHandle();
        return GetFileStore().AdoptCreatedVerified(
            handle,
            staged.RelativePath,
            staged.ExpectedLength);
    }

    internal VerifiedStableSource? TryOpenObject(
        string contentSha256)
    {
        var relativePath = GetObjectRelativePath(contentSha256);
        var fileStore = GetFileStore();
        fileStore.Revalidate();
        var absolutePath = Path.Combine(
            fileStore.ApprovedRoot,
            relativePath);
        if (!File.Exists(absolutePath))
        {
            fileStore.Revalidate();
            return null;
        }

        return fileStore.OpenExistingVerified(relativePath);
    }

    internal VerifiedStableSource? TryOpenOwnedObject(
        string contentSha256) =>
        GetFileStore().TryOpenExistingOwnedVerified(
            GetObjectRelativePath(contentSha256));

    internal void RevalidateCreatedObject(
        SafeFileHandle handle,
        string contentSha256,
        long expectedLength) =>
        GetFileStore().RevalidateCreated(
            handle,
            GetObjectRelativePath(contentSha256),
            expectedLength);

    internal void RevalidateStagingObject(
        StagedCorpusObject staged)
    {
        ArgumentNullException.ThrowIfNull(staged);
        GetFileStore().RevalidateCreated(
            staged.Handle,
            staged.RelativePath,
            staged.ExpectedLength);
    }

    internal void RevalidateObject(
        VerifiedStableSource source,
        string contentSha256)
    {
        ArgumentNullException.ThrowIfNull(source);
        source.Revalidate();
        GetFileStore().RevalidateExisting(
            source,
            GetObjectRelativePath(contentSha256));
    }

    internal void DeleteOwnedObjectOnClose(
        SafeFileHandle handle,
        string contentSha256,
        long expectedLength) =>
        GetFileStore().DeleteOwnedOnClose(
            handle,
            GetObjectRelativePath(contentSha256),
            expectedLength);

    internal void DeleteOwnedObjectOnClose(
        VerifiedStableSource source,
        string contentSha256,
        long expectedLength) =>
        GetFileStore().DeleteOwnedOnClose(
            source,
            GetObjectRelativePath(contentSha256),
            expectedLength);

    internal void DeleteOwnedStagingOnClose(
        StagedCorpusObject staged)
    {
        ArgumentNullException.ThrowIfNull(staged);
        GetFileStore().DeleteOwnedOnClose(
            staged.Handle,
            staged.RelativePath,
            staged.ExpectedLength);
    }

    internal void InjectFault(CorpusImportFaultPoint point) =>
        _injectFault?.Invoke(point);

    public void Dispose()
    {
        var store = Interlocked.Exchange(ref _store, null);
        var fileStore = Interlocked.Exchange(
            ref _fileStore,
            null);
        try
        {
            store?.Dispose();
        }
        finally
        {
            fileStore?.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        var store = Interlocked.Exchange(ref _store, null);
        var fileStore = Interlocked.Exchange(
            ref _fileStore,
            null);
        try
        {
            if (store is not null)
            {
                await store.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            fileStore?.Dispose();
        }
    }

    internal static void ValidateContentSha256(string value)
    {
        if (value is null
            || value.Length != 64
            || value.Any(
                static character =>
                    character is not (>= '0' and <= '9')
                    and not (>= 'a' and <= 'f')))
        {
            throw new WorkbenchException(
                WorkbenchFailureCode.ContentHashMismatch);
        }
    }

    private ApprovedRootFileStore GetFileStore()
    {
        ThrowIfDisposed();
        return _fileStore
            ?? throw new ObjectDisposedException(nameof(CorpusVault));
    }

    private void RecoverStagingOrphans()
    {
        var fileStore = GetFileStore();
        foreach (var name in fileStore.EnumerateVerifiedFileNames(
                     StagingRootRelativePath))
        {
            if (!IsStagingObjectName(name))
            {
                throw new WorkbenchException(
                    WorkbenchFailureCode.VaultBoundaryViolation);
            }

            var relative = Path.Combine(
                StagingRootRelativePath,
                name);
            using var orphan =
                fileStore.TryOpenExistingOwnedVerified(relative);
            if (orphan is null)
            {
                continue;
            }

            fileStore.DeleteOwnedOnClose(
                orphan,
                relative,
                orphan.Length);
        }
    }

    private static bool IsStagingObjectName(string name)
    {
        const string prefix = "import-";
        const string suffix = ".tmp";
        if (!name.StartsWith(prefix, StringComparison.Ordinal)
            || !name.EndsWith(suffix, StringComparison.Ordinal)
            || name.Length
                != prefix.Length + 32 + suffix.Length)
        {
            return false;
        }

        return name.AsSpan(prefix.Length, 32).IndexOfAnyExcept(
            "0123456789abcdef") < 0;
    }

    private void ThrowIfDisposed()
    {
        if (_fileStore is null || _store is null)
        {
            throw new ObjectDisposedException(nameof(CorpusVault));
        }
    }
}

internal enum CorpusImportFaultPoint
{
    AfterStagingObjectFlushed = 0,
    AfterObjectPromoted = 1,
    BeforeAcceptanceRevalidation = 2,
    AfterDatabaseCommit = 3,
    ExistingObjectOpenTransientShareOrLock = 4,
}

internal sealed class StagedCorpusObject : IDisposable
{
    private SafeFileHandle? _handle;

    internal StagedCorpusObject(
        SafeFileHandle handle,
        string relativePath,
        long expectedLength)
    {
        _handle = handle;
        RelativePath = relativePath;
        ExpectedLength = expectedLength;
    }

    internal SafeFileHandle Handle =>
        _handle is { IsClosed: false, IsInvalid: false } handle
            ? handle
            : throw new ObjectDisposedException(
                nameof(StagedCorpusObject));

    internal string RelativePath { get; private set; }

    internal long ExpectedLength { get; }

    internal bool IsPromoted { get; private set; }

    internal void MarkPromoted(string relativePath)
    {
        RelativePath = relativePath;
        IsPromoted = true;
    }

    internal SafeFileHandle TakeHandle() =>
        Interlocked.Exchange(ref _handle, null)
        ?? throw new ObjectDisposedException(
            nameof(StagedCorpusObject));

    public void Dispose() =>
        Interlocked.Exchange(ref _handle, null)?.Dispose();
}

internal sealed class ImportLease : IDisposable
{
    private SemaphoreSlim? _gate;

    internal ImportLease(SemaphoreSlim gate) =>
        _gate = gate;

    public void Dispose() =>
        Interlocked.Exchange(ref _gate, null)?.Release();
}
