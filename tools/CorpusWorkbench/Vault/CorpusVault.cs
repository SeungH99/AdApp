using System.Collections.Concurrent;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Persistence;
using LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.CorpusWorkbench.Vault;

public sealed class CorpusVault : IDisposable, IAsyncDisposable
{
    private const string DatabaseRelativePath = "workbench.db";
    private const string ObjectRootRelativePath =
        "objects\\sha256";

    private readonly ConcurrentDictionary<string, SemaphoreSlim>
        _importGates = new(StringComparer.Ordinal);
    private ApprovedRootFileStore? _fileStore;
    private CorpusWorkbenchStore? _store;

    private CorpusVault(
        ApprovedRootFileStore fileStore,
        CorpusWorkbenchStore store)
    {
        _fileStore = fileStore;
        _store = store;
    }

    internal CorpusWorkbenchStore Store =>
        _store
        ?? throw new ObjectDisposedException(nameof(CorpusVault));

    public static CorpusVault OpenExisting(string vaultRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultRoot);
        var guard = new ApprovedRootPathGuard(vaultRoot);
        var fileStore = new ApprovedRootFileStore(guard);
        try
        {
            fileStore.EnsureDirectoryVerified("objects");
            fileStore.EnsureDirectoryVerified(ObjectRootRelativePath);
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
                    DatabaseRelativePath));
            return new CorpusVault(fileStore, store);
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

    internal SafeFileHandle CreateObject(
        string contentSha256,
        long expectedLength)
    {
        var fileStore = GetFileStore();
        var firstPrefix = Path.Combine(
            ObjectRootRelativePath,
            contentSha256[..2]);
        fileStore.EnsureDirectoryVerified(firstPrefix);
        fileStore.EnsureDirectoryVerified(
            Path.Combine(
                firstPrefix,
                contentSha256.Substring(2, 2)));
        return fileStore.CreateNewVerified(
            GetObjectRelativePath(contentSha256),
            expectedLength);
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

    internal void RevalidateCreatedObject(
        SafeFileHandle handle,
        string contentSha256,
        long expectedLength) =>
        GetFileStore().RevalidateCreated(
            handle,
            GetObjectRelativePath(contentSha256),
            expectedLength);

    internal void DeleteOwnedObjectOnClose(
        SafeFileHandle handle,
        string contentSha256,
        long expectedLength) =>
        GetFileStore().DeleteOwnedOnClose(
            handle,
            GetObjectRelativePath(contentSha256),
            expectedLength);

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

    private void ThrowIfDisposed()
    {
        if (_fileStore is null || _store is null)
        {
            throw new ObjectDisposedException(nameof(CorpusVault));
        }
    }
}

internal sealed class ImportLease : IDisposable
{
    private SemaphoreSlim? _gate;

    internal ImportLease(SemaphoreSlim gate) =>
        _gate = gate;

    public void Dispose() =>
        Interlocked.Exchange(ref _gate, null)?.Release();
}
