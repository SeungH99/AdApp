using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public sealed class ApprovedRootFileStore : IDisposable
{
    private readonly object _sync = new();
    private readonly ApprovedRootPathGuard _guard;
    private readonly string _rootPhysicalPath;
    private readonly ulong _rootVolumeId;
    private readonly WindowsFileSystemNative.FILE_ID_INFO _rootIdentity;
    private readonly Dictionary<string, PinnedDirectoryPathScope>
        _retainedDirectories =
            new(StringComparer.OrdinalIgnoreCase);
    private PinnedDirectoryPathScope? _rootScope;

    public ApprovedRootFileStore(ApprovedRootPathGuard guard)
    {
        ArgumentNullException.ThrowIfNull(guard);
        _guard = guard;
        var rootScope = guard.OpenPinnedDirectoryPath(guard.ApprovedRoot);
        try
        {
            var snapshot = WindowsFileSystemNative.GetStableVolumeSnapshot(
                rootScope.FinalHandle);
            _rootVolumeId = StableVolumeValidator.Validate(
                snapshot.IsLocal,
                snapshot.HasVolumeInformation,
                snapshot.FileSystemName,
                snapshot.FileId.VolumeSerialNumber);
            _rootIdentity = snapshot.FileId;
            RequireSameIdentity(_rootIdentity, rootScope.FinalIdentity);
            _rootPhysicalPath = WindowsFileSystemNative.GetFinalPath(
                rootScope.FinalHandle);
            _rootScope = rootScope;
        }
        catch
        {
            rootScope.Dispose();
            throw;
        }
    }

    public string ApprovedRoot => _guard.ApprovedRoot;

    public SafeFileHandle CreateNewVerified(
        string relativePath,
        long expectedLength)
    {
        if (expectedLength < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedLength),
                "A non-negative expected length is required.");
        }

        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var absolute = GetAbsolutePath(normalized);
            var parent = Path.GetDirectoryName(absolute)
                ?? throw Boundary();
            PinnedDirectoryPathScope? parentScope = null;
            SafeFileHandle? created = null;
            try
            {
                parentScope = _guard.OpenPinnedDirectoryPath(parent);
                ValidateDirectoryScope(
                    parentScope,
                    GetRelativeParent(normalized));
                created =
                    WindowsFileSystemNative.OpenNewVerifiedFileHandle(
                        absolute);
                RandomAccess.SetLength(created, expectedLength);
                ValidateFileHandle(
                    created,
                    normalized,
                    expectedLength);
                RevalidateCore();
                RetainDirectoryScope(
                    parentScope,
                    GetRelativeParent(normalized));
                parentScope = null;
                var result = created;
                created = null;
                return result;
            }
            catch
            {
                if (created is not null)
                {
                    try
                    {
                        WindowsFileSystemNative.MarkDeleteOnClose(created);
                    }
                    catch
                    {
                        // The creation failure remains primary.
                    }

                    created.Dispose();
                }

                throw;
            }
            finally
            {
                parentScope?.Dispose();
            }
        }
    }

    public SafeFileHandle CreateNewPromotableVerified(
        string relativePath,
        long expectedLength)
    {
        if (expectedLength < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedLength),
                "A non-negative expected length is required.");
        }

        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var absolute = GetAbsolutePath(normalized);
            var parent = Path.GetDirectoryName(absolute)
                ?? throw Boundary();
            PinnedDirectoryPathScope? parentScope = null;
            SafeFileHandle? created = null;
            try
            {
                parentScope = _guard.OpenPinnedDirectoryPath(parent);
                ValidateDirectoryScope(
                    parentScope,
                    GetRelativeParent(normalized));
                created = WindowsFileSystemNative
                    .OpenNewPromotableVerifiedFileHandle(absolute);
                RandomAccess.SetLength(created, expectedLength);
                ValidateFileHandle(
                    created,
                    normalized,
                    expectedLength);
                RevalidateCore();
                RetainDirectoryScope(
                    parentScope,
                    GetRelativeParent(normalized));
                parentScope = null;
                var result = created;
                created = null;
                return result;
            }
            catch
            {
                if (created is not null)
                {
                    try
                    {
                        WindowsFileSystemNative.MarkDeleteOnClose(created);
                    }
                    catch
                    {
                        // The creation failure remains primary.
                    }

                    created.Dispose();
                }

                throw;
            }
            finally
            {
                parentScope?.Dispose();
            }
        }
    }

    public VerifiedStableSource OpenExistingVerified(string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var source = _guard.OpenVerifiedSourceFromApprovedRoot(
                GetAbsolutePath(normalized));
            try
            {
                ValidateFileHandle(
                    source.Handle,
                    normalized,
                    source.Length);
                RevalidateCore();
                return source;
            }
            catch
            {
                source.Dispose();
                throw;
            }
        }
    }

    public VerifiedStableSource? TryOpenExistingOwnedVerified(
        string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var absolute = GetAbsolutePath(normalized);
            var parent = Path.GetDirectoryName(absolute)
                ?? throw Boundary();
            PinnedDirectoryPathScope? parentScope = null;
            SafeFileHandle? probe = null;
            SafeFileHandle? opened = null;
            try
            {
                parentScope = _guard.OpenPinnedDirectoryPath(parent);
                ValidateDirectoryScope(
                    parentScope,
                    GetRelativeParent(normalized));
                probe =
                    WindowsFileSystemNative.OpenBoundaryProbeHandle(
                        absolute);
                if (probe is null)
                {
                    RevalidateCore();
                    return null;
                }

                ValidateFileHandle(
                    probe,
                    normalized,
                    expectedLength: null);
                probe.Dispose();
                probe = null;
                opened = WindowsFileSystemNative
                    .TryOpenOwnedExistingFileHandle(absolute);
                if (opened is null)
                {
                    RevalidateCore();
                    return null;
                }

                ValidateFileHandle(
                    opened,
                    normalized,
                    expectedLength: null);
                var source = VerifiedStableSource.Create(opened);
                opened = null;
                try
                {
                    source.Revalidate();
                    ValidateFileHandle(
                        source.Handle,
                        normalized,
                        source.Length);
                    RevalidateCore();
                    RetainDirectoryScope(
                        parentScope,
                        GetRelativeParent(normalized));
                    parentScope = null;
                    return source;
                }
                catch
                {
                    source.Dispose();
                    throw;
                }
            }
            finally
            {
                probe?.Dispose();
                opened?.Dispose();
                parentScope?.Dispose();
            }
        }
    }

    public VerifiedStableSource OpenExistingPromotableVerified(
        string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var absolute = GetAbsolutePath(normalized);
            var parent = Path.GetDirectoryName(absolute)
                ?? throw Boundary();
            PinnedDirectoryPathScope? parentScope = null;
            SafeFileHandle? opened = null;
            try
            {
                parentScope = _guard.OpenPinnedDirectoryPath(parent);
                ValidateDirectoryScope(
                    parentScope,
                    GetRelativeParent(normalized));
                opened = WindowsFileSystemNative
                    .OpenOwnedExistingPromotableFileHandle(absolute);
                ValidateFileHandle(
                    opened,
                    normalized,
                    expectedLength: null);
                var source = VerifiedStableSource.Create(opened);
                opened = null;
                try
                {
                    source.Revalidate();
                    ValidateFileHandle(
                        source.Handle,
                        normalized,
                        source.Length);
                    RevalidateCore();
                    RetainDirectoryScope(
                        parentScope,
                        GetRelativeParent(normalized));
                    parentScope = null;
                    return source;
                }
                catch
                {
                    source.Dispose();
                    throw;
                }
            }
            finally
            {
                opened?.Dispose();
                parentScope?.Dispose();
            }
        }
    }

    public SafeFileHandle OpenExistingMutableVerified(
        string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var absolute = GetAbsolutePath(normalized);
            var parent = Path.GetDirectoryName(absolute)
                ?? throw Boundary();
            PinnedDirectoryPathScope? parentScope = null;
            SafeFileHandle? opened = null;
            try
            {
                parentScope = _guard.OpenPinnedDirectoryPath(parent);
                ValidateDirectoryScope(
                    parentScope,
                    GetRelativeParent(normalized));
                opened =
                    WindowsFileSystemNative
                        .OpenVerifiedMutableFileHandle(absolute);
                var snapshot =
                    WindowsFileSystemNative.GetStableSourceSnapshot(
                        opened);
                ValidateFileHandle(
                    opened,
                    normalized,
                    snapshot.Length);
                RevalidateCore();
                RetainDirectoryScope(
                    parentScope,
                    GetRelativeParent(normalized));
                parentScope = null;
                var result = opened;
                opened = null;
                return result;
            }
            finally
            {
                opened?.Dispose();
                parentScope?.Dispose();
            }
        }
    }

    public void EnsureDirectoryVerified(string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var current = string.Empty;
            foreach (var component in normalized.Split(
                         Path.DirectorySeparatorChar,
                         StringSplitOptions.None))
            {
                current = current.Length == 0
                    ? component
                    : Path.Combine(current, component);
                if (_retainedDirectories.TryGetValue(
                        current,
                        out var retained))
                {
                    ValidateDirectoryScope(retained, current);
                    continue;
                }

                WindowsFileSystemNative.EnsureDirectoryEntry(
                    GetAbsolutePath(current));
                var scope = _guard.OpenPinnedDirectoryPath(
                    GetAbsolutePath(current));
                try
                {
                    ValidateDirectoryScope(scope, current);
                    _retainedDirectories.Add(current, scope);
                }
                catch
                {
                    scope.Dispose();
                    throw;
                }
            }

            RevalidateCore();
        }
    }

    public void Revalidate()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
        }
    }

    public void RevalidateDirectoryVerified(string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            using var scope = _guard.OpenPinnedDirectoryPath(
                GetAbsolutePath(normalized));
            ValidateDirectoryScope(scope, normalized);
            RevalidateCore();
        }
    }

    public VerifiedDirectoryPromotion
        OpenDirectoryPromotionVerified(string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var handle =
                WindowsFileSystemNative
                    .OpenDirectoryIdentityHandle(
                        GetAbsolutePath(normalized));
            try
            {
                var identity =
                    WindowsFileSystemNative.GetFileIdInfo(handle);
                var result = new VerifiedDirectoryPromotion(
                    this,
                    handle,
                    identity,
                    normalized);
                ValidateDirectoryPromotionCore(result);
                RevalidateCore();
                return result;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
    }

    public void RevalidateDirectoryPromotion(
        VerifiedDirectoryPromotion directory)
    {
        ArgumentNullException.ThrowIfNull(directory);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateDirectoryPromotionCore(directory);
            RevalidateCore();
        }
    }

    public VerifiedDirectoryCleanup OpenDirectoryCleanupGuardian(
        VerifiedDirectoryPromotion directory)
    {
        ArgumentNullException.ThrowIfNull(directory);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateDirectoryPromotionCore(directory);
            var handle = WindowsFileSystemNative
                .OpenDirectoryCleanupGuardianHandle(
                    GetAbsolutePath(directory.RelativePath));
            try
            {
                var cleanup = new VerifiedDirectoryCleanup(
                    this,
                    handle,
                    directory.Identity,
                    directory.RelativePath);
                ValidateDirectoryCleanupCore(cleanup);
                RevalidateCore();
                return cleanup;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
    }

    public bool QuarantineDirectoryNoReplace(
        VerifiedDirectoryPromotion directory,
        VerifiedDirectoryCleanup cleanup,
        string destinationRelativePath)
    {
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(cleanup);
        var destination =
            NormalizeRelativePath(destinationRelativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateDirectoryPromotionCore(directory);
            ValidateDirectoryCleanupCore(cleanup);
            RequireSameIdentity(directory.Identity, cleanup.Identity);
            if (!string.Equals(
                    directory.RelativePath,
                    cleanup.RelativePath,
                    StringComparison.Ordinal)
                || !string.Equals(
                    GetRelativeParent(cleanup.RelativePath),
                    GetRelativeParent(destination),
                    StringComparison.Ordinal))
            {
                throw Boundary();
            }

            var destinationParent =
                Path.GetDirectoryName(GetAbsolutePath(destination))
                ?? throw Boundary();
            using var destinationParentScope =
                _guard.OpenPinnedDirectoryPath(destinationParent);
            ValidateDirectoryScope(
                destinationParentScope,
                GetRelativeParent(destination));
            if (!WindowsFileSystemNative.RenameHandleNoReplace(
                    cleanup.Handle,
                    GetAbsolutePath(destination)))
            {
                ValidateDirectoryCleanupCore(cleanup);
                RevalidateCore();
                return false;
            }

            directory.RelativePath = destination;
            cleanup.RelativePath = destination;
            ValidateDirectoryCleanupCore(cleanup);
            ValidateDirectoryPromotionCore(directory);
            RevalidateCore();
            return true;
        }
    }

    public void DeleteBoundedOwnedDirectoryTree(
        VerifiedDirectoryCleanup cleanup,
        IReadOnlySet<string> allowedFilePaths,
        IReadOnlySet<string> allowedDirectoryPaths,
        int maximumEntryCount,
        long maximumTotalBytes,
        TimeSpan maximumDuration)
    {
        ArgumentNullException.ThrowIfNull(cleanup);
        ArgumentNullException.ThrowIfNull(allowedFilePaths);
        ArgumentNullException.ThrowIfNull(allowedDirectoryPaths);
        if (maximumEntryCount < 0
            || maximumTotalBytes < 0
            || maximumDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumEntryCount));
        }

        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateDirectoryCleanupCore(cleanup);
            var started = Stopwatch.GetTimestamp();
            var opened = new List<OwnedCleanupEntry>(
                Math.Min(maximumEntryCount, 32));
            try
            {
                var entryCount = 0;
                long totalBytes = 0;
                var directories =
                    new Queue<(string StorePath, string OwnedPath)>();
                directories.Enqueue((cleanup.RelativePath, string.Empty));
                while (directories.Count != 0)
                {
                    var parent = directories.Dequeue();
                    foreach (var path in
                             Directory.EnumerateFileSystemEntries(
                                 GetAbsolutePath(parent.StorePath),
                                 "*",
                                 SearchOption.TopDirectoryOnly))
                    {
                        entryCount = checked(entryCount + 1);
                        if (entryCount > maximumEntryCount
                            || Stopwatch.GetElapsedTime(started)
                                > maximumDuration)
                        {
                            throw Boundary();
                        }

                        var name = Path.GetFileName(path);
                        if (string.IsNullOrEmpty(name))
                        {
                            throw Boundary();
                        }

                        var relativePath = NormalizeRelativePath(
                            Path.Combine(parent.StorePath, name));
                        var ownedPath = string.IsNullOrEmpty(
                            parent.OwnedPath)
                            ? name
                            : Path.Combine(parent.OwnedPath, name);
                        SafeFileHandle? handle = null;
                        try
                        {
                            handle = WindowsFileSystemNative
                                .OpenCleanupEntryHandle(
                                    GetAbsolutePath(relativePath));
                            var attributes =
                                WindowsFileSystemNative
                                    .GetAttributeTagInfo(handle);
                            if ((attributes.FileAttributes
                                    & WindowsFileSystemNative
                                        .FileAttributeReparsePoint) != 0)
                            {
                                throw Boundary();
                            }

                            var isDirectory =
                                (attributes.FileAttributes
                                    & WindowsFileSystemNative
                                        .FileAttributeDirectory) != 0;
                            RequireRootVolume(handle);
                            RequirePhysicalPath(
                                WindowsFileSystemNative.GetFinalPath(
                                    handle),
                                GetExpectedPhysicalPath(relativePath));
                            if (WindowsFileSystemNative.GetLinkCount(
                                    handle)
                                != 1)
                            {
                                throw Boundary();
                            }

                            if (isDirectory)
                            {
                                if (!allowedDirectoryPaths.Contains(
                                        ownedPath))
                                {
                                    throw Boundary();
                                }

                                directories.Enqueue(
                                    (relativePath, ownedPath));
                            }
                            else
                            {
                                if (!allowedFilePaths.Contains(
                                        ownedPath))
                                {
                                    throw Boundary();
                                }

                                var length =
                                    RandomAccess.GetLength(handle);
                                if (length < 0)
                                {
                                    throw Boundary();
                                }

                                totalBytes = checked(
                                    totalBytes + length);
                                if (totalBytes > maximumTotalBytes)
                                {
                                    throw Boundary();
                                }
                            }

                            opened.Add(
                                new OwnedCleanupEntry(
                                    handle,
                                    relativePath,
                                    ownedPath,
                                    isDirectory));
                            handle = null;
                        }
                        finally
                        {
                            handle?.Dispose();
                        }
                    }
                }

                if (Stopwatch.GetElapsedTime(started)
                    > maximumDuration)
                {
                    throw Boundary();
                }

                ValidateDirectoryCleanupCore(cleanup);
                foreach (var entry in opened.Where(
                             static entry => !entry.IsDirectory))
                {
                    DeleteCleanupEntry(entry);
                }

                foreach (var entry in opened
                             .Where(static entry => entry.IsDirectory)
                             .OrderByDescending(static entry =>
                                 entry.OwnedRelativePath.Count(
                                     static character =>
                                         character
                                         == Path.DirectorySeparatorChar)))
                {
                    if (Directory.EnumerateFileSystemEntries(
                            GetAbsolutePath(entry.RelativePath),
                            "*",
                            SearchOption.TopDirectoryOnly)
                        .Take(1)
                        .Any())
                    {
                        throw Boundary();
                    }

                    DeleteCleanupEntry(entry);
                }

                ValidateDirectoryCleanupCore(cleanup);
                if (Directory.EnumerateFileSystemEntries(
                        GetAbsolutePath(cleanup.RelativePath),
                        "*",
                        SearchOption.TopDirectoryOnly)
                    .Take(1)
                    .Any()
                    || Stopwatch.GetElapsedTime(started)
                        > maximumDuration)
                {
                    throw Boundary();
                }

                WindowsFileSystemNative.MarkDeleteOnClose(
                    cleanup.Handle);
                cleanup.MarkDeletePending();
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or OverflowException
                    or System.Security.SecurityException)
            {
                throw Boundary();
            }
            finally
            {
                foreach (var entry in opened)
                {
                    entry.Dispose();
                }
            }
        }
    }

    private static void DeleteCleanupEntry(OwnedCleanupEntry entry)
    {
        WindowsFileSystemNative.MarkDeleteOnClose(entry.Handle);
        entry.Dispose();
    }

    public void RevalidateDatabaseFileSet(string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            RequireVerifiedEntryIfPresent(
                normalized,
                required: true);
            RequireVerifiedEntryIfPresent(
                normalized + "-journal",
                required: false);
            RequireVerifiedEntryIfPresent(
                normalized + "-wal",
                required: false);
            RequireVerifiedEntryIfPresent(
                normalized + "-shm",
                required: false);
            RevalidateCore();
        }
    }

    public IReadOnlyList<string> EnumerateVerifiedFileNames(
        string relativeDirectory)
        => EnumerateVerifiedFileNames(
            relativeDirectory,
            int.MaxValue,
            long.MaxValue,
            Timeout.InfiniteTimeSpan);

    public IReadOnlyList<string> EnumerateVerifiedFileNames(
        string relativeDirectory,
        int maximumEntryCount,
        long maximumTotalBytes,
        TimeSpan maximumDuration)
    {
        if (maximumEntryCount < 0
            || maximumTotalBytes < 0
            || maximumDuration != Timeout.InfiniteTimeSpan
                && maximumDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumEntryCount));
        }

        var normalized = NormalizeRelativePath(relativeDirectory);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            using var directory = _guard.OpenPinnedDirectoryPath(
                GetAbsolutePath(normalized));
            ValidateDirectoryScope(directory, normalized);

            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFileSystemEntries(
                        GetAbsolutePath(normalized),
                        "*",
                        SearchOption.TopDirectoryOnly);
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or System.Security.SecurityException)
            {
                throw Boundary();
            }

            var started = Stopwatch.GetTimestamp();
            var entryCount = 0;
            long totalBytes = 0;
            var names = new List<string>(
                Math.Min(maximumEntryCount, 256));
            try
            {
                foreach (var entry in entries)
                {
                    entryCount = checked(entryCount + 1);
                    ValidateEnumerationBudget(
                        entryCount,
                        totalBytes,
                        Stopwatch.GetElapsedTime(started),
                        maximumEntryCount,
                        maximumTotalBytes,
                        maximumDuration);
                    var name = Path.GetFileName(entry);
                    var relative = NormalizeRelativePath(
                        Path.Combine(normalized, name));
                    using var probe =
                        WindowsFileSystemNative.OpenBoundaryProbeHandle(
                            GetAbsolutePath(relative));
                    if (probe is null)
                    {
                        continue;
                    }

                    ValidateFileHandle(
                        probe,
                        relative,
                        expectedLength: null);
                    totalBytes = checked(
                        totalBytes + RandomAccess.GetLength(probe));
                    ValidateEnumerationBudget(
                        entryCount,
                        totalBytes,
                        Stopwatch.GetElapsedTime(started),
                        maximumEntryCount,
                        maximumTotalBytes,
                        maximumDuration);
                    names.Add(name);
                }
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or OverflowException
                    or System.Security.SecurityException)
            {
                throw Boundary();
            }

            RevalidateCore();
            return names;
        }
    }

    private static void ValidateEnumerationBudget(
        int entryCount,
        long totalBytes,
        TimeSpan elapsed,
        int maximumEntryCount,
        long maximumTotalBytes,
        TimeSpan maximumDuration)
    {
        if (entryCount > maximumEntryCount
            || totalBytes > maximumTotalBytes
            || maximumDuration != Timeout.InfiniteTimeSpan
                && elapsed > maximumDuration)
        {
            throw Boundary();
        }
    }

    public bool PromoteCreatedNoReplace(
        SafeFileHandle handle,
        string sourceRelativePath,
        string destinationRelativePath,
        long expectedLength,
        FilePromotionOwnership ownership)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(ownership);
        if (expectedLength < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedLength));
        }

        var source = NormalizeRelativePath(sourceRelativePath);
        var destination =
            NormalizeRelativePath(destinationRelativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateFileHandle(handle, source, expectedLength);
            var destinationParent =
                Path.GetDirectoryName(GetAbsolutePath(destination))
                ?? throw Boundary();
            using var destinationScope =
                _guard.OpenPinnedDirectoryPath(destinationParent);
            ValidateDirectoryScope(
                destinationScope,
                GetRelativeParent(destination));

            using (var existing =
                   WindowsFileSystemNative.OpenBoundaryProbeHandle(
                       GetAbsolutePath(destination)))
            {
                if (existing is not null)
                {
                    ValidateFileHandle(
                        existing,
                        destination,
                        expectedLength: null);
                    RevalidateCore();
                    return false;
                }
            }

            var promoted = WindowsFileSystemNative.MoveNoReplace(
                GetAbsolutePath(source),
                GetAbsolutePath(destination));
            if (promoted)
            {
                ownership.Transfer();
            }

            ValidateFileHandle(
                handle,
                promoted ? destination : source,
                expectedLength);
            RevalidateCore();
            if (promoted)
            {
                RetainDirectoryScope(
                    _guard.OpenPinnedDirectoryPath(
                        destinationParent),
                    GetRelativeParent(destination));
            }

            return promoted;
        }
    }

    public bool PromoteVerifiedDirectoryNoReplace(
        VerifiedDirectoryPromotion source,
        string destinationRelativePath)
    {
        ArgumentNullException.ThrowIfNull(source);
        var destination =
            NormalizeRelativePath(destinationRelativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateDirectoryPromotionCore(source);
            using var promotionHandle =
                WindowsFileSystemNative
                    .OpenDirectoryPromotionHandle(
                        GetAbsolutePath(source.RelativePath));
            RequireRootVolume(promotionHandle);
            RequireSameIdentity(
                source.Identity,
                WindowsFileSystemNative.GetFileIdInfo(
                    promotionHandle));
            RequirePhysicalPath(
                WindowsFileSystemNative.GetFinalPath(
                    promotionHandle),
                GetExpectedPhysicalPath(
                    source.RelativePath));
            var destinationParent =
                Path.GetDirectoryName(GetAbsolutePath(destination))
                ?? throw Boundary();
            using var destinationParentScope =
                _guard.OpenPinnedDirectoryPath(destinationParent);
            ValidateDirectoryScope(
                destinationParentScope,
                GetRelativeParent(destination));
            using (var existing =
                   WindowsFileSystemNative.OpenBoundaryProbeHandle(
                       GetAbsolutePath(destination)))
            {
                if (existing is not null)
                {
                    RevalidateCore();
                    return false;
                }
            }

            if (!WindowsFileSystemNative.RenameHandleNoReplace(
                    promotionHandle,
                    GetAbsolutePath(destination)))
            {
                RevalidateCore();
                return false;
            }

            source.RelativePath = destination;
            ValidateDirectoryPromotionCore(source);
            RequireSameIdentity(
                source.Identity,
                WindowsFileSystemNative.GetFileIdInfo(
                    promotionHandle));
            RequirePhysicalPath(
                WindowsFileSystemNative.GetFinalPath(
                    promotionHandle),
                GetExpectedPhysicalPath(destination));
            promotionHandle.Dispose();
            using var destinationScope =
                _guard.OpenPinnedDirectoryPath(
                    GetAbsolutePath(destination));
            ValidateDirectoryScope(destinationScope, destination);
            RequireSameIdentity(
                source.Identity,
                destinationScope.FinalIdentity);
            RevalidateCore();
            return true;
        }
    }

    public VerifiedStableSource AdoptCreatedVerified(
        SafeFileHandle handle,
        string relativePath,
        long expectedLength)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (expectedLength < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedLength));
        }

        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateFileHandle(handle, normalized, expectedLength);
            var source = VerifiedStableSource.Create(handle);
            try
            {
                source.Revalidate();
                ValidateFileHandle(
                    source.Handle,
                    normalized,
                    expectedLength);
                RevalidateCore();
                return source;
            }
            catch
            {
                source.Dispose();
                throw;
            }
        }
    }

    public void RevalidateCreated(
        SafeFileHandle handle,
        string relativePath,
        long expectedLength)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (expectedLength < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedLength));
        }

        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateFileHandle(
                handle,
                normalized,
                expectedLength);
            RevalidateCore();
        }
    }

    public void RevalidateExisting(
        SafeFileHandle handle,
        string relativePath)
    {
        ArgumentNullException.ThrowIfNull(handle);
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            var snapshot =
                WindowsFileSystemNative.GetStableSourceSnapshot(handle);
            ValidateFileHandle(
                handle,
                normalized,
                snapshot.Length);
            RevalidateCore();
        }
    }

    public void RevalidateExisting(
        VerifiedStableSource source,
        string relativePath)
    {
        ArgumentNullException.ThrowIfNull(source);
        source.Revalidate();
        RevalidateExisting(source.Handle, relativePath);
    }

    public void DeleteOwnedOnClose(
        SafeFileHandle handle,
        string relativePath,
        long expectedLength)
    {
        ArgumentNullException.ThrowIfNull(handle);
        var normalized = NormalizeRelativePath(relativePath);
        lock (_sync)
        {
            ThrowIfDisposed();
            RevalidateCore();
            ValidateFileHandle(
                handle,
                normalized,
                expectedLength);
            WindowsFileSystemNative.MarkDeleteOnClose(handle);
            RevalidateCore();
        }
    }

    public void DeleteOwnedOnClose(
        VerifiedStableSource source,
        string relativePath,
        long expectedLength)
    {
        ArgumentNullException.ThrowIfNull(source);
        source.Revalidate();
        DeleteOwnedOnClose(
            source.Handle,
            relativePath,
            expectedLength);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_rootScope is null)
            {
                return;
            }

            foreach (var scope in _retainedDirectories
                         .Values
                         .Reverse())
            {
                scope.Dispose();
            }

            _retainedDirectories.Clear();
            _rootScope.Dispose();
            _rootScope = null;
        }
    }

    private void RevalidateCore()
    {
        var root = _rootScope
            ?? throw new ObjectDisposedException(
                nameof(ApprovedRootFileStore));
        RequireSameIdentity(
            _rootIdentity,
            WindowsFileSystemNative.GetFileIdInfo(root.FinalHandle));
        RequirePhysicalPath(
            WindowsFileSystemNative.GetFinalPath(root.FinalHandle),
            _rootPhysicalPath);
        RequireRootVolume(root.FinalHandle);

        using var current = _guard.OpenPinnedDirectoryPath(
            _guard.ApprovedRoot);
        RequireSameIdentity(_rootIdentity, current.FinalIdentity);
        RequireSameIdentity(
            _rootIdentity,
            WindowsFileSystemNative.GetFileIdInfo(
                current.FinalHandle));
        RequirePhysicalPath(
            WindowsFileSystemNative.GetFinalPath(
                current.FinalHandle),
            _rootPhysicalPath);
        RequireRootVolume(current.FinalHandle);
    }

    private void ValidateDirectoryScope(
        PinnedDirectoryPathScope scope,
        string relativePath)
    {
        var information = WindowsFileSystemNative.GetAttributeTagInfo(
            scope.FinalHandle);
        if ((information.FileAttributes
                & WindowsFileSystemNative.FileAttributeReparsePoint) != 0
            || (information.FileAttributes
                & WindowsFileSystemNative.FileAttributeDirectory) == 0)
        {
            throw Boundary();
        }

        RequireRootVolume(scope.FinalHandle);
        RequirePhysicalPath(
            WindowsFileSystemNative.GetFinalPath(scope.FinalHandle),
            GetExpectedPhysicalPath(relativePath));
    }

    private void RetainDirectoryScope(
        PinnedDirectoryPathScope scope,
        string relativePath)
    {
        if (string.IsNullOrEmpty(relativePath)
            || _retainedDirectories.ContainsKey(relativePath))
        {
            scope.Dispose();
            return;
        }

        _retainedDirectories.Add(relativePath, scope);
    }

    private void ValidateFileHandle(
        SafeFileHandle handle,
        string relativePath,
        long? expectedLength)
    {
        if (handle.IsClosed || handle.IsInvalid)
        {
            throw Boundary();
        }

        var attributes = WindowsFileSystemNative.GetAttributeTagInfo(
            handle);
        if ((attributes.FileAttributes
                & (WindowsFileSystemNative.FileAttributeDirectory
                    | WindowsFileSystemNative
                        .FileAttributeReparsePoint)) != 0)
        {
            throw Boundary();
        }

        var snapshot =
            WindowsFileSystemNative.GetStableSourceSnapshot(handle);
        var identifiers = StableSourceValidator.Validate(
            snapshot.IsLocal,
            snapshot.HasVolumeInformation,
            snapshot.FileSystemName,
            snapshot.FileId.VolumeSerialNumber,
            snapshot.FileId.FileId.LowPart,
            snapshot.FileId.FileId.HighPart);
        if (identifiers.VolumeId != _rootVolumeId
            || snapshot.NumberOfLinks != 1
            || (expectedLength is not null
                && snapshot.Length != expectedLength.Value))
        {
            throw Boundary();
        }

        RequirePhysicalPath(
            WindowsFileSystemNative.GetFinalPath(handle),
            GetExpectedPhysicalPath(relativePath));
    }

    private void RequireVerifiedEntryIfPresent(
        string relativePath,
        bool required)
    {
        using var probe =
            WindowsFileSystemNative.OpenBoundaryProbeHandle(
                GetAbsolutePath(relativePath));
        if (probe is null)
        {
            if (required)
            {
                throw Boundary();
            }

            return;
        }

        ValidateFileHandle(
            probe,
            relativePath,
            expectedLength: null);
    }

    private void RequireRootVolume(SafeFileHandle handle)
    {
        var snapshot =
            WindowsFileSystemNative.GetStableVolumeSnapshot(handle);
        var volume = StableVolumeValidator.Validate(
            snapshot.IsLocal,
            snapshot.HasVolumeInformation,
            snapshot.FileSystemName,
            snapshot.FileId.VolumeSerialNumber);
        if (volume != _rootVolumeId)
        {
            throw Boundary();
        }
    }

    private string GetAbsolutePath(string relativePath)
    {
        var combined = Path.Combine(_guard.ApprovedRoot, relativePath);
        var canonical = _guard.CanonicalizeContainedPath(combined);
        var expected = Path.Combine(_guard.ApprovedRoot, relativePath);
        if (!string.Equals(
                canonical,
                expected,
                StringComparison.OrdinalIgnoreCase))
        {
            throw Boundary();
        }

        return canonical;
    }

    private string GetExpectedPhysicalPath(string relativePath) =>
        string.IsNullOrEmpty(relativePath)
            ? _rootPhysicalPath
            : Path.Combine(_rootPhysicalPath, relativePath);

    private static string GetRelativeParent(string relativePath) =>
        Path.GetDirectoryName(relativePath) ?? string.Empty;

    private static string NormalizeRelativePath(string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            relativePath,
            nameof(relativePath));
        if (Path.IsPathRooted(relativePath)
            || Path.IsPathFullyQualified(relativePath)
            || relativePath.Contains(
                Path.AltDirectorySeparatorChar,
                StringComparison.Ordinal)
            || relativePath.EndsWith(
                Path.DirectorySeparatorChar)
            || relativePath.Contains(':', StringComparison.Ordinal))
        {
            throw Boundary();
        }

        var components = relativePath.Split(
            Path.DirectorySeparatorChar,
            StringSplitOptions.None);
        if (components.Length == 0)
        {
            throw Boundary();
        }

        foreach (var component in components)
        {
            if (component.Length == 0
                || component is "." or ".."
                || component.EndsWith(' ')
                || component.EndsWith('.')
                || component.IndexOfAny(
                    Path.GetInvalidFileNameChars()) >= 0
                || IsReservedDeviceName(component))
            {
                throw Boundary();
            }
        }

        var normalized = string.Join(
            Path.DirectorySeparatorChar,
            components);
        if (!string.Equals(
                normalized,
                relativePath,
                StringComparison.Ordinal))
        {
            throw Boundary();
        }

        return normalized;
    }

    private static bool IsReservedDeviceName(string component)
    {
        var baseName = component.Split('.', 2)[0];
        if (baseName.Equals("CON", StringComparison.OrdinalIgnoreCase)
            || baseName.Equals("PRN", StringComparison.OrdinalIgnoreCase)
            || baseName.Equals("AUX", StringComparison.OrdinalIgnoreCase)
            || baseName.Equals("NUL", StringComparison.OrdinalIgnoreCase)
            || baseName.Equals("CLOCK$", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (baseName.Length is 4
            && (baseName.StartsWith(
                    "COM",
                    StringComparison.OrdinalIgnoreCase)
                || baseName.StartsWith(
                    "LPT",
                    StringComparison.OrdinalIgnoreCase)))
        {
            return baseName[3] is >= '1' and <= '9'
                or '\u00b9'
                or '\u00b2'
                or '\u00b3';
        }

        return false;
    }

    private static void RequirePhysicalPath(
        string actual,
        string expected)
    {
        if (!string.Equals(
                Path.TrimEndingDirectorySeparator(actual),
                Path.TrimEndingDirectorySeparator(expected),
                StringComparison.OrdinalIgnoreCase))
        {
            throw Boundary();
        }
    }

    private static void RequireSameIdentity(
        WindowsFileSystemNative.FILE_ID_INFO expected,
        WindowsFileSystemNative.FILE_ID_INFO actual)
    {
        if (expected.VolumeSerialNumber
                != actual.VolumeSerialNumber
            || expected.FileId.LowPart != actual.FileId.LowPart
            || expected.FileId.HighPart != actual.FileId.HighPart)
        {
            throw Boundary();
        }
    }

    private void ValidateDirectoryPromotionCore(
        VerifiedDirectoryPromotion directory)
    {
        if (!ReferenceEquals(directory.Owner, this)
            || directory.Handle.IsClosed
            || directory.Handle.IsInvalid)
        {
            throw Boundary();
        }

        var attributes =
            WindowsFileSystemNative.GetAttributeTagInfo(
                directory.Handle);
        if ((attributes.FileAttributes
                & WindowsFileSystemNative
                    .FileAttributeReparsePoint) != 0
            || (attributes.FileAttributes
                & WindowsFileSystemNative
                    .FileAttributeDirectory) == 0)
        {
            throw Boundary();
        }

        RequireRootVolume(directory.Handle);
        RequireSameIdentity(
            directory.Identity,
            WindowsFileSystemNative.GetFileIdInfo(
                directory.Handle));
        RequirePhysicalPath(
            WindowsFileSystemNative.GetFinalPath(
                directory.Handle),
            GetExpectedPhysicalPath(directory.RelativePath));
    }

    private void ValidateDirectoryCleanupCore(
        VerifiedDirectoryCleanup cleanup)
    {
        if (!ReferenceEquals(cleanup.Owner, this)
            || cleanup.Handle.IsClosed
            || cleanup.Handle.IsInvalid
            || cleanup.DeletePending)
        {
            throw Boundary();
        }

        var attributes =
            WindowsFileSystemNative.GetAttributeTagInfo(cleanup.Handle);
        if ((attributes.FileAttributes
                & WindowsFileSystemNative
                    .FileAttributeReparsePoint) != 0
            || (attributes.FileAttributes
                & WindowsFileSystemNative
                    .FileAttributeDirectory) == 0
            || WindowsFileSystemNative.GetLinkCount(cleanup.Handle)
                != 1)
        {
            throw Boundary();
        }

        RequireRootVolume(cleanup.Handle);
        RequireSameIdentity(
            cleanup.Identity,
            WindowsFileSystemNative.GetFileIdInfo(cleanup.Handle));
        RequirePhysicalPath(
            WindowsFileSystemNative.GetFinalPath(cleanup.Handle),
            GetExpectedPhysicalPath(cleanup.RelativePath));
    }

    private void ThrowIfDisposed()
    {
        if (_rootScope is null)
        {
            throw new ObjectDisposedException(
                nameof(ApprovedRootFileStore));
        }
    }

    private static FileSystemBoundaryException Boundary() =>
        new("The approved-root file-store boundary was not satisfied.");
}

public sealed class FileStoreEntryAlreadyExistsException : IOException
{
    internal FileStoreEntryAlreadyExistsException()
        : base("The approved-root entry already exists.")
    {
    }
}

public sealed class VerifiedDirectoryPromotion : IDisposable
{
    private SafeFileHandle? _handle;

    internal VerifiedDirectoryPromotion(
        ApprovedRootFileStore owner,
        SafeFileHandle handle,
        WindowsFileSystemNative.FILE_ID_INFO identity,
        string relativePath)
    {
        Owner = owner;
        _handle = handle;
        Identity = identity;
        RelativePath = relativePath;
    }

    internal ApprovedRootFileStore Owner { get; }

    internal SafeFileHandle Handle =>
        _handle
        ?? throw new ObjectDisposedException(
            nameof(VerifiedDirectoryPromotion));

    internal WindowsFileSystemNative.FILE_ID_INFO Identity { get; }

    internal string RelativePath { get; set; }

    public void Dispose()
    {
        Interlocked.Exchange(ref _handle, null)?.Dispose();
    }
}

public sealed class VerifiedDirectoryCleanup : IDisposable
{
    private SafeFileHandle? _handle;
    private int _deletePending;

    internal VerifiedDirectoryCleanup(
        ApprovedRootFileStore owner,
        SafeFileHandle handle,
        WindowsFileSystemNative.FILE_ID_INFO identity,
        string relativePath)
    {
        Owner = owner;
        _handle = handle;
        Identity = identity;
        RelativePath = relativePath;
    }

    internal ApprovedRootFileStore Owner { get; }

    internal SafeFileHandle Handle =>
        _handle
        ?? throw new ObjectDisposedException(
            nameof(VerifiedDirectoryCleanup));

    internal WindowsFileSystemNative.FILE_ID_INFO Identity { get; }

    internal string RelativePath { get; set; }

    internal bool DeletePending =>
        Volatile.Read(ref _deletePending) != 0;

    internal void MarkDeletePending() =>
        Volatile.Write(ref _deletePending, 1);

    public void Dispose()
    {
        Interlocked.Exchange(ref _handle, null)?.Dispose();
    }
}

internal sealed class OwnedCleanupEntry : IDisposable
{
    private SafeFileHandle? _handle;

    internal OwnedCleanupEntry(
        SafeFileHandle handle,
        string relativePath,
        string ownedRelativePath,
        bool isDirectory)
    {
        _handle = handle;
        RelativePath = relativePath;
        OwnedRelativePath = ownedRelativePath;
        IsDirectory = isDirectory;
    }

    internal SafeFileHandle Handle =>
        _handle
        ?? throw new ObjectDisposedException(
            nameof(OwnedCleanupEntry));

    internal string RelativePath { get; }

    internal string OwnedRelativePath { get; }

    internal bool IsDirectory { get; }

    public void Dispose()
    {
        Interlocked.Exchange(ref _handle, null)?.Dispose();
    }
}

public sealed class FilePromotionOwnership
{
    private int _transferred;

    public bool IsTransferred =>
        Volatile.Read(ref _transferred) != 0;

    internal void Transfer() =>
        Volatile.Write(ref _transferred, 1);
}
