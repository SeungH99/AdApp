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
        long expectedLength)
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
            || snapshot.Length != expectedLength)
        {
            throw Boundary();
        }

        RequirePhysicalPath(
            WindowsFileSystemNative.GetFinalPath(handle),
            GetExpectedPhysicalPath(relativePath));
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
