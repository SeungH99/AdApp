using System.Collections.Concurrent;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public enum VaultLeaseMode
{
    Read,
    Mutation,
    Rebuild,
}

public sealed class VaultMaintenanceGate
{
    private static readonly ConcurrentDictionary<string, VaultAdmissionState> ProcessAdmissions =
        new(StringComparer.Ordinal);
    private static readonly AsyncLocal<AmbientLeaseState?> AmbientLeases = new();

    private readonly string _identity;
    private readonly VaultAdmissionState _processAdmission;

    public VaultMaintenanceGate(string keyRingPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyRingPath);
        KeyRingPath = Path.GetFullPath(keyRingPath);
        _identity = OperatingSystem.IsWindows()
            ? KeyRingPath.ToUpperInvariant()
            : KeyRingPath;
        LockPath = KeyRingPath + ".lock";
        RebuildLockPath = KeyRingPath + ".rebuild.lock";
        AdmissionLockPath = KeyRingPath + ".admission.lock";
        WriterIntentLockPath = KeyRingPath + ".writer-intent.lock";
        ActiveRebuildLockPath = KeyRingPath + ".active-rebuild.lock";
        _processAdmission = ProcessAdmissions.GetOrAdd(
            _identity,
            static _ => new VaultAdmissionState());
    }

    public string KeyRingPath { get; }

    public string LockPath { get; }

    public string RebuildLockPath { get; }

    public string AdmissionLockPath { get; }

    public string WriterIntentLockPath { get; }

    public string ActiveRebuildLockPath { get; }

    public ValueTask<VaultMaintenanceLease> AcquireReadAsync(
        CancellationToken cancellationToken) =>
        AcquireWithAmbient(VaultLeaseMode.Read, cancellationToken);

    public ValueTask<VaultMaintenanceLease> AcquireMutationAsync(
        CancellationToken cancellationToken) =>
        AcquireWithAmbient(VaultLeaseMode.Mutation, cancellationToken);

    public ValueTask<VaultMaintenanceLease> AcquireRebuildAsync(
        CancellationToken cancellationToken) =>
        AcquireWithAmbient(VaultLeaseMode.Rebuild, cancellationToken);

    public ValueTask<VaultMaintenanceLease> AcquireAsync(CancellationToken cancellationToken) =>
        AcquireMutationAsync(cancellationToken);

    private ValueTask<VaultMaintenanceLease> AcquireWithAmbient(
        VaultLeaseMode mode,
        CancellationToken cancellationToken)
    {
        var ambient = AmbientLeases.Value;
        if (ambient is null)
        {
            ambient = new AmbientLeaseState();
            AmbientLeases.Value = ambient;
        }

        ambient.ValidateBeforeAcquire(_identity, mode);
        return AcquireModeAsync(mode, ambient, cancellationToken);
    }

    private async ValueTask<VaultMaintenanceLease> AcquireModeAsync(
        VaultLeaseMode mode,
        AmbientLeaseState ambient,
        CancellationToken cancellationToken)
    {
        RequireSafeLockPaths();
        FileStream? rebuildLock = null;
        FileStream? writerIntentLock = null;
        FileStream? activeRebuildLock = null;
        FileStream? admissionLock = null;
        FileStream? canonicalLock = null;
        VaultAdmissionTicket? processTicket = null;
        try
        {
            if (mode == VaultLeaseMode.Mutation)
            {
                writerIntentLock = await OpenLockAsync(
                    WriterIntentLockPath,
                    FileShare.None,
                    cancellationToken).ConfigureAwait(false);
            }
            else if (mode == VaultLeaseMode.Rebuild)
            {
                writerIntentLock = await OpenLockAsync(
                    WriterIntentLockPath,
                    FileShare.ReadWrite,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                writerIntentLock = await OpenReaderIntentAsync(cancellationToken)
                    .ConfigureAwait(false);
            }

            if (mode is VaultLeaseMode.Mutation or VaultLeaseMode.Rebuild)
            {
                rebuildLock = await OpenLockAsync(
                    RebuildLockPath,
                    FileShare.None,
                    cancellationToken).ConfigureAwait(false);
            }

            if (mode == VaultLeaseMode.Rebuild)
            {
                activeRebuildLock = await OpenLockAsync(
                    ActiveRebuildLockPath,
                    FileShare.None,
                    cancellationToken).ConfigureAwait(false);
                writerIntentLock!.Dispose();
                writerIntentLock = null;
            }

            processTicket = await _processAdmission
                .AcquireAsync(mode, cancellationToken)
                .ConfigureAwait(false);

            admissionLock = await OpenLockAsync(
                AdmissionLockPath,
                mode == VaultLeaseMode.Mutation ? FileShare.None : FileShare.ReadWrite,
                cancellationToken).ConfigureAwait(false);

            canonicalLock = await OpenLockAsync(
                LockPath,
                mode == VaultLeaseMode.Mutation ? FileShare.None : FileShare.ReadWrite,
                cancellationToken).ConfigureAwait(false);

            WindowsVaultPathGuard.RequireSafeForOpen(KeyRingPath);
            admissionLock.Dispose();
            admissionLock = null;
            if (mode == VaultLeaseMode.Read)
            {
                writerIntentLock?.Dispose();
                writerIntentLock = null;
            }

            var lease = new VaultMaintenanceLease(
                _identity,
                mode,
                processTicket,
                canonicalLock,
                rebuildLock,
                writerIntentLock,
                activeRebuildLock,
                ambient);
            processTicket = null;
            canonicalLock = null;
            rebuildLock = null;
            writerIntentLock = null;
            activeRebuildLock = null;
            return lease;
        }
        catch
        {
            canonicalLock?.Dispose();
            admissionLock?.Dispose();
            processTicket?.Dispose();
            activeRebuildLock?.Dispose();
            rebuildLock?.Dispose();
            writerIntentLock?.Dispose();
            throw;
        }
    }

    private void RequireSafeLockPaths()
    {
        WindowsVaultPathGuard.RequireSafeEntryShape(KeyRingPath);
        WindowsVaultPathGuard.RequireSafeEntryShape(LockPath);
        WindowsVaultPathGuard.RequireSafeEntryShape(RebuildLockPath);
        WindowsVaultPathGuard.RequireSafeEntryShape(AdmissionLockPath);
        WindowsVaultPathGuard.RequireSafeEntryShape(WriterIntentLockPath);
        WindowsVaultPathGuard.RequireSafeEntryShape(ActiveRebuildLockPath);
    }

    private async ValueTask<FileStream?> OpenReaderIntentAsync(
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var readerIntent = TryOpenLock(WriterIntentLockPath, FileShare.ReadWrite);
            if (readerIntent is not null) return readerIntent;

            var activeRebuildProbe = TryOpenLock(
                ActiveRebuildLockPath,
                FileShare.ReadWrite);
            if (activeRebuildProbe is null)
            {
                // A queued mutation must not stop reads until the active rebuild
                // releases its separate marker.
                return null;
            }

            activeRebuildProbe.Dispose();
            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static FileStream? TryOpenLock(string path, FileShare share)
    {
        try
        {
            var stream = new FileStream(
                path,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                share,
                bufferSize: 1,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            try
            {
                WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(
                    path,
                    stream.SafeFileHandle);
                return stream;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }
        catch (IOException exception) when (IsSharingViolation(exception))
        {
            return null;
        }
        catch (IOException exception)
        {
            throw new VaultMaintenancePersistenceException(exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new VaultMaintenancePersistenceException(exception);
        }
    }

    private static async ValueTask<FileStream> OpenLockAsync(
        string path,
        FileShare share,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var stream = new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    share,
                    bufferSize: 1,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
                try
                {
                    WindowsVaultPathGuard.RequireOpenedCanonicalSingleLinkFile(
                        path,
                        stream.SafeFileHandle);
                    return stream;
                }
                catch
                {
                    stream.Dispose();
                    throw;
                }
            }
            catch (IOException exception) when (IsSharingViolation(exception))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                throw new VaultMaintenancePersistenceException(exception);
            }
            catch (UnauthorizedAccessException exception)
            {
                throw new VaultMaintenancePersistenceException(exception);
            }
        }
    }

    private static bool IsSharingViolation(IOException exception)
    {
        var nativeCode = exception.HResult & 0xFFFF;
        return nativeCode is 32 or 33;
    }

    internal void Validate(VaultMaintenanceLease lease)
    {
        ArgumentNullException.ThrowIfNull(lease);
        if (!lease.IsValidFor(_identity))
        {
            throw new InvalidVaultMaintenanceLeaseException();
        }
    }

    internal void Validate(VaultMaintenanceLease lease, params VaultLeaseMode[] allowedModes)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(allowedModes);
        if (allowedModes.Length == 0
            || !lease.IsValidFor(_identity)
            || !allowedModes.Contains(lease.Mode))
        {
            throw new InvalidVaultMaintenanceLeaseException();
        }
    }

    internal ValueTask<VaultMaintenanceOperation> EnterOperationAsync(
        VaultMaintenanceLease lease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lease);
        return lease.EnterOperationAsync(_identity, cancellationToken);
    }

    private sealed class VaultAdmissionState
    {
        private readonly object _sync = new();
        private int _activeReaders;
        private bool _activeMutation;
        private bool _activeRebuild;
        private int _waitingMutations;

        internal async ValueTask<VaultAdmissionTicket> AcquireAsync(
            VaultLeaseMode mode,
            CancellationToken cancellationToken)
        {
            var registeredMutation = false;
            if (mode == VaultLeaseMode.Mutation)
            {
                lock (_sync)
                {
                    _waitingMutations++;
                    registeredMutation = true;
                }
            }

            try
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    lock (_sync)
                    {
                        if (CanEnter(mode))
                        {
                            if (registeredMutation)
                            {
                                _waitingMutations--;
                                registeredMutation = false;
                            }

                            Enter(mode);
                            return new VaultAdmissionTicket(this, mode);
                        }
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            finally
            {
                if (registeredMutation)
                {
                    lock (_sync)
                    {
                        _waitingMutations--;
                    }
                }
            }
        }

        private bool CanEnter(VaultLeaseMode mode) => mode switch
        {
            VaultLeaseMode.Read =>
                !_activeMutation && !(_waitingMutations > 0 && !_activeRebuild),
            VaultLeaseMode.Mutation =>
                !_activeMutation && !_activeRebuild && _activeReaders == 0,
            VaultLeaseMode.Rebuild =>
                !_activeMutation && !_activeRebuild && _waitingMutations == 0,
            _ => false,
        };

        private void Enter(VaultLeaseMode mode)
        {
            switch (mode)
            {
                case VaultLeaseMode.Read:
                    _activeReaders++;
                    break;
                case VaultLeaseMode.Mutation:
                    _activeMutation = true;
                    break;
                case VaultLeaseMode.Rebuild:
                    _activeRebuild = true;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mode));
            }
        }

        internal void Release(VaultLeaseMode mode)
        {
            lock (_sync)
            {
                switch (mode)
                {
                    case VaultLeaseMode.Read when _activeReaders > 0:
                        _activeReaders--;
                        break;
                    case VaultLeaseMode.Mutation when _activeMutation:
                        _activeMutation = false;
                        break;
                    case VaultLeaseMode.Rebuild when _activeRebuild:
                        _activeRebuild = false;
                        break;
                    default:
                        throw new InvalidOperationException("The Vault admission state is unbalanced.");
                }
            }
        }
    }

    internal sealed class AmbientLeaseState
    {
        private readonly object _sync = new();
        private readonly Dictionary<string, HeldModes> _held = new(StringComparer.Ordinal);

        internal void ValidateBeforeAcquire(string identity, VaultLeaseMode requestedMode)
        {
            lock (_sync)
            {
                if (_held.TryGetValue(identity, out var held) && !CanAcquire(held, requestedMode))
                    throw new InvalidVaultMaintenanceLeaseException();
            }
        }

        internal void Register(string identity, VaultLeaseMode mode)
        {
            lock (_sync)
            {
                _held.TryGetValue(identity, out var held);
                if (!CanAcquire(held, mode))
                    throw new InvalidVaultMaintenanceLeaseException();
                _held[identity] = held.Add(mode);
            }
        }

        internal void Release(string identity, VaultLeaseMode mode)
        {
            lock (_sync)
            {
                if (!_held.TryGetValue(identity, out var held))
                    throw new InvalidOperationException("The ambient Vault lease state is unbalanced.");
                var remaining = held.Remove(mode);
                if (remaining.IsEmpty) _held.Remove(identity);
                else _held[identity] = remaining;
            }
        }

        private static bool CanAcquire(HeldModes held, VaultLeaseMode requestedMode) =>
            requestedMode switch
            {
                VaultLeaseMode.Read => true,
                VaultLeaseMode.Mutation => held.Reads == 0,
                VaultLeaseMode.Rebuild => held.Reads == 0,
                _ => false,
            };

        private readonly record struct HeldModes(int Reads, int Mutations, int Rebuilds)
        {
            internal bool IsEmpty => Reads == 0 && Mutations == 0 && Rebuilds == 0;

            internal HeldModes Add(VaultLeaseMode mode) => mode switch
            {
                VaultLeaseMode.Read => this with { Reads = checked(Reads + 1) },
                VaultLeaseMode.Mutation => this with { Mutations = checked(Mutations + 1) },
                VaultLeaseMode.Rebuild => this with { Rebuilds = checked(Rebuilds + 1) },
                _ => throw new ArgumentOutOfRangeException(nameof(mode)),
            };

            internal HeldModes Remove(VaultLeaseMode mode) => mode switch
            {
                VaultLeaseMode.Read when Reads > 0 => this with { Reads = Reads - 1 },
                VaultLeaseMode.Mutation when Mutations > 0 => this with { Mutations = Mutations - 1 },
                VaultLeaseMode.Rebuild when Rebuilds > 0 => this with { Rebuilds = Rebuilds - 1 },
                _ => throw new InvalidOperationException("The ambient Vault lease state is unbalanced."),
            };
        }
    }

    private sealed class VaultAdmissionTicket : IDisposable
    {
        private VaultAdmissionState? _state;

        internal VaultAdmissionTicket(VaultAdmissionState state, VaultLeaseMode mode)
        {
            _state = state;
            Mode = mode;
        }

        internal VaultLeaseMode Mode { get; }

        public void Dispose()
        {
            Interlocked.Exchange(ref _state, null)?.Release(Mode);
        }
    }
}

public sealed class VaultMaintenanceLease : IAsyncDisposable
{
    private readonly string _identity;
    private readonly VaultLeaseMode _mode;
    private IDisposable? _processTicket;
    private FileStream? _canonicalLock;
    private FileStream? _rebuildLock;
    private FileStream? _writerIntentLock;
    private FileStream? _activeRebuildLock;
    private VaultMaintenanceGate.AmbientLeaseState? _ambientState;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private int _disposeStarted;

    internal VaultMaintenanceLease(
        string identity,
        VaultLeaseMode mode,
        IDisposable processTicket,
        FileStream canonicalLock,
        FileStream? rebuildLock,
        FileStream? writerIntentLock,
        FileStream? activeRebuildLock,
        VaultMaintenanceGate.AmbientLeaseState ambientState)
    {
        _identity = identity;
        _mode = mode;
        _processTicket = processTicket;
        _canonicalLock = canonicalLock;
        _rebuildLock = rebuildLock;
        _writerIntentLock = writerIntentLock;
        _activeRebuildLock = activeRebuildLock;
        _ambientState = ambientState;
        ambientState.Register(identity, mode);
    }

    public VaultLeaseMode Mode => _mode;

    internal bool IsValidFor(string identity) =>
        string.Equals(_identity, identity, StringComparison.Ordinal)
        && Volatile.Read(ref _disposeStarted) == 0
        && Volatile.Read(ref _canonicalLock) is not null
        && Volatile.Read(ref _processTicket) is not null;

    internal async ValueTask<VaultMaintenanceOperation> EnterOperationAsync(
        string identity,
        CancellationToken cancellationToken)
    {
        if (!IsValidFor(identity))
        {
            throw new InvalidVaultMaintenanceLeaseException();
        }

        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (!IsValidFor(identity))
        {
            _operationGate.Release();
            throw new InvalidVaultMaintenanceLeaseException();
        }

        return new VaultMaintenanceOperation(_operationGate);
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0)
        {
            return ValueTask.CompletedTask;
        }

        return DisposeCoreAsync();
    }

    private async ValueTask DisposeCoreAsync()
    {
        await _operationGate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            try
            {
                Interlocked.Exchange(ref _canonicalLock, null)?.Dispose();
                Interlocked.Exchange(ref _processTicket, null)?.Dispose();
                Interlocked.Exchange(ref _activeRebuildLock, null)?.Dispose();
                Interlocked.Exchange(ref _rebuildLock, null)?.Dispose();
                Interlocked.Exchange(ref _writerIntentLock, null)?.Dispose();
            }
            finally
            {
                Interlocked.Exchange(ref _ambientState, null)?.Release(_identity, _mode);
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }
}

internal sealed class VaultMaintenanceOperation : IAsyncDisposable
{
    private SemaphoreSlim? _operationGate;

    internal VaultMaintenanceOperation(SemaphoreSlim operationGate)
    {
        _operationGate = operationGate;
    }

    public ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref _operationGate, null)?.Release();
        return ValueTask.CompletedTask;
    }
}

public sealed class InvalidVaultMaintenanceLeaseException : InvalidOperationException
{
    public InvalidVaultMaintenanceLeaseException()
        : base("The Vault maintenance lease is invalid, foreign, released, or has the wrong mode.")
    {
    }
}

public sealed class VaultMaintenancePersistenceException : IOException
{
    internal VaultMaintenancePersistenceException(Exception innerException)
        : base("The Vault maintenance lock could not be acquired.", innerException)
    {
    }
}
