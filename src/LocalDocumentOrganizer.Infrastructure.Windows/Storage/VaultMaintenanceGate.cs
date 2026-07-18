using System.Collections.Concurrent;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

public sealed class VaultMaintenanceGate
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> ProcessGates =
        new(StringComparer.Ordinal);

    private readonly string _identity;
    private readonly SemaphoreSlim _processGate;

    public VaultMaintenanceGate(string keyRingPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyRingPath);
        KeyRingPath = Path.GetFullPath(keyRingPath);
        _identity = OperatingSystem.IsWindows()
            ? KeyRingPath.ToUpperInvariant()
            : KeyRingPath;
        LockPath = KeyRingPath + ".lock";
        _processGate = ProcessGates.GetOrAdd(_identity, static _ => new SemaphoreSlim(1, 1));
    }

    public string KeyRingPath { get; }

    public string LockPath { get; }

    public async ValueTask<VaultMaintenanceLease> AcquireAsync(CancellationToken cancellationToken)
    {
        await _processGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var stream = new FileStream(
                        LockPath,
                        FileMode.OpenOrCreate,
                        FileAccess.ReadWrite,
                        FileShare.None,
                        bufferSize: 1,
                        FileOptions.Asynchronous | FileOptions.WriteThrough);
                    return new VaultMaintenanceLease(_identity, _processGate, stream);
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
        catch
        {
            _processGate.Release();
            throw;
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
}

public sealed class VaultMaintenanceLease : IAsyncDisposable
{
    private readonly string _identity;
    private SemaphoreSlim? _processGate;
    private FileStream? _lockStream;

    internal VaultMaintenanceLease(
        string identity,
        SemaphoreSlim processGate,
        FileStream lockStream)
    {
        _identity = identity;
        _processGate = processGate;
        _lockStream = lockStream;
    }

    internal bool IsValidFor(string identity) =>
        string.Equals(_identity, identity, StringComparison.Ordinal)
        && Volatile.Read(ref _lockStream) is not null;

    public ValueTask DisposeAsync()
    {
        var stream = Interlocked.Exchange(ref _lockStream, null);
        if (stream is null)
        {
            return ValueTask.CompletedTask;
        }

        stream.Dispose();
        Interlocked.Exchange(ref _processGate, null)?.Release();
        return ValueTask.CompletedTask;
    }
}

public sealed class InvalidVaultMaintenanceLeaseException : InvalidOperationException
{
    public InvalidVaultMaintenanceLeaseException()
        : base("The Vault maintenance lease is invalid, foreign, or released.")
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
