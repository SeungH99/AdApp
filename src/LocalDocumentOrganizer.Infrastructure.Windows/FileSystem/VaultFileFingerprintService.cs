using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Win32.SafeHandles;

namespace LocalDocumentOrganizer.Infrastructure.Windows.FileSystem;

public sealed class VaultFileFingerprintService
{
    private const int FileStreamBufferSize = 64 * 1024;
    private readonly VaultKeyRingStore _keyRing;
    private readonly NtfsFileIdentityProvider _identityProvider;

    public VaultFileFingerprintService(
        VaultKeyRingStore keyRing,
        ApprovedRootPathGuard pathGuard)
        : this(keyRing, new NtfsFileIdentityProvider(pathGuard))
    {
    }

    public VaultFileFingerprintService(
        VaultKeyRingStore keyRing,
        NtfsFileIdentityProvider identityProvider)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(identityProvider);
        _keyRing = keyRing;
        _identityProvider = identityProvider;
    }

    public async Task<byte[]> ComputeAsync(
        SensitiveObjectRef owner,
        DataKeyId expectedKeyId,
        string path,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return await _keyRing.UseFileFingerprintSubkeyAsync(
            owner,
            expectedKeyId,
            async (subkey, token) =>
            {
                SafeFileHandle? handle = _identityProvider.OpenSourceReadHandle(path);
                try
                {
                    await using var content = new FileStream(
                        handle,
                        FileAccess.Read,
                        FileStreamBufferSize,
                        isAsync: true);
                    handle = null;
                    return await KeyedContentFingerprint
                        .ComputeAsync(subkey, content, token)
                        .ConfigureAwait(false);
                }
                finally
                {
                    handle?.Dispose();
                }
            },
            cancellationToken).ConfigureAwait(false);
    }
}
