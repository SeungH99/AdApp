using System.Collections.Concurrent;
using System.Security.Cryptography;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

namespace LocalDocumentOrganizer.CorpusWorkbench.Validation;

internal sealed class PilotAuthenticationService
{
    private static readonly ReadOnlyMemory<byte> CheckpointKeyDomain =
        "LocalDocumentOrganizer/CorpusWorkbench/CheckpointMac/v1"u8
            .ToArray();
    private static readonly ReadOnlyMemory<byte> ResultKeyDomain =
        "LocalDocumentOrganizer/CorpusWorkbench/ResultAttestation/v1"u8
            .ToArray();
    private static readonly ConcurrentDictionary<string, SemaphoreSlim>
        CreationGates = new(StringComparer.OrdinalIgnoreCase);

    private readonly CorpusVault? _vault;
    private readonly VaultKeyRingStore? _keyRing;
    private readonly byte[]? _testRoot;

    internal PilotAuthenticationService(CorpusVault vault)
    {
        _vault = vault
            ?? throw new ArgumentNullException(nameof(vault));
        _keyRing = new VaultKeyRingStore(
            Path.Combine(vault.ApprovedRoot, "vault.keys"));
    }

    private PilotAuthenticationService(ReadOnlySpan<byte> testRoot)
    {
        if (testRoot.Length != VaultKeyRing.RootSize)
        {
            throw new ArgumentException(
                "The test authentication root length is invalid.",
                nameof(testRoot));
        }

        _testRoot = testRoot.ToArray();
    }

    internal static PilotAuthenticationService CreateForTesting(
        ReadOnlySpan<byte> root) =>
        new(root);

    internal ValueTask<byte[]> SignCheckpointAsync(
        ReadOnlyMemory<byte> canonicalInput,
        CancellationToken cancellationToken) =>
        ComputeAsync(
            CheckpointKeyDomain,
            canonicalInput,
            allowCreate: true,
            cancellationToken);

    internal ValueTask<bool> VerifyCheckpointAsync(
        ReadOnlyMemory<byte> canonicalInput,
        ReadOnlyMemory<byte> authenticationTag,
        CancellationToken cancellationToken) =>
        VerifyAsync(
            CheckpointKeyDomain,
            canonicalInput,
            authenticationTag,
            cancellationToken);

    internal ValueTask<byte[]> AttestResultAsync(
        ReadOnlyMemory<byte> canonicalResult,
        CancellationToken cancellationToken) =>
        ComputeAsync(
            ResultKeyDomain,
            canonicalResult,
            allowCreate: true,
            cancellationToken);

    internal ValueTask<bool> VerifyResultAsync(
        ReadOnlyMemory<byte> canonicalResult,
        ReadOnlyMemory<byte> attestation,
        CancellationToken cancellationToken) =>
        VerifyAsync(
            ResultKeyDomain,
            canonicalResult,
            attestation,
            cancellationToken);

    private async ValueTask<bool> VerifyAsync(
        ReadOnlyMemory<byte> domain,
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> expected,
        CancellationToken cancellationToken)
    {
        if (expected.Length != 32)
        {
            return false;
        }

        var actual = await ComputeAsync(
                domain,
                message,
                allowCreate: false,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                actual,
                expected.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private async ValueTask<byte[]> ComputeAsync(
        ReadOnlyMemory<byte> domain,
        ReadOnlyMemory<byte> message,
        bool allowCreate,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_testRoot is not null)
        {
            var subkey = HMACSHA256.HashData(
                _testRoot,
                domain.Span);
            try
            {
                return HMACSHA256.HashData(subkey, message.Span);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(subkey);
            }
        }

        try
        {
            await EnsureKeyRingAsync(allowCreate, cancellationToken)
                .ConfigureAwait(false);
            return await _keyRing!.UseDomainSeparatedSubkeyAsync(
                    domain,
                    (key, _) =>
                        ValueTask.FromResult(
                            HMACSHA256.HashData(
                                key.Span,
                                message.Span)),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (PilotAuthenticationException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is VaultKeyRingException
                or IOException
                or UnauthorizedAccessException
                or CryptographicException
                or System.Security.SecurityException
                or ArgumentException
                or NotSupportedException)
        {
            throw new PilotAuthenticationException(exception);
        }
    }

    private async Task EnsureKeyRingAsync(
        bool allowCreate,
        CancellationToken cancellationToken)
    {
        var path = Path.Combine(_vault!.ApprovedRoot, "vault.keys");
        var gate = CreationGates.GetOrAdd(
            path,
            static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            try
            {
                await _keyRing!.OpenAsync(cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
            catch (VaultKeyRingNotFoundException)
            {
                if (!allowCreate
                    || await _vault.Store
                        .HasPilotValidationCheckpointAsync(
                            cancellationToken)
                        .ConfigureAwait(false))
                {
                    throw new PilotAuthenticationException();
                }
            }

            try
            {
                await _keyRing!.CreateAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (VaultKeyRingPersistenceException)
            {
                await _keyRing!.OpenAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            gate.Release();
        }
    }
}

internal sealed class PilotAuthenticationException : Exception
{
    internal PilotAuthenticationException()
        : base("Pilot authentication failed.")
    {
    }

    internal PilotAuthenticationException(Exception innerException)
        : base("Pilot authentication failed.", innerException)
    {
    }
}
