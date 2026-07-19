using System.Security.Cryptography;
using System.Text;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public sealed class DpapiCurrentUserVaultKeyProtector : IVaultKeyProtector
{
    private static readonly byte[] Entropy =
        Encoding.UTF8.GetBytes("LocalDocumentOrganizer/VaultRoot/DPAPI/v1");

    public byte[] Protect(ReadOnlySpan<byte> vaultRoot)
    {
        if (vaultRoot.Length != VaultKeyRing.RootSize)
        {
            throw new ArgumentException("The Vault root length is invalid.", nameof(vaultRoot));
        }

        var plaintext = vaultRoot.ToArray();
        try
        {
            return ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException exception)
        {
            throw new VaultKeyProtectionException("Vault root protection failed.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public void Unprotect(ReadOnlySpan<byte> protectedVaultRoot, Span<byte> destination)
    {
        if (protectedVaultRoot.IsEmpty)
        {
            throw new ArgumentException("The protected Vault root is empty.", nameof(protectedVaultRoot));
        }

        if (destination.Length != VaultKeyRing.RootSize)
        {
            throw new ArgumentException("The Vault root destination length is invalid.", nameof(destination));
        }

        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedVaultRoot.ToArray(),
                Entropy,
                DataProtectionScope.CurrentUser);
            if (plaintext.Length != VaultKeyRing.RootSize)
            {
                throw new VaultKeyProtectionException("The unprotected Vault root length is invalid.");
            }

            plaintext.CopyTo(destination);
        }
        catch (CryptographicException exception)
        {
            CryptographicOperations.ZeroMemory(destination);
            throw new VaultKeyProtectionException("Vault root authentication failed.", exception);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(destination);
            throw;
        }
        finally
        {
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }
}
