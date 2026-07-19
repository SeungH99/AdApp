namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

public interface IVaultKeyProtector
{
    byte[] Protect(ReadOnlySpan<byte> vaultRoot);

    void Unprotect(ReadOnlySpan<byte> protectedVaultRoot, Span<byte> destination);
}
