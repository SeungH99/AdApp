using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using LocalDocumentOrganizer.CorpusWorkbench.Contracts;
using LocalDocumentOrganizer.CorpusWorkbench.Validation;
using LocalDocumentOrganizer.CorpusWorkbench.Vault;

namespace LocalDocumentOrganizer.CorpusWorkbench.Security;

internal enum AuthenticatedVaultEnvelopeKind : byte
{
    Configuration = 1,
    WorkerBinding = 2,
}

internal sealed record OpenedAuthenticatedVaultEnvelope(
    byte[] Payload,
    string PayloadIdentitySha256);

internal static class AuthenticatedVaultEnvelope
{
    private static readonly byte[] Magic =
        "CWVAULT1"u8.ToArray();
    private const ushort Version = 1;
    private const uint Generation = 1;
    private const int HeaderLength = 84;
    private const int TagLength = 32;
    internal const int MaximumEnvelopeBytes = 32 * 1024;
    internal const int MaximumPayloadBytes = 16 * 1024;

    internal static async ValueTask<byte[]> SealAsync(
        CorpusVault vault,
        PilotAuthenticationService authentication,
        AuthenticatedVaultEnvelopeKind kind,
        ReadOnlyMemory<byte> payload,
        string? configurationIdentitySha256,
        CancellationToken cancellationToken,
        string? vaultIdentityRoot = null)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(authentication);
        cancellationToken.ThrowIfCancellationRequested();
        if (payload.Length is 0 or > MaximumPayloadBytes)
        {
            throw InvalidEnvelope();
        }

        var payloadIdentity = ComputePayloadIdentity(kind, payload.Span);
        var configurationIdentity = kind switch
        {
            AuthenticatedVaultEnvelopeKind.Configuration =>
                payloadIdentity,
            AuthenticatedVaultEnvelopeKind.WorkerBinding
                when PilotValidator.IsLowerSha256(
                    configurationIdentitySha256) =>
                configurationIdentitySha256!,
            _ => throw InvalidEnvelope(),
        };
        var canonicalLength = checked(HeaderLength + payload.Length);
        var envelope = new byte[checked(canonicalLength + TagLength)];
        WriteHeader(
            envelope,
            vault,
            kind,
            payload.Length,
            configurationIdentity,
            vaultIdentityRoot);
        payload.Span.CopyTo(envelope.AsSpan(HeaderLength));
        byte[] tag;
        try
        {
            tag = kind switch
            {
                AuthenticatedVaultEnvelopeKind.Configuration =>
                    await authentication
                        .SignConfigurationEnvelopeAsync(
                            envelope.AsMemory(0, canonicalLength),
                            cancellationToken)
                        .ConfigureAwait(false),
                AuthenticatedVaultEnvelopeKind.WorkerBinding =>
                    await authentication
                        .SignWorkerBindingEnvelopeAsync(
                            envelope.AsMemory(0, canonicalLength),
                            cancellationToken)
                        .ConfigureAwait(false),
                _ => throw InvalidEnvelope(),
            };
        }
        catch (PilotAuthenticationException exception)
        {
            throw InvalidEnvelope(exception);
        }

        try
        {
            if (tag.Length != TagLength)
            {
                throw InvalidEnvelope();
            }

            tag.CopyTo(envelope.AsSpan(canonicalLength));
            return envelope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    internal static async ValueTask<
        OpenedAuthenticatedVaultEnvelope> OpenAsync(
        CorpusVault vault,
        PilotAuthenticationService authentication,
        AuthenticatedVaultEnvelopeKind expectedKind,
        ReadOnlyMemory<byte> envelope,
        string? expectedConfigurationIdentitySha256,
        CancellationToken cancellationToken,
        string? vaultIdentityRoot = null)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(authentication);
        cancellationToken.ThrowIfCancellationRequested();
        if (envelope.Length < HeaderLength + 1 + TagLength
            || envelope.Length > MaximumEnvelopeBytes)
        {
            throw InvalidEnvelope();
        }

        var payloadLength = ReadPayloadLength(
            envelope.Span,
            expectedKind);
        if (payloadLength is <= 0 or > MaximumPayloadBytes)
        {
            throw InvalidEnvelope();
        }

        var canonicalLength = checked(HeaderLength + payloadLength);
        if (envelope.Length != canonicalLength + TagLength)
        {
            throw InvalidEnvelope();
        }

        bool verified;
        try
        {
            verified = expectedKind switch
            {
                AuthenticatedVaultEnvelopeKind.Configuration =>
                    await authentication
                        .VerifyConfigurationEnvelopeAsync(
                            envelope[..canonicalLength],
                            envelope.Slice(canonicalLength, TagLength),
                            cancellationToken)
                        .ConfigureAwait(false),
                AuthenticatedVaultEnvelopeKind.WorkerBinding =>
                    await authentication
                        .VerifyWorkerBindingEnvelopeAsync(
                            envelope[..canonicalLength],
                            envelope.Slice(canonicalLength, TagLength),
                            cancellationToken)
                        .ConfigureAwait(false),
                _ => false,
            };
        }
        catch (PilotAuthenticationException exception)
        {
            throw InvalidEnvelope(exception);
        }

        if (!verified)
        {
            throw InvalidEnvelope();
        }

        var expectedVault = ComputeVaultIdentity(
            vaultIdentityRoot ?? vault.ApprovedRoot);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    expectedVault,
                    envelope.Span.Slice(20, 32)))
            {
                throw InvalidEnvelope();
            }

            if (expectedKind
                    == AuthenticatedVaultEnvelopeKind.WorkerBinding
                && (!PilotValidator.IsLowerSha256(
                        expectedConfigurationIdentitySha256)
                    || !CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(
                            expectedConfigurationIdentitySha256!),
                        envelope.Span.Slice(52, 32))))
            {
                throw InvalidEnvelope();
            }

            var payload = envelope
                .Slice(HeaderLength, payloadLength)
                .ToArray();
            var payloadIdentity =
                ComputePayloadIdentity(expectedKind, payload);
            if (expectedKind
                    == AuthenticatedVaultEnvelopeKind.Configuration
                && !CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(payloadIdentity),
                    envelope.Span.Slice(52, 32)))
            {
                CryptographicOperations.ZeroMemory(payload);
                throw InvalidEnvelope();
            }

            return new OpenedAuthenticatedVaultEnvelope(
                payload,
                payloadIdentity);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedVault);
        }
    }

    private static int ReadPayloadLength(
        ReadOnlySpan<byte> envelope,
        AuthenticatedVaultEnvelopeKind expectedKind)
    {
        if (!envelope[..Magic.Length].SequenceEqual(Magic)
            || BinaryPrimitives.ReadUInt16LittleEndian(
                envelope.Slice(8, 2)) != Version
            || envelope[10] != (byte)expectedKind
            || envelope[11] != 0
            || BinaryPrimitives.ReadUInt32LittleEndian(
                envelope.Slice(12, 4)) != Generation)
        {
            throw InvalidEnvelope();
        }

        return BinaryPrimitives.ReadInt32LittleEndian(
            envelope.Slice(16, 4));
    }

    internal static string ComputePayloadIdentity(
        AuthenticatedVaultEnvelopeKind kind,
        ReadOnlySpan<byte> payload)
    {
        using var stream = new MemoryStream();
        stream.Write(
            kind == AuthenticatedVaultEnvelopeKind.Configuration
                ? "corpus-workbench-configuration-payload-v1\n"u8
                : "corpus-workbench-worker-binding-payload-v1\n"u8);
        stream.Write(payload);
        return Convert.ToHexStringLower(
            SHA256.HashData(stream.ToArray()));
    }

    private static void WriteHeader(
        Span<byte> target,
        CorpusVault vault,
        AuthenticatedVaultEnvelopeKind kind,
        int payloadLength,
        string configurationIdentitySha256,
        string? vaultIdentityRoot)
    {
        target.Clear();
        Magic.CopyTo(target);
        BinaryPrimitives.WriteUInt16LittleEndian(
            target.Slice(8, 2),
            Version);
        target[10] = (byte)kind;
        BinaryPrimitives.WriteUInt32LittleEndian(
            target.Slice(12, 4),
            Generation);
        BinaryPrimitives.WriteInt32LittleEndian(
            target.Slice(16, 4),
            payloadLength);
        var vaultIdentity = ComputeVaultIdentity(
            vaultIdentityRoot ?? vault.ApprovedRoot);
        try
        {
            vaultIdentity.CopyTo(target.Slice(20, 32));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultIdentity);
        }

        Convert.FromHexString(configurationIdentitySha256)
            .CopyTo(target.Slice(52, 32));
    }

    private static byte[] ComputeVaultIdentity(CorpusVault vault)
        => ComputeVaultIdentity(vault.ApprovedRoot);

    private static byte[] ComputeVaultIdentity(string vaultRoot)
    {
        var canonicalRoot = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(vaultRoot))
            .ToUpperInvariant();
        return SHA256.HashData(
            Encoding.UTF8.GetBytes(
                "corpus-workbench-vault-identity-v1\n"
                + canonicalRoot
                + "\n"));
    }

    private static WorkbenchException InvalidEnvelope(
        Exception? inner = null) =>
        new(WorkbenchFailureCode.VaultBoundaryViolation, inner);
}
