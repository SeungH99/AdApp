using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal static class ProductEventContracts
{
    internal const int SchemaVersion = 1;
    internal const string DocumentImported = "product.document-imported";
    internal const string DocumentImportDuplicate = "product.document-import-duplicate";
    internal const string ExtractionCommitted = "product.extraction-committed";
    internal const string ReviewCommitted = "product.review-committed";
    internal const string ReceivableCaseCommitted = "product.receivable-case-committed";

    internal static EventSchemaRegistry CreateSchemaRegistry() =>
        new(
            new Dictionary<string, int>(StringComparer.Ordinal)
            {
                [DocumentImported] = SchemaVersion,
                [DocumentImportDuplicate] = SchemaVersion,
                [ExtractionCommitted] = SchemaVersion,
                [ReviewCommitted] = SchemaVersion,
                [ReceivableCaseCommitted] = SchemaVersion,
            },
            []);
}

internal sealed record ProductImportPayload(
    string DocumentId,
    string InboxId,
    string ContentSha256,
    string ReceivedAtUtc,
    string FileName,
    string AuthenticatedMetadata,
    ProductDocumentSourceBinding? SourceBinding,
    string ExtractionAttemptId,
    int TargetExtractionRevision,
    string ExtractionCommitOperationId,
    string CommitFingerprint);

internal sealed record ProductDuplicateImportPayload(
    string ExistingDocumentId,
    string ExistingInboxId,
    string ContentSha256,
    string CommitFingerprint);

internal sealed record ProductDocumentProgressPayload(
    string DocumentId,
    string OccurredAtUtc,
    string AuthenticatedPayload,
    int? InboxStatus,
    Guid? ClaimOwnerId,
    Guid? ClaimAttemptId,
    int? ClaimTargetRevision,
    string? ClaimLeaseExpiresAtUtc,
    int? ExpectedExtractionRevision,
    int? ReviewRevision,
    string CommitFingerprint);

internal sealed record ProductReceivableCasePayload(
    string CaseId,
    string SourceDocumentId,
    string DueDate,
    string CreatedAtUtc,
    string AuthenticatedMetadata,
    int? ConfirmedReviewRevision,
    string CommitFingerprint);

internal static class ProductEventPayloads
{
    internal static byte[] SerializeImport(
        CommitImportCommand command,
        ReadOnlySpan<byte> fingerprint) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new ProductImportPayload(
                Canonical(command.DocumentId.Value),
                Canonical(command.InboxId.Value),
                command.ContentSha256.Hex,
                Utc(command.ReceivedAtUtc),
                command.FileName,
                command.AuthenticatedMetadata,
                command.SourceBinding,
                Canonical(command.ExtractionAttemptId.Value),
                command.TargetExtractionRevision,
                Canonical(command.ExtractionCommitOperationId.Value),
                Convert.ToHexString(fingerprint).ToLowerInvariant()));

    internal static byte[] SerializeDuplicate(
        DocumentId existingDocumentId,
        InboxId existingInboxId,
        ContentSha256 contentSha256,
        ReadOnlySpan<byte> fingerprint) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new ProductDuplicateImportPayload(
                Canonical(existingDocumentId.Value),
                Canonical(existingInboxId.Value),
                contentSha256.Hex,
                Convert.ToHexString(fingerprint).ToLowerInvariant()));

    internal static byte[] SerializeExtraction(
        CommitExtractionCommand command,
        ReadOnlySpan<byte> fingerprint) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new ProductDocumentProgressPayload(
                Canonical(command.DocumentId.Value),
                Utc(command.ExtractedAtUtc),
                command.AuthenticatedExtraction,
                (int)command.InboxStatus,
                command.ClaimBinding?.OwnerId,
                command.ClaimBinding?.AttemptId,
                command.ClaimBinding?.TargetRevision,
                command.ClaimBinding is { } claim ? Utc(claim.LeaseExpiresAtUtc) : null,
                null,
                null,
                Convert.ToHexString(fingerprint).ToLowerInvariant()));

    internal static byte[] SerializeReview(
        CommitReviewCommand command,
        ReadOnlySpan<byte> fingerprint) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new ProductDocumentProgressPayload(
                Canonical(command.DocumentId.Value),
                Utc(command.ReviewedAtUtc),
                command.AuthenticatedReview,
                null,
                null,
                null,
                null,
                null,
                command.ExpectedExtractionRevision,
                command.ReviewRevision,
                Convert.ToHexString(fingerprint).ToLowerInvariant()));

    internal static byte[] SerializeReceivableCase(
        CommitReceivableCaseCommand command,
        ReadOnlySpan<byte> fingerprint) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new ProductReceivableCasePayload(
                Canonical(command.CaseId.Value),
                Canonical(command.SourceDocumentId.Value),
                command.DueDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                Utc(command.CreatedAtUtc),
                command.AuthenticatedMetadata,
                command.ConfirmedReviewRevision,
                Convert.ToHexString(fingerprint).ToLowerInvariant()));

    internal static T Read<T>(ReadOnlyMemory<byte> payload)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(payload.Span)
                ?? throw new VaultRecoveryRequiredException();
        }
        catch (VaultRecoveryRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    internal static byte[] ImportFingerprint(CommitImportCommand command)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(hash, "product.commit.import.v1");
        Add(hash, command.OperationId.Value);
        Add(hash, command.EventId.Value);
        Add(hash, command.DocumentId.Value);
        Add(hash, command.InboxId.Value);
        Add(hash, command.ContentSha256.Bytes.Span);
        Add(hash, Utc(command.ReceivedAtUtc));
        Add(hash, command.FileName);
        Add(hash, command.AuthenticatedMetadata);
        Add(hash, SourceBindingFingerprintValue(command.SourceBinding));
        Add(hash, command.ExtractionAttemptId.Value);
        Add(hash, command.TargetExtractionRevision);
        Add(hash, command.ExtractionCommitOperationId.Value);
        return hash.GetHashAndReset();
    }

    internal static byte[] ExtractionFingerprint(CommitExtractionCommand command)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(hash, "product.commit.extraction.v1");
        Add(hash, command.OperationId.Value);
        Add(hash, command.EventId.Value);
        Add(hash, command.DocumentId.Value);
        Add(hash, command.ExpectedVersion.Value);
        Add(hash, Utc(command.ExtractedAtUtc));
        Add(hash, command.AuthenticatedExtraction);
        Add(hash, (int)command.InboxStatus);
        return hash.GetHashAndReset();
    }

    internal static byte[] ReviewFingerprint(CommitReviewCommand command)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(hash, "product.commit.review.v1");
        Add(hash, command.OperationId.Value);
        Add(hash, command.EventId.Value);
        Add(hash, command.DocumentId.Value);
        Add(hash, command.ExpectedVersion.Value);
        Add(hash, Utc(command.ReviewedAtUtc));
        Add(hash, command.AuthenticatedReview);
        Add(hash, command.ExpectedExtractionRevision ?? 0);
        Add(hash, command.ReviewRevision ?? 0);
        return hash.GetHashAndReset();
    }

    internal static byte[] ReceivableCaseFingerprint(CommitReceivableCaseCommand command)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(hash, "product.commit.receivable-case.v1");
        Add(hash, command.OperationId.Value);
        Add(hash, command.EventId.Value);
        Add(hash, command.CaseId.Value);
        Add(hash, command.SourceDocumentId.Value);
        Add(hash, command.DueDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        Add(hash, Utc(command.CreatedAtUtc));
        Add(hash, command.AuthenticatedMetadata);
        Add(hash, command.ConfirmedReviewRevision ?? 0);
        return hash.GetHashAndReset();
    }

    internal static Guid GuidValue(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed)
            || !string.Equals(Canonical(parsed), value, StringComparison.Ordinal))
        {
            throw new VaultRecoveryRequiredException();
        }

        return parsed;
    }

    internal static DateTimeOffset UtcValue(string value)
    {
        if (!DateTimeOffset.TryParseExact(
                value,
                "O",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var parsed)
            || parsed.Offset != TimeSpan.Zero
            || !string.Equals(Utc(parsed), value, StringComparison.Ordinal))
        {
            throw new VaultRecoveryRequiredException();
        }

        return parsed;
    }

    internal static DateOnly DateValue(string value)
    {
        if (!DateOnly.TryParseExact(
                value,
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var parsed)
            || !string.Equals(
                parsed.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                value,
                StringComparison.Ordinal))
        {
            throw new VaultRecoveryRequiredException();
        }

        return parsed;
    }

    internal static byte[] FingerprintValue(string value)
    {
        if (value.Length != 64
            || !value.All(character => character is >= '0' and <= '9'
                or >= 'a' and <= 'f'))
        {
            throw new VaultRecoveryRequiredException();
        }

        try
        {
            return Convert.FromHexString(value);
        }
        catch (FormatException exception)
        {
            throw new VaultRecoveryRequiredException(exception);
        }
    }

    internal static string Canonical(Guid value) =>
        value.ToString("D").ToLowerInvariant();

    internal static string Utc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static void Add(IncrementalHash hash, Guid value) =>
        Add(hash, Canonical(value));

    private static string SourceBindingFingerprintValue(
        ProductDocumentSourceBinding? sourceBinding) =>
        sourceBinding is null
            ? string.Empty
            : string.Join('|',
                ((int)sourceBinding.Format).ToString(CultureInfo.InvariantCulture),
                sourceBinding.CanonicalMimeType,
                sourceBinding.CanonicalExtension,
                sourceBinding.DeclaredLength.ToString(CultureInfo.InvariantCulture));

    private static void Add(IncrementalHash hash, long value) =>
        Add(hash, value.ToString(CultureInfo.InvariantCulture));

    private static void Add(IncrementalHash hash, string value) =>
        Add(hash, Encoding.UTF8.GetBytes(value));

    private static void Add(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }
}
