using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.Application.Products;
using LocalDocumentOrganizer.Core.Cases;
using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Intake;

internal sealed record VaultImportJournalPayload(
    Guid EventId,
    Guid DocumentId,
    Guid InboxId,
    string ContentSha256,
    long Length,
    Guid ExtractionAttemptId,
    Guid ExtractionCommitOperationId,
    string ReceivedAtUtc,
    string FileName,
    string AuthenticatedMetadata,
    string TemporaryRelativePath,
    string DestinationRelativePath)
{
    internal static VaultImportJournalPayload Create(
        EventId eventId,
        DocumentId documentId,
        InboxId inboxId,
        ContentSha256 contentSha256,
        long length,
        DateTimeOffset receivedAtUtc,
        string fileName,
        string authenticatedMetadata,
        string temporaryRelativePath,
        string destinationRelativePath) =>
        new(
            eventId.Value,
            documentId.Value,
            inboxId.Value,
            contentSha256.Hex,
            length,
            Guid.NewGuid(),
            Guid.NewGuid(),
            receivedAtUtc.ToString("O"),
            fileName,
            authenticatedMetadata,
            temporaryRelativePath,
            destinationRelativePath);

    internal byte[] Serialize() =>
        JsonSerializer.SerializeToUtf8Bytes(this);

    internal static VaultImportJournalPayload Deserialize(
        ReadOnlyMemory<byte> value) =>
        JsonSerializer.Deserialize<VaultImportJournalPayload>(value.Span)
        ?? throw new InvalidDataException(
            "The VaultImport recovery evidence is invalid.");

    internal CommitImportCommand ToCommand(OperationId operationId) =>
        new(
            operationId,
            new EventId(EventId),
            new DocumentId(DocumentId),
            new InboxId(InboxId),
            new ContentSha256(Convert.FromHexString(ContentSha256)),
            DateTimeOffset.Parse(
                ReceivedAtUtc,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind),
            FileName,
            AuthenticatedMetadata,
            new LocalDocumentOrganizer.Application.Processing.ExtractionAttemptId(
                ExtractionAttemptId),
            targetExtractionRevision: 1,
            new OperationId(ExtractionCommitOperationId));

    internal byte[] ComputeCommitFingerprint(OperationId operationId)
    {
        var payload = Serialize();
        try
        {
            var operation = operationId.Value.ToByteArray();
            var combined = new byte[operation.Length + payload.Length];
            operation.CopyTo(combined, 0);
            payload.CopyTo(combined, operation.Length);
            try
            {
                return SHA256.HashData(combined);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(combined);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }
}
