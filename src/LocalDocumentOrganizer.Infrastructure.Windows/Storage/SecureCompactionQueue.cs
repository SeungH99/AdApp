using LocalDocumentOrganizer.Core.Events;
using LocalDocumentOrganizer.Core.Security;
using LocalDocumentOrganizer.Infrastructure.Windows.Crypto;
using Microsoft.Data.Sqlite;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Storage;

internal sealed record SecureCompactionWorkItem(
    SensitiveObjectRef Owner,
    DataKeyId DestroyedKeyId,
    StreamId StreamId,
    StreamVersion TombstoneStreamVersion,
    OperationId OperationId,
    EventId TombstoneEventId);

internal static class SecureCompactionQueue
{
    internal static async Task<IReadOnlyList<SecureCompactionWorkItem>> ReadValidatedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        VaultKeyRing keyRing,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(keyRing);
        var receipts = keyRing.DestroyedReceipts.ToDictionary(receipt => receipt.Owner);
        var work = new List<SecureCompactionWorkItem>();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT owner_kind,owner_id,destroyed_key_id,stream_id,
                   tombstone_stream_version,operation_id,tombstone_event_id
            FROM main.secure_compaction_queue
            ORDER BY owner_kind,owner_id COLLATE BINARY;
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            try
            {
                if (reader.GetValue(0) is not long rawKind
                    || rawKind is < int.MinValue or > int.MaxValue
                    || !Enum.IsDefined((SensitiveObjectKind)(int)rawKind)
                    || reader.GetValue(1) is not string ownerText
                    || reader.GetValue(2) is not string keyText
                    || reader.GetValue(3) is not string streamText
                    || reader.GetValue(4) is not long streamVersion
                    || reader.GetValue(5) is not string operationText
                    || reader.GetValue(6) is not string eventText)
                {
                    throw new VaultRecoveryRequiredException();
                }

                var owner = new SensitiveObjectRef(
                    (SensitiveObjectKind)(int)rawKind,
                    new SensitiveObjectId(ParseCanonicalGuid(ownerText)));
                var item = new SecureCompactionWorkItem(
                    owner,
                    new DataKeyId(ParseCanonicalGuid(keyText)),
                    new StreamId(ParseCanonicalGuid(streamText)),
                    new StreamVersion(streamVersion),
                    new OperationId(ParseCanonicalGuid(operationText)),
                    new EventId(ParseCanonicalGuid(eventText)));
                if (!receipts.TryGetValue(owner, out var receipt)
                    || receipt.State != VaultDestroyedReceiptState.Completed
                    || receipt.KeyId != item.DestroyedKeyId
                    || receipt.StreamId != item.StreamId
                    || receipt.ExpectedStreamVersion.Next() != item.TombstoneStreamVersion
                    || receipt.OperationId != item.OperationId
                    || receipt.TombstoneEventId != item.TombstoneEventId)
                {
                    throw new VaultRecoveryRequiredException();
                }

                work.Add(item);
            }
            catch (VaultRecoveryRequiredException)
            {
                throw;
            }
            catch (Exception exception) when (exception is ArgumentException
                or InvalidOperationException or OverflowException)
            {
                throw new VaultRecoveryRequiredException(exception);
            }
        }

        return work.AsReadOnly();
    }

    internal static async Task DeleteValidatedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<SecureCompactionWorkItem> expected,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        foreach (var item in expected)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                DELETE FROM main.secure_compaction_queue
                WHERE owner_kind=$owner_kind AND owner_id=$owner_id
                  AND destroyed_key_id=$key_id AND stream_id=$stream_id
                  AND tombstone_stream_version=$stream_version
                  AND operation_id=$operation_id AND tombstone_event_id=$event_id;
                """;
            command.Parameters.AddWithValue("$owner_kind", (int)item.Owner.Kind);
            command.Parameters.AddWithValue("$owner_id", item.Owner.Id.Value.ToString("D"));
            command.Parameters.AddWithValue("$key_id", item.DestroyedKeyId.Value.ToString("D"));
            command.Parameters.AddWithValue("$stream_id", item.StreamId.Value.ToString("D"));
            command.Parameters.AddWithValue("$stream_version", item.TombstoneStreamVersion.Value);
            command.Parameters.AddWithValue("$operation_id", item.OperationId.Value.ToString("D"));
            command.Parameters.AddWithValue("$event_id", item.TombstoneEventId.Value.ToString("D"));
            if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
                throw new VaultRecoveryRequiredException();
        }
    }

    private static Guid ParseCanonicalGuid(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed)
            || parsed == Guid.Empty
            || !string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal))
        {
            throw new VaultRecoveryRequiredException();
        }
        return parsed;
    }
}
