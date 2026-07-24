using System.Buffers.Binary;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

internal static class OperationJournalAdditionalData
{
    private static readonly byte[] DomainSeparator =
        "ProofToClosure.OperationJournalPayload.AAD.v1"u8.ToArray();

    internal static byte[] Create(OperationJournalEncryptionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var length = checked(
            sizeof(uint) + DomainSeparator.Length
            + sizeof(uint) + sizeof(int)
            + sizeof(uint) + 16
            + sizeof(uint) + sizeof(int)
            + sizeof(uint) + 16
            + sizeof(uint) + 16
            + sizeof(uint) + sizeof(int)
            + sizeof(uint) + sizeof(int)
            + sizeof(uint) + sizeof(long)
            + sizeof(uint) + sizeof(int));
        var additionalData = new byte[length];
        var destination = additionalData.AsSpan();
        var offset = 0;

        WriteBytes(DomainSeparator, destination, ref offset);
        WriteInt32(context.EnvelopeVersion, destination, ref offset);
        WriteGuid(context.KeyId.Value, destination, ref offset);
        WriteInt32((int)context.Owner.Kind, destination, ref offset);
        WriteGuid(context.Owner.Id.Value, destination, ref offset);
        WriteGuid(context.OperationId.Value, destination, ref offset);
        WriteInt32((int)context.OperationKind, destination, ref offset);
        WriteInt32((int)context.State, destination, ref offset);
        WriteInt64(context.Revision, destination, ref offset);
        WriteInt32(context.PayloadSchemaVersion, destination, ref offset);

        if (offset != additionalData.Length)
        {
            throw new InvalidOperationException(
                "The operation Journal authentication data was not encoded canonically.");
        }

        return additionalData;
    }

    private static void WriteBytes(
        ReadOnlySpan<byte> value,
        Span<byte> destination,
        ref int offset)
    {
        WriteLength(value.Length, destination, ref offset);
        value.CopyTo(destination[offset..]);
        offset += value.Length;
    }

    private static void WriteInt32(
        int value,
        Span<byte> destination,
        ref int offset)
    {
        WriteLength(sizeof(int), destination, ref offset);
        BinaryPrimitives.WriteInt32BigEndian(destination[offset..], value);
        offset += sizeof(int);
    }

    private static void WriteInt64(
        long value,
        Span<byte> destination,
        ref int offset)
    {
        WriteLength(sizeof(long), destination, ref offset);
        BinaryPrimitives.WriteInt64BigEndian(destination[offset..], value);
        offset += sizeof(long);
    }

    private static void WriteGuid(
        Guid value,
        Span<byte> destination,
        ref int offset)
    {
        WriteLength(16, destination, ref offset);
        if (!value.TryWriteBytes(destination[offset..], bigEndian: true, out var bytesWritten)
            || bytesWritten != 16)
        {
            throw new InvalidOperationException(
                "The operation Journal identifier could not be encoded.");
        }

        offset += bytesWritten;
    }

    private static void WriteLength(
        int value,
        Span<byte> destination,
        ref int offset)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], checked((uint)value));
        offset += sizeof(uint);
    }
}
