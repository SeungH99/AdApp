using System.Buffers.Binary;
using System.Text;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Crypto;

internal static class EventAdditionalData
{
    private static readonly byte[] DomainSeparator =
        "ProofToClosure.EventPayload.AAD.v1"u8.ToArray();

    public static byte[] Create(EventEncryptionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var eventTypeLength = Encoding.UTF8.GetByteCount(context.EventType);
        var length = checked(
            sizeof(uint) + DomainSeparator.Length
            + sizeof(int)
            + 16
            + sizeof(int)
            + 16
            + 16
            + sizeof(long)
            + 16
            + sizeof(uint) + eventTypeLength
            + sizeof(int)
            + 16);
        var additionalData = new byte[length];
        var destination = additionalData.AsSpan();
        var offset = 0;

        WriteLengthPrefixedBytes(DomainSeparator, destination, ref offset);
        WriteInt32(context.EnvelopeVersion, destination, ref offset);
        WriteGuid(context.KeyId.Value, destination, ref offset);
        WriteInt32((int)context.Owner.Kind, destination, ref offset);
        WriteGuid(context.Owner.Id.Value, destination, ref offset);
        WriteGuid(context.StreamId.Value, destination, ref offset);
        WriteInt64(context.StreamVersion.Value, destination, ref offset);
        WriteGuid(context.EventId.Value, destination, ref offset);
        WriteLengthPrefixedString(context.EventType, eventTypeLength, destination, ref offset);
        WriteInt32(context.SchemaVersion, destination, ref offset);
        WriteGuid(context.OperationId.Value, destination, ref offset);

        return additionalData;
    }

    private static void WriteLengthPrefixedBytes(
        ReadOnlySpan<byte> value,
        Span<byte> destination,
        ref int offset)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], (uint)value.Length);
        offset += sizeof(uint);
        value.CopyTo(destination[offset..]);
        offset += value.Length;
    }

    private static void WriteLengthPrefixedString(
        string value,
        int byteCount,
        Span<byte> destination,
        ref int offset)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], (uint)byteCount);
        offset += sizeof(uint);
        offset += Encoding.UTF8.GetBytes(value, destination[offset..]);
    }

    private static void WriteInt32(int value, Span<byte> destination, ref int offset)
    {
        BinaryPrimitives.WriteInt32BigEndian(destination[offset..], value);
        offset += sizeof(int);
    }

    private static void WriteInt64(long value, Span<byte> destination, ref int offset)
    {
        BinaryPrimitives.WriteInt64BigEndian(destination[offset..], value);
        offset += sizeof(long);
    }

    private static void WriteGuid(Guid value, Span<byte> destination, ref int offset)
    {
        if (!value.TryWriteBytes(destination[offset..], bigEndian: true, out var bytesWritten)
            || bytesWritten != 16)
        {
            throw new InvalidOperationException("The identifier could not be encoded.");
        }

        offset += bytesWritten;
    }
}
