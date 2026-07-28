using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using LocalDocumentOrganizer.Core.Documents;

namespace LocalDocumentOrganizer.DocumentExtractionWorker.Protocol;

public sealed record DocumentWorkerRequestEnvelope(
    DocumentWorkerOperation Operation,
    DocumentExtractionRequest? ExtractionRequest,
    DocumentInspectionRequest? InspectionRequest);

public static class FramedJsonTransport
{
    private const int PrefixLength = sizeof(int);

    public static async Task<DocumentExtractionRequest> ReadRequestAsync(
        Stream input,
        CancellationToken cancellationToken)
    {
        var operation = await ReadOperationAsync(
                input,
                cancellationToken)
            .ConfigureAwait(false);
        return operation.Operation
                   == DocumentWorkerOperation.ExtractDocument
               && operation.ExtractionRequest is not null
            ? operation.ExtractionRequest
            : throw new InvalidDataException(
                "The protocol operation is not an extraction request.");
    }

    public static async Task<DocumentWorkerRequestEnvelope>
        ReadOperationAsync(
            Stream input,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);

        var prefix = new byte[PrefixLength];
        await ReadExactlyAsync(input, prefix, cancellationToken).ConfigureAwait(false);
        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (payloadLength <= 0
            || payloadLength > DocumentExtractionLimits.MaxSerializedResponseBytes)
        {
            throw new InvalidDataException("The protocol frame length is invalid.");
        }

        var payload = ArrayPool<byte>.Shared.Rent(payloadLength);
        try
        {
            await ReadExactlyAsync(
                    input,
                    payload.AsMemory(0, payloadLength),
                    cancellationToken)
                .ConfigureAwait(false);

            var trailing = new byte[1];
            if (await input.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw new InvalidDataException("The protocol stream contains trailing data.");
            }

            using var document = JsonDocument.Parse(
                payload.AsMemory(0, payloadLength));
            if (!document.RootElement.TryGetProperty(
                    "operation",
                    out var operationElement))
            {
                var extraction = JsonSerializer.Deserialize(
                        payload.AsSpan(0, payloadLength),
                        DocumentExtractionJsonContext.Default
                            .DocumentExtractionRequest)
                    ?? throw new JsonException(
                        "The extraction request payload is null.");
                return new DocumentWorkerRequestEnvelope(
                    DocumentWorkerOperation.ExtractDocument,
                    extraction,
                    InspectionRequest: null);
            }

            if (operationElement.ValueKind != JsonValueKind.Number
                || !operationElement.TryGetInt32(out var operationValue)
                || operationValue
                    != (int)DocumentWorkerOperation.InspectDocument)
            {
                throw new InvalidDataException(
                    "The protocol operation is invalid.");
            }

            var inspection = JsonSerializer.Deserialize(
                    payload.AsSpan(0, payloadLength),
                    DocumentExtractionJsonContext.Default
                        .DocumentInspectionRequest)
                ?? throw new JsonException(
                    "The inspection request payload is null.");
            return new DocumentWorkerRequestEnvelope(
                DocumentWorkerOperation.InspectDocument,
                ExtractionRequest: null,
                inspection);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload.AsSpan(0, payloadLength));
            ArrayPool<byte>.Shared.Return(payload);
        }
    }

    public static async Task WriteResponseAsync(
        Stream output,
        DocumentExtractionResponse response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(response);

        using var payload = new BoundedPooledByteBufferWriter(
            DocumentExtractionLimits.MaxSerializedResponseBytes);
        try
        {
            using (var writer = new Utf8JsonWriter(payload))
            {
                JsonSerializer.Serialize(
                    writer,
                    response,
                    DocumentExtractionJsonContext.Default.DocumentExtractionResponse);
            }
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidDataException("The response exceeds the protocol limit.", exception);
        }

        var prefix = new byte[PrefixLength];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.WrittenCount);
        await output.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await output.WriteAsync(payload.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    public static async Task WriteInspectionResponseAsync(
        Stream output,
        DocumentInspectionResponse response,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(response);

        using var payload = new BoundedPooledByteBufferWriter(
            DocumentExtractionLimits.MaxSerializedResponseBytes);
        try
        {
            using var writer = new Utf8JsonWriter(payload);
            JsonSerializer.Serialize(
                writer,
                response,
                DocumentExtractionJsonContext.Default
                    .DocumentInspectionResponse);
        }
        catch (InvalidOperationException exception)
        {
            throw new InvalidDataException(
                "The response exceeds the protocol limit.",
                exception);
        }

        var prefix = new byte[PrefixLength];
        BinaryPrimitives.WriteInt32LittleEndian(
            prefix,
            payload.WrittenCount);
        await output.WriteAsync(prefix, cancellationToken)
            .ConfigureAwait(false);
        await output.WriteAsync(
                payload.WrittenMemory,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task ReadExactlyAsync(
        Stream input,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await input.ReadAsync(destination[offset..], cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The protocol frame ended prematurely.");
            }

            offset += read;
        }
    }

    private sealed class BoundedPooledByteBufferWriter : IBufferWriter<byte>, IDisposable
    {
        private byte[]? buffer;

        public BoundedPooledByteBufferWriter(int capacity)
        {
            buffer = ArrayPool<byte>.Shared.Rent(capacity);
            Capacity = capacity;
        }

        public int Capacity { get; }

        public int WrittenCount { get; private set; }

        public ReadOnlyMemory<byte> WrittenMemory =>
            (buffer ?? throw new ObjectDisposedException(GetType().Name))
                .AsMemory(0, WrittenCount);

        public void Advance(int count)
        {
            if (count < 0 || count > Capacity - WrittenCount)
            {
                throw new InvalidOperationException("The response exceeds the protocol limit.");
            }

            WrittenCount += count;
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            EnsureAvailable(sizeHint);
            return buffer!.AsMemory(WrittenCount, Capacity - WrittenCount);
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            EnsureAvailable(sizeHint);
            return buffer!.AsSpan(WrittenCount, Capacity - WrittenCount);
        }

        public void Dispose()
        {
            if (buffer is null)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
            buffer = null;
            WrittenCount = 0;
        }

        private void EnsureAvailable(int sizeHint)
        {
            if (sizeHint < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sizeHint));
            }

            if (sizeHint == 0)
            {
                sizeHint = 1;
            }

            if (buffer is null)
            {
                throw new ObjectDisposedException(GetType().Name);
            }

            if (sizeHint > Capacity - WrittenCount)
            {
                throw new InvalidOperationException("The response exceeds the protocol limit.");
            }
        }
    }
}
