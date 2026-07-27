namespace LocalDocumentOrganizer.CorpusWorkbench.Security;

internal sealed class BoundedMemoryStream : Stream
{
    private readonly MemoryStream _inner = new();
    private readonly int _maximumLength;

    internal BoundedMemoryStream(int maximumLength)
    {
        if (maximumLength <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumLength));
        }

        _maximumLength = maximumLength;
    }

    public override bool CanRead => _inner.CanRead;

    public override bool CanSeek => _inner.CanSeek;

    public override bool CanWrite => _inner.CanWrite;

    public override long Length => _inner.Length;

    public override long Position
    {
        get => _inner.Position;
        set
        {
            if (value < 0 || value > _maximumLength)
            {
                throw new BoundedBufferExceededException();
            }

            _inner.Position = value;
        }
    }

    internal byte[] ToArray() => _inner.ToArray();

    public override void Flush() => _inner.Flush();

    public override int Read(
        byte[] buffer,
        int offset,
        int count) =>
        _inner.Read(buffer, offset, count);

    public override long Seek(
        long offset,
        SeekOrigin origin)
    {
        long next;
        try
        {
            next = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_inner.Position + offset),
                SeekOrigin.End => checked(_inner.Length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };
        }
        catch (OverflowException)
        {
            throw new BoundedBufferExceededException();
        }

        Position = next;
        return next;
    }

    public override void SetLength(long value)
    {
        if (value < 0 || value > _maximumLength)
        {
            throw new BoundedBufferExceededException();
        }

        _inner.SetLength(value);
    }

    public override void Write(
        byte[] buffer,
        int offset,
        int count)
    {
        EnsureCapacity(count);
        _inner.Write(buffer, offset, count);
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        EnsureCapacity(buffer.Length);
        _inner.Write(buffer);
    }

    public override void WriteByte(byte value)
    {
        EnsureCapacity(1);
        _inner.WriteByte(value);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }

    private void EnsureCapacity(long additional)
    {
        if (additional < 0
            || _inner.Position > _maximumLength - additional)
        {
            throw new BoundedBufferExceededException();
        }
    }
}

internal sealed class BoundedBufferExceededException : Exception
{
}
