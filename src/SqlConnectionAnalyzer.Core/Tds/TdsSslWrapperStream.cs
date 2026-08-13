using System.Buffers.Binary;

namespace SqlConnectionAnalyzer.Core.Tds;

/// <summary>
/// Encapsulates TLS handshake records inside TDS PRELOGIN packets.
/// <para>
/// In TDS 7.x the TLS handshake is tunneled: every handshake record the client sends is
/// wrapped in a TDS packet with type 0x12, and the server's handshake records arrive the
/// same way. Once the handshake completes, TLS records travel directly on the wire, so the
/// wrapper must be switched off with <see cref="FinishHandshake"/>. Without this framing the
/// server never recognizes the ClientHello and the connection simply stalls.
/// </para>
/// </summary>
public sealed class TdsSslWrapperStream : Stream
{
    private const int HeaderLength = 8;

    private readonly Stream _inner;
    private byte[] _readBuffer = Array.Empty<byte>();
    private int _readOffset;
    private bool _handshakeComplete;

    public TdsSslWrapperStream(Stream inner) => _inner = inner;

    /// <summary>Stops wrapping once the TLS handshake is negotiated.</summary>
    public void FinishHandshake() => _handshakeComplete = true;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        if (_handshakeComplete)
        {
            return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        if (_readOffset >= _readBuffer.Length)
        {
            if (!await FillAsync(cancellationToken).ConfigureAwait(false))
            {
                return 0;
            }
        }

        int available = _readBuffer.Length - _readOffset;
        int count = Math.Min(available, buffer.Length);
        _readBuffer.AsMemory(_readOffset, count).CopyTo(buffer);
        _readOffset += count;
        return count;
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        if (_handshakeComplete)
        {
            await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            return;
        }

        var packet = new byte[HeaderLength + buffer.Length];
        packet[0] = (byte)TdsPacketType.PreLogin;
        packet[1] = (byte)TdsPacketStatus.EndOfMessage;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        buffer.CopyTo(packet.AsMemory(HeaderLength));

        await _inner.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one complete TDS message and exposes its payload as the TLS byte stream.</summary>
    private async Task<bool> FillAsync(CancellationToken cancellationToken)
    {
        var header = new byte[HeaderLength];
        using var payload = new MemoryStream();

        while (true)
        {
            if (!await ReadExactAsync(header, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            int totalLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2, 2));
            if (totalLength < HeaderLength)
            {
                throw new InvalidDataException($"TDS packet declared an invalid length of {totalLength} bytes.");
            }

            int bodyLength = totalLength - HeaderLength;
            if (bodyLength > 0)
            {
                var body = new byte[bodyLength];
                if (!await ReadExactAsync(body, cancellationToken).ConfigureAwait(false))
                {
                    return false;
                }

                payload.Write(body, 0, body.Length);
            }

            if (((TdsPacketStatus)header[1]).HasFlag(TdsPacketStatus.EndOfMessage))
            {
                break;
            }
        }

        _readBuffer = payload.ToArray();
        _readOffset = 0;
        return _readBuffer.Length > 0;
    }

    private async Task<bool> ReadExactAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await _inner
                .ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken)
                .ConfigureAwait(false);

            if (n == 0)
            {
                return false;
            }

            read += n;
        }

        return true;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
