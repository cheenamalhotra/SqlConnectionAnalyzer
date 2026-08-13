using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace SqlConnectionAnalyzer.Core.Tds;

/// <summary>A TDS message reassembled from one or more packets.</summary>
public sealed record TdsMessage(TdsPacketType Type, byte[] Payload);

/// <summary>
/// Minimal TDS framing over a raw socket. Only what the PRELOGIN exchange needs:
/// write one message, read the reply, then hand the stream to TLS if encryption is negotiated.
/// </summary>
public sealed class TdsTransport : IAsyncDisposable
{
    private readonly Socket _socket;
    private readonly NetworkStream _stream;

    private TdsTransport(Socket socket)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: false);
    }

    /// <summary>Underlying stream, exposed so the TLS stage can wrap it.</summary>
    public Stream Stream => _stream;

    public static async Task<TdsTransport> ConnectAsync(
        IPAddress address,
        int port,
        CancellationToken cancellationToken)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };

        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken).ConfigureAwait(false);
            return new TdsTransport(socket);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public Task SendAsync(byte[] packet, CancellationToken cancellationToken) =>
        _stream.WriteAsync(packet, cancellationToken).AsTask();

    /// <summary>Reads packets until one carries the EOM status flag.</summary>
    public async Task<TdsMessage> ReceiveAsync(CancellationToken cancellationToken)
    {
        var header = new byte[PreLoginPacket.HeaderLength];
        using var body = new MemoryStream();
        TdsPacketType type = TdsPacketType.TabularResult;

        while (true)
        {
            await ReadExactAsync(header, cancellationToken).ConfigureAwait(false);

            type = (TdsPacketType)header[0];
            var status = (TdsPacketStatus)header[1];
            int totalLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2, 2));

            if (totalLength < PreLoginPacket.HeaderLength)
            {
                throw new InvalidDataException($"TDS packet declared an invalid length of {totalLength} bytes.");
            }

            int payloadLength = totalLength - PreLoginPacket.HeaderLength;
            if (payloadLength > 0)
            {
                var payload = new byte[payloadLength];
                await ReadExactAsync(payload, cancellationToken).ConfigureAwait(false);
                body.Write(payload, 0, payload.Length);
            }

            if (status.HasFlag(TdsPacketStatus.EndOfMessage))
            {
                break;
            }
        }

        return new TdsMessage(type, body.ToArray());
    }

    private async Task ReadExactAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await _stream
                .ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken)
                .ConfigureAwait(false);

            if (n == 0)
            {
                throw new EndOfStreamException(
                    $"The server closed the connection after {read} of {buffer.Length} expected bytes.");
            }

            read += n;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
        _socket.Dispose();
    }
}
