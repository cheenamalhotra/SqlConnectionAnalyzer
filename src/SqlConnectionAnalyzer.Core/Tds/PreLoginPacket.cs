using System.Buffers.Binary;
using System.Text;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Core.Tds;

/// <summary>
/// Builds and parses TDS PRELOGIN messages (MS-TDS 2.2.6.5). Sending this packet by hand
/// lets the analyzer observe the server's encryption requirement and federated-auth hint
/// before any credential is involved.
/// </summary>
public static class PreLoginPacket
{
    public const int HeaderLength = 8;

    /// <summary>
    /// Builds a PRELOGIN request. The option offsets are relative to the start of the
    /// PRELOGIN payload, not the packet header.
    /// </summary>
    public static byte[] Build(
        TdsEncryptionOption encryption,
        string? instanceName = null,
        bool requestFedAuth = false,
        Guid? traceId = null)
    {
        var options = new List<(PreLoginOptionToken Token, byte[] Data)>
        {
            // UL_VERSION (4 bytes) + US_SUBBUILD (2 bytes). Advertise a modern client build.
            (PreLoginOptionToken.Version, new byte[] { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00 }),
            (PreLoginOptionToken.Encryption, new[] { (byte)encryption }),
            (PreLoginOptionToken.InstOpt, BuildInstanceOption(instanceName)),
            (PreLoginOptionToken.ThreadId, BitConverter.GetBytes(Environment.CurrentManagedThreadId)),
            (PreLoginOptionToken.Mars, new byte[] { 0x00 })
        };

        if (traceId is { } id)
        {
            // TRACEID is a 16-byte connection ID plus a 16-byte activity ID and a 4-byte sequence.
            var trace = new byte[36];
            id.ToByteArray().CopyTo(trace, 0);
            options.Add((PreLoginOptionToken.TraceId, trace));
        }

        if (requestFedAuth)
        {
            options.Add((PreLoginOptionToken.FedAuthRequired, new byte[] { 0x01 }));
        }

        // Each option entry is 5 bytes (token + 2-byte offset + 2-byte length), then a terminator.
        int optionHeaderLength = (options.Count * 5) + 1;
        int payloadLength = optionHeaderLength + options.Sum(o => o.Data.Length);

        var packet = new byte[HeaderLength + payloadLength];

        packet[0] = (byte)TdsPacketType.PreLogin;
        packet[1] = (byte)TdsPacketStatus.EndOfMessage;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        // Bytes 4-5 SPID, 6 PacketID, 7 Window are all zero for PRELOGIN.

        int headerCursor = HeaderLength;
        int dataCursor = HeaderLength + optionHeaderLength;

        foreach ((PreLoginOptionToken token, byte[] data) in options)
        {
            packet[headerCursor++] = (byte)token;
            BinaryPrimitives.WriteUInt16BigEndian(
                packet.AsSpan(headerCursor, 2),
                (ushort)(dataCursor - HeaderLength));
            headerCursor += 2;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(headerCursor, 2), (ushort)data.Length);
            headerCursor += 2;

            data.CopyTo(packet, dataCursor);
            dataCursor += data.Length;
        }

        packet[headerCursor] = (byte)PreLoginOptionToken.Terminator;

        return packet;
    }

    private static byte[] BuildInstanceOption(string? instanceName)
    {
        if (string.IsNullOrEmpty(instanceName))
        {
            return new byte[] { 0x00 };
        }

        byte[] name = Encoding.ASCII.GetBytes(instanceName);
        var buffer = new byte[name.Length + 1];
        name.CopyTo(buffer, 0);
        buffer[^1] = 0x00;
        return buffer;
    }

    /// <summary>Parses a PRELOGIN response payload (the packet body, header already stripped).</summary>
    public static PreLoginResponse Parse(ReadOnlySpan<byte> payload)
    {
        Version? version = null;
        int subBuild = 0;
        var encryption = TdsEncryptionOption.NotSupported;
        string? instanceValidity = null;
        bool mars = false;
        bool fedAuth = false;
        Guid? traceId = null;

        int cursor = 0;
        while (cursor < payload.Length)
        {
            var token = (PreLoginOptionToken)payload[cursor];
            if (token == PreLoginOptionToken.Terminator)
            {
                break;
            }

            if (cursor + 5 > payload.Length)
            {
                break;
            }

            int offset = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor + 1, 2));
            int length = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor + 3, 2));
            cursor += 5;

            if (offset + length > payload.Length)
            {
                continue;
            }

            ReadOnlySpan<byte> data = payload.Slice(offset, length);

            switch (token)
            {
                case PreLoginOptionToken.Version when length >= 6:
                    version = new Version(data[0], data[1], BinaryPrimitives.ReadUInt16BigEndian(data.Slice(2, 2)));
                    subBuild = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(4, 2));
                    break;

                case PreLoginOptionToken.Encryption when length >= 1:
                    encryption = (TdsEncryptionOption)data[0];
                    break;

                case PreLoginOptionToken.InstOpt when length >= 1:
                    // 0x00 means the requested instance name is valid on this server.
                    instanceValidity = data[0] == 0x00 ? "valid" : "invalid";
                    break;

                case PreLoginOptionToken.Mars when length >= 1:
                    mars = data[0] == 0x01;
                    break;

                case PreLoginOptionToken.FedAuthRequired when length >= 1:
                    fedAuth = data[0] == 0x01;
                    break;

                case PreLoginOptionToken.TraceId when length >= 16:
                    traceId = new Guid(data[..16].ToArray());
                    break;
            }
        }

        return new PreLoginResponse
        {
            ServerVersion = version,
            SubBuild = subBuild,
            Encryption = encryption,
            InstanceValidity = instanceValidity,
            MarsSupported = mars,
            FedAuthRequired = fedAuth,
            TraceId = traceId,
            RawPayload = payload.ToArray()
        };
    }
}
