using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Tds;

namespace SqlConnectionAnalyzer.Tests;

public class PreLoginPacketTests
{
    [Fact]
    public void BuildProducesAValidTdsHeader()
    {
        byte[] packet = PreLoginPacket.Build(TdsEncryptionOption.On);

        Assert.Equal((byte)TdsPacketType.PreLogin, packet[0]);
        Assert.Equal((byte)TdsPacketStatus.EndOfMessage, packet[1]);

        int declaredLength = (packet[2] << 8) | packet[3];
        Assert.Equal(packet.Length, declaredLength);
    }

    [Fact]
    public void BuildTerminatesTheOptionList()
    {
        byte[] packet = PreLoginPacket.Build(TdsEncryptionOption.On);
        ReadOnlySpan<byte> payload = packet.AsSpan(PreLoginPacket.HeaderLength);

        // Walk the fixed-size option entries until the terminator token.
        int cursor = 0;
        int optionCount = 0;
        while (payload[cursor] != (byte)PreLoginOptionToken.Terminator)
        {
            cursor += 5;
            optionCount++;
            Assert.True(optionCount < 16, "The option list was not terminated.");
        }

        Assert.True(optionCount >= 5);
    }

    [Fact]
    public void RoundTripsThroughParse()
    {
        byte[] packet = PreLoginPacket.Build(TdsEncryptionOption.Required, "SQLEXPRESS", requestFedAuth: true);

        PreLoginResponse parsed = PreLoginPacket.Parse(packet.AsSpan(PreLoginPacket.HeaderLength));

        Assert.Equal(TdsEncryptionOption.Required, parsed.Encryption);
        Assert.True(parsed.FedAuthRequired);
    }

    [Fact]
    public void ParseReadsAServerResponse()
    {
        // A minimal response advertising VERSION 16.0.4235 and ENCRYPT_ON.
        // Two 5-byte option entries plus the terminator occupy offsets 0-10,
        // so the option data begins at offset 11.
        byte[] payload =
        [
            0x00, 0x00, 0x0B, 0x00, 0x06, // VERSION at offset 11, length 6
            0x01, 0x00, 0x11, 0x00, 0x01, // ENCRYPTION at offset 17, length 1
            0xFF,                         // terminator
            0x10, 0x00, 0x10, 0x8B, 0x00, 0x00, // 16.0.4235
            0x01                          // ENCRYPT_ON
        ];

        PreLoginResponse parsed = PreLoginPacket.Parse(payload);

        Assert.Equal(16, parsed.ServerVersion!.Major);
        Assert.Equal(0, parsed.ServerVersion.Minor);
        Assert.Equal(4235, parsed.ServerVersion.Build);
        Assert.Equal(TdsEncryptionOption.On, parsed.Encryption);
    }

    [Fact]
    public void ParseIgnoresOptionsPointingOutsideThePayload()
    {
        byte[] payload = [0x00, 0xFF, 0xFF, 0x00, 0x06, 0xFF];

        PreLoginResponse parsed = PreLoginPacket.Parse(payload);

        Assert.Null(parsed.ServerVersion);
    }
}
