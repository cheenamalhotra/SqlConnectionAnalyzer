namespace SqlConnectionAnalyzer.Core.Model;

/// <summary>ENCRYPTION option values exchanged in the TDS PRELOGIN packet.</summary>
public enum TdsEncryptionOption : byte
{
    Off = 0x00,
    On = 0x01,
    NotSupported = 0x02,
    Required = 0x03,
    ClientCertRequested = 0x80
}

/// <summary>Parsed server response to a TDS PRELOGIN request.</summary>
public sealed class PreLoginResponse
{
    public Version? ServerVersion { get; init; }

    public int SubBuild { get; init; }

    public TdsEncryptionOption Encryption { get; init; }

    public string? InstanceValidity { get; init; }

    public bool MarsSupported { get; init; }

    public bool FedAuthRequired { get; init; }

    public Guid? TraceId { get; init; }

    public byte[] RawPayload { get; init; } = Array.Empty<byte>();
}
