namespace SqlConnectionAnalyzer.Core.Tds;

/// <summary>TDS packet types from MS-TDS section 2.2.3.1.1.</summary>
public enum TdsPacketType : byte
{
    SqlBatch = 0x01,
    PreTds7Login = 0x02,
    Rpc = 0x03,
    TabularResult = 0x04,
    Attention = 0x06,
    BulkLoadData = 0x07,
    FederatedAuthToken = 0x08,
    TransactionManagerRequest = 0x0E,
    Login7 = 0x10,
    Sspi = 0x11,
    PreLogin = 0x12
}

/// <summary>PRELOGIN option tokens from MS-TDS section 2.2.6.5.</summary>
public enum PreLoginOptionToken : byte
{
    Version = 0x00,
    Encryption = 0x01,
    InstOpt = 0x02,
    ThreadId = 0x03,
    Mars = 0x04,
    TraceId = 0x05,
    FedAuthRequired = 0x06,
    NonceOpt = 0x07,
    Terminator = 0xFF
}

/// <summary>Status flags in the 8-byte TDS packet header.</summary>
[Flags]
public enum TdsPacketStatus : byte
{
    Normal = 0x00,
    EndOfMessage = 0x01,
    IgnoreEvent = 0x02,
    ResetConnection = 0x08,
    ResetConnectionSkipTran = 0x10
}
