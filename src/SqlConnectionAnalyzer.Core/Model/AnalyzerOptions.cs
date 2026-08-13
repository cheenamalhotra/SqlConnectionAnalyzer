namespace SqlConnectionAnalyzer.Core.Model;

public enum NetworkProtocol
{
    Tcp,
    NamedPipes,
    SharedMemory,
    Admin,
    Unknown
}

/// <summary>Classification of the target endpoint, which drives stage expectations.</summary>
public enum EndpointKind
{
    Unknown,
    OnPremises,
    AzureSqlDatabase,
    AzureSqlManagedInstance,
    AzureSynapse,
    Fabric,
    LocalDb,
    Loopback
}

public sealed class AnalyzerOptions
{
    /// <summary>Per-stage network timeout.</summary>
    public TimeSpan ProbeTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Continue running stages after a fatal failure (best-effort mode).</summary>
    public bool ContinueOnFatal { get; set; }

    /// <summary>Attempt a real SqlConnection open at the login stage.</summary>
    public bool AttemptLogin { get; set; } = true;

    /// <summary>Retry with relaxed Encrypt/TrustServerCertificate settings to prove root cause.</summary>
    public bool MatrixMode { get; set; }

    /// <summary>Capture Microsoft.Data.SqlClient EventSource traces during the login attempt.</summary>
    public bool CaptureEventSource { get; set; }
}
