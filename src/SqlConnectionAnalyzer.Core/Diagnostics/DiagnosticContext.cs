using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Core.Diagnostics;

/// <summary>
/// Mutable state shared across stages. Earlier stages publish what they discovered
/// (resolved addresses, negotiated encryption, redirected endpoints) so later stages
/// can reuse it instead of re-probing.
/// </summary>
public sealed class DiagnosticContext
{
    public required string ConnectionString { get; init; }

    public required SqlConnectionStringBuilder Builder { get; init; }

    public required AnalyzerOptions Options { get; init; }

    /// <summary>Server host as parsed from the connection string, without prefix or instance.</summary>
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; }

    public string? InstanceName { get; set; }

    public NetworkProtocol Protocol { get; set; } = NetworkProtocol.Tcp;

    public EndpointKind EndpointKind { get; set; } = EndpointKind.Unknown;

    public List<System.Net.IPAddress> ResolvedAddresses { get; } = new();

    /// <summary>Endpoint actually used after Azure gateway redirection or AG routing.</summary>
    public string? EffectiveHost { get; set; }

    public int? EffectivePort { get; set; }

    public PreLoginResponse? PreLogin { get; set; }

    public TlsInspection? Tls { get; set; }

    public string? AccessToken { get; set; }

    /// <summary>Set by the login stage so later stages know a session was actually established.</summary>
    public bool LoginSucceeded { get; set; }

    public string TargetHost => EffectiveHost ?? Host;

    public int TargetPort => EffectivePort ?? Port;
}
