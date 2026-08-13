using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SqlConnectionAnalyzer.Core.Model;

/// <summary>Everything observed during the TLS handshake with the SQL endpoint.</summary>
public sealed class TlsInspection
{
    public SslProtocols NegotiatedProtocol { get; init; }

    public string? CipherSuite { get; init; }

    public X509Certificate2? ServerCertificate { get; init; }

    public IReadOnlyList<X509Certificate2> Chain { get; init; } = Array.Empty<X509Certificate2>();

    public SslPolicyErrors PolicyErrors { get; init; }

    public IReadOnlyList<string> ChainStatus { get; init; } = Array.Empty<string>();

    public bool HandshakeSucceeded { get; init; }

    public string? HandshakeError { get; init; }
}
