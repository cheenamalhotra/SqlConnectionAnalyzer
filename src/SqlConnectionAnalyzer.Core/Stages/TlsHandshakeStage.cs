using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Tds;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 4. Repeats PRELOGIN and then performs the TLS handshake exactly where SqlClient
/// would, capturing the negotiated protocol and the full certificate chain. Validation
/// errors are collected rather than thrown so the report can explain precisely which
/// check failed instead of surfacing a generic trust error.
/// </summary>
public sealed class TlsHandshakeStage : IDiagnosticStage
{
    public string Id => "tls-handshake";

    public string Title => "TLS handshake and certificate";

    public bool AppliesTo(DiagnosticContext context) =>
        context.Protocol == NetworkProtocol.Tcp &&
        context.ResolvedAddresses.Count > 0 &&
        context.PreLogin is not null &&
        context.PreLogin.Encryption != TdsEncryptionOption.NotSupported;

    public async Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        string targetName = ResolveTargetName(context);
        result.Record("Certificate name checked", targetName);

        await using TdsTransport transport = await TdsTransport
            .ConnectAsync(context.ResolvedAddresses[0], context.TargetPort, cancellationToken)
            .ConfigureAwait(false);

        bool strict = context.Builder.Encrypt.ToString()
            .Equals("Strict", StringComparison.OrdinalIgnoreCase);
        result.Record("TDS 8.0 strict mode", strict.ToString());

        Stream tlsTransport = transport.Stream;
        TdsSslWrapperStream? wrapper = null;

        if (!strict)
        {
            // In non-strict mode TLS begins only after PRELOGIN negotiates encryption,
            // and the handshake records are tunneled inside TDS packets.
            byte[] request = PreLoginPacket.Build(TdsEncryptionOption.On, context.InstanceName);
            await transport.SendAsync(request, cancellationToken).ConfigureAwait(false);
            await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);

            wrapper = new TdsSslWrapperStream(transport.Stream);
            tlsTransport = wrapper;
        }

        SslPolicyErrors policyErrors = SslPolicyErrors.None;
        var chainStatus = new List<string>();
        X509Certificate2? serverCertificate = null;
        var chainCertificates = new List<X509Certificate2>();

        var sslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = targetName,
            EnabledSslProtocols = SslProtocols.None,
            RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
            {
                policyErrors = errors;

                if (certificate is not null)
                {
                    serverCertificate = new X509Certificate2(certificate);
                }

                if (chain is not null)
                {
                    chainCertificates.AddRange(chain.ChainElements.Select(e => new X509Certificate2(e.Certificate)));
                    chainStatus.AddRange(chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}"));
                }

                // Always accept so the handshake completes and we can report every detail.
                return true;
            }
        };

        await using var ssl = new SslStream(tlsTransport, leaveInnerStreamOpen: true);

        try
        {
            await ssl.AuthenticateAsClientAsync(sslOptions, cancellationToken).ConfigureAwait(false);
            wrapper?.FinishHandshake();
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException)
        {
            context.Tls = new TlsInspection { HandshakeSucceeded = false, HandshakeError = ex.Message };
            result.Add(BuildHandshakeFailure(ex, strict));
            result.IsFatal = true;
            return;
        }

        var inspection = new TlsInspection
        {
            NegotiatedProtocol = ssl.SslProtocol,
            CipherSuite = ssl.NegotiatedCipherSuite.ToString(),
            ServerCertificate = serverCertificate,
            Chain = chainCertificates,
            PolicyErrors = policyErrors,
            ChainStatus = chainStatus,
            HandshakeSucceeded = true
        };
        context.Tls = inspection;

        RecordEvidence(result, inspection, targetName);
        EvaluateProtocol(result, inspection);
        EvaluateCertificate(context, result, inspection, targetName);
    }

    /// <summary>
    /// SqlClient validates the certificate against HostNameInCertificate when supplied,
    /// otherwise against the server name from the connection string.
    /// </summary>
    /// <summary>
    /// Builds the handshake failure finding. Strict mode fails for a different reason than
    /// ordinary TLS, so generic "check your TLS version" advice would send the user down the
    /// wrong path: an immediate EOF in strict mode almost always means the endpoint is not
    /// listening for TDS 8.0 at all.
    /// </summary>
    private static Finding BuildHandshakeFailure(Exception ex, bool strict)
    {
        string detail = ex.GetBaseException().Message;

        if (!strict)
        {
            return Finding.Error(
                "SCA0500",
                DiagnosticLayer.Tls,
                "The TLS handshake failed.",
                detail,
                "Verify the client and server share a supported TLS version; SQL Server requires TLS 1.2 or later.",
                "On Linux, a strict OpenSSL security level can reject older certificates. Check /etc/ssl/openssl.cnf.",
                "Confirm the server certificate uses a key size and signature algorithm the client accepts.");
        }

        bool abruptClose =
            detail.Contains("unexpected EOF", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("0 bytes", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("forcibly closed", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("connection was closed", StringComparison.OrdinalIgnoreCase);

        return Finding.Error(
            "SCA0501",
            DiagnosticLayer.Tls,
            abruptClose
                ? "The server closed the connection immediately during the TDS 8.0 strict handshake."
                : "The TDS 8.0 strict TLS handshake failed.",
            abruptClose
                ? $"{detail} With 'Encrypt=Strict' the client sends a TLS ClientHello before any TDS "
                    + "packet. A silent close at that point means the endpoint is not accepting TDS 8.0."
                : detail,
            "Confirm the server is SQL Server 2022 or later, or Azure SQL; earlier versions do not support Encrypt=Strict.",
            "Provision a real server certificate. The auto-generated self-signed fallback certificate does not enable strict mode.",
            "Re-run with 'Encrypt=Mandatory'. If that succeeds, the endpoint works but does not accept TDS 8.0.",
            "For Azure SQL, connect on port 1433 and ensure no proxy is intercepting the session.");
    }


    private static string ResolveTargetName(DiagnosticContext context)
    {
        string? overrideName = context.Builder.HostNameInCertificate;
        if (!string.IsNullOrWhiteSpace(overrideName))
        {
            return overrideName;
        }

        return string.IsNullOrWhiteSpace(context.TargetHost) ? "localhost" : context.TargetHost;
    }

    private static void RecordEvidence(StageResult result, TlsInspection tls, string targetName)
    {
        result.Record("Protocol", tls.NegotiatedProtocol.ToString());
        result.Record("Cipher suite", tls.CipherSuite);
        result.Record("Policy errors", tls.PolicyErrors.ToString());

        if (tls.ServerCertificate is { } cert)
        {
            result.Record("Subject", cert.Subject);
            result.Record("Issuer", cert.Issuer);
            result.Record("Valid from", cert.NotBefore.ToString("u"));
            result.Record("Valid to", cert.NotAfter.ToString("u"));
            result.Record("Thumbprint", cert.Thumbprint);
            result.Record("Signature algorithm", cert.SignatureAlgorithm.FriendlyName);
            result.Record("SAN", GetSubjectAlternativeNames(cert));
        }

        result.Record("Chain length", tls.Chain.Count.ToString());
        if (tls.ChainStatus.Count > 0)
        {
            result.Record("Chain status", string.Join("; ", tls.ChainStatus));
        }
    }

    private static void EvaluateProtocol(StageResult result, TlsInspection tls)
    {
#pragma warning disable SYSLIB0039 // Obsolete protocols are reported precisely so users can remediate.
        if (tls.NegotiatedProtocol is SslProtocols.Tls or SslProtocols.Tls11)
        {
            result.Add(Finding.Warn(
                "SCA0510",
                DiagnosticLayer.Tls,
                $"The session negotiated {tls.NegotiatedProtocol}, which is deprecated.",
                null,
                "Patch SQL Server so it supports TLS 1.2, then disable TLS 1.0 and 1.1 on both ends."));
        }
#pragma warning restore SYSLIB0039
        else
        {
            result.Add(Finding.Info(
                "SCA0511",
                DiagnosticLayer.Tls,
                $"TLS handshake succeeded using {tls.NegotiatedProtocol}."));
        }
    }

    private static void EvaluateCertificate(
        DiagnosticContext context,
        StageResult result,
        TlsInspection tls,
        string targetName)
    {
        bool trustServerCertificate = context.Builder.TrustServerCertificate;

        if (tls.ServerCertificate is not { } cert)
        {
            result.Add(Finding.Error(
                "SCA0520",
                DiagnosticLayer.Tls,
                "The server did not present a certificate.",
                null,
                "Configure a certificate for the SQL Server instance."));
            return;
        }

        DateTime now = DateTime.Now;
        if (now > cert.NotAfter)
        {
            result.Add(Finding.Error(
                "SCA0521",
                DiagnosticLayer.Tls,
                $"The server certificate expired on {cert.NotAfter:u}.",
                $"Subject: {cert.Subject}",
                "Renew the certificate and rebind it to the SQL Server instance."));
        }
        else if (now < cert.NotBefore)
        {
            result.Add(Finding.Error(
                "SCA0522",
                DiagnosticLayer.Tls,
                $"The server certificate is not valid until {cert.NotBefore:u}.",
                "Check for clock skew between the client and the server."));
        }
        else if ((cert.NotAfter - now).TotalDays < 30)
        {
            result.Add(Finding.Warn(
                "SCA0523",
                DiagnosticLayer.Tls,
                $"The server certificate expires in {(cert.NotAfter - now).Days} days.",
                null,
                "Schedule renewal before connections start failing."));
        }

        if (tls.PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            string sans = GetSubjectAlternativeNames(cert);
            var finding = Finding.Error(
                "SCA0524",
                DiagnosticLayer.Tls,
                $"The certificate does not match the name '{targetName}'.",
                $"Subject: {cert.Subject}. SAN: {(string.IsNullOrEmpty(sans) ? "(none)" : sans)}",
                $"Connect using a name present in the certificate, or set 'HostNameInCertificate={FirstSan(sans) ?? "<cert name>"}'.",
                "Reissue the certificate with the connection name in its Subject Alternative Name extension.");

            result.Add(trustServerCertificate ? Downgrade(finding, "TrustServerCertificate=true suppresses this at runtime.") : finding);
        }

        if (tls.PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
        {
            var finding = Finding.Error(
                "SCA0525",
                DiagnosticLayer.Tls,
                "The certificate chain could not be validated.",
                tls.ChainStatus.Count > 0
                    ? string.Join("; ", tls.ChainStatus)
                    : "The issuing authority is not trusted by this client.",
                "Install the issuing CA certificate into the client trust store.",
                "On Linux, add the CA to /usr/local/share/ca-certificates and run update-ca-certificates.",
                "On macOS, add the CA to the System keychain and mark it trusted.",
                "Alternatively pin the certificate file with the 'ServerCertificate' connection string keyword.");

            result.Add(trustServerCertificate ? Downgrade(finding, "TrustServerCertificate=true suppresses this at runtime.") : finding);
        }

        if (tls.PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
        {
            result.Add(Finding.Error(
                "SCA0526",
                DiagnosticLayer.Tls,
                "No certificate was available for validation.",
                null,
                "Ensure the SQL Server instance has a certificate bound to it."));
        }

        if (tls.PolicyErrors == SslPolicyErrors.None)
        {
            result.Add(Finding.Info(
                "SCA0527",
                DiagnosticLayer.Tls,
                "The server certificate passed full validation.",
                trustServerCertificate
                    ? "'TrustServerCertificate=true' is unnecessary here and can safely be removed."
                    : null));

            if (trustServerCertificate)
            {
                result.Add(Finding.Warn(
                    "SCA0528",
                    DiagnosticLayer.Tls,
                    "'TrustServerCertificate=true' is set even though validation succeeds without it.",
                    null,
                    "Remove 'TrustServerCertificate' to restore man-in-the-middle protection."));
            }
        }
    }

    private static Finding Downgrade(Finding finding, string note) => new()
    {
        Code = finding.Code,
        Severity = Severity.Warning,
        Layer = finding.Layer,
        Message = finding.Message,
        Detail = string.IsNullOrEmpty(finding.Detail) ? note : $"{finding.Detail} {note}",
        Remediation = finding.Remediation,
        References = finding.References
    };

    private static string GetSubjectAlternativeNames(X509Certificate2 certificate)
    {
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.17")
            {
                return extension.Format(false);
            }
        }

        return string.Empty;
    }

    private static string? FirstSan(string sans)
    {
        if (string.IsNullOrEmpty(sans))
        {
            return null;
        }

        string[] parts = sans.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string? dns = parts.FirstOrDefault(p => p.Contains("DNS", StringComparison.OrdinalIgnoreCase));
        int equals = dns?.IndexOf('=') ?? -1;
        return equals >= 0 ? dns![(equals + 1)..].Trim() : null;
    }
}
