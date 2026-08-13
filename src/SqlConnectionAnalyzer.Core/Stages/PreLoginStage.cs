using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Tds;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 3. Performs a hand-built TDS PRELOGIN exchange. This confirms the endpoint really
/// speaks TDS, reveals the server build, and captures the encryption and federated-auth
/// negotiation results that determine what the TLS and authentication stages should expect.
/// </summary>
public sealed class PreLoginStage : IDiagnosticStage
{
    public string Id => "tds-prelogin";

    public string Title => "TDS Pre-Login";

    public bool AppliesTo(DiagnosticContext context) =>
        context.Protocol == NetworkProtocol.Tcp && context.ResolvedAddresses.Count > 0;

    public async Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        TdsEncryptionOption clientOption = MapClientEncryption(context);
        result.Record("Client ENCRYPTION option", clientOption.ToString());

        byte[] request = PreLoginPacket.Build(
            clientOption,
            context.InstanceName,
            requestFedAuth: RequiresFedAuth(context));

        result.Record("Request bytes", request.Length.ToString());

        await using TdsTransport transport = await TdsTransport
            .ConnectAsync(context.ResolvedAddresses[0], context.TargetPort, cancellationToken)
            .ConfigureAwait(false);

        try
        {
            await transport.SendAsync(request, cancellationToken).ConfigureAwait(false);
            TdsMessage response = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);

            if (response.Type != TdsPacketType.TabularResult)
            {
                result.Add(Finding.Error(
                    "SCA0400",
                    DiagnosticLayer.Tds,
                    $"The endpoint replied with an unexpected TDS packet type 0x{(byte)response.Type:X2}.",
                    "A SQL Server endpoint answers PRELOGIN with a table response packet (0x04).",
                    "Confirm the port belongs to SQL Server and is not fronted by a load balancer or proxy."));
                result.IsFatal = true;
                return;
            }

            PreLoginResponse preLogin = PreLoginPacket.Parse(response.Payload);
            context.PreLogin = preLogin;

            RecordEvidence(result, preLogin);
            EvaluateEncryption(context, result, clientOption, preLogin);
            EvaluateInstance(context, result, preLogin);
            EvaluateFedAuth(context, result, preLogin);
        }
        catch (EndOfStreamException ex)
        {
            result.Add(Finding.Error(
                "SCA0401",
                DiagnosticLayer.Tds,
                "The server accepted the TCP connection but closed it during PRELOGIN.",
                ex.Message,
                "A firewall or proxy in the path may be terminating the connection.",
                "On the server, check the SQL error log for a rejected connection or an exhausted worker pool.",
                "Verify the port is SQL Server itself and not a redirector."));
            result.IsFatal = true;
        }
        catch (InvalidDataException ex)
        {
            result.Add(Finding.Error(
                "SCA0402",
                DiagnosticLayer.Tds,
                "The reply was not a well-formed TDS packet.",
                ex.Message,
                "The port is likely serving a protocol other than TDS."));
            result.IsFatal = true;
        }
    }

    private static bool RequiresFedAuth(DiagnosticContext context)
    {
        Microsoft.Data.SqlClient.SqlAuthenticationMethod auth = context.Builder.Authentication;
        return auth is not Microsoft.Data.SqlClient.SqlAuthenticationMethod.NotSpecified
            and not Microsoft.Data.SqlClient.SqlAuthenticationMethod.SqlPassword;
    }

    private static TdsEncryptionOption MapClientEncryption(DiagnosticContext context)
    {
        string encrypt = context.Builder.Encrypt.ToString();

        if (encrypt.Equals("Strict", StringComparison.OrdinalIgnoreCase))
        {
            // Strict performs TLS before PRELOGIN, so the option byte is not negotiated.
            return TdsEncryptionOption.Required;
        }

        bool disabled = encrypt.Equals("False", StringComparison.OrdinalIgnoreCase) ||
                        encrypt.Equals("Optional", StringComparison.OrdinalIgnoreCase);

        return disabled ? TdsEncryptionOption.Off : TdsEncryptionOption.On;
    }

    private static void RecordEvidence(StageResult result, PreLoginResponse preLogin)
    {
        result.Record("Server version", preLogin.ServerVersion?.ToString());
        result.Record("Sub-build", preLogin.SubBuild.ToString());
        result.Record("Server ENCRYPTION option", preLogin.Encryption.ToString());
        result.Record("MARS supported", preLogin.MarsSupported.ToString());
        result.Record("FEDAUTHREQUIRED", preLogin.FedAuthRequired.ToString());
        result.Record("Instance validity", preLogin.InstanceValidity);

        if (preLogin.ServerVersion is { } version)
        {
            result.Add(Finding.Info(
                "SCA0410",
                DiagnosticLayer.Tds,
                $"The endpoint is SQL Server {DescribeVersion(version)} (build {version}).",
                "The PRELOGIN handshake completed, so the transport and TDS layers are healthy."));
        }
    }

    private static void EvaluateEncryption(
        DiagnosticContext context,
        StageResult result,
        TdsEncryptionOption client,
        PreLoginResponse preLogin)
    {
        switch (preLogin.Encryption)
        {
            case TdsEncryptionOption.NotSupported when client is TdsEncryptionOption.On or TdsEncryptionOption.Required:
                result.Add(Finding.Error(
                    "SCA0420",
                    DiagnosticLayer.Tls,
                    "The client requires encryption but the server reports ENCRYPT_NOT_SUP.",
                    "The server has no usable certificate or TLS is disabled for the instance.",
                    "Provision a server certificate and enable 'Force Encryption' in SQL Server Configuration Manager.",
                    "Confirm the service account can read the certificate's private key."));
                result.IsFatal = true;
                break;

            case TdsEncryptionOption.Required when client == TdsEncryptionOption.Off:
                result.Add(Finding.Error(
                    "SCA0421",
                    DiagnosticLayer.Tls,
                    "The server requires encryption but the client requested ENCRYPT_OFF.",
                    "The server is configured with Force Encryption.",
                    "Set 'Encrypt=Mandatory' in the connection string."));
                result.IsFatal = true;
                break;

            case TdsEncryptionOption.Off:
                result.Add(Finding.Warn(
                    "SCA0422",
                    DiagnosticLayer.Tls,
                    "Only the login packet will be encrypted; the rest of the session is cleartext.",
                    "The server negotiated ENCRYPT_OFF.",
                    "Set 'Encrypt=Mandatory' on the client and enable Force Encryption on the server."));
                break;

            case TdsEncryptionOption.On or TdsEncryptionOption.Required:
                result.Add(Finding.Info(
                    "SCA0423",
                    DiagnosticLayer.Tls,
                    $"Encryption negotiated as {preLogin.Encryption}; the whole session will be TLS protected."));
                break;
        }
    }

    private static void EvaluateInstance(DiagnosticContext context, StageResult result, PreLoginResponse preLogin)
    {
        if (context.InstanceName is not null && preLogin.InstanceValidity == "invalid")
        {
            result.Add(Finding.Error(
                "SCA0430",
                DiagnosticLayer.Tds,
                $"The server rejected instance name '{context.InstanceName}'.",
                "PRELOGIN returned INSTOPT with a non-zero value.",
                "Check the instance name spelling, or connect using the instance's TCP port directly."));
            result.IsFatal = true;
        }
    }

    private static void EvaluateFedAuth(DiagnosticContext context, StageResult result, PreLoginResponse preLogin)
    {
        bool clientWantsFedAuth = RequiresFedAuth(context);

        if (clientWantsFedAuth && !preLogin.FedAuthRequired)
        {
            result.Add(Finding.Warn(
                "SCA0440",
                DiagnosticLayer.Authentication,
                "The client requested federated authentication but the server did not acknowledge FEDAUTHREQUIRED.",
                "The server may not support Microsoft Entra authentication.",
                "Confirm the target supports Entra ID; on-premises SQL Server requires SQL Server 2022 with Entra authentication configured."));
        }
        else if (preLogin.FedAuthRequired && !clientWantsFedAuth)
        {
            result.Add(Finding.Info(
                "SCA0441",
                DiagnosticLayer.Authentication,
                "The server supports federated (Microsoft Entra) authentication.",
                "The current connection string uses a non-federated method."));
        }
    }

    private static string DescribeVersion(Version version) => version.Major switch
    {
        >= 16 => "2022 or later",
        15 => "2019",
        14 => "2017",
        13 => "2016",
        12 => "2014",
        11 => "2012",
        _ => "an older release"
    };
}
