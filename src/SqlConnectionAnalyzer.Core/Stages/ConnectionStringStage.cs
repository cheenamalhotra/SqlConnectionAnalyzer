using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 0. Validates the connection string before any packet is sent: option conflicts,
/// encryption defaults, timeout sanity, and the shape of the Data Source value.
/// </summary>
public sealed class ConnectionStringStage : IDiagnosticStage
{
    public string Id => "connection-string";

    public string Title => "Connection string";

    public Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        SqlConnectionStringBuilder builder = context.Builder;

        ServerSpec spec = ServerNameParser.Parse(builder.DataSource);
        context.Host = spec.Host;
        context.InstanceName = spec.InstanceName;
        context.Protocol = spec.Protocol;
        context.Port = spec.Port ?? ServerNameParser.DefaultPort;
        context.EndpointKind = ServerNameParser.Classify(spec.Host, spec.InstanceName);

        result.Record("Data Source", builder.DataSource);
        result.Record("Protocol", spec.Protocol.ToString());
        result.Record("Host", spec.Host);
        result.Record("Instance", spec.InstanceName ?? "(default)");
        result.Record("Port", spec.Port?.ToString() ?? $"{ServerNameParser.DefaultPort} (default)");
        result.Record("Endpoint kind", context.EndpointKind.ToString());
        result.Record("Initial Catalog", string.IsNullOrEmpty(builder.InitialCatalog) ? "(server default)" : builder.InitialCatalog);
        result.Record("Authentication", builder.Authentication.ToString());
        result.Record("Encrypt", builder.Encrypt.ToString());
        result.Record("TrustServerCertificate", builder.TrustServerCertificate.ToString());
        result.Record("Connect Timeout", $"{builder.ConnectTimeout}s");
        result.Record("ConnectRetryCount", builder.ConnectRetryCount.ToString());

        if (string.IsNullOrWhiteSpace(spec.Host))
        {
            result.Add(Finding.Error(
                "SCA0100",
                DiagnosticLayer.Configuration,
                "No server was specified.",
                "The Data Source / Server keyword is empty.",
                "Set 'Server=<host>' or 'Data Source=<host>' in the connection string."));
            result.IsFatal = true;
            return Task.CompletedTask;
        }

        if (spec.Port is { } port && (port <= 0 || port > 65535))
        {
            result.Add(Finding.Error(
                "SCA0101",
                DiagnosticLayer.Configuration,
                $"Port {port} is outside the valid range 1-65535.",
                null,
                "Correct the port in 'Server=host,port'."));
            result.IsFatal = true;
        }

        if (spec.InstanceName is not null && spec.Port is not null)
        {
            result.Add(Finding.Warn(
                "SCA0102",
                DiagnosticLayer.Configuration,
                "Both a named instance and an explicit port were supplied.",
                $"Instance '{spec.InstanceName}' will be ignored because the port takes precedence.",
                "Specify either 'host\\instance' (resolved via SQL Browser) or 'host,port', not both."));
        }

        InspectAuthentication(builder, context.ConnectionString, result);
        InspectEncryption(builder, context, result);
        InspectTimeouts(builder, result);

        return Task.CompletedTask;
    }

    private static void InspectAuthentication(
        SqlConnectionStringBuilder builder,
        string rawConnectionString,
        StageResult result)
    {
        bool hasUserId = !string.IsNullOrEmpty(builder.UserID);
        bool hasPassword = !string.IsNullOrEmpty(builder.Password);
        SqlAuthenticationMethod auth = builder.Authentication;

#pragma warning disable CS0618 // Deprecated modes are still analyzed so we can advise migration.
        if (auth == SqlAuthenticationMethod.ActiveDirectoryPassword)
        {
            result.Add(Finding.Warn(
                "SCA0116",
                DiagnosticLayer.Authentication,
                "'Active Directory Password' is deprecated and blocked for accounts requiring MFA.",
                "Microsoft is retiring resource-owner password credential flows.",
                "Switch to 'Active Directory Default', 'Active Directory Interactive', or a managed identity.",
                "See https://aka.ms/SqlClientEntraIDAuthentication"));
        }
#pragma warning restore CS0618

        if (auth != SqlAuthenticationMethod.NotSpecified && builder.IntegratedSecurity)
        {
            result.Add(Finding.Error(
                "SCA0110",
                DiagnosticLayer.Configuration,
                "'Authentication' and 'Integrated Security=true' cannot be combined.",
                $"Authentication={auth} conflicts with Integrated Security.",
                "Remove 'Integrated Security', or use 'Authentication=Active Directory Integrated'."));
            result.IsFatal = true;
        }

        switch (auth)
        {
            case SqlAuthenticationMethod.NotSpecified when !builder.IntegratedSecurity && !hasUserId:
                result.Add(Finding.Warn(
                    "SCA0111",
                    DiagnosticLayer.Authentication,
                    "No authentication method, user, or Integrated Security was specified.",
                    "The connection will only succeed if an AccessToken or a credential is supplied in code.",
                    "Set 'Authentication=', 'Integrated Security=true', or 'User ID'/'Password'."));
                break;

#pragma warning disable CS0618
            case SqlAuthenticationMethod.SqlPassword
                or SqlAuthenticationMethod.ActiveDirectoryPassword
                or SqlAuthenticationMethod.ActiveDirectoryServicePrincipal
                when !hasUserId || !hasPassword:
#pragma warning restore CS0618

                result.Add(Finding.Error(
                    "SCA0112",
                    DiagnosticLayer.Authentication,
                    $"Authentication={auth} requires both a user and a password/secret.",
                    $"User ID {(hasUserId ? "present" : "missing")}, Password {(hasPassword ? "present" : "missing")}.",
                    "Supply 'User ID' and 'Password', or pass a SqlCredential in code."));
                break;
        }

        InspectRejectedKeywordCombinations(auth, rawConnectionString, result);

        if (builder.PersistSecurityInfo && hasPassword)
        {
            result.Add(Finding.Warn(
                "SCA0115",
                DiagnosticLayer.Configuration,
                "'Persist Security Info=true' keeps the password readable after the connection opens.",
                null,
                "Set 'Persist Security Info=false' unless you specifically need it."));
        }
    }

    /// <summary>
    /// Reproduces the authentication keyword rules enforced by SqlConnectionOptions. These are
    /// hard rejections: SqlConnection throws ArgumentException before any network traffic, so they
    /// are fatal errors rather than advice about an ignored value.
    /// </summary>
    /// <remarks>
    /// The driver tests whether the keyword was <em>supplied</em>, not whether it holds a value, so
    /// even <c>Password=</c> with an empty value fails. Verified against Microsoft.Data.SqlClient 7.0.2.
    /// </remarks>
    private static void InspectRejectedKeywordCombinations(
        SqlAuthenticationMethod auth,
        string rawConnectionString,
        StageResult result)
    {
        bool passwordSupplied = ConnectionStringKeywords.HasPassword(rawConnectionString);
        bool userIdSupplied = ConnectionStringKeywords.HasUserId(rawConnectionString);

        // Device code flow rejects both keywords; every other listed mode rejects only a password.
        if (auth == SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow && (userIdSupplied || passwordSupplied))
        {
            result.Add(Finding.Error(
                "SCA0117",
                DiagnosticLayer.Configuration,
                "'Active Directory Device Code Flow' cannot be combined with 'User ID' or 'Password'.",
                "SqlConnection throws: Cannot use 'Authentication=Active Directory Device Code Flow' with "
                    + "'User ID', 'UID', 'Password' or 'PWD' connection string keywords. "
                    + "The keyword being present is enough; an empty value still fails.",
                "Remove 'User ID' and 'Password'; the account is chosen at the device-code prompt."));
            result.IsFatal = true;
            return;
        }

        if (!passwordSupplied)
        {
            return;
        }

        string? mode = auth switch
        {
            SqlAuthenticationMethod.ActiveDirectoryIntegrated => "Active Directory Integrated",
            SqlAuthenticationMethod.ActiveDirectoryInteractive => "Active Directory Interactive",
            SqlAuthenticationMethod.ActiveDirectoryManagedIdentity => "Active Directory Managed Identity",
            SqlAuthenticationMethod.ActiveDirectoryMSI => "Active Directory MSI",
            SqlAuthenticationMethod.ActiveDirectoryDefault => "Active Directory Default",
            SqlAuthenticationMethod.ActiveDirectoryWorkloadIdentity => "Active Directory Workload Identity",
            _ => null
        };

        if (mode is null)
        {
            return;
        }

        result.Add(Finding.Error(
            "SCA0118",
            DiagnosticLayer.Configuration,
            $"'{mode}' cannot be combined with a 'Password' keyword.",
            $"SqlConnection throws: Cannot use 'Authentication={mode}' with 'Password' or 'PWD' "
                + "connection string keywords. The keyword being present is enough; an empty value still fails.",
            "Remove 'Password' (and 'PWD') from the connection string.",
            auth is SqlAuthenticationMethod.ActiveDirectoryManagedIdentity or SqlAuthenticationMethod.ActiveDirectoryMSI
                ? "For a user-assigned identity, set only 'User ID' to its client ID."
                : "If you need to supply a secret, use 'Active Directory Service Principal'."));
        result.IsFatal = true;
    }

    private static void InspectEncryption(
        SqlConnectionStringBuilder builder,
        DiagnosticContext context,
        StageResult result)
    {
        bool isAzure = context.EndpointKind is EndpointKind.AzureSqlDatabase
            or EndpointKind.AzureSqlManagedInstance
            or EndpointKind.AzureSynapse
            or EndpointKind.Fabric;

        string encrypt = builder.Encrypt.ToString();
        bool encryptDisabled = encrypt.Equals("False", StringComparison.OrdinalIgnoreCase) ||
                               encrypt.Equals("Optional", StringComparison.OrdinalIgnoreCase);

        if (encryptDisabled && isAzure)
        {
            result.Add(Finding.Error(
                "SCA0120",
                DiagnosticLayer.Configuration,
                "Encryption is disabled but the target is an Azure SQL endpoint that mandates TLS.",
                $"Encrypt={encrypt}.",
                "Set 'Encrypt=Mandatory' (or 'true'). Azure SQL rejects unencrypted connections."));
        }

        if (builder.TrustServerCertificate)
        {
            result.Add(Finding.Warn(
                "SCA0121",
                DiagnosticLayer.Tls,
                "'TrustServerCertificate=true' disables server certificate validation.",
                "The connection is encrypted but not authenticated, leaving it open to man-in-the-middle attacks.",
                "Install the server's CA certificate in the client trust store and set 'TrustServerCertificate=false'.",
                "Alternatively pin the certificate with the 'ServerCertificate' keyword."));
        }

        if (!string.IsNullOrEmpty(builder.HostNameInCertificate))
        {
            result.Record("HostNameInCertificate", builder.HostNameInCertificate);
        }

        result.Add(Finding.Info(
            "SCA0122",
            DiagnosticLayer.Configuration,
            $"Effective encryption setting is Encrypt={encrypt}.",
            "Microsoft.Data.SqlClient 4.0 and later default to Encrypt=Mandatory."));
    }

    private static void InspectTimeouts(SqlConnectionStringBuilder builder, StageResult result)
    {
        if (builder.ConnectTimeout == 0)
        {
            result.Add(Finding.Warn(
                "SCA0130",
                DiagnosticLayer.Configuration,
                "'Connect Timeout=0' means the open attempt waits indefinitely.",
                null,
                "Use a bounded timeout such as 30 seconds so failures surface promptly."));
        }
        else if (builder.ConnectTimeout < 15 &&
                 builder.Authentication != SqlAuthenticationMethod.NotSpecified)
        {
            result.Add(Finding.Warn(
                "SCA0131",
                DiagnosticLayer.Configuration,
                $"'Connect Timeout={builder.ConnectTimeout}' may be too short for Microsoft Entra token acquisition.",
                "Interactive and federated flows routinely need more than 15 seconds.",
                "Increase 'Connect Timeout' to at least 30 seconds."));
        }

        if (builder.ConnectRetryCount == 0)
        {
            result.Add(Finding.Warn(
                "SCA0132",
                DiagnosticLayer.Resiliency,
                "Connection resiliency is disabled ('ConnectRetryCount=0').",
                null,
                "Set 'ConnectRetryCount=3' and 'ConnectRetryInterval=10' to absorb transient faults."));
        }
    }
}
