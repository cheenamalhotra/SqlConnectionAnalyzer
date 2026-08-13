using Azure.Core;
using Azure.Identity;
using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 6. Verifies that a credential can actually be obtained before the login packet is
/// sent. Splitting this out means an Entra token failure is never misreported as a SQL
/// Server login failure, and vice versa.
/// </summary>
public sealed class CredentialStage : IDiagnosticStage
{
    /// <summary>
    /// Resource SQL accepts tokens for in the public cloud. SqlClient does not hardcode this: the
    /// server supplies the resource (SPN) and authority (STSURL) in the FEDAUTHINFO token during
    /// login, so the value here is a pre-login approximation chosen from the endpoint suffix.
    /// </summary>
    private const string PublicCloudScope = "https://database.windows.net/.default";

    /// <summary>
    /// Sovereign clouds issue tokens for a different resource. Matching SqlClient's own endpoint
    /// suffixes keeps the probe from requesting a token the server would reject.
    /// </summary>
    private static readonly (string Suffix, string Scope)[] SovereignScopes =
    [
        (".database.usgovcloudapi.net", "https://database.usgovcloudapi.net/.default"),
        (".database.chinacloudapi.cn", "https://database.chinacloudapi.cn/.default"),
        (".database.cloudapi.de", "https://database.cloudapi.de/.default")
    ];

    internal static string ResolveScope(string host)
    {
        foreach ((string suffix, string scope) in SovereignScopes)
        {
            if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return scope;
            }
        }

        return PublicCloudScope;
    }

    public string Id => "credentials";

    public string Title => "Credential acquisition";

    public async Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        SqlConnectionStringBuilder builder = context.Builder;
        SqlAuthenticationMethod auth = builder.Authentication;

        result.Record("Method", auth == SqlAuthenticationMethod.NotSpecified
            ? builder.IntegratedSecurity ? "Integrated Security (SSPI/Kerberos)" : "SQL authentication"
            : auth.ToString());

        if (auth == SqlAuthenticationMethod.NotSpecified)
        {
            if (builder.IntegratedSecurity)
            {
                await InspectIntegratedAsync(context, result, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                InspectSqlAuthentication(context, result);
            }

            return;
        }

        switch (auth)
        {
            case SqlAuthenticationMethod.SqlPassword:
                InspectSqlAuthentication(context, result);
                break;

            case SqlAuthenticationMethod.ActiveDirectoryIntegrated:
                // Despite the name this is not SSPI/Kerberos against SQL Server. SqlClient calls
                // MSAL's AcquireTokenByIntegratedWindowsAuth to get an Entra token from the domain
                // session, so no MSSQLSvc service ticket is involved and SPN advice would mislead.
                result.Add(Finding.Info(
                    "SCA0617",
                    DiagnosticLayer.Authentication,
                    "'Active Directory Integrated' authenticates to Microsoft Entra ID, not to SQL Server via Kerberos.",
                    "SqlClient uses Integrated Windows Authentication against Entra ID to obtain a token. "
                        + "The MSSQLSvc service principal name is only relevant to 'Integrated Security=true'.",
                    "For Kerberos to SQL Server, use 'Integrated Security=true' instead."));
                await AcquireEntraTokenAsync(context, result, cancellationToken).ConfigureAwait(false);
                break;

            default:
                await AcquireEntraTokenAsync(context, result, cancellationToken).ConfigureAwait(false);
                break;
        }
    }

    private static void InspectSqlAuthentication(DiagnosticContext context, StageResult result)
    {
        SqlConnectionStringBuilder builder = context.Builder;

        result.Record("User ID", builder.UserID);
        result.Record("Password", Redactor.Mask(builder.Password));

        if (string.IsNullOrEmpty(builder.UserID))
        {
            result.Add(Finding.Error(
                "SCA0600",
                DiagnosticLayer.Authentication,
                "SQL authentication was selected but no user was supplied.",
                null,
                "Set 'User ID', or pass a SqlCredential to the SqlConnection."));
            return;
        }

        if (builder.UserID.Contains('@') && context.EndpointKind == EndpointKind.AzureSqlDatabase)
        {
            result.Add(Finding.Info(
                "SCA0601",
                DiagnosticLayer.Authentication,
                "The user name contains '@', which Azure SQL treats as 'user@servername' shorthand.",
                "This form is only needed for older tooling; the plain login name normally works."));
        }

        result.Add(Finding.Info(
            "SCA0602",
            DiagnosticLayer.Authentication,
            "SQL authentication needs no pre-login token; the credential is validated by the server during LOGIN7."));
    }

    private static async Task InspectIntegratedAsync(
        DiagnosticContext context,
        StageResult result,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> spnCandidates = KerberosProbe.BuildSpnCandidates(
            context.TargetHost,
            context.TargetPort,
            context.InstanceName,
            context.Builder.ServerSPN);
        string spn = spnCandidates[0];
        result.Record("Expected SPN", string.Join(" or ", spnCandidates));

        if (!string.IsNullOrWhiteSpace(context.Builder.ServerSPN))
        {
            result.Record("SPN source", "'Server SPN' keyword (used verbatim by SqlClient)");
        }

        if (KerberosProbe.SupportsIntegratedSecurity())
        {
            result.Add(Finding.Info(
                "SCA0610",
                DiagnosticLayer.Authentication,
                "Windows Integrated authentication will use the logged-on user's credentials.",
                $"SqlClient requests the service ticket for {spn}. If that SPN is missing, authentication silently falls back to NTLM."));
        }
        else
        {
            result.Add(Finding.Info(
                "SCA0611",
                DiagnosticLayer.Authentication,
                "Integrated Security on this platform requires a Kerberos credential cache; NTLM fallback is not available.",
                "Obtain a ticket with 'kinit user@REALM' before connecting."));
        }

        KerberosState state = await KerberosProbe.InspectAsync(cancellationToken).ConfigureAwait(false);

        if (!state.ToolAvailable)
        {
            result.Record("Kerberos cache", "not inspected");
            result.Add(Finding.Info(
                "SCA0612",
                DiagnosticLayer.Authentication,
                "The Kerberos cache could not be inspected because 'klist' is unavailable.",
                state.Error));
            return;
        }

        result.Record("Kerberos principal", state.Principals.Count > 0 ? string.Join(", ", state.Principals) : "(none)");
        result.Record("Cached tickets", state.ServiceTickets.Count.ToString());
        result.Record("Ticket-granting ticket", state.HasTicketGrantingTicket ? "present" : "absent");

        if (!state.HasCredentialCache)
        {
            result.Add(Finding.Error(
                "SCA0613",
                DiagnosticLayer.Authentication,
                "No Kerberos credential cache was found for the current user.",
                state.Error,
                "Run 'kinit <user>@<REALM>' to obtain a ticket-granting ticket.",
                "Verify /etc/krb5.conf points at a reachable KDC for the realm.",
                "On Windows, confirm the machine is domain-joined and the user signed in with domain credentials."));
            return;
        }

        // Without a TGT no service ticket can be requested, so report that first.
        if (!state.HasTicketGrantingTicket)
        {
            result.Add(Finding.Warn(
                "SCA0616",
                DiagnosticLayer.Authentication,
                "The cache holds tickets but no ticket-granting ticket (krbtgt).",
                "Service tickets are obtained using the TGT, so authentication will fail once the "
                    + "cached service tickets expire.",
                "Run 'kinit' to refresh the TGT."));
        }

        // Match on the target host: a ticket for a different server proves nothing here.
        if (state.HasTicketForAny(spnCandidates))
        {
            result.Add(Finding.Info(
                "SCA0614",
                DiagnosticLayer.Authentication,
                $"A cached MSSQLSvc service ticket matching {string.Join(" or ", spnCandidates)} is present.",
                string.Join(", ", state.ServiceTickets.Where(t =>
                    t.StartsWith("MSSQLSvc/", StringComparison.OrdinalIgnoreCase)))));
        }
        else
        {
            bool hasOtherSqlTicket = state.ServiceTickets.Any(t =>
                t.StartsWith("MSSQLSvc/", StringComparison.OrdinalIgnoreCase));

            result.Add(Finding.Warn(
                "SCA0615",
                DiagnosticLayer.Authentication,
                $"No cached service ticket for {string.Join(" or ", spnCandidates)} was found.",
                hasOtherSqlTicket
                    ? "SQL service tickets exist for other hosts, so Kerberos itself works; the ticket for "
                        + "this host is simply not cached yet. It is normally acquired on demand."
                    : "The ticket is normally acquired on demand, so this is only a problem if the SPN is not registered.",
                $"On a domain controller, run: setspn -L <sql service account> and confirm {spn} is listed.",
                "Register a missing SPN with: setspn -S " + spn + " <domain\\\\service account>",
                "A duplicate SPN registered on two accounts also breaks Kerberos; check with 'setspn -X'."));
        }
    }

    private static async Task AcquireEntraTokenAsync(
        DiagnosticContext context,
        StageResult result,
        CancellationToken cancellationToken)
    {
        SqlConnectionStringBuilder builder = context.Builder;
        SqlAuthenticationMethod auth = builder.Authentication;

        TokenCredential? credential = BuildCredential(auth, builder, result);
        if (credential is null)
        {
            return;
        }

        string scope = ResolveScope(context.TargetHost);
        result.Record("Scope", scope);
        result.Record("Scope source", scope == PublicCloudScope
            ? "public cloud default (server confirms the real resource via FEDAUTHINFO)"
            : "sovereign cloud, inferred from the endpoint suffix");

        try
        {
            AccessToken token = await credential
                .GetTokenAsync(new TokenRequestContext(new[] { scope }), cancellationToken)
                .ConfigureAwait(false);

            context.AccessToken = token.Token;
            result.Record("Token", Redactor.Token(token.Token));
            result.Record("Token expires", token.ExpiresOn.ToLocalTime().ToString("u"));

            if (JwtInspector.TryDecode(token.Token, out TokenClaims? claims) && claims is not null)
            {
                result.Record("Claims", JwtInspector.Describe(claims));
                EvaluateClaims(context, result, claims);
            }

            result.Add(Finding.Info(
                "SCA0620",
                DiagnosticLayer.Authentication,
                $"A Microsoft Entra access token was acquired for {scope}.",
                "Token acquisition succeeded, so any remaining failure is on the SQL Server side. "
                    + "SqlClient itself requests the resource and authority named by the server in its "
                    + "FEDAUTHINFO token, so a working token here confirms the credential, not the audience."));
        }
        catch (CredentialUnavailableException ex)
        {
            result.Add(Finding.Error(
                "SCA0622",
                DiagnosticLayer.Authentication,
                "No usable credential source was available.",
                ex.Message,
                BuildTokenRemediation(auth)));
            result.IsFatal = true;
        }
        catch (AuthenticationFailedException ex)
        {
            result.Add(Finding.Error(
                "SCA0621",
                DiagnosticLayer.Authentication,
                "Microsoft Entra token acquisition failed.",
                ex.Message,
                BuildTokenRemediation(auth)));
            result.IsFatal = true;
        }
    }

    private static TokenCredential? BuildCredential(
        SqlAuthenticationMethod auth,
        SqlConnectionStringBuilder builder,
        StageResult result)
    {
        string? tenantId = ExtractTenantId();

        switch (auth)
        {
            case SqlAuthenticationMethod.ActiveDirectoryDefault:
                return new DefaultAzureCredential(new DefaultAzureCredentialOptions { TenantId = tenantId });

            case SqlAuthenticationMethod.ActiveDirectoryManagedIdentity:
            case SqlAuthenticationMethod.ActiveDirectoryMSI:
                result.Record("Identity", string.IsNullOrEmpty(builder.UserID)
                    ? "system-assigned"
                    : $"user-assigned ({builder.UserID})");
                return string.IsNullOrEmpty(builder.UserID)
                    ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                    : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(builder.UserID));

            case SqlAuthenticationMethod.ActiveDirectoryServicePrincipal:
                if (string.IsNullOrEmpty(tenantId))
                {
                    // Not a failure: SqlClient never reads a tenant from the connection string. It
                    // uses the STSURL that the server returns in FEDAUTHINFO during login, which is
                    // unavailable before login and therefore cannot be probed here.
                    result.Add(Finding.Info(
                        "SCA0630",
                        DiagnosticLayer.Authentication,
                        "Service principal token acquisition cannot be probed without a tenant.",
                        "SqlClient obtains the tenant from the authority (STSURL) that the server sends in its "
                            + "FEDAUTHINFO login token, so this does not indicate a misconfiguration. "
                            + "The credential is still validated during the login stage.",
                        "To probe token acquisition here as well, set AZURE_TENANT_ID to the tenant that owns the SQL resource."));
                    return null;
                }

                return new ClientSecretCredential(tenantId, builder.UserID, builder.Password);

            case SqlAuthenticationMethod.ActiveDirectoryInteractive:
                return new InteractiveBrowserCredential(
                    new InteractiveBrowserCredentialOptions { TenantId = tenantId });

            case SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow:
                return new DeviceCodeCredential(new DeviceCodeCredentialOptions { TenantId = tenantId });

            case SqlAuthenticationMethod.ActiveDirectoryWorkloadIdentity:
                return new WorkloadIdentityCredential();

            case SqlAuthenticationMethod.ActiveDirectoryIntegrated:
                // SqlClient uses the OS broker here; DefaultAzureCredential is the closest probe.
                return new DefaultAzureCredential(new DefaultAzureCredentialOptions { TenantId = tenantId });

            default:
#pragma warning disable CS0618
                if (auth == SqlAuthenticationMethod.ActiveDirectoryPassword)
                {
                    result.Add(Finding.Warn(
                        "SCA0631",
                        DiagnosticLayer.Authentication,
                        "Token acquisition for 'Active Directory Password' cannot be probed independently.",
                        "The resource-owner password flow is deprecated and unsupported by Azure.Identity.",
                        "Switch to 'Active Directory Default' or 'Active Directory Interactive'."));
                    return null;
                }
#pragma warning restore CS0618

                result.Add(Finding.Info(
                    "SCA0632",
                    DiagnosticLayer.Authentication,
                    $"Authentication method {auth} is validated during the login attempt."));
                return null;
        }
    }

    private static void EvaluateClaims(DiagnosticContext context, StageResult result, TokenClaims claims)
    {
        if (claims.IsExpired)
        {
            result.Add(Finding.Error(
                "SCA0640",
                DiagnosticLayer.Authentication,
                "The acquired token is already expired.",
                $"Expiry: {claims.ExpiresOn:u}. Check for clock skew on this machine.",
                "Synchronize the system clock with a time server."));
        }

        // The audience is compared against the resource for this endpoint's cloud. The previous
        // check accepted any audience containing "database", which passed tokens issued for a
        // different cloud entirely.
        string expectedResource = ResolveScope(context.TargetHost)
            .Replace("https://", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("/.default", string.Empty, StringComparison.OrdinalIgnoreCase);

        if (claims.Audience is { } audience &&
            !audience.Contains(expectedResource, StringComparison.OrdinalIgnoreCase))
        {
            result.Add(Finding.Error(
                "SCA0641",
                DiagnosticLayer.Authentication,
                $"The token audience '{audience}' is not the SQL resource for this endpoint.",
                $"SQL rejects tokens issued for a different resource. Expected an audience for '{expectedResource}'.",
                $"Request the token with the scope '{ResolveScope(context.TargetHost)}'."));
        }

        result.Record("Identity", claims.UniqueName ?? claims.AppId ?? claims.ObjectId);
        result.Record("Tenant", claims.TenantId);
    }

    /// <summary>
    /// SqlClient has no tenant connection-string keyword; the tenant reaches MSAL through the
    /// authority the server returns in FEDAUTHINFO. Only the ambient environment can be consulted
    /// before login, so that is all this reads.
    /// </summary>
    private static string? ExtractTenantId()
    {
        string? fromEnvironment = Environment.GetEnvironmentVariable("AZURE_TENANT_ID");
        return string.IsNullOrWhiteSpace(fromEnvironment) ? null : fromEnvironment;
    }

    private static string[] BuildTokenRemediation(SqlAuthenticationMethod auth) => auth switch
    {
        SqlAuthenticationMethod.ActiveDirectoryManagedIdentity or SqlAuthenticationMethod.ActiveDirectoryMSI =>
        [
            "Confirm the code runs on an Azure resource with a managed identity assigned.",
            "Verify the IMDS endpoint 169.254.169.254 is reachable and not blocked by a proxy.",
            "For a user-assigned identity, set 'User ID' to its client ID."
        ],
        SqlAuthenticationMethod.ActiveDirectoryServicePrincipal =>
        [
            "Verify the application ID and client secret are correct and the secret has not expired.",
            "Confirm the service principal exists in the tenant that owns the SQL resource."
        ],
        SqlAuthenticationMethod.ActiveDirectoryWorkloadIdentity =>
        [
            "Confirm the pod has the federated identity token file and the AZURE_* environment variables projected.",
            "Verify the federated credential subject matches the Kubernetes service account."
        ],
        SqlAuthenticationMethod.ActiveDirectoryInteractive or SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow =>
        [
            "Complete the browser or device-code prompt within the timeout.",
            "Check that conditional access policies permit sign-in from this device and network."
        ],
        _ =>
        [
            "Sign in with 'az login', or configure an explicit credential.",
            "Confirm the tenant and account have access to the SQL resource."
        ]
    };
}
