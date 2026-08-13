using System.Data;
using System.Security.Authentication;
using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 7. Performs the real login through Microsoft.Data.SqlClient. Every earlier stage
/// has already proven its layer works, so any failure here is attributable to LOGIN7
/// processing: credentials, permissions, or database access.
/// </summary>
public sealed class LoginStage : IDiagnosticStage
{
    public string Id => "login";

    public string Title => "LOGIN7 and authentication";

    public bool AppliesTo(DiagnosticContext context) => context.Options.AttemptLogin;

    public async Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        var builder = new SqlConnectionStringBuilder(context.ConnectionString)
        {
            // Pooling would hide a real handshake behind a cached connection.
            Pooling = false
        };

        await using var connection = new SqlConnection(builder.ConnectionString);

        // A pre-acquired token proves the Entra failure, if any, was in token acquisition.
        if (context.AccessToken is { } token && RequiresExplicitToken(builder))
        {
            connection.AccessToken = token;
        }

        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

            context.LoginSucceeded = true;

            result.Record("Server version", connection.ServerVersion);
            result.Record("Workstation ID", connection.WorkstationId);
            result.Record("Client connection ID", connection.ClientConnectionId.ToString());
            result.Record("Database", connection.Database);

            result.Add(Finding.Info(
                "SCA0700",
                DiagnosticLayer.Authentication,
                "The login succeeded and a session was established.",
                $"Connected to {connection.DataSource} as of server version {connection.ServerVersion}."));

            await CaptureSessionDetailsAsync(connection, result, cancellationToken).ConfigureAwait(false);
        }
        catch (SqlException ex)
        {
            result.Record("Client connection ID", ex.ClientConnectionId.ToString());

            foreach (SqlError error in ex.Errors)
            {
                result.Add(SqlErrorClassifier.Classify(error, DiagnosticLayer.Authentication));
            }

            if (ex.Errors.Count == 0)
            {
                result.Add(Finding.Error(
                    "SCA0701",
                    DiagnosticLayer.Authentication,
                    "The login attempt failed.",
                    ex.Message));
            }

            RecordInnerCause(ex, result);

            result.IsFatal = true;
        }
        catch (InvalidOperationException ex)
        {
            result.Add(Finding.Error(
                "SCA0702",
                DiagnosticLayer.Configuration,
                "The connection could not be opened because of a client-side configuration conflict.",
                ex.Message,
                "Review the combination of Authentication, AccessToken, and Credential settings."));
            result.IsFatal = true;
        }
    }

    /// <summary>
    /// Only supply the token when the connection string does not already drive its own
    /// token acquisition; otherwise SqlClient rejects the combination.
    /// </summary>
    private static bool RequiresExplicitToken(SqlConnectionStringBuilder builder) =>
        builder.Authentication == SqlAuthenticationMethod.NotSpecified &&
        !builder.IntegratedSecurity &&
        string.IsNullOrEmpty(builder.UserID);

    /// <summary>
    /// Surfaces the inner exception behind a <see cref="SqlException"/>.
    /// <para>
    /// SqlClient reports a failed TLS negotiation as "An internal exception was caught"
    /// with provider error 35 and buries the real reason — an expired certificate, an
    /// untrusted root, a name mismatch — in the inner exception. Reporting only the outer
    /// error tells the user nothing they can act on.
    /// </para>
    /// </summary>
    internal static void RecordInnerCause(Exception exception, StageResult result)
    {
        var chain = new List<Exception>();

        for (Exception? inner = exception.InnerException; inner is not null; inner = inner.InnerException)
        {
            chain.Add(inner);
        }

        if (chain.Count == 0)
        {
            return;
        }

        result.Record("Underlying exception", string.Join(" -> ", chain.Select(e => e.GetType().Name)));

        if (chain.OfType<AuthenticationException>().FirstOrDefault() is { } authentication)
        {
            string detail = Flatten(authentication.Message);

            // Always keep the verbatim reason, which names the exact defect.
            result.Record("TLS failure detail", detail);

            // Only escalate to a finding when the error number was not already recognised as a
            // TLS fault; otherwise the stage would report the same root cause twice.
            if (!result.Findings.Any(f => f.Layer == DiagnosticLayer.Tls))
            {
                result.Add(Finding.Error(
                    "SCA0703",
                    DiagnosticLayer.Tls,
                    "The TLS handshake failed during the pre-login exchange.",
                    detail,
                    "The TCP connection was accepted, so this is a certificate problem rather than a credential problem.",
                    "See the TLS handshake stage above, which probes the certificate directly and names the specific defect."));
            }

            return;
        }

        result.Record("Underlying cause", Flatten(chain[^1].Message));
    }

    /// <summary>Collapses embedded newlines so a multi-line message stays readable in a report.</summary>
    private static string Flatten(string message) => Redactor.FreeText(
        string.Join(" ", message.Split('\n', '\r').Select(l => l.Trim()).Where(l => l.Length > 0)));

    private static async Task CaptureSessionDetailsAsync(
        SqlConnection connection,
        StageResult result,
        CancellationToken cancellationToken)
    {
        const string query = """
            SELECT
                SUSER_SNAME()                       AS LoginName,
                USER_NAME()                         AS DatabaseUser,
                DB_NAME()                           AS CurrentDatabase,
                @@VERSION                           AS ServerVersion,
                CONVERT(nvarchar(128), SERVERPROPERTY('Edition'))  AS Edition,
                ISNULL(CONVERT(nvarchar(64), ENCRYPT_OPTION), '')  AS EncryptOption,
                ISNULL(CONVERT(nvarchar(64), auth_scheme), '')     AS AuthScheme,
                ISNULL(CONVERT(nvarchar(64), protocol_type), '')   AS ProtocolType
            FROM sys.dm_exec_connections
            WHERE session_id = @@SPID;
            """;

        try
        {
            await using var command = new SqlCommand(query, connection) { CommandTimeout = 10 };
            await using SqlDataReader reader = await command
                .ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken)
                .ConfigureAwait(false);

            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            string authScheme = reader["AuthScheme"]?.ToString() ?? string.Empty;
            string encryptOption = reader["EncryptOption"]?.ToString() ?? string.Empty;

            result.Record("Login name", reader["LoginName"]?.ToString());
            result.Record("Database user", reader["DatabaseUser"]?.ToString());
            result.Record("Current database", reader["CurrentDatabase"]?.ToString());
            result.Record("Edition", reader["Edition"]?.ToString());
            result.Record("Authentication scheme", authScheme);
            result.Record("Session encrypted", encryptOption);

            if (authScheme.Equals("NTLM", StringComparison.OrdinalIgnoreCase))
            {
                result.Add(Finding.Warn(
                    "SCA0710",
                    DiagnosticLayer.Authentication,
                    "The session authenticated with NTLM rather than Kerberos.",
                    "SqlClient fell back to NTLM, which blocks delegation and double-hop scenarios.",
                    "Register the MSSQLSvc SPN for the SQL Server service account so Kerberos can be used."));
            }
            else if (authScheme.Equals("KERBEROS", StringComparison.OrdinalIgnoreCase))
            {
                result.Add(Finding.Info(
                    "SCA0711",
                    DiagnosticLayer.Authentication,
                    "The session authenticated with Kerberos, so the SPN is correctly registered."));
            }

            if (encryptOption.Equals("FALSE", StringComparison.OrdinalIgnoreCase))
            {
                result.Add(Finding.Warn(
                    "SCA0712",
                    DiagnosticLayer.Tls,
                    "The established session is not encrypted.",
                    "sys.dm_exec_connections reports encrypt_option = FALSE.",
                    "Set 'Encrypt=Mandatory' and ensure the server has a usable certificate."));
            }
        }
        catch (SqlException ex)
        {
            result.Add(Finding.Info(
                "SCA0713",
                DiagnosticLayer.Authorization,
                "Connected successfully, but the session detail query was not permitted.",
                $"{ex.Message} This usually means the login lacks VIEW SERVER STATE."));
        }
    }
}
