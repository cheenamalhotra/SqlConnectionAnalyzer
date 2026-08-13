using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SqlConnectionAnalyzer.Core.Probes;

/// <summary>Observations about the local Kerberos credential cache.</summary>
public sealed record KerberosState(
    bool ToolAvailable,
    bool HasCredentialCache,
    IReadOnlyList<string> Principals,
    IReadOnlyList<string> ServiceTickets,
    string? Error)
{
    public static KerberosState Unavailable(string error) =>
        new(false, false, Array.Empty<string>(), Array.Empty<string>(), error);

    /// <summary>True when a ticket-granting ticket is present, which is the prerequisite for any SPN.</summary>
    public bool HasTicketGrantingTicket =>
        ServiceTickets.Any(t => t.StartsWith("krbtgt/", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True when a SQL Server service ticket for the given host is already cached.
    /// Matching ignores the port because a ticket is issued per SPN, and an instance may be
    /// registered with or without one.
    /// </summary>
    public bool HasSqlTicketFor(string host) =>
        ServiceTickets.Any(t =>
            t.StartsWith("MSSQLSvc/", StringComparison.OrdinalIgnoreCase) &&
            t.Contains(host, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True when the cache holds a ticket for any of the SPN forms the driver would accept.
    /// Tickets are often listed as <c>SPN@REALM</c>, so a prefix match is used.
    /// </summary>
    public bool HasTicketForAny(IEnumerable<string> spnCandidates) =>
        spnCandidates.Any(candidate => ServiceTickets.Any(ticket =>
            ticket.StartsWith(candidate, StringComparison.OrdinalIgnoreCase)));
}

/// <summary>
/// Inspects the local Kerberos credential cache so Integrated Security failures can be
/// attributed to a missing TGT or service ticket rather than to SQL Server.
/// <para>
/// Three <c>klist</c> implementations are in circulation and none share an output format:
/// MIT (<c>Default principal:</c> plus a ticket table), Heimdal on macOS
/// (<c>Principal:</c>), and Windows (<c>Client:</c> / <c>Server:</c> pairs). All three are
/// parsed here, because assuming one would silently report "no tickets" on the others.
/// </para>
/// </summary>
public static class KerberosProbe
{
    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Matches the service principal column of an MIT/Heimdal ticket table row.</summary>
    private static readonly Regex ServicePrincipal = new(
        @"(?<spn>[A-Za-z][A-Za-z0-9_.-]*/[^\s@]+(?:@[^\s]+)?)",
        RegexOptions.Compiled);

    /// <summary>
    /// Windows klist prefixes the first line of each cached ticket with its index, as in
    /// "#0>     Client: alice @ CONTOSO.COM", which would otherwise defeat label matching.
    /// </summary>
    private static readonly Regex TicketIndexPrefix = new(@"^#\d+>\s*", RegexOptions.Compiled);

    /// <summary>Builds the SPN SqlClient derives for a TCP connection.</summary>
    public static string BuildSpn(string host, int port) => $"MSSQLSvc/{host.ToLowerInvariant()}:{port}";

    /// <summary>
    /// Reproduces the SPN candidates SqlClient's managed SNI builds. For a default instance over
    /// TCP the driver accepts both the bare <c>MSSQLSvc/fqdn</c> form and <c>MSSQLSvc/fqdn:1433</c>,
    /// because SQL Server registers both at startup and either may be the one that exists in the
    /// directory. Reporting only the port form produces false "no ticket" warnings.
    /// </summary>
    /// <param name="serverSpnOverride">
    /// Value of the 'Server SPN' connection string keyword, which SqlClient uses verbatim and which
    /// suppresses all derivation when set.
    /// </param>
    public static IReadOnlyList<string> BuildSpnCandidates(
        string host,
        int port,
        string? instanceName = null,
        string? serverSpnOverride = null)
    {
        if (!string.IsNullOrWhiteSpace(serverSpnOverride))
        {
            return [serverSpnOverride];
        }

        string fqdn = ResolveFqdn(host);

        if (!string.IsNullOrWhiteSpace(instanceName))
        {
            // TCP uses the port; named pipes use the instance name. Both are registered, so both
            // are offered rather than guessing the protocol.
            return [$"MSSQLSvc/{fqdn}:{port}", $"MSSQLSvc/{fqdn}:{instanceName}"];
        }

        return port == DefaultSqlServerPort
            ? [$"MSSQLSvc/{fqdn}", $"MSSQLSvc/{fqdn}:{port}"]
            : [$"MSSQLSvc/{fqdn}:{port}"];
    }

    /// <summary>
    /// SqlClient builds the SPN from the DNS-resolved canonical name, falling back to the supplied
    /// host when resolution fails. A short name that resolves to a different FQDN would otherwise
    /// yield an SPN that never matches a cached ticket.
    /// </summary>
    internal static string ResolveFqdn(string host)
    {
        try
        {
            return System.Net.Dns.GetHostEntry(host).HostName;
        }
        catch (System.Net.Sockets.SocketException)
        {
            return host;
        }
        catch (ArgumentException)
        {
            return host;
        }
    }

    private const int DefaultSqlServerPort = 1433;

    /// <summary>True when the platform can use Windows Integrated authentication natively.</summary>
    public static bool SupportsIntegratedSecurity() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    public static async Task<KerberosState> InspectAsync(CancellationToken cancellationToken)
    {
        // Windows klist needs no arguments; MIT and Heimdal list the default cache the same way.
        return await RunKlistAsync("klist", string.Empty, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<KerberosState> RunKlistAsync(
        string fileName,
        string arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        Process? process = null;

        try
        {
            process = Process.Start(startInfo);
            if (process is null)
            {
                return KerberosState.Unavailable("klist could not be started.");
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(ToolTimeout);

            Task<string> stdout = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            Task<string> stderr = process.StandardError.ReadToEndAsync(timeoutCts.Token);

            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);

            // Heimdal reports a missing cache on stderr, so both streams matter.
            string output = await stdout.ConfigureAwait(false) + "\n" + await stderr.ConfigureAwait(false);

            return ParseKlist(output, process.ExitCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            return KerberosState.Unavailable("klist did not complete within the probe timeout.");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or FileNotFoundException)
        {
            return KerberosState.Unavailable(
                "The 'klist' tool is not installed, so the Kerberos cache could not be inspected.");
        }
        finally
        {
            process?.Dispose();
        }
    }

    /// <summary>Parses MIT, Heimdal, and Windows klist output into a single shape.</summary>
    internal static KerberosState ParseKlist(string output, int exitCode)
    {
        var principals = new List<string>();
        var tickets = new List<string>();
        bool sawNoCacheMessage = false;

        foreach (string rawLine in output.Split('\n'))
        {
            string line = TicketIndexPrefix.Replace(rawLine.Trim(), string.Empty);
            if (line.Length == 0)
            {
                continue;
            }

            if (IsNoCacheMessage(line))
            {
                sawNoCacheMessage = true;
                continue;
            }

            if (TryReadLabel(line, "Default principal:", out string? mit))
            {
                AddDistinct(principals, mit);
            }
            else if (TryReadLabel(line, "Principal:", out string? heimdal))
            {
                AddDistinct(principals, heimdal);
            }
            else if (TryReadLabel(line, "Client:", out string? windowsClient))
            {
                // Windows renders "alice @ CONTOSO.COM"; normalise to alice@CONTOSO.COM.
                AddDistinct(principals, NormalisePrincipal(windowsClient));
            }
            else if (TryReadLabel(line, "Server:", out string? windowsServer))
            {
                AddDistinct(tickets, NormalisePrincipal(windowsServer));
            }
            else if (LooksLikeTicketTableRow(line))
            {
                Match match = ServicePrincipal.Match(line);
                if (match.Success)
                {
                    AddDistinct(tickets, match.Groups["spn"].Value);
                }
            }
        }

        bool hasCache = !sawNoCacheMessage && (principals.Count > 0 || tickets.Count > 0);

        string? error = hasCache
            ? null
            : sawNoCacheMessage || exitCode != 0
                ? "No Kerberos credential cache was found. Run 'kinit' to obtain a ticket-granting ticket."
                : "The Kerberos cache could not be interpreted from the klist output.";

        return new KerberosState(true, hasCache, principals, tickets, error);
    }

    /// <summary>
    /// A ticket table row contains a service principal in <c>service/host@REALM</c> form.
    /// Header rows are excluded so the column caption is not mistaken for a ticket.
    /// </summary>
    private static bool LooksLikeTicketTableRow(string line) =>
        line.Contains('/', StringComparison.Ordinal) &&
        !line.StartsWith("Service principal", StringComparison.OrdinalIgnoreCase) &&
        !line.StartsWith("Ticket cache:", StringComparison.OrdinalIgnoreCase) &&
        !line.StartsWith("Credentials cache:", StringComparison.OrdinalIgnoreCase) &&
        !line.StartsWith("Ticket Flags", StringComparison.OrdinalIgnoreCase) &&
        !line.StartsWith("Cached Tickets", StringComparison.OrdinalIgnoreCase);

    private static bool IsNoCacheMessage(string line) =>
        line.Contains("No credentials cache", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("Cache not found", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("not found in keytab", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("Credentials cache file", StringComparison.OrdinalIgnoreCase) &&
            line.Contains("not found", StringComparison.OrdinalIgnoreCase);

    private static bool TryReadLabel(string line, string label, out string? value)
    {
        if (line.StartsWith(label, StringComparison.OrdinalIgnoreCase))
        {
            value = line[label.Length..].Trim();
            return value.Length > 0;
        }

        value = null;
        return false;
    }

    private static string NormalisePrincipal(string? value) =>
        (value ?? string.Empty).Replace(" @ ", "@", StringComparison.Ordinal).Trim();

    private static void AddDistinct(List<string> target, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value) && !target.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            target.Add(value);
        }
    }

    private static void TryKill(Process? process)
    {
        try
        {
            if (process is { HasExited: false })
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            // The process already exited; nothing to clean up.
        }
    }
}
