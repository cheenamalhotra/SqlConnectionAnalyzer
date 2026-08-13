using System.Net;
using System.Net.Sockets;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 1. Resolves the server name to IP addresses and, for named instances,
/// asks the SQL Browser for the instance's TCP port.
/// </summary>
public sealed class NameResolutionStage : IDiagnosticStage
{
    public string Id => "name-resolution";

    public string Title => "Name resolution";

    public bool AppliesTo(DiagnosticContext context) =>
        context.EndpointKind != EndpointKind.LocalDb && context.Protocol != NetworkProtocol.SharedMemory;

    public async Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        string host = NormalizeLocalHost(context.Host);
        result.Record("Query name", host);

        if (IPAddress.TryParse(host, out IPAddress? literal))
        {
            context.ResolvedAddresses.Add(literal);
            result.Record("Resolution", "Literal IP address, DNS not used");
            result.Add(Finding.Info(
                "SCA0200",
                DiagnosticLayer.NameResolution,
                $"Server specified as a literal {(literal.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")} address.",
                "Certificate validation will require the address to appear in the certificate SAN."));
        }
        else
        {
            if (!await ResolveDnsAsync(host, context, result, cancellationToken).ConfigureAwait(false))
            {
                return;
            }
        }

        result.Record("Addresses", string.Join(", ", context.ResolvedAddresses.Select(a => a.ToString())));

        if (context.ResolvedAddresses.Count > 1)
        {
            bool multiSubnet = context.Builder.MultiSubnetFailover;
            result.Add(Finding.Info(
                "SCA0203",
                DiagnosticLayer.NameResolution,
                $"The name resolves to {context.ResolvedAddresses.Count} addresses.",
                multiSubnet
                    ? "MultiSubnetFailover=true, so addresses are tried in parallel."
                    : "Without MultiSubnetFailover the client tries addresses serially, which slows failover."));

            if (!multiSubnet)
            {
                result.Add(Finding.Warn(
                    "SCA0204",
                    DiagnosticLayer.NameResolution,
                    "Multiple addresses resolved but 'MultiSubnetFailover' is not enabled.",
                    "For an availability group listener this can cause long connect times after failover.",
                    "Add 'MultiSubnetFailover=true' when connecting to an AG listener or a multi-subnet FCI."));
            }
        }

        await ResolveInstanceAsync(context, result, cancellationToken).ConfigureAwait(false);
    }

    private static string NormalizeLocalHost(string host) =>
        host is "." or "(local)" or "" ? "localhost" : host;

    private static async Task<bool> ResolveDnsAsync(
        string host,
        DiagnosticContext context,
        StageResult result,
        CancellationToken cancellationToken)
    {
        try
        {
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            if (addresses.Length == 0)
            {
                result.Add(Finding.Error(
                    "SCA0201",
                    DiagnosticLayer.NameResolution,
                    $"'{host}' resolved to zero addresses.",
                    null,
                    "Verify the DNS record exists and the client uses the expected DNS server."));
                result.IsFatal = true;
                return false;
            }

            context.ResolvedAddresses.AddRange(addresses);
            return true;
        }
        catch (SocketException ex)
        {
            result.Add(Finding.Error(
                "SCA0202",
                DiagnosticLayer.NameResolution,
                $"DNS resolution of '{host}' failed: {ex.SocketErrorCode}.",
                ex.Message,
                "Check the spelling of the server name.",
                "Verify the client can reach its DNS server, and that any required search domain or VPN is active.",
                context.EndpointKind == EndpointKind.AzureSqlDatabase
                    ? "For Azure SQL with Private Link, confirm the private DNS zone 'privatelink.database.windows.net' is linked to this VNet."
                    : "For a domain-joined server, confirm the machine is on the corporate network."));
            result.IsFatal = true;
            return false;
        }
    }

    private static async Task ResolveInstanceAsync(
        DiagnosticContext context,
        StageResult result,
        CancellationToken cancellationToken)
    {
        if (context.InstanceName is null)
        {
            return;
        }

        ServerSpec spec = ServerNameParser.Parse(context.Builder.DataSource);
        if (spec.Port is not null)
        {
            result.Record("Browser lookup", "Skipped, explicit port supplied");
            return;
        }

        IPAddress address = context.ResolvedAddresses[0];
        result.Record("Browser lookup", $"UDP {address}:{ServerNameParser.BrowserPort} for instance '{context.InstanceName}'");

        try
        {
            IReadOnlyList<BrowserInstanceInfo> instances = await SqlBrowserProbe
                .QueryAsync(address, context.InstanceName, TimeSpan.FromSeconds(3), cancellationToken)
                .ConfigureAwait(false);

            BrowserInstanceInfo? match = instances.FirstOrDefault(i =>
                string.Equals(i.InstanceName, context.InstanceName, StringComparison.OrdinalIgnoreCase));

            if (match is null)
            {
                result.Add(Finding.Error(
                    "SCA0210",
                    DiagnosticLayer.NameResolution,
                    $"The SQL Browser did not return instance '{context.InstanceName}'.",
                    instances.Count == 0
                        ? "No response was received on UDP 1434 (SQL Server error 26)."
                        : $"Instances reported: {string.Join(", ", instances.Select(i => i.InstanceName))}.",
                    "Confirm the SQL Server Browser service is running on the host.",
                    "Open UDP port 1434 in the firewall between client and server.",
                    "Or bypass the Browser entirely by connecting with an explicit port: 'Server=host,port'."));
                result.IsFatal = true;
                return;
            }

            if (match.TcpPort is null)
            {
                result.Add(Finding.Error(
                    "SCA0211",
                    DiagnosticLayer.NameResolution,
                    $"Instance '{match.InstanceName}' is not listening on TCP/IP.",
                    match.RawRecord,
                    "Enable the TCP/IP protocol for the instance in SQL Server Configuration Manager and restart it."));
                result.IsFatal = true;
                return;
            }

            context.Port = match.TcpPort.Value;
            result.Record("Resolved port", match.TcpPort.Value.ToString());
            result.Record("Server version", match.Version);
            result.Record("Clustered", match.IsClustered.ToString());
            result.Add(Finding.Info(
                "SCA0212",
                DiagnosticLayer.NameResolution,
                $"Instance '{match.InstanceName}' listens on TCP port {match.TcpPort}.",
                match.RawRecord));
        }
        catch (SocketException ex)
        {
            result.Add(Finding.Error(
                "SCA0213",
                DiagnosticLayer.NameResolution,
                $"The SQL Browser query failed: {ex.SocketErrorCode}.",
                ex.Message,
                "Open UDP port 1434, or specify the instance port directly as 'Server=host,port'."));
            result.IsFatal = true;
        }
    }
}
