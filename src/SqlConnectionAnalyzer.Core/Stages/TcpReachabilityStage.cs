using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 2. Opens a raw TCP connection to every resolved address so transport failures
/// are separated from TDS, TLS, and authentication failures.
/// </summary>
public sealed class TcpReachabilityStage : IDiagnosticStage
{
    public string Id => "tcp-reachability";

    public string Title => "TCP reachability";

    public bool AppliesTo(DiagnosticContext context) =>
        context.Protocol == NetworkProtocol.Tcp && context.ResolvedAddresses.Count > 0;

    public async Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        int port = context.TargetPort;
        result.Record("Target port", port.ToString());

        var reachable = new List<IPAddress>();

        foreach (IPAddress address in context.ResolvedAddresses)
        {
            (bool ok, TimeSpan elapsed, string? error) =
                await TryConnectAsync(address, port, cancellationToken).ConfigureAwait(false);

            string label = $"{address}:{port}";
            if (ok)
            {
                reachable.Add(address);
                result.Record(label, $"connected in {elapsed.TotalMilliseconds:0} ms");
            }
            else
            {
                result.Record(label, $"failed after {elapsed.TotalMilliseconds:0} ms - {error}");
            }
        }

        if (reachable.Count == 0)
        {
            result.Add(BuildUnreachableFinding(context, port));
            result.IsFatal = true;
            return;
        }

        // Prefer a reachable address for the remaining stages.
        context.ResolvedAddresses.Clear();
        context.ResolvedAddresses.AddRange(reachable);

        if (context.EndpointKind == EndpointKind.AzureSqlDatabase && port == 1433)
        {
            result.Add(Finding.Info(
                "SCA0305",
                DiagnosticLayer.Transport,
                "Azure SQL Database may use the Redirect connection policy.",
                "Redirect requires outbound access to ports 11000-11999 in addition to 1433. The routing stage verifies this."));
        }
    }

    private static async Task<(bool Ok, TimeSpan Elapsed, string? Error)> TryConnectAsync(
        IPAddress address,
        int port,
        CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken).ConfigureAwait(false);
            sw.Stop();
            return (true, sw.Elapsed, null);
        }
        catch (SocketException ex)
        {
            sw.Stop();
            return (false, sw.Elapsed, ex.SocketErrorCode.ToString());
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return (false, sw.Elapsed, "timed out");
        }
    }

    private static Finding BuildUnreachableFinding(DiagnosticContext context, int port)
    {
        var steps = new List<string>();

        if (context.EndpointKind is EndpointKind.AzureSqlDatabase or EndpointKind.AzureSynapse)
        {
            steps.Add("Add the client's public IP to the server firewall rules, or enable 'Allow Azure services'.");
            steps.Add("If using Private Link, verify the private endpoint and its DNS record resolve to the VNet address.");
            steps.Add("Confirm outbound TCP 1433 is not blocked by the local network or ISP.");
        }
        else if (context.EndpointKind == EndpointKind.AzureSqlManagedInstance)
        {
            steps.Add("Managed Instance is only reachable from inside its VNet, a peered VNet, or over VPN/ExpressRoute.");
            steps.Add("Check the subnet NSG allows inbound 1433 (private endpoint) or 3342 (public endpoint).");
        }
        else
        {
            steps.Add($"Verify SQL Server is running and listening on TCP port {port}.");
            steps.Add("Enable the TCP/IP protocol in SQL Server Configuration Manager and restart the service.");
            steps.Add($"Open TCP port {port} in the Windows Firewall or any network firewall in the path.");
            steps.Add("Rule out a proxy or VPN silently dropping the connection.");
        }

        return Finding.Error(
            "SCA0300",
            DiagnosticLayer.Transport,
            $"No resolved address accepted a TCP connection on port {port}.",
            "The failure is at the transport layer, before any TDS packet is exchanged.",
            steps.ToArray());
    }
}
