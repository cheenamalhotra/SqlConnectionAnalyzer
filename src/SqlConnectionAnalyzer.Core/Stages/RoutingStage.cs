using System.Net;
using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 5. Verifies the paths a connection can be redirected onto after Pre-Login:
/// the Azure SQL gateway Redirect policy (ports 11000-11999) and availability group
/// read-write / read-only routing.
/// <para>
/// This stage exists because a Redirect-policy failure is invisible at stage 2: TCP 1433
/// connects to the gateway perfectly, Pre-Login and TLS both succeed, and the connection
/// only dies later when the client is told to reconnect to a node port that the local
/// firewall blocks. Probing the range up front turns that late, confusing timeout into an
/// explicit finding.
/// </para>
/// </summary>
public sealed class RoutingStage : IDiagnosticStage
{
    /// <summary>Ports sampled from the 11000-11999 Azure redirect range.</summary>
    private static readonly int[] RedirectSamplePorts = [11000, 11055, 11999];

    private static readonly TimeSpan PortProbeTimeout = TimeSpan.FromSeconds(4);

    public string Id => "routing";

    public string Title => "Routing and redirection";

    public bool AppliesTo(DiagnosticContext context) =>
        context.Protocol == NetworkProtocol.Tcp && context.ResolvedAddresses.Count > 0;

    public async Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        bool isAzureGateway = context.EndpointKind is EndpointKind.AzureSqlDatabase or EndpointKind.AzureSynapse;

        if (isAzureGateway)
        {
            await ProbeRedirectRangeAsync(context, result, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            result.Record("Redirect range probe", "skipped - not an Azure SQL gateway endpoint");
        }

        InspectAvailabilityGroupRouting(context, result);
    }

    /// <summary>
    /// Samples the redirect port range. A refusal is good news: the packet reached the host,
    /// so the range is not filtered. Silence across every sample is the firewall signature.
    /// </summary>
    private static async Task ProbeRedirectRangeAsync(
        DiagnosticContext context,
        StageResult result,
        CancellationToken cancellationToken)
    {
        IPAddress address = context.ResolvedAddresses[0];
        result.Record("Redirect probe target", address.ToString());

        IReadOnlyDictionary<int, PortReachability> probes = await PortScanner
            .ProbeManyAsync(address, RedirectSamplePorts, PortProbeTimeout, cancellationToken)
            .ConfigureAwait(false);

        foreach ((int port, PortReachability reachability) in probes)
        {
            result.Record($"Port {port}", Describe(reachability));
        }

        bool anyReached = probes.Values.Any(r => r is PortReachability.Open or PortReachability.Refused);

        if (anyReached)
        {
            result.Add(Finding.Info(
                "SCA0900",
                DiagnosticLayer.Routing,
                "Outbound traffic to the 11000-11999 redirect range is not being filtered.",
                "At least one sampled port answered, so the Redirect connection policy can complete."));
            return;
        }

        result.Add(Finding.Warn(
            "SCA0901",
            DiagnosticLayer.Routing,
            "Every sampled port in the 11000-11999 redirect range timed out.",
            "TCP 1433 reaches the gateway, but nothing in the redirect range responds. If this server "
                + "uses the Redirect connection policy, the login will be told to reconnect to a node "
                + "port that the network drops, producing a timeout that looks like a login failure.",
            "Allow outbound TCP 11000-11999 to the SQL service tag in the client firewall or NSG.",
            "Alternatively set the server's connection policy to Proxy, which keeps all traffic on 1433 at the cost of latency.",
            "Connections from inside Azure default to Redirect, so this matters most for VM and container clients."));
    }

    private static void InspectAvailabilityGroupRouting(DiagnosticContext context, StageResult result)
    {
        SqlConnectionStringBuilder builder = context.Builder;
        bool readOnlyIntent = builder.ApplicationIntent == ApplicationIntent.ReadOnly;
        bool multiSubnet = builder.MultiSubnetFailover;

        result.Record("Application intent", builder.ApplicationIntent.ToString());
        result.Record("MultiSubnetFailover", multiSubnet ? "true" : "false");

        if (readOnlyIntent)
        {
            result.Add(Finding.Info(
                "SCA0910",
                DiagnosticLayer.Routing,
                "ApplicationIntent=ReadOnly requests read-only routing.",
                "The listener will hand the connection to a readable secondary. If the routing list is "
                    + "misconfigured the connection silently lands on the primary instead, which is a "
                    + "correctness problem rather than a connectivity one.",
                "Confirm READ_ONLY_ROUTING_LIST and READ_ONLY_ROUTING_URL are set on every replica.",
                "Verify the target is connected to the availability group listener, not a node name."));
        }

        if (multiSubnet)
        {
            result.Add(Finding.Info(
                "SCA0911",
                DiagnosticLayer.Routing,
                "MultiSubnetFailover=true is set, so all listener IPs are attempted in parallel.",
                "This is the correct setting for a multi-subnet availability group and avoids the "
                    + "serial DNS-order timeout."));
        }
        else if (context.ResolvedAddresses.Count > 1 && context.EndpointKind == EndpointKind.OnPremises)
        {
            result.Add(Finding.Warn(
                "SCA0912",
                DiagnosticLayer.Routing,
                $"The host resolves to {context.ResolvedAddresses.Count} addresses but MultiSubnetFailover is false.",
                "If this is a multi-subnet availability group listener, the client tries each address in "
                    + "sequence and can exhaust the connect timeout on a dead subnet before reaching the live one.",
                "Set MultiSubnetFailover=true when connecting to an availability group listener."));
        }
    }

    private static string Describe(PortReachability reachability) => reachability switch
    {
        PortReachability.Open => "open - a listener answered",
        PortReachability.Refused => "refused - reachable but closed, so the range is not filtered",
        _ => "no response - consistent with a firewall dropping packets"
    };
}
