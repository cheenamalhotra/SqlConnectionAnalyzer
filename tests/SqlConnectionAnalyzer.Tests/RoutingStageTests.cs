using System.Net;
using System.Net.Sockets;
using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Probes;
using SqlConnectionAnalyzer.Core.Stages;

namespace SqlConnectionAnalyzer.Tests;

public class RoutingStageTests
{
    /// <summary>
    /// The entire Azure Redirect diagnosis depends on telling a refusal apart from silence,
    /// so both halves are exercised against a real socket rather than mocked.
    /// </summary>
    [Fact]
    public async Task AListeningPortIsReportedAsOpen()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            PortReachability result = await PortScanner.ProbeAsync(
                IPAddress.Loopback, port, TimeSpan.FromSeconds(3), CancellationToken.None);

            Assert.Equal(PortReachability.Open, result);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task AClosedLoopbackPortIsRefusedRatherThanFiltered()
    {
        // Bind and immediately release, so the port is almost certainly unused.
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        PortReachability result = await PortScanner.ProbeAsync(
            IPAddress.Loopback, port, TimeSpan.FromSeconds(3), CancellationToken.None);

        Assert.Equal(PortReachability.Refused, result);
    }

    [Fact]
    public async Task AnUnroutableAddressTimesOutAndIsReportedAsFiltered()
    {
        // TEST-NET-1 is reserved for documentation and is not routable.
        PortReachability result = await PortScanner.ProbeAsync(
            IPAddress.Parse("192.0.2.1"), 11000, TimeSpan.FromMilliseconds(750), CancellationToken.None);

        Assert.Equal(PortReachability.Filtered, result);
    }

    [Fact]
    public async Task MultipleAddressesWithoutMultiSubnetFailoverAreFlagged()
    {
        StageResult result = await RunRoutingAsync(
            "Server=ag-listener;Database=db",
            EndpointKind.OnPremises,
            [IPAddress.Parse("10.0.0.1"), IPAddress.Parse("10.1.0.1")]);

        Assert.Contains(result.Findings, f => f.Code == "SCA0912");
    }

    [Fact]
    public async Task MultiSubnetFailoverSuppressesTheWarning()
    {
        StageResult result = await RunRoutingAsync(
            "Server=ag-listener;Database=db;MultiSubnetFailover=true",
            EndpointKind.OnPremises,
            [IPAddress.Parse("10.0.0.1"), IPAddress.Parse("10.1.0.1")]);

        Assert.DoesNotContain(result.Findings, f => f.Code == "SCA0912");
        Assert.Contains(result.Findings, f => f.Code == "SCA0911");
    }

    [Fact]
    public async Task ReadOnlyIntentExplainsReadOnlyRouting()
    {
        StageResult result = await RunRoutingAsync(
            "Server=ag-listener;Database=db;ApplicationIntent=ReadOnly",
            EndpointKind.OnPremises,
            [IPAddress.Parse("10.0.0.1")]);

        Assert.Contains(result.Findings, f => f.Code == "SCA0910");
    }

    [Fact]
    public async Task NonAzureEndpointsSkipTheRedirectRangeProbe()    {
        StageResult result = await RunRoutingAsync(
            "Server=sql01;Database=db",
            EndpointKind.OnPremises,
            [IPAddress.Loopback]);

        Assert.Contains("skipped", result.Evidence["Redirect range probe"], StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Loopback refuses the redirect ports rather than dropping them, which is exactly the
    /// signal that proves the range is reachable and Redirect policy could work.
    /// </summary>
    [Fact]
    public async Task RefusedRedirectPortsProveTheRangeIsNotFiltered()
    {
        StageResult result = await RunRoutingAsync(
            "Server=example.database.windows.net;Database=db",
            EndpointKind.AzureSqlDatabase,
            [IPAddress.Loopback]);

        Assert.Contains(result.Findings, f => f.Code == "SCA0900");
        Assert.DoesNotContain(result.Findings, f => f.Code == "SCA0901");
        Assert.Contains("refused", result.Evidence["Port 11000"], StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<StageResult> RunRoutingAsync(        string connectionString,
        EndpointKind kind,
        IPAddress[] addresses)
    {
        var context = new DiagnosticContext
        {
            ConnectionString = connectionString,
            Builder = new SqlConnectionStringBuilder(connectionString),
            Options = new AnalyzerOptions()
        };

        context.EndpointKind = kind;
        context.ResolvedAddresses.AddRange(addresses);

        var result = StageResult.Start("routing", "Routing and redirection");
        await new RoutingStage().RunAsync(context, result, CancellationToken.None);
        return result;
    }
}
