using System.Net.Sockets;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Tests;

/// <summary>
/// A stage that blows up must still produce a usable diagnosis rather than a stack dump.
/// </summary>
public class StageFaultHandlingTests
{
    private sealed class ThrowingStage(string id, Exception toThrow) : IDiagnosticStage
    {
        public string Id => id;

        public string Title => id;

        public Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken ct) =>
            throw toThrow;
    }

    /// <summary>
    /// Builds a pipeline of just the connection-string stage (which populates the context) plus a
    /// stage that throws. Keeping real network stages out means the test asserts on fault handling
    /// rather than on whether a server happens to be listening.
    /// </summary>
    private static ConnectivityAnalyzer AnalyzerThatThrows(string stageId, Exception ex)
    {
        List<IDiagnosticStage> stages =
        [
            AnalyzerFactory.CreateDefaultStages().First(s => s.Id == "connection-string"),
            new ThrowingStage(stageId, ex)
        ];

        return new ConnectivityAnalyzer(stages);
    }

    private const string LocalConnection =
        "Server=127.0.0.1,14333;User ID=sa;Password=irrelevant;TrustServerCertificate=true";

    [Fact]
    public async Task ASocketFailureIsDiagnosed_NotReportedAsAnUnexpectedException()
    {
        ConnectivityAnalyzer analyzer = AnalyzerThatThrows(
            "tds-prelogin", new SocketException((int)SocketError.ConnectionRefused));

        AnalysisReport report = await analyzer.AnalyzeAsync(LocalConnection);

        Assert.Contains(report.AllFindings, f => f.Code == "SCA0004");
        Assert.DoesNotContain(report.AllFindings, f => f.Code == "SCA0003");
    }

    [Fact]
    public async Task ASocketFailureAfterTcpSucceeded_CallsOutTheChangeInBehaviour()
    {
        ConnectivityAnalyzer analyzer = AnalyzerThatThrows(
            "tds-prelogin", new SocketException((int)SocketError.ConnectionRefused));

        AnalysisReport report = await analyzer.AnalyzeAsync(LocalConnection);

        Finding socket = Assert.Single(report.AllFindings.Where(f => f.Code == "SCA0004"));
        Assert.Contains("refused", socket.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("between the two probes", socket.Detail);
        Assert.NotEmpty(socket.Remediation);
    }

    [Fact]
    public async Task ASocketFailureAtTheTcpStageItself_DoesNotClaimAnEarlierProbeSucceeded()
    {
        ConnectivityAnalyzer analyzer = AnalyzerThatThrows(
            "tcp-reachability", new SocketException((int)SocketError.TimedOut));

        AnalysisReport report = await analyzer.AnalyzeAsync(LocalConnection);

        Finding socket = Assert.Single(report.AllFindings.Where(f => f.Code == "SCA0004"));
        Assert.DoesNotContain("between the two probes", socket.Detail);
    }

    /// <summary>
    /// Stack traces carry build-machine paths that are meaningless to users and would be pasted
    /// into support tickets verbatim.
    /// </summary>
    [Fact]
    public async Task AnUnexpectedExceptionDoesNotLeakAStackTraceIntoTheFinding()
    {
        ConnectivityAnalyzer analyzer = AnalyzerThatThrows(
            "tds-prelogin", new InvalidOperationException("something odd"));

        AnalysisReport report = await analyzer.AnalyzeAsync(LocalConnection);

        Finding generic = Assert.Single(report.AllFindings.Where(f => f.Code == "SCA0003"));
        Assert.Equal("InvalidOperationException: something odd", generic.Detail);
        Assert.DoesNotContain("   at ", generic.Detail);
    }
}
