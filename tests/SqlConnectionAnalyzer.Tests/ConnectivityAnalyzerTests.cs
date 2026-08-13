using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Tests;

public class ConnectivityAnalyzerTests
{
    /// <summary>
    /// The matrix gate matches stages by id, so a rename would silently disable it.
    /// This pins the ids the gate depends on.
    /// </summary>
    [Theory]
    [InlineData("connection-string")]
    [InlineData("name-resolution")]
    [InlineData("tcp-reachability")]
    [InlineData("tds-prelogin")]
    [InlineData("tls-handshake")]
    [InlineData("routing")]
    [InlineData("credentials")]
    [InlineData("login")]
    [InlineData("resiliency")]
    public void DefaultPipelineContainsTheExpectedStageId(string stageId)
    {
        IReadOnlyList<IDiagnosticStage> stages = AnalyzerFactory.CreateDefaultStages();

        Assert.Contains(stages, s => s.Id == stageId);
    }

    [Fact]
    public void StagesRunInTdsLoginFlowOrder()
    {
        string[] ids = AnalyzerFactory.CreateDefaultStages().Select(s => s.Id).ToArray();

        Assert.Equal(
            [
                "connection-string", "name-resolution", "tcp-reachability", "tds-prelogin",
                "tls-handshake", "routing", "credentials", "login", "resiliency"
            ],
            ids);
    }

    [Fact]
    public async Task AnUnparsableConnectionStringFailsImmediately()
    {
        ConnectivityAnalyzer analyzer = AnalyzerFactory.Create();

        AnalysisReport report = await analyzer.AnalyzeAsync("Server=x;Bogus Keyword=1");

        Assert.False(report.Succeeded);
        Assert.Contains(report.AllFindings, f => f.Code == "SCA0001");
    }

    /// <summary>
    /// A transport failure must not trigger four doomed encryption attempts, each costing a
    /// full connect timeout.
    /// </summary>
    [Fact]
    public async Task MatrixIsSkippedWhenFailureIsBelowTheEncryptionLayer()
    {
        ConnectivityAnalyzer analyzer = AnalyzerFactory.Create();

        var options = new AnalyzerOptions
        {
            MatrixMode = true,
            ProbeTimeout = TimeSpan.FromSeconds(3)
        };

        AnalysisReport report = await analyzer.AnalyzeAsync(
            "Server=no-such-host.invalid;Database=db;User ID=u;Password=p;Connect Timeout=3",
            options);

        Assert.False(report.Succeeded);
        Assert.Empty(report.MatrixOutcomes);
        Assert.Equal("SCA1005", report.MatrixVerdict?.Code);
    }
}
