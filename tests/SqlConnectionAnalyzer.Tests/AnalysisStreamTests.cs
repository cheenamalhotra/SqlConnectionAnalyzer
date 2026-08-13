using Microsoft.Extensions.DependencyInjection;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Tests;

public class AnalysisStreamTests
{
    /// <summary>An unreachable port keeps every test below fast and offline.</summary>
    private const string DeadEndpoint =
        "Server=127.0.0.1,9;User ID=sa;Password=p;TrustServerCertificate=true;Connect Timeout=1";

    private static AnalyzerOptions FastOptions => new() { ProbeTimeout = TimeSpan.FromSeconds(2) };

    [Fact]
    public async Task StreamEndsWithExactlyOneFinishedItem()
    {
        ConnectivityAnalyzer analyzer = AnalyzerFactory.Create();

        List<AnalysisProgress> items = await Collect(analyzer, DeadEndpoint);

        Assert.Single(items.OfType<AnalysisProgress.Finished>());
        Assert.IsType<AnalysisProgress.Finished>(items[^1]);
    }

    /// <summary>
    /// The point of the stream is that a UI sees a stage before the pipeline ends, so a
    /// start must always precede its matching finish.
    /// </summary>
    [Fact]
    public async Task EveryStageIsStartedBeforeItFinishes()
    {
        ConnectivityAnalyzer analyzer = AnalyzerFactory.Create();

        List<AnalysisProgress> items = await Collect(analyzer, DeadEndpoint);

        var started = new HashSet<string>(StringComparer.Ordinal);
        foreach (AnalysisProgress item in items)
        {
            switch (item)
            {
                case AnalysisProgress.StageStarted s:
                    Assert.True(started.Add(s.Stage.StageId), $"{s.Stage.StageId} started twice.");
                    break;
                case AnalysisProgress.StageFinished f:
                    Assert.Contains(f.Stage.StageId, started);
                    break;
            }
        }
    }

    [Fact]
    public async Task StreamReportsEveryStageInThePipeline()
    {
        ConnectivityAnalyzer analyzer = AnalyzerFactory.Create();
        int expected = AnalyzerFactory.CreateDefaultStages().Count;

        List<AnalysisProgress> items = await Collect(analyzer, DeadEndpoint);

        Assert.Equal(expected, items.OfType<AnalysisProgress.StageFinished>().Count());
        Assert.All(items.OfType<AnalysisProgress.StageFinished>(), f => Assert.Equal(expected, f.Total));
    }

    /// <summary>The streamed report must be the same report the blocking API produces.</summary>
    [Fact]
    public async Task FinishedReportMatchesTheBlockingApi()
    {
        List<AnalysisProgress> items = await Collect(AnalyzerFactory.Create(), DeadEndpoint);
        AnalysisReport streamed = items.OfType<AnalysisProgress.Finished>().Single().Report;

        AnalysisReport direct = await AnalyzerFactory.Create()
            .AnalyzeAsync(DeadEndpoint, FastOptions);

        Assert.Equal(direct.Succeeded, streamed.Succeeded);
        Assert.Equal(
            direct.Stages.Select(s => s.StageId),
            streamed.Stages.Select(s => s.StageId));
    }

    /// <summary>A parse failure short-circuits, but the stream must still terminate cleanly.</summary>
    [Fact]
    public async Task StreamCompletesEvenWhenTheConnectionStringCannotBeParsed()
    {
        List<AnalysisProgress> items = await Collect(AnalyzerFactory.Create(), "Server=x;Bogus Keyword=1");

        AnalysisReport report = items.OfType<AnalysisProgress.Finished>().Single().Report;
        Assert.False(report.Succeeded);
        Assert.Contains(report.AllFindings, f => f.Code == "SCA0001");
    }

    [Fact]
    public async Task CancellingTheStreamStopsEnumeration()
    {
        ConnectivityAnalyzer analyzer = AnalyzerFactory.Create();
        using var cts = new CancellationTokenSource();
        var seen = new List<AnalysisProgress>();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (AnalysisProgress p in analyzer.AnalyzeStreamAsync(DeadEndpoint, FastOptions, cts.Token))
            {
                seen.Add(p);
                await cts.CancelAsync();
            }
        });

        Assert.NotEmpty(seen);
    }

    /// <summary>
    /// Unsubscribing on completion matters: a leaked handler would make a reused analyzer
    /// emit progress for an unrelated run.
    /// </summary>
    [Fact]
    public async Task HandlersAreDetachedSoAReusedAnalyzerDoesNotDoubleReport()
    {
        ConnectivityAnalyzer analyzer = AnalyzerFactory.Create();
        int expected = AnalyzerFactory.CreateDefaultStages().Count;

        await Collect(analyzer, DeadEndpoint);
        List<AnalysisProgress> second = await Collect(analyzer, DeadEndpoint);

        Assert.Equal(expected, second.OfType<AnalysisProgress.StageFinished>().Count());
    }

    [Fact]
    public void DependencyInjectionResolvesTheFullPipeline()
    {
        ServiceProvider provider = new ServiceCollection()
            .AddConnectivityAnalyzer()
            .BuildServiceProvider();

        var analyzer = provider.GetRequiredService<ConnectivityAnalyzer>();
        var stages = provider.GetServices<IDiagnosticStage>().ToList();

        Assert.NotNull(analyzer);
        Assert.Equal(AnalyzerFactory.CreateDefaultStages().Count, stages.Count);
        Assert.Equal(
            AnalyzerFactory.CreateDefaultStages().Select(s => s.Id),
            stages.Select(s => s.Id));
    }

    /// <summary>Progress is instance-scoped, so each resolve must yield a fresh analyzer.</summary>
    [Fact]
    public void DependencyInjectionYieldsATransientAnalyzer()
    {
        ServiceProvider provider = new ServiceCollection()
            .AddConnectivityAnalyzer()
            .BuildServiceProvider();

        Assert.NotSame(
            provider.GetRequiredService<ConnectivityAnalyzer>(),
            provider.GetRequiredService<ConnectivityAnalyzer>());
    }

    /// <summary>
    /// The stream crosses a thread boundary: the pipeline keeps mutating a stage after it
    /// starts, so a consumer that held the live object would enumerate collections while
    /// they were being written. Snapshots must therefore be detached copies.
    /// </summary>
    [Fact]
    public async Task StageSnapshotsAreDetachedFromTheLiveStageResult()
    {
        List<AnalysisProgress> items = await Collect(AnalyzerFactory.Create(), DeadEndpoint);
        AnalysisReport report = items.OfType<AnalysisProgress.Finished>().Single().Report;

        AnalysisProgress.StageStarted started = items.OfType<AnalysisProgress.StageStarted>()
            .First(s => s.Stage.StageId == "connection-string");
        StageResult live = report.Stages.Single(s => s.StageId == "connection-string");

        // The start snapshot was taken before the stage ran, so it cannot have grown with it.
        Assert.NotSame(live.Findings, started.Stage.Findings);
        Assert.Empty(started.Stage.Findings);
        Assert.NotEmpty(live.Findings);
    }

    /// <summary>Mutating the source after the snapshot must not change what was emitted.</summary>
    [Fact]
    public async Task MutatingAStageAfterwardsDoesNotAlterAnEmittedSnapshot()
    {
        List<AnalysisProgress> items = await Collect(AnalyzerFactory.Create(), DeadEndpoint);
        AnalysisReport report = items.OfType<AnalysisProgress.Finished>().Single().Report;

        AnalysisProgress.StageFinished finished = items.OfType<AnalysisProgress.StageFinished>()
            .First(s => s.Stage.StageId == "connection-string");
        int findingsAtSnapshot = finished.Stage.Findings.Count;
        int evidenceAtSnapshot = finished.Stage.Evidence.Count;

        StageResult live = report.Stages.Single(s => s.StageId == "connection-string");
        live.Add(Finding.Info("SCA9999", DiagnosticLayer.Configuration, "Added after the fact."));
        live.Record("added-later", "value");

        Assert.Equal(findingsAtSnapshot, finished.Stage.Findings.Count);
        Assert.Equal(evidenceAtSnapshot, finished.Stage.Evidence.Count);
    }

    private static async Task<List<AnalysisProgress>> Collect(
        ConnectivityAnalyzer analyzer,
        string connectionString)
    {
        var items = new List<AnalysisProgress>();
        await foreach (AnalysisProgress p in analyzer.AnalyzeStreamAsync(
            connectionString, FastOptions))
        {
            items.Add(p);
        }

        return items;
    }
}
