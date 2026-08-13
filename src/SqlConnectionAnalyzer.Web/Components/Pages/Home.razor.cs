using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Reporting;

namespace SqlConnectionAnalyzer.Web.Components.Pages;

public partial class Home
{
    private readonly AnalysisForm _form = new();
    private readonly List<StageSnapshot> _stages = new();

    private AnalysisReport? _report;
    private CancellationTokenSource? _cts;
    private bool _running;
    private int _total;

    [Inject]
    private IJSRuntime Js { get; set; } = default!;

    private int CompletedCount =>
        _stages.Count(s => s.Status is not (StageStatus.Running or StageStatus.Pending));

    private string StatusText => _running
        ? $"Running stage {Math.Min(CompletedCount + 1, Math.Max(_total, 1))} of {_total}."
        : _report is null ? string.Empty : $"Finished {_total} stages.";

    protected override void OnInitialized()
    {
        if (!string.IsNullOrWhiteSpace(UiOptions.InitialConnectionString))
        {
            _form.ConnectionString = UiOptions.InitialConnectionString!;
        }
    }

    private async Task RunAsync()
    {
        if (_running)
        {
            return;
        }

        _running = true;
        _report = null;
        _stages.Clear();
        _cts = new CancellationTokenSource();

        // Resolved per run: progress notifications are instance-scoped on the analyzer.
        var analyzer = Services.GetRequiredService<ConnectivityAnalyzer>();
        _total = Services.GetServices<IDiagnosticStage>().Count();

        var options = new AnalyzerOptions
        {
            ProbeTimeout = TimeSpan.FromSeconds(Math.Clamp(_form.TimeoutSeconds, 1, 120)),
            MatrixMode = _form.Matrix,
            CaptureEventSource = _form.Trace
        };

        try
        {
            await foreach (AnalysisProgress progress in analyzer.AnalyzeStreamAsync(
                _form.ConnectionString, options, _cts.Token))
            {
                switch (progress)
                {
                    case AnalysisProgress.StageStarted started:
                        _stages.Add(started.Stage);
                        _total = started.Total;
                        break;

                    // The finished snapshot supersedes the placeholder added when it started.
                    case AnalysisProgress.StageFinished finished when finished.Index < _stages.Count:
                        _stages[finished.Index] = finished.Stage;
                        break;

                    case AnalysisProgress.Finished finished:
                        _report = finished.Report;
                        break;
                }

                // Each item is a discrete transition, so the UI repaints as the pipeline advances.
                await InvokeAsync(StateHasChanged);
            }
        }
        catch (OperationCanceledException)
        {
            // Cancellation is a user action, not an error.
        }
        finally
        {
            _running = false;
            _cts?.Dispose();
            _cts = null;
            await InvokeAsync(StateHasChanged);
        }
    }

    private void Cancel() => _cts?.Cancel();

    private async Task DownloadJson()
    {
        if (_report is { } report)
        {
            await Download($"sqlconn-report-{Stamp()}.json", JsonReportWriter.Render(report));
        }
    }

    private async Task DownloadMarkdown()
    {
        if (_report is { } report)
        {
            await Download($"sqlconn-report-{Stamp()}.md", MarkdownReportWriter.Render(report));
        }
    }

    private async Task Download(string fileName, string content) =>
        await Js.InvokeVoidAsync("sca.download", fileName, content);

    private static string Stamp() => DateTime.Now.ToString("yyyyMMdd-HHmmss");

    private static string FormatMs(TimeSpan elapsed) =>
        elapsed.TotalMilliseconds >= 1000
            ? $"{elapsed.TotalSeconds:0.00} s"
            : $"{elapsed.TotalMilliseconds:0} ms";

    private static int Percent(StageSnapshot stage, AnalysisReport report)
    {
        double longest = report.Stages.Max(s => s.Elapsed.TotalMilliseconds);
        return longest <= 0 ? 0 : (int)Math.Round(stage.Elapsed.TotalMilliseconds / longest * 100);
    }

    private static string BadgeClass(StageStatus status) => status switch
    {
        StageStatus.Passed => "pass",
        StageStatus.Warning => "warn",
        StageStatus.Failed => "fail",
        StageStatus.Skipped or StageStatus.NotApplicable => "skip",
        _ => "run"
    };

    /// <summary>
    /// Status is spelled out rather than shown only as a colour, so the checklist is
    /// readable without colour perception.
    /// </summary>
    private static string BadgeText(StageStatus status) => status switch
    {
        StageStatus.Passed => "Pass",
        StageStatus.Warning => "Warning",
        StageStatus.Failed => "Fail",
        StageStatus.Skipped => "Skipped",
        StageStatus.NotApplicable => "N/A",
        _ => "Running"
    };

    private static string SeverityClass(Severity severity) => severity switch
    {
        Severity.Error or Severity.Critical => "error",
        Severity.Warning => "warning",
        _ => "info"
    };

    private static string VerdictClass(AnalysisReport report) =>
        !report.Succeeded ? "bad" : report.Concerns.Count > 0 ? "caution" : "ok";

    private static string VerdictHeading(AnalysisReport report) =>
        !report.Succeeded
            ? "FAILED: the connection did not succeed"
            : report.Concerns.Count > 0
                ? "CONNECTED, WITH CONCERNS"
                : "SUCCESS: all stages passed";

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
    }

    private sealed class AnalysisForm
    {
        public string ConnectionString { get; set; } = string.Empty;

        public int TimeoutSeconds { get; set; } = 10;

        public bool Matrix { get; set; }

        public bool Trace { get; set; }
    }
}
