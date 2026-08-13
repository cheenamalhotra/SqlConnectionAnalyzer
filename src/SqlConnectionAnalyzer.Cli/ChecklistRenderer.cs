using Spectre.Console;
using Spectre.Console.Rendering;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Cli;

/// <summary>Renders the analysis as a live checklist followed by a detailed report.</summary>
public sealed class ChecklistRenderer
{
    private readonly bool _verbose;

    public ChecklistRenderer(bool verbose) => _verbose = verbose;

    public void Attach(ConnectivityAnalyzer analyzer)
    {
        analyzer.StageStarted += (_, e) =>
            AnsiConsole.MarkupLine($"[grey]{Glyph(e.Result.Status)}[/] [grey]{Escape(e.Result.Title)}…[/]");

        analyzer.StageCompleted += (_, e) =>
        {
            StageResult r = e.Result;
            string timing = r.Elapsed > TimeSpan.Zero ? $" [grey]({r.Elapsed.TotalMilliseconds:0} ms)[/]" : string.Empty;
            AnsiConsole.MarkupLine(
                $"{Glyph(r.Status)} [{Color(r.Status)}]{Escape(r.Title)}[/]{timing} {Summary(r)}");
        };
    }

    public void RenderReport(AnalysisReport report)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]Details[/]").LeftJustified());

        foreach (StageResult stage in report.Stages)
        {
            if (stage.Status == StageStatus.NotApplicable && !_verbose)
            {
                continue;
            }

            RenderStage(stage);
        }

        RenderMatrix(report);
        RenderTrace(report);
        RenderVerdict(report);
    }

    /// <summary>Renders the encryption permutation grid, which localises a TLS fault to one setting.</summary>
    private void RenderMatrix(AnalysisReport report)
    {
        if (report.MatrixVerdict is null && report.MatrixOutcomes.Count == 0)
        {
            return;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]Encryption matrix[/]").LeftJustified());

        if (report.MatrixOutcomes.Count > 0)
        {
            var table = new Table { Border = TableBorder.Rounded, Expand = true };
            table.AddColumn("Encrypt");
            table.AddColumn("TrustServerCertificate");
            table.AddColumn("Result");
            table.AddColumn("Time");
            table.AddColumn("Detail");

            foreach (MatrixOutcome outcome in report.MatrixOutcomes)
            {
                bool strict = outcome.Encrypt.Equals("Strict", StringComparison.OrdinalIgnoreCase);
                string detail = outcome.Succeeded
                    ? string.Empty
                    : $"{(outcome.ErrorNumber is { } n ? $"[{n}] " : string.Empty)}{outcome.Error}";

                table.AddRow(
                    Escape(outcome.Encrypt),
                    strict ? "[grey]n/a[/]" : outcome.TrustServerCertificate.ToString().ToLowerInvariant(),
                    outcome.Succeeded ? "[green]succeeded[/]" : "[red]failed[/]",
                    $"[grey]{outcome.Elapsed.TotalMilliseconds:0} ms[/]",
                    $"[grey]{Escape(Truncate(detail, 70))}[/]");
            }

            AnsiConsole.Write(table);
        }

        if (report.MatrixVerdict is { } verdict)
        {
            AnsiConsole.MarkupLine(
                $"{SeverityGlyph(verdict.Severity)} [{SeverityColor(verdict.Severity)}]{Escape(verdict.Message)}[/] [grey]({verdict.Code})[/]");

            if (!string.IsNullOrWhiteSpace(verdict.Detail))
            {
                AnsiConsole.MarkupLine($"  [grey]{Escape(verdict.Detail)}[/]");
            }

            foreach (string step in verdict.Remediation)
            {
                AnsiConsole.MarkupLine($"  [green]→[/] {Escape(step)}");
            }
        }
    }

    /// <summary>Shows what the driver itself logged, which is only useful at verbose detail.</summary>
    private void RenderTrace(AnalysisReport report)
    {
        if (report.TraceEvents.Count == 0)
        {
            return;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule($"[bold]SqlClient trace[/] [grey]({report.TraceEvents.Count} events)[/]").LeftJustified());

        IEnumerable<SqlClientTraceEvent> shown = _verbose
            ? report.TraceEvents
            : report.TraceEvents.TakeLast(40);

        foreach (SqlClientTraceEvent e in shown)
        {
            AnsiConsole.MarkupLine(
                $"[grey]{e.TimestampUtc:HH:mm:ss.fff}[/] [blue]{Escape(e.EventName)}[/] [grey]{Escape(Truncate(e.Message, 160))}[/]");
        }

        if (!_verbose && report.TraceEvents.Count > 40)
        {
            AnsiConsole.MarkupLine($"[grey]… {report.TraceEvents.Count - 40} earlier events hidden; use --verbose to see all.[/]");
        }
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "…";

    private void RenderStage(StageResult stage)
    {
        var panelContent = new Rows(BuildStageRows(stage).ToArray());

        AnsiConsole.Write(new Panel(panelContent)
        {
            Header = new PanelHeader($" {Glyph(stage.Status)} [{Color(stage.Status)}]{Escape(stage.Title)}[/] "),
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(StatusColor(stage.Status)),
            Expand = true
        });
    }

    private IEnumerable<IRenderable> BuildStageRows(StageResult stage)
    {
        if (stage.SkipReason is { } reason)
        {
            yield return new Markup($"[grey]{Escape(reason)}[/]");
        }

        if (_verbose && stage.Evidence.Count > 0)
        {
            var table = new Table { Border = TableBorder.None, ShowHeaders = false };
            table.AddColumn(new TableColumn(string.Empty).PadRight(2));
            table.AddColumn(new TableColumn(string.Empty));

            foreach ((string key, string? value) in stage.Evidence)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    table.AddRow($"[grey]{Escape(key)}[/]", Escape(value));
                }
            }

            if (table.Rows.Count > 0)
            {
                yield return table;
            }
        }

        foreach (Finding finding in stage.Findings)
        {
            if (finding.Severity == Severity.Info && !_verbose)
            {
                continue;
            }

            yield return new Markup(
                $"{SeverityGlyph(finding.Severity)} [{SeverityColor(finding.Severity)}]{Escape(finding.Message)}[/] [grey]({finding.Code})[/]");

            if (!string.IsNullOrWhiteSpace(finding.Detail))
            {
                yield return new Markup($"  [grey]{Escape(finding.Detail)}[/]");
            }

            foreach (string step in finding.Remediation)
            {
                yield return new Markup($"  [green]→[/] {Escape(step)}");
            }
        }
    }

    /// <summary>
    /// Renders the verdict when every stage passed. Connectivity succeeding is not the same as
    /// the configuration being sound, so outstanding warnings are surfaced here rather than left
    /// buried in the detail panels above.
    /// </summary>
    private static void RenderSuccessVerdict(AnalysisReport report)
    {
        IReadOnlyList<Finding> concerns = report.Concerns;
        string timing = $"Total time {report.TotalElapsed.TotalMilliseconds:0} ms.";

        if (concerns.Count == 0)
        {
            AnsiConsole.Write(new Panel(new Markup($"[green]All stages passed.[/] {timing}"))
            {
                Header = new PanelHeader(" [green]Verdict[/] "),
                Border = BoxBorder.Heavy,
                BorderStyle = new Style(Spectre.Console.Color.Green),
                Expand = true
            });
            return;
        }

        var lines = new List<IRenderable>
        {
            new Markup(
                $"[green]The connection succeeded[/], but {Pluralize(concerns.Count)} need attention. {timing}")
        };

        foreach (Finding concern in concerns)
        {
            lines.Add(new Markup(
                $"  {SeverityGlyph(concern.Severity)} [{SeverityColor(concern.Severity)}]{Escape(concern.Message)}[/] [grey]({concern.Code})[/]"));
        }

        AnsiConsole.Write(new Panel(new Rows(lines))
        {
            Header = new PanelHeader(" [yellow]Verdict[/] "),
            Border = BoxBorder.Heavy,
            BorderStyle = new Style(Spectre.Console.Color.Yellow),
            Expand = true
        });
    }

    private static string Pluralize(int count) => count == 1 ? "1 issue" : $"{count} issues";

    private static void RenderVerdict(AnalysisReport report)
    {        AnsiConsole.WriteLine();

        StageResult? failure = report.FirstFailure;

        if (failure is null)
        {
            RenderSuccessVerdict(report);
            return;
        }

        Finding? worst = failure.WorstFinding;
        var lines = new List<IRenderable>
        {
            new Markup($"Connectivity failed at [red]{Escape(failure.Title)}[/]."),
        };

        if (worst is not null)
        {
            lines.Add(new Markup($"[bold]Cause:[/] {Escape(worst.Message)} [grey]({worst.Code})[/]"));
            lines.Add(new Markup($"[bold]Layer:[/] {worst.Layer}"));

            if (worst.Remediation.Count > 0)
            {
                lines.Add(new Markup("[bold]Next steps:[/]"));
                lines.AddRange(worst.Remediation.Select(s => new Markup($"  [green]→[/] {Escape(s)}")));
            }
        }

        AnsiConsole.Write(new Panel(new Rows(lines.ToArray()))
        {
            Header = new PanelHeader(" [red]Verdict[/] "),
            Border = BoxBorder.Heavy,
            BorderStyle = new Style(Spectre.Console.Color.Red),
            Expand = true
        });
    }

    private static string Summary(StageResult r)
    {
        Finding? worst = r.WorstFinding;
        if (r.Status == StageStatus.Skipped)
        {
            return "[grey]skipped[/]";
        }

        if (r.Status == StageStatus.NotApplicable)
        {
            return "[grey]not applicable[/]";
        }

        return worst is null || worst.Severity == Severity.Info
            ? string.Empty
            : $"[grey]- {Escape(worst.Message)}[/]";
    }

    private static string Glyph(StageStatus status) => status switch
    {
        StageStatus.Passed => "[green]✔[/]",
        StageStatus.Warning => "[yellow]![/]",
        StageStatus.Failed => "[red]✘[/]",
        StageStatus.Skipped or StageStatus.NotApplicable => "[grey]○[/]",
        _ => "[grey]·[/]"
    };

    private static string SeverityGlyph(Severity severity) => severity switch
    {
        Severity.Info => "[blue]i[/]",
        Severity.Warning => "[yellow]![/]",
        _ => "[red]✘[/]"
    };

    private static string Color(StageStatus status) => status switch
    {
        StageStatus.Passed => "green",
        StageStatus.Warning => "yellow",
        StageStatus.Failed => "red",
        _ => "grey"
    };

    private static Spectre.Console.Color StatusColor(StageStatus status) => status switch
    {
        StageStatus.Passed => Spectre.Console.Color.Green,
        StageStatus.Warning => Spectre.Console.Color.Yellow,
        StageStatus.Failed => Spectre.Console.Color.Red,
        _ => Spectre.Console.Color.Grey
    };

    private static string SeverityColor(Severity severity) => severity switch
    {
        Severity.Info => "blue",
        Severity.Warning => "yellow",
        _ => "red"
    };

    private static string Escape(string value) => Markup.Escape(value);
}
