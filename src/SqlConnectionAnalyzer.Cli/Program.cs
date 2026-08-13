using Spectre.Console;
using SqlConnectionAnalyzer.Cli;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Reporting;
using SqlConnectionAnalyzer.Core.Probes;
using SqlConnectionAnalyzer.Core.Rules;
using System.Text.Json;

CommandLineOptions options = CommandLineOptions.Parse(args);

if (options.ShowHelp)
{
    AnsiConsole.WriteLine(CommandLineOptions.HelpText);
    return 0;
}

if (options.Error is { } error)
{
    AnsiConsole.MarkupLine($"[red]{Markup.Escape(error)}[/]");
    AnsiConsole.WriteLine();
    AnsiConsole.WriteLine(CommandLineOptions.HelpText);
    return 2;
}

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cancellation.Cancel();
};

ConnectivityAnalyzer analyzer = AnalyzerFactory.Create();
// A custom rules file overlays the built-in knowledge base rather than replacing it.
if (options.RulesPath is { } rulesPath)
{
    try
    {
        DiagnosticRuleSet custom = DiagnosticRuleSet.LoadFromFile(rulesPath);
        SqlErrorClassifier.RuleSet = DiagnosticRuleSet.BuiltIn.MergedWith(custom);
        AnsiConsole.MarkupLine(
            $"[grey]Loaded {custom.Rules.Count} custom rule(s) from {Markup.Escape(rulesPath)}.[/]");
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or UnauthorizedAccessException)
    {
        AnsiConsole.MarkupLine($"[red]Could not load rules file '{Markup.Escape(rulesPath)}': {Markup.Escape(ex.Message)}[/]");
        return 2;
    }
}

if (options.Serve)
{
    return await WebUiLauncher.RunAsync(options, cancellation.Token);
}

var renderer = new ChecklistRenderer(options.Verbose);
renderer.Attach(analyzer);

AnsiConsole.Write(new Rule("[bold]SQL connectivity analysis[/]").LeftJustified());
AnsiConsole.MarkupLine($"[grey]{Markup.Escape(Redactor.ConnectionString(options.ConnectionString!))}[/]");
AnsiConsole.WriteLine();

try
{
    AnalysisReport report = await analyzer.AnalyzeAsync(
        options.ConnectionString!,
        options.ToAnalyzerOptions(),
        cancellation.Token);

    renderer.RenderReport(report);

    if (options.JsonPath is { } jsonPath)
    {
        await JsonReportWriter.WriteAsync(report, jsonPath, cancellation.Token);
        AnsiConsole.MarkupLine($"[grey]Report written to {Markup.Escape(jsonPath)}[/]");
    }

    if (options.MarkdownPath is { } markdownPath)
    {
        await MarkdownReportWriter.WriteAsync(report, markdownPath, cancellation.Token);
        AnsiConsole.MarkupLine($"[grey]Markdown report written to {Markup.Escape(markdownPath)}[/]");
    }

    return report.Succeeded ? 0 : 1;
}
catch (OperationCanceledException)
{
    AnsiConsole.MarkupLine("[yellow]Analysis cancelled.[/]");
    return 1;
}
