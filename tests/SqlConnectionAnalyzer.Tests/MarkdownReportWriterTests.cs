using SqlConnectionAnalyzer.Cli;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Reporting;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Tests;

public class MarkdownReportWriterTests
{
    private static AnalysisReport BuildReport(bool failed)
    {
        var report = new AnalysisReport
        {
            RedactedConnectionString = "data source=sql01;user id=sa;password=St******;",
            StartedAt = DateTimeOffset.UnixEpoch
        };

        report.TotalElapsed = TimeSpan.FromMilliseconds(120);
        report.EndpointKind = EndpointKind.OnPremises;

        var passed = StageResult.Start("tcp-reachability", "TCP reachability");
        passed.Record("Target port", "1433");
        passed.MarkPassed();
        report.Stages.Add(passed);

        var login = StageResult.Start("login", "LOGIN7 and authentication");
        if (failed)
        {
            login.Add(Finding.Error(
                "SQL18456.8",
                DiagnosticLayer.Authentication,
                "Login failed: the password is incorrect.",
                "Login failed for user 'sa'.",
                "Verify the password."));
            login.IsFatal = true;
        }

        login.MarkPassed();
        report.Stages.Add(login);

        return report;
    }

    [Fact]
    public void RendersAFailureVerdictWithTheCauseAndSteps()
    {
        string markdown = MarkdownReportWriter.Render(BuildReport(failed: true));

        Assert.Contains("# SQL connectivity analysis", markdown, StringComparison.Ordinal);
        Assert.Contains("**Result:** failed", markdown, StringComparison.Ordinal);
        Assert.Contains("LOGIN7 and authentication", markdown, StringComparison.Ordinal);
        Assert.Contains("SQL18456.8", markdown, StringComparison.Ordinal);
        Assert.Contains("Verify the password.", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void RendersASuccessVerdict()
    {
        string markdown = MarkdownReportWriter.Render(BuildReport(failed: false));

        Assert.Contains("**Result:** succeeded", markdown, StringComparison.Ordinal);
        Assert.Contains("All stages passed.", markdown, StringComparison.Ordinal);
    }

    /// <summary>The report is meant to be pasted into a ticket, so it must carry no secrets.</summary>
    [Fact]
    public void TheRedactedConnectionStringIsUsedVerbatim()
    {
        string markdown = MarkdownReportWriter.Render(BuildReport(failed: true));

        Assert.Contains("password=St******;", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("Str0ng", markdown, StringComparison.Ordinal);
    }

    /// <summary>A pipe in an evidence value would otherwise split the table cell.</summary>
    [Fact]
    public void PipeCharactersInEvidenceAreEscaped()
    {
        AnalysisReport report = BuildReport(failed: false);
        var stage = StageResult.Start("custom", "Custom");
        stage.Record("Cipher", "TLS_ECDHE|AES_128");
        stage.MarkPassed();
        report.Stages.Add(stage);

        string markdown = MarkdownReportWriter.Render(report);

        Assert.Contains(@"TLS_ECDHE\|AES_128", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void NewlinesInEvidenceDoNotBreakTableRows()
    {
        AnalysisReport report = BuildReport(failed: false);
        var stage = StageResult.Start("custom", "Custom");
        stage.Record("Chain", "root\nintermediate");
        stage.MarkPassed();
        report.Stages.Add(stage);

        string markdown = MarkdownReportWriter.Render(report);

        Assert.Contains("root intermediate", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void TheStageSummaryTableListsEveryStage()
    {
        string markdown = MarkdownReportWriter.Render(BuildReport(failed: true));

        Assert.Contains("| Stage | Status | Time |", markdown, StringComparison.Ordinal);
        Assert.Contains("TCP reachability", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void TheMatrixSectionIsOmittedWhenTheMatrixDidNotRun()
    {
        string markdown = MarkdownReportWriter.Render(BuildReport(failed: false));

        Assert.DoesNotContain("## Encryption matrix", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void TheMatrixSectionIsRenderedWhenPresent()
    {
        AnalysisReport report = BuildReport(failed: false);
        report.MatrixOutcomes.Add(new MatrixOutcome("Mandatory", false, false, TimeSpan.FromMilliseconds(9), 18456, "bad"));
        report.MatrixOutcomes.Add(new MatrixOutcome("Mandatory", true, true, TimeSpan.FromMilliseconds(8), null, null));
        report.MatrixVerdict = ConnectionMatrixRunner.Interpret(report.MatrixOutcomes);

        string markdown = MarkdownReportWriter.Render(report);

        Assert.Contains("## Encryption matrix", markdown, StringComparison.Ordinal);
        Assert.Contains("| Mandatory | true | succeeded |", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WritesToDiskAndCanBeReadBack()
    {
        string path = Path.Combine(Path.GetTempPath(), $"sca-md-{Guid.NewGuid():N}.md");

        try
        {
            await MarkdownReportWriter.WriteAsync(BuildReport(failed: true), path, CancellationToken.None);

            Assert.True(File.Exists(path));
            Assert.Contains("# SQL connectivity analysis", await File.ReadAllTextAsync(path), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
