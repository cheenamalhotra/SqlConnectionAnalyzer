using SqlConnectionAnalyzer.Cli;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Reporting;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Tests;

/// <summary>
/// A connection that only works because validation was bypassed must not be summarised as
/// "All stages passed". These tests pin the distinction between "connected" and "sound".
/// </summary>
public class VerdictConcernTests
{
    private static AnalysisReport NewReport() => new()
    {
        RedactedConnectionString = "data source=sql01;******;",
        StartedAt = DateTimeOffset.UnixEpoch
    };

    [Fact]
    public void Concerns_IsEmpty_WhenEverythingPassedCleanly()
    {
        AnalysisReport report = NewReport();
        var stage = StageResult.Start("tcp-reachability", "TCP reachability");
        stage.MarkPassed();
        report.Stages.Add(stage);

        Assert.True(report.Succeeded);
        Assert.Empty(report.Concerns);
    }

    [Fact]
    public void Concerns_IncludeMatrixVerdict_WhichBelongsToNoStage()
    {
        AnalysisReport report = NewReport();
        var stage = StageResult.Start("tls", "TLS handshake");
        stage.MarkPassed();
        report.Stages.Add(stage);
        report.MatrixVerdict = Finding.Error(
            "SCA1003",
            DiagnosticLayer.Tls,
            "The connection only succeeds when certificate validation is bypassed.");

        Assert.True(report.Succeeded, "connectivity itself still works");
        Finding concern = Assert.Single(report.Concerns);
        Assert.Equal("SCA1003", concern.Code);
    }

    [Fact]
    public void Concerns_ExcludeInformationalFindings()
    {
        AnalysisReport report = NewReport();
        var stage = StageResult.Start("routing", "Routing");
        stage.Add(Finding.Info("SCA0900", DiagnosticLayer.Routing, "No redirection observed."));
        stage.MarkPassed();
        report.Stages.Add(stage);

        Assert.Empty(report.Concerns);
    }

    [Fact]
    public void Concerns_AreOrderedBySeverity()
    {
        AnalysisReport report = NewReport();
        var stage = StageResult.Start("conn", "Connection string");
        stage.Add(Finding.Warn("SCA0121", DiagnosticLayer.Tls, "Validation disabled."));
        stage.MarkPassed();
        report.Stages.Add(stage);
        report.MatrixVerdict = Finding.Error(
            "SCA1003", DiagnosticLayer.Tls, "Only succeeds without validation.");

        Assert.Equal(new[] { "SCA1003", "SCA0121" }, report.Concerns.Select(c => c.Code));
    }

    [Fact]
    public async Task MarkdownVerdict_ReportsConcerns_InsteadOfClaimingAllPassed()
    {
        AnalysisReport report = NewReport();
        var stage = StageResult.Start("conn", "Connection string");
        stage.Add(Finding.Warn(
            "SCA0121", DiagnosticLayer.Tls, "TrustServerCertificate disables validation."));
        stage.MarkPassed();
        report.Stages.Add(stage);

        string path = Path.Combine(Path.GetTempPath(), $"verdict-{Guid.NewGuid():N}.md");
        try
        {
            await MarkdownReportWriter.WriteAsync(report, path, CancellationToken.None);
            string md = await File.ReadAllTextAsync(path);

            Assert.DoesNotContain("All stages passed.", md);
            Assert.Contains("The connection succeeded, but 1 issue(s) need attention.", md);
            Assert.Contains("SCA0121", md);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task MarkdownVerdict_StillReportsCleanRun_WhenNothingIsWrong()
    {
        AnalysisReport report = NewReport();
        var stage = StageResult.Start("conn", "Connection string");
        stage.MarkPassed();
        report.Stages.Add(stage);

        string path = Path.Combine(Path.GetTempPath(), $"verdict-{Guid.NewGuid():N}.md");
        try
        {
            await MarkdownReportWriter.WriteAsync(report, path, CancellationToken.None);
            string md = await File.ReadAllTextAsync(path);
            Assert.Contains("All stages passed.", md);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
