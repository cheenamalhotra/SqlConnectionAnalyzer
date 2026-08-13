using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Tests;

public class ConnectionStringStageTests
{
    private static async Task<StageResult> AnalyzeAsync(string connectionString)
    {
        var analyzer = new ConnectivityAnalyzer([new Core.Stages.ConnectionStringStage()]);
        AnalysisReport report = await analyzer.AnalyzeAsync(
            connectionString,
            new AnalyzerOptions { AttemptLogin = false });

        return report.Stages.Single();
    }

    [Fact]
    public async Task FlagsConflictingAuthenticationOptions()
    {
        StageResult result = await AnalyzeAsync(
            "Server=s;Authentication=Active Directory Default;Integrated Security=true;");

        Assert.Contains(result.Findings, f => f.Code == "SCA0110");
        Assert.Equal(StageStatus.Failed, result.Status);
    }

    [Fact]
    public async Task FlagsDisabledEncryptionAgainstAzure()
    {
        StageResult result = await AnalyzeAsync(
            "Server=s.database.windows.net;Encrypt=false;User ID=u;Password=p;");

        Assert.Contains(result.Findings, f => f.Code == "SCA0120");
    }

    [Fact]
    public async Task WarnsAboutTrustServerCertificate()
    {
        StageResult result = await AnalyzeAsync("Server=s;TrustServerCertificate=true;User ID=u;Password=p;");

        Assert.Contains(result.Findings, f => f.Code == "SCA0121");
    }

    [Fact]
    public async Task FlagsMissingPasswordForSqlAuthentication()
    {
        StageResult result = await AnalyzeAsync("Server=s;Authentication=Sql Password;User ID=u;");

        Assert.Contains(result.Findings, f => f.Code == "SCA0112");
    }

    [Fact]
    public async Task WarnsWhenBothInstanceAndPortAreSupplied()
    {
        StageResult result = await AnalyzeAsync("Server=host\\INST,1433;User ID=u;Password=p;");

        Assert.Contains(result.Findings, f => f.Code == "SCA0102");
    }

    [Fact]
    public async Task ReportsAnUnparsableConnectionString()
    {
        var analyzer = new ConnectivityAnalyzer([new Core.Stages.ConnectionStringStage()]);

        AnalysisReport report = await analyzer.AnalyzeAsync("this is not = a valid ; connection = string");

        Assert.False(report.Succeeded);
    }
}
