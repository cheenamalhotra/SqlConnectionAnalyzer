using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Stages;

namespace SqlConnectionAnalyzer.Tests;

/// <summary>
/// Pins the analyzer's authentication rules to Microsoft.Data.SqlClient's own behaviour. Each
/// rejection case is cross-checked against a real SqlConnection, so if the driver ever relaxes a
/// rule the corresponding test fails and tells us to relax ours too.
/// </summary>
public class DriverParityTests
{
    private static StageResult AnalyzeConnectionString(string connectionString)
    {
        var stage = new ConnectionStringStage();
        var result = StageResult.Start(stage.Id, stage.Title);
        var context = new DiagnosticContext
        {
            ConnectionString = connectionString,
            Builder = new SqlConnectionStringBuilder(connectionString),
            Options = new AnalyzerOptions()
        };

        stage.RunAsync(context, result, CancellationToken.None).GetAwaiter().GetResult();
        return result;
    }

    /// <summary>True when SqlClient itself refuses the connection string.</summary>
    private static bool DriverRejects(string connectionString)
    {
        try
        {
            using var connection = new SqlConnection(connectionString);
            _ = connection.ConnectionTimeout;
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    [Theory]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Default;Password=p")]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Integrated;Password=p")]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Interactive;Password=p")]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Managed Identity;Password=p")]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Workload Identity;Password=p")]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Device Code Flow;User ID=u")]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Device Code Flow;Password=p")]
    public void CombinationsTheDriverRejectsAreFatalErrors(string connectionString)
    {
        Assert.True(DriverRejects(connectionString), "precondition: the driver must reject this");

        StageResult result = AnalyzeConnectionString(connectionString);

        Assert.True(result.IsFatal, "an impossible connection must stop the pipeline");
        Assert.Contains(result.Findings, f =>
            f.Severity >= Severity.Error && f.Code is "SCA0117" or "SCA0118");
    }

    /// <summary>
    /// SqlClient tests for keyword presence, so an empty password still makes the connection
    /// impossible. Checking the value instead of the keyword would miss this.
    /// </summary>
    [Fact]
    public void AnEmptyPasswordKeywordIsStillRejected()
    {
        const string cs = "Server=s.database.windows.net;Authentication=Active Directory Default;Password=";
        Assert.True(DriverRejects(cs));

        StageResult result = AnalyzeConnectionString(cs);

        Assert.Contains(result.Findings, f => f.Code == "SCA0118");
    }

    [Theory]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Service Principal;User ID=app;Password=secret")]
    [InlineData("Server=s.database.windows.net;Authentication=Active Directory Default")]
    [InlineData("Server=s;User ID=sa;Password=p")]
    public void CombinationsTheDriverAcceptsAreNotReportedAsImpossible(string connectionString)
    {
        Assert.False(DriverRejects(connectionString), "precondition: the driver must accept this");

        StageResult result = AnalyzeConnectionString(connectionString);

        Assert.DoesNotContain(result.Findings, f => f.Code is "SCA0117" or "SCA0118");
    }

    [Fact]
    public void PwdSynonymIsDetectedTheSameAsPassword()
    {
        const string cs = "Server=s.database.windows.net;Authentication=Active Directory Default;PWD=p";
        Assert.True(DriverRejects(cs));

        Assert.Contains(AnalyzeConnectionString(cs).Findings, f => f.Code == "SCA0118");
    }

    /// <summary>
    /// 'Active Directory Integrated' authenticates to Entra ID via MSAL, not to SQL Server via
    /// Kerberos, so MSSQLSvc SPN advice would send the user down the wrong path entirely.
    /// </summary>
    [Fact]
    public async Task ActiveDirectoryIntegratedDoesNotEmitKerberosSpnAdvice()
    {
        var stage = new CredentialStage();
        var result = StageResult.Start(stage.Id, stage.Title);
        const string cs = "Server=s.database.windows.net;Authentication=Active Directory Integrated";
        var context = new DiagnosticContext
        {
            ConnectionString = cs,
            Builder = new SqlConnectionStringBuilder(cs),
            Options = new AnalyzerOptions()
        };
        context.Host = "s.database.windows.net";
        context.Port = 1433;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            await stage.RunAsync(context, result, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Token acquisition may not be possible here; the SPN assertions below still hold.
        }

        Assert.Contains(result.Findings, f => f.Code == "SCA0617");
        Assert.DoesNotContain(result.Findings, f => f.Code is "SCA0614" or "SCA0615");
        Assert.DoesNotContain(result.Evidence.Keys, k => k.Contains("SPN", StringComparison.OrdinalIgnoreCase));
    }
}
