using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Stages;

namespace SqlConnectionAnalyzer.Tests;

public class ResiliencyStageTests
{
    private static (DiagnosticContext Context, StageResult Result) Build(string connectionString)
    {
        var context = new DiagnosticContext
        {
            ConnectionString = connectionString,
            Builder = new SqlConnectionStringBuilder(connectionString),
            Options = new AnalyzerOptions()
        };

        return (context, StageResult.Start("resiliency", "Resiliency and pooling"));
    }

    [Fact]
    public void StageIsSkippedWhenNoSessionWasEstablished()
    {
        (DiagnosticContext context, _) = Build("Server=x;Database=y");
        context.LoginSucceeded = false;

        Assert.False(new ResiliencyStage().AppliesTo(context));
    }

    [Fact]
    public void StageAppliesOnlyAfterASuccessfulLogin()
    {
        (DiagnosticContext context, _) = Build("Server=x;Database=y");
        context.LoginSucceeded = true;

        Assert.True(new ResiliencyStage().AppliesTo(context));
    }

    [Fact]
    public void DisabledPoolingIsReported()
    {
        (DiagnosticContext context, StageResult result) = Build("Server=x;Pooling=false");

        InvokeConfigurationReview(context, result);

        Assert.Contains(result.Findings, f => f.Code == "SCA0800");
    }

    [Fact]
    public void DisabledConnectionResiliencyIsReported()
    {
        (DiagnosticContext context, StageResult result) = Build("Server=x;ConnectRetryCount=0");

        InvokeConfigurationReview(context, result);

        Assert.Contains(result.Findings, f => f.Code == "SCA0801");
    }

    [Fact]
    public void ShortConnectTimeoutIsOnlyFlaggedForAzure()
    {
        (DiagnosticContext onPrem, StageResult onPremResult) = Build("Server=x;Connect Timeout=5");
        onPrem.EndpointKind = EndpointKind.OnPremises;
        InvokeConfigurationReview(onPrem, onPremResult);
        Assert.DoesNotContain(onPremResult.Findings, f => f.Code == "SCA0802");

        (DiagnosticContext azure, StageResult azureResult) = Build("Server=x;Connect Timeout=5");
        azure.EndpointKind = EndpointKind.AzureSqlDatabase;
        InvokeConfigurationReview(azure, azureResult);
        Assert.Contains(azureResult.Findings, f => f.Code == "SCA0802");
    }

    [Fact]
    public void ReducedPoolSizeIsCalledOutAsALoadRisk()
    {
        (DiagnosticContext context, StageResult result) = Build("Server=x;Max Pool Size=10");

        InvokeConfigurationReview(context, result);

        Assert.Contains(result.Findings, f => f.Code == "SCA0803");
    }

    /// <summary>Exercises the configuration review without opening a real connection.</summary>
    private static void InvokeConfigurationReview(DiagnosticContext context, StageResult result)
    {
        System.Reflection.MethodInfo method = typeof(ResiliencyStage).GetMethod(
            "ReviewConfiguration",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;

        method.Invoke(null, new object[] { context, result });
    }
}
