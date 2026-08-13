using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Tests;

public class ConnectionMatrixRunnerTests
{
    private static MatrixOutcome Outcome(string encrypt, bool trust, bool ok) =>
        new(encrypt, trust, ok, TimeSpan.FromMilliseconds(10), ok ? null : 18456, ok ? null : "failed");

    [Fact]
    public void AllFailuresPointAwayFromEncryption()
    {
        var outcomes = new[]
        {
            Outcome("Mandatory", false, false),
            Outcome("Mandatory", true, false),
            Outcome("Optional", false, false)
        };

        Finding verdict = ConnectionMatrixRunner.Interpret(outcomes);

        Assert.Equal("SCA1000", verdict.Code);
        Assert.Equal(Severity.Error, verdict.Severity);
    }

    [Fact]
    public void AllSuccessesReportAFullyTrustedCertificate()
    {
        var outcomes = new[]
        {
            Outcome("Mandatory", false, true),
            Outcome("Mandatory", true, true),
            Outcome("Optional", false, true),
            Outcome("Strict", false, true)
        };

        Finding verdict = ConnectionMatrixRunner.Interpret(outcomes);

        Assert.Equal("SCA1001", verdict.Code);
        Assert.Equal(Severity.Info, verdict.Severity);
    }

    /// <summary>The signature case: validation is the only thing standing between fail and pass.</summary>
    [Fact]
    public void SuccessOnlyWithoutValidationIsolatesCertificateTrust()
    {
        var outcomes = new[]
        {
            Outcome("Mandatory", false, false),
            Outcome("Mandatory", true, true),
            Outcome("Optional", false, true),
            Outcome("Strict", false, false)
        };

        Finding verdict = ConnectionMatrixRunner.Interpret(outcomes);

        Assert.Equal("SCA1003", verdict.Code);
        Assert.Equal(Severity.Error, verdict.Severity);
        Assert.NotEmpty(verdict.Remediation);
    }

    [Fact]
    public void VerifiedEncryptionWithoutStrictSuggestsAnOlderServer()
    {
        var outcomes = new[]
        {
            Outcome("Mandatory", false, true),
            Outcome("Mandatory", true, true),
            Outcome("Optional", false, true),
            Outcome("Strict", false, false)
        };

        Finding verdict = ConnectionMatrixRunner.Interpret(outcomes);

        Assert.Equal("SCA1002", verdict.Code);
        Assert.Equal(Severity.Warning, verdict.Severity);
    }
}
