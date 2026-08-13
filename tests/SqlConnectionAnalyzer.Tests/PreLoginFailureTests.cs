using System.Security.Authentication;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Stages;

namespace SqlConnectionAnalyzer.Tests;

/// <summary>
/// SqlClient surfaces a failed TLS negotiation as "An internal exception was caught"
/// (provider error 35) and hides the real reason in the inner exception. These tests pin
/// the unwrapping, because without it the report names no actionable cause.
/// </summary>
public class PreLoginFailureTests
{
    private static StageResult NewResult() => new() { StageId = "login", Title = "LOGIN7 and authentication" };

    [Fact]
    public void TheInnerAuthenticationExceptionBecomesATlsFinding()
    {
        var inner = new AuthenticationException(
            "Certificate failed chain validation. Error(s): 'The certificate was not trusted., "
                + "[Status: UntrustedRoot]\n'.\nCertificate name mismatch.");
        var outer = new InvalidOperationException("An internal exception was caught", inner);

        StageResult result = NewResult();
        LoginStage.RecordInnerCause(outer, result);

        Finding finding = Assert.Single(result.Findings, f => f.Code == "SCA0703");
        Assert.Equal(DiagnosticLayer.Tls, finding.Layer);
        Assert.Equal(Severity.Error, finding.Severity);
        Assert.Contains("UntrustedRoot", finding.Detail!, StringComparison.Ordinal);
        Assert.Contains("name mismatch", finding.Detail!, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// When the error number was already recognised as a TLS fault the cause is on the
    /// report once; repeating it as a second error would read as two separate problems.
    /// </summary>
    [Fact]
    public void TheCauseIsNotReportedTwiceWhenARuleAlreadyDiagnosedTheTlsFault()
    {
        StageResult result = NewResult();
        result.Add(Finding.Error(
            "SQLPRELOGIN.UNTRUSTEDROOT",
            DiagnosticLayer.Tls,
            "The TLS handshake failed during pre-login because the server certificate was not trusted."));

        LoginStage.RecordInnerCause(
            new InvalidOperationException("outer", new AuthenticationException("UntrustedRoot")),
            result);

        Assert.DoesNotContain(result.Findings, f => f.Code == "SCA0703");
        Assert.Equal("UntrustedRoot", result.Evidence["TLS failure detail"]);
    }

    /// <summary>A multi-line message must not break the report layout.</summary>
    [Fact]
    public void TheDetailIsFlattenedOntoASingleLine()
    {
        var outer = new InvalidOperationException(
            "outer",
            new AuthenticationException("first line\r\n  second line\n\nthird line"));

        StageResult result = NewResult();
        LoginStage.RecordInnerCause(outer, result);

        string detail = result.Findings.Single(f => f.Code == "SCA0703").Detail!;

        Assert.DoesNotContain('\n', detail);
        Assert.DoesNotContain('\r', detail);
        Assert.Equal("first line second line third line", detail);
    }

    [Fact]
    public void TheExceptionChainIsRecordedAsEvidence()
    {
        var outer = new InvalidOperationException(
            "outer",
            new IOException("io", new AuthenticationException("tls")));

        StageResult result = NewResult();
        LoginStage.RecordInnerCause(outer, result);

        Assert.Equal("IOException -> AuthenticationException", result.Evidence["Underlying exception"]);
    }

    /// <summary>
    /// When nothing in the chain is a TLS fault, the deepest message is still the most
    /// specific one, so it is recorded rather than discarded.
    /// </summary>
    [Fact]
    public void ANonTlsChainRecordsTheDeepestCauseWithoutInventingATlsFinding()
    {
        var outer = new InvalidOperationException(
            "outer",
            new IOException("io", new SocketException_Stub("connection reset by peer")));

        StageResult result = NewResult();
        LoginStage.RecordInnerCause(outer, result);

        Assert.DoesNotContain(result.Findings, f => f.Code == "SCA0703");
        Assert.Equal("connection reset by peer", result.Evidence["Underlying cause"]);
    }

    [Fact]
    public void AnExceptionWithNoInnerCauseRecordsNothing()
    {
        StageResult result = NewResult();

        LoginStage.RecordInnerCause(new InvalidOperationException("alone"), result);

        Assert.Empty(result.Findings);
        Assert.Empty(result.Evidence);
    }

    private sealed class SocketException_Stub(string message) : Exception(message);
}
