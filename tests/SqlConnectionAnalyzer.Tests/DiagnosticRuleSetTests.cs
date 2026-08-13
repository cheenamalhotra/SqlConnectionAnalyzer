using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Probes;
using SqlConnectionAnalyzer.Core.Rules;

namespace SqlConnectionAnalyzer.Tests;

public class DiagnosticRuleSetTests
{
    private static SqlErrorFacts Login(byte state) =>
        new(18456, state, 14, "Login failed for user 'sa'.");

    [Fact]
    public void TheBuiltInKnowledgeBaseLoadsFromTheEmbeddedResource()
    {
        DiagnosticRuleSet rules = DiagnosticRuleSet.BuiltIn;

        Assert.NotEmpty(rules.Rules);
        Assert.All(rules.Rules, r => Assert.False(string.IsNullOrWhiteSpace(r.Code)));
        Assert.All(rules.Rules, r => Assert.NotEmpty(r.ErrorNumbers));
    }

    [Fact]
    public void EveryRuleCodeIsUnique()
    {
        string[] codes = DiagnosticRuleSet.BuiltIn.Rules.Select(r => r.Code).ToArray();

        Assert.Equal(codes.Length, codes.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    /// <summary>
    /// The whole point of the state table: a state-qualified rule must win over the
    /// catch-all defined for the same error number.
    /// </summary>
    [Theory]
    [InlineData(5, "SQL18456.5")]
    [InlineData(2, "SQL18456.5")]
    [InlineData(6, "SQL18456.6")]
    [InlineData(7, "SQL18456.7")]
    [InlineData(8, "SQL18456.8")]
    [InlineData(9, "SQL18456.8")]
    [InlineData(11, "SQL18456.11")]
    [InlineData(18, "SQL18456.18")]
    [InlineData(38, "SQL18456.38")]
    [InlineData(58, "SQL18456.58")]
    [InlineData(104, "SQL18456.104")]
    [InlineData(146, "SQL18456.146")]
    public void StateQualifiedRulesBeatTheCatchAll(byte state, string expectedCode)
    {
        Finding finding = DiagnosticRuleSet.BuiltIn.Classify(Login(state), DiagnosticLayer.Authentication);

        Assert.Equal(expectedCode, finding.Code);
    }

    /// <summary>SQL Server masks the true state as 1, so that path must stay useful.</summary>
    [Fact]
    public void TheMaskedStateFallsBackToTheExplanatoryRule()
    {
        Finding finding = DiagnosticRuleSet.BuiltIn.Classify(Login(1), DiagnosticLayer.Authentication);

        Assert.Equal("SQL18456", finding.Code);
        Assert.Contains("masks", string.Join(" ", finding.Remediation), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnUnknownErrorProducesAGenericFindingInTheFallbackLayer()
    {
        var facts = new SqlErrorFacts(999999, 3, 16, "Something unusual happened.");

        Finding finding = DiagnosticRuleSet.BuiltIn.Classify(facts, DiagnosticLayer.Resiliency);

        Assert.Equal("SQL999999", finding.Code);
        Assert.Equal(DiagnosticLayer.Resiliency, finding.Layer);
        Assert.Equal("Something unusual happened.", finding.Detail);
    }

    [Fact]
    public void TemplateTokensAreExpandedFromTheError()
    {
        Finding finding = DiagnosticRuleSet.BuiltIn.Classify(Login(1), DiagnosticLayer.Authentication);

        Assert.Contains("state 1", finding.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("{state}", finding.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheServerMessageBecomesTheDetailWhenNoneIsSpecified()
    {
        Finding finding = DiagnosticRuleSet.BuiltIn.Classify(Login(8), DiagnosticLayer.Authentication);

        Assert.Equal("Login failed for user 'sa'.", finding.Detail);
    }

    [Fact]
    public void CustomRulesOverrideBuiltInGuidanceByCode()
    {
        const string json = """
            {
              "version": 1,
              "rules": [
                {
                  "code": "SQL18456.8",
                  "errorNumbers": [18456],
                  "states": [8],
                  "layer": "Authentication",
                  "message": "See internal runbook KB-1234.",
                  "remediation": ["Contact the database on-call team."]
                }
              ]
            }
            """;

        DiagnosticRuleSet merged = DiagnosticRuleSet.BuiltIn.MergedWith(DiagnosticRuleSet.FromJson(json));
        Finding finding = merged.Classify(Login(8), DiagnosticLayer.Authentication);

        Assert.Equal("See internal runbook KB-1234.", finding.Message);
        // Overriding must not drop the rest of the knowledge base.
        Assert.Equal("SQL4060", merged.Classify(new SqlErrorFacts(4060, 1, 11, "x"), DiagnosticLayer.Authentication).Code);
    }

    [Fact]
    public void NewRulesCanBeAddedWithoutRecompiling()
    {
        const string json = """
            {
              "version": 1,
              "rules": [
                {
                  "code": "SQL12345",
                  "errorNumbers": [12345],
                  "layer": "Transport",
                  "severity": "Warning",
                  "message": "Custom error {number} on {server}.",
                  "remediation": ["Do the thing."]
                }
              ]
            }
            """;

        DiagnosticRuleSet merged = DiagnosticRuleSet.BuiltIn.MergedWith(DiagnosticRuleSet.FromJson(json));
        var facts = new SqlErrorFacts(12345, 1, 16, "raw", Server: "sql01");

        Finding finding = merged.Classify(facts, DiagnosticLayer.Authentication);

        Assert.Equal("Custom error 12345 on sql01.", finding.Message);
        Assert.Equal(Severity.Warning, finding.Severity);
        Assert.Equal(DiagnosticLayer.Transport, finding.Layer);
    }

    [Theory]
    [InlineData("""{"version":1,"rules":[{"errorNumbers":[1],"message":"no code"}]}""")]
    [InlineData("""{"version":1,"rules":[{"code":"X","message":"no numbers"}]}""")]
    public void MalformedRulesAreRejectedRatherThanSilentlyIgnored(string json)
    {
        Assert.Throws<InvalidDataException>(() => DiagnosticRuleSet.FromJson(json));
    }

    [Fact]
    public void TheClassifierUsesTheBuiltInSetByDefault()
    {
        Finding finding = SqlErrorClassifier.Classify(Login(8), DiagnosticLayer.Authentication);

        Assert.Equal("SQL18456.8", finding.Code);
    }

    /// <summary>
    /// SqlClient reports a failed TLS negotiation as provider error 35 with an HRESULT in
    /// place of a server error number. These must be attributed to the TLS layer, because
    /// blaming authentication sends the user hunting for a password problem that is not there.
    /// </summary>
    [Theory]
    [InlineData(-2146893019, "SQLPRELOGIN.UNTRUSTEDROOT")]
    [InlineData(-2146762487, "SQLPRELOGIN.UNTRUSTEDROOT")]
    [InlineData(-2146762481, "SQLPRELOGIN.NAMEMISMATCH")]
    [InlineData(-2146893022, "SQLPRELOGIN.NAMEMISMATCH")]
    [InlineData(-2146893016, "SQLPRELOGIN.CERTEXPIRED")]
    [InlineData(-2146762495, "SQLPRELOGIN.CERTEXPIRED")]
    public void PreLoginHandshakeHresultsAreDiagnosedAsTlsFailures(int number, string expectedCode)
    {
        var facts = new SqlErrorFacts(
            number,
            0,
            20,
            "A connection was successfully established with the server, but then an error "
                + "occurred during the pre-login handshake. (provider: TCP Provider, error: 35)");

        Finding finding = DiagnosticRuleSet.BuiltIn.Classify(facts, DiagnosticLayer.Authentication);

        Assert.Equal(expectedCode, finding.Code);
        Assert.Equal(DiagnosticLayer.Tls, finding.Layer);
        Assert.NotEmpty(finding.Remediation);
        Assert.DoesNotContain("SQL Server returned", finding.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A negative number is an HRESULT raised on the client, so the server never sent a
    /// state or class. Reporting "state 0, class 20" as if the server spoke is a fabrication.
    /// </summary>
    [Fact]
    public void AnUnmappedClientHresultIsNotReportedAsAServerError()
    {
        var facts = new SqlErrorFacts(-2146893048, 0, 20, "An internal exception was caught.");

        Finding finding = DiagnosticRuleSet.BuiltIn.Classify(facts, DiagnosticLayer.Authentication);

        Assert.DoesNotContain("SQL Server returned", finding.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("state 0", finding.Message, StringComparison.Ordinal);
        Assert.Contains("0x80090308", finding.Message, StringComparison.Ordinal);
        Assert.Equal("SQLCLIENT0x80090308", finding.Code);
    }

    [Fact]
    public void AnUnmappedServerErrorStillReportsStateAndClass()
    {
        var facts = new SqlErrorFacts(31337, 3, 16, "Something unusual.");

        Finding finding = DiagnosticRuleSet.BuiltIn.Classify(facts, DiagnosticLayer.Authentication);

        Assert.Equal("SQL31337", finding.Code);
        Assert.Contains("SQL Server returned error 31337 (state 3, class 16)", finding.Message, StringComparison.Ordinal);
    }
}
