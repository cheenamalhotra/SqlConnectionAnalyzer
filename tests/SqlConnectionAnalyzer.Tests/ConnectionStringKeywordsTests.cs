using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Tests;

public class ConnectionStringKeywordsTests
{
    [Theory]
    [InlineData("Server=s;Password=p", true)]
    [InlineData("Server=s;PWD=p", true)]
    [InlineData("Server=s;pwd=p", true)]
    [InlineData("Server=s;Password=", true)]     // presence, not value
    [InlineData("Server=s; Password = p ", true)]
    [InlineData("Server=s;User ID=u", false)]
    [InlineData("Server=s", false)]
    [InlineData("", false)]
    public void PasswordPresenceMatchesTheDriverSemantics(string cs, bool expected) =>
        Assert.Equal(expected, ConnectionStringKeywords.HasPassword(cs));

    [Theory]
    [InlineData("Server=s;User ID=u", true)]
    [InlineData("Server=s;UID=u", true)]
    [InlineData("Server=s;Password=p", false)]
    public void UserIdPresenceHandlesSynonyms(string cs, bool expected) =>
        Assert.Equal(expected, ConnectionStringKeywords.HasUserId(cs));

    /// <summary>
    /// A ';' or '=' inside a quoted password must not be mistaken for a separator, or the scan
    /// would report keywords that were never supplied.
    /// </summary>
    [Fact]
    public void SeparatorsInsideAQuotedValueAreNotTreatedAsKeywords()
    {
        string[] keys = ConnectionStringKeywords
            .EnumerateKeywords("Server=s;Password='a;b=c';Encrypt=true")
            .ToArray();

        Assert.Equal(["Server", "Password", "Encrypt"], keys);
    }

    [Fact]
    public void DoubleQuotedValuesAreAlsoHandled()
    {
        string[] keys = ConnectionStringKeywords
            .EnumerateKeywords("Server=s;Password=\"x;y\";Encrypt=true")
            .ToArray();

        Assert.Equal(["Server", "Password", "Encrypt"], keys);
    }
}

public class SpnCandidateTests
{
    /// <summary>
    /// SQL Server registers both forms for a default instance and either may be the one present in
    /// the directory, so the driver accepts both. Offering only the port form caused false
    /// "no cached ticket" warnings.
    /// </summary>
    [Fact]
    public void DefaultPortOffersBothThePortlessAndPortForms()
    {
        IReadOnlyList<string> candidates = KerberosProbe.BuildSpnCandidates("sql.contoso.com", 1433);

        Assert.Contains("MSSQLSvc/sql.contoso.com", candidates);
        Assert.Contains("MSSQLSvc/sql.contoso.com:1433", candidates);
    }

    [Fact]
    public void ANonDefaultPortOffersOnlyThePortForm()
    {
        IReadOnlyList<string> candidates = KerberosProbe.BuildSpnCandidates("sql.contoso.com", 14333);

        Assert.Equal(["MSSQLSvc/sql.contoso.com:14333"], candidates);
    }

    [Fact]
    public void ANamedInstanceOffersBothThePortAndInstanceForms()
    {
        IReadOnlyList<string> candidates =
            KerberosProbe.BuildSpnCandidates("sql.contoso.com", 14333, "SQL2022");

        Assert.Contains("MSSQLSvc/sql.contoso.com:14333", candidates);
        Assert.Contains("MSSQLSvc/sql.contoso.com:SQL2022", candidates);
    }

    /// <summary>The 'Server SPN' keyword is used verbatim by SqlClient and suppresses derivation.</summary>
    [Fact]
    public void TheServerSpnKeywordOverridesEverything()
    {
        IReadOnlyList<string> candidates =
            KerberosProbe.BuildSpnCandidates("sql.contoso.com", 1433, "INST", "MSSQLSvc/custom.contoso.com:1433");

        Assert.Equal(["MSSQLSvc/custom.contoso.com:1433"], candidates);
    }

    [Fact]
    public void TicketMatchingAcceptsARealmSuffix()
    {
        var state = new KerberosState(
            ToolAvailable: true,
            HasCredentialCache: true,
            Principals: ["alice@CONTOSO.COM"],
            ServiceTickets: ["MSSQLSvc/sql.contoso.com:1433@CONTOSO.COM"],
            Error: null);

        Assert.True(state.HasTicketForAny(["MSSQLSvc/sql.contoso.com:1433"]));
        Assert.False(state.HasTicketForAny(["MSSQLSvc/other.contoso.com:1433"]));
    }
}
