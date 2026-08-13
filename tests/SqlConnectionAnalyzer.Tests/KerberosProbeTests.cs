using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Tests;

/// <summary>
/// Exercises all three klist dialects. Assuming a single format would make the probe
/// silently report "no tickets" on the other two platforms, which is worse than no probe.
/// </summary>
public class KerberosProbeTests
{
    private const string MitOutput = """
        Ticket cache: FILE:/tmp/krb5cc_1000
        Default principal: alice@CONTOSO.COM

        Valid starting       Expires              Service principal
        01/15/24 09:00:00    01/15/24 19:00:00    krbtgt/CONTOSO.COM@CONTOSO.COM
        01/15/24 09:05:00    01/15/24 19:00:00    MSSQLSvc/sql01.contoso.com:1433@CONTOSO.COM
        """;

    private const string HeimdalOutput = """
        Credentials cache: API:501:9
                Principal: alice@CONTOSO.COM

          Issued                Expires               Principal
        Jan 15 09:00:00 2024  Jan 15 19:00:00 2024  krbtgt/CONTOSO.COM@CONTOSO.COM
        """;

    private const string WindowsOutput = """
        Current LogonId is 0:0x3e7

        Cached Tickets: (2)

        #0>     Client: alice @ CONTOSO.COM
                Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
                KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
                Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent
        #1>     Client: alice @ CONTOSO.COM
                Server: MSSQLSvc/sql01.contoso.com:1433 @ CONTOSO.COM
                KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        """;

    [Fact]
    public void ParsesMitOutput()
    {
        KerberosState state = KerberosProbe.ParseKlist(MitOutput, 0);

        Assert.True(state.HasCredentialCache);
        Assert.Contains("alice@CONTOSO.COM", state.Principals);
        Assert.True(state.HasTicketGrantingTicket);
        Assert.True(state.HasSqlTicketFor("sql01.contoso.com"));
        Assert.Null(state.Error);
    }

    [Fact]
    public void ParsesHeimdalOutputWhichUsesADifferentPrincipalLabel()
    {
        KerberosState state = KerberosProbe.ParseKlist(HeimdalOutput, 0);

        Assert.True(state.HasCredentialCache);
        Assert.Contains("alice@CONTOSO.COM", state.Principals);
        Assert.True(state.HasTicketGrantingTicket);
        Assert.False(state.HasSqlTicketFor("sql01.contoso.com"));
    }

    [Fact]
    public void ParsesWindowsClientServerPairs()
    {
        KerberosState state = KerberosProbe.ParseKlist(WindowsOutput, 0);

        Assert.True(state.HasCredentialCache);
        Assert.Contains("alice@CONTOSO.COM", state.Principals);
        Assert.True(state.HasTicketGrantingTicket);
        Assert.True(state.HasSqlTicketFor("sql01.contoso.com"));
    }

    [Fact]
    public void WindowsPrincipalSpacingIsNormalised()
    {
        KerberosState state = KerberosProbe.ParseKlist(WindowsOutput, 0);

        Assert.DoesNotContain(state.Principals, p => p.Contains(" @ ", StringComparison.Ordinal));
    }

    [Fact]
    public void DuplicateClientLinesCollapseToASinglePrincipal()
    {
        KerberosState state = KerberosProbe.ParseKlist(WindowsOutput, 0);

        Assert.Single(state.Principals);
    }

    [Theory]
    [InlineData("klist: No credentials cache found (filename: /tmp/krb5cc_1000)")]
    [InlineData("klist: Cache not found: API:7CCC63FA-5912-48C7-9194-A48F15119850")]
    public void RecognisesAnEmptyCacheAndSaysHowToFixIt(string output)
    {
        KerberosState state = KerberosProbe.ParseKlist(output, 1);

        Assert.False(state.HasCredentialCache);
        Assert.Empty(state.Principals);
        Assert.Contains("kinit", state.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TableHeadersAreNotMistakenForTickets()
    {
        KerberosState state = KerberosProbe.ParseKlist(MitOutput, 0);

        Assert.DoesNotContain(state.ServiceTickets, t => t.Contains("Service principal", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, state.ServiceTickets.Count);
    }

    [Fact]
    public void CacheLocationLinesAreNotMistakenForTickets()
    {
        // "FILE:/tmp/krb5cc_1000" and "API:501:9" both contain a slash or colon.
        KerberosState mit = KerberosProbe.ParseKlist(MitOutput, 0);
        Assert.DoesNotContain(mit.ServiceTickets, t => t.Contains("krb5cc", StringComparison.OrdinalIgnoreCase));

        KerberosState heimdal = KerberosProbe.ParseKlist(HeimdalOutput, 0);
        Assert.DoesNotContain(heimdal.ServiceTickets, t => t.Contains("API:", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SqlTicketMatchingIgnoresThePortBecauseSpnsVary()
    {
        KerberosState state = KerberosProbe.ParseKlist(MitOutput, 0);

        Assert.True(state.HasSqlTicketFor("SQL01.CONTOSO.COM"));
        Assert.False(state.HasSqlTicketFor("other.contoso.com"));
    }

    [Theory]
    [InlineData("sql01", 1433, "MSSQLSvc/sql01:1433")]
    [InlineData("SQL01.Contoso.COM", 1433, "MSSQLSvc/sql01.contoso.com:1433")]
    [InlineData("sql01", 14333, "MSSQLSvc/sql01:14333")]
    public void BuildsTheSpnSqlClientWouldUse(string host, int port, string expected)
    {
        Assert.Equal(expected, KerberosProbe.BuildSpn(host, port));
    }

    /// <summary>The probe must never throw on a machine without Kerberos configured.</summary>
    [Fact]
    public async Task InspectingARealMachineDoesNotThrow()
    {
        KerberosState state = await KerberosProbe.InspectAsync(CancellationToken.None);

        Assert.NotNull(state);
        if (!state.HasCredentialCache)
        {
            Assert.False(string.IsNullOrWhiteSpace(state.Error));
        }
    }
}
