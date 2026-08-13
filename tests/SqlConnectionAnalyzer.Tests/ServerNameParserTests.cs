using SqlConnectionAnalyzer.Core.Model;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Tests;

public class ServerNameParserTests
{
    [Theory]
    [InlineData("myserver", "myserver", null, null)]
    [InlineData("myserver,1433", "myserver", null, 1433)]
    [InlineData("myserver\\SQLEXPRESS", "myserver", "SQLEXPRESS", null)]
    [InlineData("myserver\\SQLEXPRESS,1450", "myserver", "SQLEXPRESS", 1450)]
    [InlineData("tcp:myserver,1433", "myserver", null, 1433)]
    [InlineData("  tcp:myserver , 1433 ", "myserver", null, 1433)]
    public void ParsesHostInstanceAndPort(string dataSource, string host, string? instance, int? port)
    {
        ServerSpec spec = ServerNameParser.Parse(dataSource);

        Assert.Equal(host, spec.Host);
        Assert.Equal(instance, spec.InstanceName);
        Assert.Equal(port, spec.Port);
    }

    [Fact]
    public void DefaultsToTcpWhenNoPrefixIsPresent()
    {
        Assert.Equal(NetworkProtocol.Tcp, ServerNameParser.Parse("myserver").Protocol);
    }

    [Fact]
    public void RecognizesNamedPipesPrefix()
    {
        Assert.Equal(NetworkProtocol.NamedPipes, ServerNameParser.Parse(@"np:\\server\pipe\sql\query").Protocol);
    }

    [Fact]
    public void RecognizesDedicatedAdminConnection()
    {
        ServerSpec spec = ServerNameParser.Parse("admin:myserver");

        Assert.True(spec.IsAdminConnection);
        Assert.Equal("myserver", spec.Host);
    }

    [Theory]
    [InlineData("myserver.database.windows.net", EndpointKind.AzureSqlDatabase)]
    [InlineData("myinstance.abcd1234ef.database.windows.net", EndpointKind.AzureSqlManagedInstance)]
    [InlineData("myws.sql.azuresynapse.net", EndpointKind.AzureSynapse)]
    [InlineData("localhost", EndpointKind.Loopback)]
    [InlineData(".", EndpointKind.Loopback)]
    [InlineData("sqlprod01.corp.local", EndpointKind.OnPremises)]
    public void ClassifiesEndpoints(string host, EndpointKind expected)
    {
        Assert.Equal(expected, ServerNameParser.Classify(host, null));
    }
}
