using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Core.Probes;

/// <summary>Result of splitting a Data Source value into its protocol/host/instance/port parts.</summary>
public sealed record ServerSpec(
    NetworkProtocol Protocol,
    string Host,
    string? InstanceName,
    int? Port,
    bool IsAdminConnection);

/// <summary>
/// Parses the <c>Data Source</c> value the same way Microsoft.Data.SqlClient does:
/// <c>[protocol:]host[\instance][,port]</c>, plus the <c>admin:</c> DAC prefix.
/// </summary>
public static class ServerNameParser
{
    public const int DefaultPort = 1433;
    public const int BrowserPort = 1434;

    public static ServerSpec Parse(string? dataSource)
    {
        string value = (dataSource ?? string.Empty).Trim();
        bool isAdmin = false;
        var protocol = NetworkProtocol.Unknown;

        // Prefixes may be chained, e.g. "admin:tcp:server,1433".
        while (true)
        {
            int colon = value.IndexOf(':');
            if (colon <= 0)
            {
                break;
            }

            string prefix = value[..colon].Trim();
            NetworkProtocol? matched = prefix.ToLowerInvariant() switch
            {
                "tcp" => NetworkProtocol.Tcp,
                "np" => NetworkProtocol.NamedPipes,
                "lpc" => NetworkProtocol.SharedMemory,
                "admin" => NetworkProtocol.Admin,
                _ => null
            };

            if (matched is null)
            {
                break;
            }

            if (matched == NetworkProtocol.Admin)
            {
                isAdmin = true;
            }
            else
            {
                protocol = matched.Value;
            }

            value = value[(colon + 1)..].Trim();
        }

        if (value.StartsWith(@"\\", StringComparison.Ordinal))
        {
            protocol = NetworkProtocol.NamedPipes;
        }

        if (protocol == NetworkProtocol.Unknown)
        {
            protocol = NetworkProtocol.Tcp;
        }

        int? port = null;
        int comma = value.LastIndexOf(',');
        if (comma >= 0)
        {
            string portText = value[(comma + 1)..].Trim();
            if (int.TryParse(portText, out int parsedPort))
            {
                port = parsedPort;
                value = value[..comma].Trim();
            }
        }

        string? instance = null;
        int backslash = value.IndexOf('\\');
        if (backslash >= 0 && protocol != NetworkProtocol.NamedPipes)
        {
            instance = value[(backslash + 1)..].Trim();
            value = value[..backslash].Trim();
            if (instance.Length == 0)
            {
                instance = null;
            }
        }

        return new ServerSpec(protocol, value, instance, port, isAdmin);
    }

    /// <summary>Classifies the endpoint so stages can apply cloud- or on-prem-specific expectations.</summary>
    public static EndpointKind Classify(string host, string? instanceName)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return EndpointKind.Unknown;
        }

        string h = host.Trim().ToLowerInvariant();

        if (h.StartsWith("(localdb)", StringComparison.Ordinal))
        {
            return EndpointKind.LocalDb;
        }

        if (h is "." or "localhost" or "127.0.0.1" or "::1" or "(local)")
        {
            return EndpointKind.Loopback;
        }

        if (h.EndsWith(".database.windows.net", StringComparison.Ordinal))
        {
            // Managed Instance host names carry a generated DNS zone segment.
            return CountSegments(h) >= 5 ? EndpointKind.AzureSqlManagedInstance : EndpointKind.AzureSqlDatabase;
        }

        if (h.EndsWith(".sql.azuresynapse.net", StringComparison.Ordinal) ||
            h.EndsWith(".database.windows.net.", StringComparison.Ordinal))
        {
            return EndpointKind.AzureSynapse;
        }

        if (h.EndsWith(".datawarehouse.fabric.microsoft.com", StringComparison.Ordinal) ||
            h.EndsWith(".datawarehouse.pbidedicated.windows.net", StringComparison.Ordinal))
        {
            return EndpointKind.Fabric;
        }

        return EndpointKind.OnPremises;
    }

    private static int CountSegments(string host) => host.Split('.', StringSplitOptions.RemoveEmptyEntries).Length;
}
