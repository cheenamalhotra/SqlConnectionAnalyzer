using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SqlConnectionAnalyzer.Core.Probes;

/// <summary>Instance details returned by the SQL Server Browser service.</summary>
public sealed record BrowserInstanceInfo(
    string ServerName,
    string InstanceName,
    string? Version,
    int? TcpPort,
    bool IsClustered,
    string RawRecord);

/// <summary>
/// Queries the SQL Server Browser (UDP 1434) to resolve a named instance to its TCP port,
/// which is the step that fails with "error 26" when UDP is blocked.
/// </summary>
public static class SqlBrowserProbe
{
    private const byte ClntUcastInst = 0x04;
    private const byte ClntUcastEx = 0x03;

    public static async Task<IReadOnlyList<BrowserInstanceInfo>> QueryAsync(
        IPAddress address,
        string? instanceName,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(address.AddressFamily);
        udp.Client.ReceiveTimeout = (int)timeout.TotalMilliseconds;

        byte[] request = BuildRequest(instanceName);
        var endpoint = new IPEndPoint(address, ServerNameParser.BrowserPort);

        await udp.SendAsync(request, request.Length, endpoint).ConfigureAwait(false);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        UdpReceiveResult response;
        try
        {
            response = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Array.Empty<BrowserInstanceInfo>();
        }

        return Parse(response.Buffer);
    }

    private static byte[] BuildRequest(string? instanceName)
    {
        if (string.IsNullOrEmpty(instanceName))
        {
            return new[] { ClntUcastEx };
        }

        // CLNT_UCAST_INST: opcode followed by the null-terminated ASCII instance name.
        byte[] name = Encoding.ASCII.GetBytes(instanceName);
        var buffer = new byte[name.Length + 2];
        buffer[0] = ClntUcastInst;
        Array.Copy(name, 0, buffer, 1, name.Length);
        buffer[^1] = 0x00;
        return buffer;
    }

    /// <summary>
    /// The response is a 3-byte header (SVR_RESP, 2-byte length) followed by
    /// semicolon-delimited key/value pairs, with instances separated by ";;".
    /// </summary>
    private static IReadOnlyList<BrowserInstanceInfo> Parse(byte[] buffer)
    {
        if (buffer.Length <= 3 || buffer[0] != 0x05)
        {
            return Array.Empty<BrowserInstanceInfo>();
        }

        string payload = Encoding.ASCII.GetString(buffer, 3, buffer.Length - 3).TrimEnd('\0');
        var results = new List<BrowserInstanceInfo>();

        foreach (string block in payload.Split(";;", StringSplitOptions.RemoveEmptyEntries))
        {
            string[] parts = block.Split(';');
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i + 1 < parts.Length; i += 2)
            {
                if (!string.IsNullOrEmpty(parts[i]))
                {
                    map[parts[i]] = parts[i + 1];
                }
            }

            if (map.Count == 0)
            {
                continue;
            }

            results.Add(new BrowserInstanceInfo(
                map.GetValueOrDefault("ServerName", string.Empty),
                map.GetValueOrDefault("InstanceName", string.Empty),
                map.GetValueOrDefault("Version"),
                int.TryParse(map.GetValueOrDefault("tcp"), out int tcp) ? tcp : null,
                string.Equals(map.GetValueOrDefault("IsClustered"), "Yes", StringComparison.OrdinalIgnoreCase),
                block));
        }

        return results;
    }
}
