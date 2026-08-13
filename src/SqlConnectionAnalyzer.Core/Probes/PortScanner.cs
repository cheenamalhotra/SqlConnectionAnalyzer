using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SqlConnectionAnalyzer.Core.Probes;

/// <summary>How a TCP endpoint responded to a connection attempt.</summary>
public enum PortReachability
{
    /// <summary>The handshake completed; something is listening.</summary>
    Open,

    /// <summary>The host actively refused with an RST, so packets do reach it.</summary>
    Refused,

    /// <summary>No response at all, which is the signature of a dropping firewall.</summary>
    Filtered
}

/// <summary>
/// Distinguishes a filtered port from a merely closed one.
/// <para>
/// This distinction is what makes the Azure SQL Redirect diagnosis possible: a closed port
/// answers with an RST, proving outbound traffic on that port is permitted, whereas a
/// firewall that silently drops packets produces a timeout. Both look like "cannot connect"
/// to SqlClient, but they call for completely different fixes.
/// </para>
/// </summary>
public static class PortScanner
{
    public static async Task<PortReachability> ProbeAsync(
        IPAddress address,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), timeoutCts.Token).ConfigureAwait(false);
            return PortReachability.Open;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return PortReachability.Refused;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return PortReachability.Filtered;
        }
        catch (SocketException)
        {
            return PortReachability.Filtered;
        }
    }

    /// <summary>Probes a sample of ports and reports how many were reachable in any form.</summary>
    public static async Task<IReadOnlyDictionary<int, PortReachability>> ProbeManyAsync(
        IPAddress address,
        IEnumerable<int> ports,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var results = new Dictionary<int, PortReachability>();

        foreach (int port in ports)
        {
            results[port] = await ProbeAsync(address, port, timeout, cancellationToken).ConfigureAwait(false);
        }

        return results;
    }
}
