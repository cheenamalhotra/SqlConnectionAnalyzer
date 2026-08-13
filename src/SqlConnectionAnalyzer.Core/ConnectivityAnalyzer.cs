using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Core;

/// <summary>Raised as each stage transitions so a UI can render a live checklist.</summary>
public sealed class StageProgressEventArgs : EventArgs
{
    public required StageResult Result { get; init; }

    public required int Index { get; init; }

    public required int Total { get; init; }
}

/// <summary>
/// Runs the ordered set of stages that mirror the MS-TDS login flow, stopping at the
/// first fatal failure so the report points at a single responsible layer.
/// </summary>
public sealed class ConnectivityAnalyzer
{
    private readonly IReadOnlyList<IDiagnosticStage> _stages;

    public ConnectivityAnalyzer(IEnumerable<IDiagnosticStage> stages) => _stages = stages.ToList();

    public event EventHandler<StageProgressEventArgs>? StageStarted;

    public event EventHandler<StageProgressEventArgs>? StageCompleted;

    public async Task<AnalysisReport> AnalyzeAsync(
        string connectionString,
        AnalyzerOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new AnalyzerOptions();

        var report = new AnalysisReport
        {
            RedactedConnectionString = Redactor.ConnectionString(connectionString),
            StartedAt = DateTimeOffset.Now
        };

        SqlConnectionStringBuilder builder;
        try
        {
            builder = new SqlConnectionStringBuilder(connectionString);
        }
        catch (Exception ex)
        {
            var parseFailure = StageResult.Start("connection-string", "Connection string");
            parseFailure.Add(Finding.Error(
                "SCA0001",
                DiagnosticLayer.Configuration,
                "The connection string could not be parsed.",
                ex.Message,
                "Check for unbalanced quotes, stray semicolons, or keywords that Microsoft.Data.SqlClient does not recognize."));
            parseFailure.IsFatal = true;
            report.Stages.Add(parseFailure);
            return report;
        }

        var context = new DiagnosticContext
        {
            ConnectionString = connectionString,
            Builder = builder,
            Options = options
        };

        // The listener must be attached before any SqlClient work so nothing is missed.
        SqlClientEventListener? listener = options.CaptureEventSource ? new SqlClientEventListener() : null;

        try
        {
            await RunStagesAsync(report, context, options, cancellationToken).ConfigureAwait(false);

            if (options.MatrixMode)
            {
                await RunMatrixAsync(report, context, options, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            if (listener is not null)
            {
                report.TraceEvents.AddRange(listener.Events);
                listener.Dispose();
            }
        }

        report.EndpointKind = context.EndpointKind;
        return report;
    }

    /// <summary>
    /// Runs the analysis, yielding each stage transition as it happens and the completed
    /// report as the final item. This is the API a live UI should use: it turns the
    /// event-based progress notifications into a sequence that can be consumed with
    /// <c>await foreach</c>, with cancellation and back-pressure handled for the caller.
    /// </summary>
    /// <remarks>
    /// Progress events are instance-scoped, so a single analyzer instance must not run two
    /// analyses concurrently. Create one instance per analysis (see <see cref="AnalyzerFactory"/>).
    /// </remarks>
    public async IAsyncEnumerable<AnalysisProgress> AnalyzeStreamAsync(
        string connectionString,
        AnalyzerOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var channel = Channel.CreateUnbounded<AnalysisProgress>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });

        void OnStarted(object? _, StageProgressEventArgs e) =>
            channel.Writer.TryWrite(new AnalysisProgress.StageStarted(StageSnapshot.From(e.Result), e.Index, e.Total));

        void OnFinished(object? _, StageProgressEventArgs e) =>
            channel.Writer.TryWrite(new AnalysisProgress.StageFinished(StageSnapshot.From(e.Result), e.Index, e.Total));

        StageStarted += OnStarted;
        StageCompleted += OnFinished;

        // The pipeline runs detached so the reader can drain progress while it is still going.
        Task worker = Task.Run(
            async () =>
            {
                try
                {
                    AnalysisReport report = await AnalyzeAsync(connectionString, options, cancellationToken)
                        .ConfigureAwait(false);
                    channel.Writer.TryWrite(new AnalysisProgress.Finished(report));
                    channel.Writer.TryComplete();
                }
                catch (Exception ex)
                {
                    // Surfaced to the consumer on the next read rather than lost on a background task.
                    channel.Writer.TryComplete(ex);
                }
            },
            CancellationToken.None);

        try
        {
            await foreach (AnalysisProgress progress in channel.Reader
                .ReadAllAsync(cancellationToken)
                .ConfigureAwait(false))
            {
                yield return progress;
            }
        }
        finally
        {
            StageStarted -= OnStarted;
            StageCompleted -= OnFinished;

            // Observe the worker so a fault never becomes an unobserved task exception.
            await worker.ConfigureAwait(false);
        }
    }

    private async Task RunStagesAsync(
        AnalysisReport report,
        DiagnosticContext context,
        AnalyzerOptions options,
        CancellationToken cancellationToken)
    {
        var overall = Stopwatch.StartNew();
        bool aborted = false;

        for (int i = 0; i < _stages.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IDiagnosticStage stage = _stages[i];
            var result = StageResult.Start(stage.Id, stage.Title);
            report.Stages.Add(result);

            var args = new StageProgressEventArgs { Result = result, Index = i, Total = _stages.Count };
            StageStarted?.Invoke(this, args);

            if (aborted)
            {
                result.Skip("A previous stage failed fatally.");
            }
            else if (!stage.AppliesTo(context))
            {
                result.Status = StageStatus.NotApplicable;
                result.SkipReason = "Not applicable to this endpoint or authentication mode.";
            }
            else
            {
                using (result.Timer())
                {
                    try
                    {
                        using var stageCts =
                            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        stageCts.CancelAfter(options.ProbeTimeout);
                        await stage.RunAsync(context, result, stageCts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                    {
                        result.Add(Finding.Error(
                            "SCA0002",
                            DiagnosticLayer.Transport,
                            $"Stage timed out after {options.ProbeTimeout.TotalSeconds:0.#}s.",
                            null,
                            "Increase the probe timeout, or investigate a firewall silently dropping packets."));
                        result.IsFatal = true;
                    }
                    catch (SocketException ex)
                    {
                        result.Add(Finding.Error(
                            "SCA0004",
                            DiagnosticLayer.Transport,
                            $"The socket failed with {ex.SocketErrorCode}.",
                            DescribeSocketFailure(ex, result.StageId),
                            SocketRemediation(ex)));
                        result.IsFatal = true;
                    }
                    catch (Exception ex)
                    {
                        // Only the type and message are surfaced: a stack trace carries build-machine
                        // paths that mean nothing to the user and would leak into support tickets.
                        result.Record("Exception", ex.ToString());
                        result.Add(Finding.Error(
                            "SCA0003",
                            DiagnosticLayer.Configuration,
                            "The stage threw an unexpected exception.",
                            $"{ex.GetType().Name}: {ex.Message}",
                            "Re-run with --verbose to see the full exception.",
                            "If this looks like a defect in the analyzer, please report it with that output."));
                    }
                }

                result.MarkPassed();

                if (result.IsFatal && !options.ContinueOnFatal)
                {
                    aborted = true;
                }
            }

            StageCompleted?.Invoke(this, args);
        }

        overall.Stop();
        report.TotalElapsed = overall.Elapsed;
    }

    /// <summary>
    /// Re-runs the connection across encryption permutations so the report can name the
    /// specific setting responsible rather than merely reporting that something failed.
    /// <para>
    /// Skipped when a layer below TLS already failed: every permutation would fail for the
    /// same unrelated reason, costing one full connect timeout each and burying the real
    /// verdict under noise.
    /// </para>
    /// </summary>
    private static async Task RunMatrixAsync(
        AnalysisReport report,
        DiagnosticContext context,
        AnalyzerOptions options,
        CancellationToken cancellationToken)
    {
        if (report.FirstFailure is { } failure && IsBelowEncryption(failure))
        {
            report.MatrixVerdict = Finding.Info(
                "SCA1005",
                DiagnosticLayer.Tls,
                "The encryption matrix was skipped.",
                $"'{failure.Title}' failed below the encryption layer, so no encryption setting could "
                    + "change the outcome. Resolve that stage first, then re-run with --matrix.");
            return;
        }

        IReadOnlyList<MatrixOutcome> outcomes = await ConnectionMatrixRunner
            .RunAsync(context.ConnectionString, context.AccessToken, options.ProbeTimeout, cancellationToken)
            .ConfigureAwait(false);

        report.MatrixOutcomes.AddRange(outcomes);
        report.MatrixVerdict = ConnectionMatrixRunner.Interpret(outcomes);
    }

    /// <summary>Stages whose failure makes any encryption experiment meaningless.</summary>
    /// <summary>
    /// Explains a socket failure in terms of what the peer did. A refusal or reset that arrives
    /// after the TCP stage already succeeded is especially informative: the endpoint's behaviour
    /// changed between two probes seconds apart, which points at something in front of SQL Server
    /// rather than at SQL Server itself.
    /// </summary>
    private static string DescribeSocketFailure(SocketException ex, string stageId)
    {
        string basis = ex.SocketErrorCode switch
        {
            SocketError.ConnectionRefused =>
                "The peer actively refused the connection (TCP RST). Nothing is listening on that port now.",
            SocketError.ConnectionReset =>
                "The peer reset an established connection. A device closed it mid-conversation.",
            SocketError.TimedOut =>
                "The connection attempt timed out with no response at all, which is the signature of a packet filter that drops rather than rejects.",
            SocketError.HostUnreachable or SocketError.NetworkUnreachable =>
                "No route to the host. The address is not reachable from this network.",
            SocketError.AddressNotAvailable =>
                "The local address could not be used for an outbound connection.",
            _ => $"Socket error {ex.SocketErrorCode} ({ex.ErrorCode})."
        };

        bool afterTcpProbe = stageId is not ("tcp-reachability" or "name-resolution" or "connection-string");

        return afterTcpProbe
            ? basis + " Note that the TCP reachability stage connected successfully moments earlier, "
                    + "so the endpoint stopped accepting connections between the two probes."
            : basis;
    }

    private static string[] SocketRemediation(SocketException ex) => ex.SocketErrorCode switch
    {
        SocketError.ConnectionRefused =>
        [
            "Confirm the SQL Server service is running and still listening on that port.",
            "If a load balancer or proxy fronts the server, check whether the backend pool is healthy.",
            "A port that accepts one connection and then refuses the next often indicates a health-check-only listener."
        ],
        SocketError.ConnectionReset =>
        [
            "Look for a firewall, proxy, or load balancer terminating connections that do not match an expected protocol.",
            "Confirm the port really serves SQL Server and not another service."
        ],
        SocketError.TimedOut =>
        [
            "Check network ACLs, security groups, or a host firewall dropping packets silently.",
            "For Azure SQL, confirm the client IP is allowed by the server firewall."
        ],
        SocketError.HostUnreachable or SocketError.NetworkUnreachable =>
        [
            "Verify routing and VPN or ExpressRoute connectivity to the target network."
        ],
        _ => ["Investigate host networking and any device between this client and the server."]
    };

    private static bool IsBelowEncryption(StageResult failure) =>
        failure.StageId is "connection-string" or "name-resolution" or "tcp-reachability" or "tds-prelogin";
}
