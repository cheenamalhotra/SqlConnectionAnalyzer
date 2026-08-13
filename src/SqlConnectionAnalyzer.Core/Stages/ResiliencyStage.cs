using System.Diagnostics;
using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Core.Stages;

/// <summary>
/// Stage 8. Measures how much headroom the connection actually has once it works.
/// <para>
/// A connection that succeeds in a quiet test can still fail under load, and the two most
/// common causes look identical from the outside: a cold open that nearly exhausts
/// Connect Timeout, and a pool that runs out of slots. This stage separates them by timing a
/// cold open against pooled reuse and comparing both to the configured budget.
/// </para>
/// </summary>
public sealed class ResiliencyStage : IDiagnosticStage
{
    private const int PooledSampleCount = 5;

    /// <summary>Fraction of Connect Timeout a cold open may consume before it is called fragile.</summary>
    private const double HeadroomWarningRatio = 0.5;

    public string Id => "resiliency";

    public string Title => "Resiliency and pooling";

    public bool AppliesTo(DiagnosticContext context) => context.Options.AttemptLogin && context.LoginSucceeded;

    public async Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken)
    {
        ReviewConfiguration(context, result);
        await MeasureOpenLatencyAsync(context, result, cancellationToken).ConfigureAwait(false);
    }

    private static void ReviewConfiguration(DiagnosticContext context, StageResult result)
    {
        SqlConnectionStringBuilder builder = context.Builder;

        result.Record("Connect timeout", $"{builder.ConnectTimeout} s");
        result.Record("Connection pooling", builder.Pooling ? "enabled" : "disabled");
        result.Record("Pool size", $"min {builder.MinPoolSize}, max {builder.MaxPoolSize}");
        result.Record("Connection retry", $"count {builder.ConnectRetryCount}, interval {builder.ConnectRetryInterval} s");

        if (!builder.Pooling)
        {
            result.Add(Finding.Warn(
                "SCA0800",
                DiagnosticLayer.Resiliency,
                "Connection pooling is disabled.",
                "Every open pays the full TCP, TLS, and LOGIN7 cost. On Azure SQL that is typically "
                    + "tens to hundreds of milliseconds per call and multiplies under load.",
                "Remove 'Pooling=false' unless a specific requirement forces it."));
        }

        if (builder.ConnectRetryCount == 0)
        {
            result.Add(Finding.Warn(
                "SCA0801",
                DiagnosticLayer.Resiliency,
                "Idle connection resiliency is disabled (ConnectRetryCount=0).",
                "SqlClient will not transparently recover a broken idle connection, so routine Azure "
                    + "SQL maintenance and failovers surface as application errors.",
                "Set ConnectRetryCount to 3 (the default) or higher."));
        }

        if (builder.ConnectTimeout is > 0 and < 15 &&
            context.EndpointKind is Model.EndpointKind.AzureSqlDatabase or Model.EndpointKind.AzureSynapse)
        {
            result.Add(Finding.Warn(
                "SCA0802",
                DiagnosticLayer.Resiliency,
                $"Connect Timeout is {builder.ConnectTimeout} s, which is aggressive for Azure SQL.",
                "Gateway redirection plus TLS plus token acquisition can exceed a short budget during "
                    + "a failover, turning a recoverable blip into a hard failure.",
                "Use at least 30 seconds for Azure SQL endpoints."));
        }

        if (builder.MaxPoolSize < 100)
        {
            result.Add(Finding.Info(
                "SCA0803",
                DiagnosticLayer.Resiliency,
                $"Max Pool Size is lowered to {builder.MaxPoolSize}.",
                "Once every slot is leased, further opens block until Connect Timeout elapses and then "
                    + "throw a timeout that looks exactly like a network failure. If timeouts appear only "
                    + "under load, this is the first thing to rule out."));
        }
    }

    /// <summary>
    /// Times one cold open (pooling off) and several pooled opens. The gap between them is the
    /// real cost of a handshake, and the cold figure is what a failover has to fit inside.
    /// </summary>
    private static async Task MeasureOpenLatencyAsync(
        DiagnosticContext context,
        StageResult result,
        CancellationToken cancellationToken)
    {
        var coldBuilder = new SqlConnectionStringBuilder(context.ConnectionString) { Pooling = false };
        var pooledBuilder = new SqlConnectionStringBuilder(context.ConnectionString) { Pooling = true };

        TimeSpan? cold = await TimeOpenAsync(context, coldBuilder, result, cancellationToken).ConfigureAwait(false);
        if (cold is null)
        {
            return;
        }

        result.Record("Cold open (no pool)", $"{cold.Value.TotalMilliseconds:0} ms");

        var pooledSamples = new List<double>(PooledSampleCount);
        for (int i = 0; i < PooledSampleCount; i++)
        {
            TimeSpan? sample = await TimeOpenAsync(context, pooledBuilder, result, cancellationToken).ConfigureAwait(false);
            if (sample is null)
            {
                return;
            }

            pooledSamples.Add(sample.Value.TotalMilliseconds);
        }

        // The first pooled open still performs a handshake; later ones measure reuse.
        double warmAverage = pooledSamples.Skip(1).DefaultIfEmpty(pooledSamples[0]).Average();
        result.Record("Pooled reuse (avg)", $"{warmAverage:0.0} ms over {pooledSamples.Count - 1} samples");
        result.Record("Pooled samples", string.Join(", ", pooledSamples.Select(s => $"{s:0.0} ms")));

        int connectTimeoutSeconds = context.Builder.ConnectTimeout;
        if (connectTimeoutSeconds > 0)
        {
            double ratio = cold.Value.TotalSeconds / connectTimeoutSeconds;
            result.Record("Cold open vs timeout budget", $"{ratio * 100:0.0}% of {connectTimeoutSeconds} s");

            if (ratio >= HeadroomWarningRatio)
            {
                result.Add(Finding.Warn(
                    "SCA0810",
                    DiagnosticLayer.Resiliency,
                    $"A cold open consumes {ratio * 100:0}% of the Connect Timeout budget.",
                    "There is little margin left for a transient slowdown, so intermittent timeouts are likely.",
                    "Raise Connect Timeout, or investigate why the handshake is slow (DNS, TLS, or geographic distance)."));
            }
        }

        result.Add(Finding.Info(
            "SCA0811",
            DiagnosticLayer.Resiliency,
            $"Handshake costs about {cold.Value.TotalMilliseconds:0} ms; pooled reuse costs about {warmAverage:0.0} ms.",
            "Use this gap to judge how much pooling is saving and whether a timeout under load would be "
                + "pool exhaustion rather than a network fault."));
    }

    private static async Task<TimeSpan?> TimeOpenAsync(
        DiagnosticContext context,
        SqlConnectionStringBuilder builder,
        StageResult result,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(builder.ConnectionString);

        if (context.AccessToken is { } token && RequiresExplicitToken(builder))
        {
            connection.AccessToken = token;
        }

        var sw = Stopwatch.StartNew();
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            sw.Stop();
            return sw.Elapsed;
        }
        catch (SqlException ex)
        {
            sw.Stop();

            // The login stage already proved credentials work, so a failure here is instability.
            result.Add(Finding.Warn(
                "SCA0812",
                DiagnosticLayer.Resiliency,
                "A repeat connection failed even though the initial login succeeded.",
                $"Failed after {sw.Elapsed.TotalMilliseconds:0} ms: {ex.Message}"));

            foreach (SqlError error in ex.Errors)
            {
                result.Add(SqlErrorClassifier.Classify(error, DiagnosticLayer.Resiliency));
            }

            return null;
        }
    }

    private static bool RequiresExplicitToken(SqlConnectionStringBuilder builder) =>
        builder.Authentication == SqlAuthenticationMethod.NotSpecified &&
        !builder.IntegratedSecurity &&
        string.IsNullOrEmpty(builder.UserID);
}
