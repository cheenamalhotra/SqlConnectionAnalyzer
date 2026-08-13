using System.Text.Json;
using System.Text.Json.Serialization;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Core.Reporting;

/// <summary>Serializes a report to JSON for CI pipelines and support tickets.</summary>
public static class JsonReportWriter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public static async Task WriteAsync(AnalysisReport report, string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, BuildPayload(report), Options, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Serializes to a string, for callers that are not writing to disk.</summary>
    public static string Render(AnalysisReport report) =>
        JsonSerializer.Serialize(BuildPayload(report), Options);

    private static object BuildPayload(AnalysisReport report)
    {
        return new
        {
            report.RedactedConnectionString,
            report.StartedAt,
            TotalElapsedMs = report.TotalElapsed.TotalMilliseconds,
            EndpointKind = report.EndpointKind.ToString(),
            report.Succeeded,
            FirstFailure = report.FirstFailure?.StageId,
            Stages = report.Stages.Select(s => new
            {
                s.StageId,
                s.Title,
                Status = s.Status.ToString(),
                ElapsedMs = s.Elapsed.TotalMilliseconds,
                s.SkipReason,
                Evidence = s.Evidence,
                Findings = s.Findings.Select(f => new
                {
                    f.Code,
                    Severity = f.Severity.ToString(),
                    Layer = f.Layer.ToString(),
                    f.Message,
                    f.Detail,
                    f.Remediation
                })
            }),
            Matrix = report.MatrixOutcomes.Count == 0
                ? null
                : report.MatrixOutcomes.Select(m => new
                {
                    m.Encrypt,
                    m.TrustServerCertificate,
                    m.Succeeded,
                    ElapsedMs = m.Elapsed.TotalMilliseconds,
                    m.ErrorNumber,
                    m.Error
                }),
            MatrixVerdict = report.MatrixVerdict is null
                ? null
                : new
                {
                    report.MatrixVerdict.Code,
                    Severity = report.MatrixVerdict.Severity.ToString(),
                    report.MatrixVerdict.Message,
                    report.MatrixVerdict.Detail,
                    report.MatrixVerdict.Remediation
                },
            Trace = report.TraceEvents.Count == 0
                ? null
                : report.TraceEvents.Select(t => new
                {
                    t.TimestampUtc,
                    t.EventName,
                    t.Message
                })
        };
    }
}
