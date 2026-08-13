using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Core;

/// <summary>Full analysis output, suitable for console rendering or serialization.</summary>
public sealed class AnalysisReport
{
    public required string RedactedConnectionString { get; init; }

    public required DateTimeOffset StartedAt { get; init; }

    public TimeSpan TotalElapsed { get; set; }

    public EndpointKind EndpointKind { get; set; }

    public List<StageResult> Stages { get; } = new();

    /// <summary>Encryption permutation results, populated only in matrix mode.</summary>
    public List<MatrixOutcome> MatrixOutcomes { get; } = new();

    /// <summary>Conclusion drawn from the matrix, if one was run.</summary>
    public Finding? MatrixVerdict { get; set; }

    /// <summary>SqlClient EventSource trace lines, populated only when tracing is enabled.</summary>
    public List<SqlClientTraceEvent> TraceEvents { get; } = new();

    public bool Succeeded => Stages.All(s => s.Status is not StageStatus.Failed);

    /// <summary>
    /// Findings that still warrant attention when connectivity itself succeeded, such as a
    /// working connection that is unauthenticated. The matrix verdict is included because it
    /// belongs to no stage and would otherwise never reach the summary.
    /// </summary>
    public IReadOnlyList<Finding> Concerns =>
        AllFindings
            .Concat(MatrixVerdict is null ? Array.Empty<Finding>() : new[] { MatrixVerdict })
            .Where(f => f.Severity >= Severity.Warning)
            .OrderByDescending(f => f.Severity)
            .ToList();

    /// <summary>First failing stage, which is the layer the caller should focus on.</summary>
    public StageResult? FirstFailure => Stages.FirstOrDefault(s => s.Status == StageStatus.Failed);

    public IEnumerable<Finding> AllFindings => Stages.SelectMany(s => s.Findings);
}
