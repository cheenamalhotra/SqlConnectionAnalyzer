using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Core;

/// <summary>
/// An immutable copy of a stage's state at one instant.
/// </summary>
/// <remarks>
/// <see cref="StageResult"/> is mutated by the pipeline as a stage runs. A UI on another
/// thread that held a reference to the live object would enumerate collections while they
/// were being written, so the stream hands out snapshots taken at points where the pipeline
/// is not touching the stage: immediately before it starts and immediately after it ends.
/// </remarks>
public sealed record StageSnapshot
{
    public required string StageId { get; init; }

    public required string Title { get; init; }

    public required StageStatus Status { get; init; }

    public required TimeSpan Elapsed { get; init; }

    public string? SkipReason { get; init; }

    public bool IsFatal { get; init; }

    public IReadOnlyList<Finding> Findings { get; init; } = Array.Empty<Finding>();

    public IReadOnlyList<KeyValuePair<string, string?>> Evidence { get; init; } =
        Array.Empty<KeyValuePair<string, string?>>();

    public Finding? WorstFinding =>
        Findings.Count == 0 ? null : Findings.OrderByDescending(f => f.Severity).First();

    /// <summary>Copies the mutable stage state. Must be called when the pipeline is not writing.</summary>
    public static StageSnapshot From(StageResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new StageSnapshot
        {
            StageId = result.StageId,
            Title = result.Title,
            Status = result.Status,
            Elapsed = result.Elapsed,
            SkipReason = result.SkipReason,
            IsFatal = result.IsFatal,
            Findings = result.Findings.ToArray(),
            Evidence = result.Evidence.ToArray()
        };
    }
}
