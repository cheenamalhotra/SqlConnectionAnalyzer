namespace SqlConnectionAnalyzer.Core;

/// <summary>
/// A single observation emitted while an analysis runs, so a caller can render progress
/// as it happens instead of waiting for the whole pipeline to finish.
/// </summary>
/// <remarks>
/// The hierarchy is closed: the private constructor means every case is declared here, so
/// consumers can switch over it exhaustively.
/// </remarks>
public abstract record AnalysisProgress
{
    private AnalysisProgress()
    {
    }

    /// <summary>A stage is about to run.</summary>
    public sealed record StageStarted(StageSnapshot Stage, int Index, int Total) : AnalysisProgress;

    /// <summary>A stage finished, succeeded, was skipped, or failed.</summary>
    public sealed record StageFinished(StageSnapshot Stage, int Index, int Total) : AnalysisProgress;

    /// <summary>The pipeline finished. Always the last item in the sequence.</summary>
    public sealed record Finished(AnalysisReport Report) : AnalysisProgress;
}
