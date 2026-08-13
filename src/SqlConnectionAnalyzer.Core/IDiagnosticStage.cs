using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Core;

/// <summary>One step of the TDS login flow that can be independently probed.</summary>
public interface IDiagnosticStage
{
    /// <summary>Stable identifier used in reports and rule matching.</summary>
    string Id { get; }

    /// <summary>Human-readable checklist label.</summary>
    string Title { get; }

    /// <summary>Returns false when the stage does not apply to the current context.</summary>
    bool AppliesTo(DiagnosticContext context) => true;

    Task RunAsync(DiagnosticContext context, StageResult result, CancellationToken cancellationToken);
}
