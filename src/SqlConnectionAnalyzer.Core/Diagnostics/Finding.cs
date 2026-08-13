namespace SqlConnectionAnalyzer.Core.Diagnostics;

/// <summary>
/// A single observation produced by a stage. Findings carry both the evidence that
/// was observed and the remediation that follows from it.
/// </summary>
public sealed class Finding
{
    public required string Code { get; init; }

    public required Severity Severity { get; init; }

    public required DiagnosticLayer Layer { get; init; }

    public required string Message { get; init; }

    public string? Detail { get; init; }

    /// <summary>Concrete, ordered steps the user can take to resolve the finding.</summary>
    public IReadOnlyList<string> Remediation { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> References { get; init; } = Array.Empty<string>();

    public static Finding Info(string code, DiagnosticLayer layer, string message, string? detail = null,
        params string[] remediation) =>
        new()
        {
            Code = code,
            Severity = Severity.Info,
            Layer = layer,
            Message = message,
            Detail = detail,
            Remediation = remediation
        };

    public static Finding Warn(string code, DiagnosticLayer layer, string message, string? detail = null,
        params string[] remediation) =>
        new()
        {
            Code = code,
            Severity = Severity.Warning,
            Layer = layer,
            Message = message,
            Detail = detail,
            Remediation = remediation
        };

    public static Finding Error(string code, DiagnosticLayer layer, string message, string? detail = null,
        params string[] remediation) =>
        new()
        {
            Code = code,
            Severity = Severity.Error,
            Layer = layer,
            Message = message,
            Detail = detail,
            Remediation = remediation
        };
}
