namespace SqlConnectionAnalyzer.Core.Diagnostics;

/// <summary>Outcome of a single stage in the connectivity pipeline.</summary>
public enum StageStatus
{
    Pending,
    Running,
    Passed,
    Warning,
    Failed,
    Skipped,
    NotApplicable
}

public enum Severity
{
    Info,
    Warning,
    Error,
    Critical
}

/// <summary>Layer a finding belongs to, used to isolate the failing tier.</summary>
public enum DiagnosticLayer
{
    Configuration,
    NameResolution,
    Transport,
    Tds,
    Tls,
    Routing,
    Authentication,
    Authorization,
    Resiliency
}
