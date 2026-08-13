using System.Diagnostics;

namespace SqlConnectionAnalyzer.Core.Diagnostics;

/// <summary>Result of running one pipeline stage.</summary>
public sealed class StageResult
{
    public required string StageId { get; init; }

    public required string Title { get; init; }

    public StageStatus Status { get; set; } = StageStatus.Pending;

    public TimeSpan Elapsed { get; set; }

    public List<Finding> Findings { get; } = new();

    /// <summary>Structured key/value evidence rendered in verbose output and reports.</summary>
    public Dictionary<string, string?> Evidence { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Set when the stage failed in a way that makes downstream stages meaningless.</summary>
    public bool IsFatal { get; set; }

    public string? SkipReason { get; set; }

    public Finding? WorstFinding =>
        Findings.Count == 0 ? null : Findings.OrderByDescending(f => f.Severity).First();

    public void Add(Finding finding)
    {
        Findings.Add(finding);
        Status = finding.Severity switch
        {
            Severity.Error or Severity.Critical => StageStatus.Failed,
            Severity.Warning when Status != StageStatus.Failed => StageStatus.Warning,
            _ => Status
        };
    }

    public void Record(string key, string? value) => Evidence[key] = value;

    public void MarkPassed()
    {
        if (Status is StageStatus.Running or StageStatus.Pending)
        {
            Status = StageStatus.Passed;
        }
    }

    public void Skip(string reason)
    {
        Status = StageStatus.Skipped;
        SkipReason = reason;
    }

    public static StageResult Start(string id, string title) => new()
    {
        StageId = id,
        Title = title,
        Status = StageStatus.Running
    };

    public IDisposable Timer() => new StageTimer(this);

    private sealed class StageTimer : IDisposable
    {
        private readonly StageResult _result;
        private readonly Stopwatch _sw = Stopwatch.StartNew();

        public StageTimer(StageResult result) => _result = result;

        public void Dispose()
        {
            _sw.Stop();
            _result.Elapsed = _sw.Elapsed;
        }
    }
}
