using System.Diagnostics.Tracing;
using System.Text;

namespace SqlConnectionAnalyzer.Core.Diagnostics;

/// <summary>A single trace line emitted by the SqlClient provider.</summary>
public sealed record SqlClientTraceEvent(DateTime TimestampUtc, string EventName, string Message);

/// <summary>
/// Captures Microsoft.Data.SqlClient's own EventSource output during the analysis.
/// <para>
/// The staged probes describe what an independent observer sees; this listener records what
/// the driver itself decided. When the two disagree - for example the TLS stage negotiates
/// cleanly but SqlClient reports an SNI error - the disagreement is the diagnosis.
/// </para>
/// </summary>
public sealed class SqlClientEventListener : EventListener
{
    private const string SqlClientSourceName = "Microsoft.Data.SqlClient.EventSource";

    /// <summary>Trace, Scope, PoolerTrace, PoolerScope, SNITrace, and SNIScope keywords.</summary>
    private const EventKeywords CapturedKeywords = (EventKeywords)(1 | 2 | 16 | 32 | 512 | 1024);

    private const int MaxEvents = 2000;

    private readonly List<SqlClientTraceEvent> _events = new();
    private readonly object _gate = new();

    private volatile bool _enabled;
    public IReadOnlyList<SqlClientTraceEvent> Events
    {
        get
        {
            lock (_gate)
            {
                return _events.ToArray();
            }
        }
    }

    public bool Truncated { get; private set; }

    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        if (!string.Equals(eventSource.Name, SqlClientSourceName, StringComparison.Ordinal))
        {
            return;
        }

        EnableEvents(eventSource, EventLevel.Verbose, CapturedKeywords);
        _enabled = true;
    }

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        // The base constructor can dispatch before derived field initializers have run.
        if (_events is null || _gate is null)
        {
            return;
        }

        if (!string.Equals(eventData.EventSource?.Name, SqlClientSourceName, StringComparison.Ordinal))
        {
            return;
        }

        string message = FormatPayload(eventData);
        if (message.Length == 0)
        {
            return;
        }

        // Never store an unredacted trace line; the tool guarantees secret-free output.
        message = Redactor.FreeText(message);

        lock (_gate)
        {
            if (_events.Count >= MaxEvents)
            {
                Truncated = true;
                return;
            }

            _events.Add(new SqlClientTraceEvent(
                DateTime.UtcNow,
                eventData.EventName ?? $"Event{eventData.EventId}",
                message));
        }
    }

    public bool IsAttached => _enabled;

    private static string FormatPayload(EventWrittenEventArgs eventData)
    {
        if (eventData.Payload is not { Count: > 0 } payload)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        for (int i = 0; i < payload.Count; i++)
        {
            string? value = payload[i]?.ToString();
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (sb.Length > 0)
            {
                sb.Append(" | ");
            }

            sb.Append(value);
        }

        return sb.ToString();
    }
}
