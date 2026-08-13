using System.Text;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Core.Reporting;

/// <summary>
/// Renders the report as Markdown for pasting into a support ticket or issue.
/// <para>
/// JSON is for machines and the console output is ephemeral; when someone escalates a
/// connectivity problem they need something readable that carries the full evidence trail and
/// still contains no secrets.
/// </para>
/// </summary>
public static class MarkdownReportWriter
{
    public static async Task WriteAsync(AnalysisReport report, string path, CancellationToken cancellationToken)
    {
        await File.WriteAllTextAsync(path, Render(report), cancellationToken).ConfigureAwait(false);
    }

    public static string Render(AnalysisReport report)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# SQL connectivity analysis");
        sb.AppendLine();
        sb.AppendLine($"- **Result:** {(report.Succeeded ? "succeeded" : "failed")}");
        sb.AppendLine($"- **Started:** {report.StartedAt:u}");
        sb.AppendLine($"- **Total time:** {report.TotalElapsed.TotalMilliseconds:0} ms");
        sb.AppendLine($"- **Endpoint kind:** {report.EndpointKind}");
        sb.AppendLine();
        sb.AppendLine("Connection string (redacted):");
        sb.AppendLine();
        sb.AppendLine("```");
        sb.AppendLine(report.RedactedConnectionString);
        sb.AppendLine("```");
        sb.AppendLine();

        AppendVerdict(sb, report);
        AppendStageSummary(sb, report);
        AppendStageDetail(sb, report);
        AppendMatrix(sb, report);
        AppendTrace(sb, report);

        return sb.ToString();
    }

    private static void AppendVerdict(StringBuilder sb, AnalysisReport report)
    {
        sb.AppendLine("## Verdict");
        sb.AppendLine();

        if (report.FirstFailure is not { } failure)
        {
            IReadOnlyList<Finding> concerns = report.Concerns;

            if (concerns.Count == 0)
            {
                sb.AppendLine("All stages passed.");
                sb.AppendLine();
                return;
            }

            sb.AppendLine(
                $"The connection succeeded, but {concerns.Count} issue(s) need attention.");
            sb.AppendLine();

            foreach (Finding concern in concerns)
            {
                sb.AppendLine($"- **{concern.Severity}:** {Escape(concern.Message)} (`{concern.Code}`)");
            }

            sb.AppendLine();
            return;
        }

        sb.AppendLine($"Connectivity failed at **{failure.Title}**.");
        sb.AppendLine();

        if (failure.WorstFinding is { } worst)
        {
            sb.AppendLine($"- **Cause:** {worst.Message} (`{worst.Code}`)");
            sb.AppendLine($"- **Layer:** {worst.Layer}");

            if (!string.IsNullOrWhiteSpace(worst.Detail))
            {
                sb.AppendLine($"- **Detail:** {worst.Detail}");
            }

            if (worst.Remediation.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("**Next steps:**");
                sb.AppendLine();
                foreach (string step in worst.Remediation)
                {
                    sb.AppendLine($"1. {step}");
                }
            }
        }

        sb.AppendLine();
    }

    private static void AppendStageSummary(StringBuilder sb, AnalysisReport report)
    {
        sb.AppendLine("## Stages");
        sb.AppendLine();
        sb.AppendLine("| Stage | Status | Time |");
        sb.AppendLine("| --- | --- | --- |");

        foreach (StageResult stage in report.Stages)
        {
            string time = stage.Elapsed > TimeSpan.Zero ? $"{stage.Elapsed.TotalMilliseconds:0} ms" : "-";
            sb.AppendLine($"| {Escape(stage.Title)} | {Glyph(stage.Status)} {stage.Status} | {time} |");
        }

        sb.AppendLine();
    }

    private static void AppendStageDetail(StringBuilder sb, AnalysisReport report)
    {
        sb.AppendLine("## Details");
        sb.AppendLine();

        foreach (StageResult stage in report.Stages)
        {
            if (stage.Status is StageStatus.NotApplicable && stage.Findings.Count == 0)
            {
                continue;
            }

            sb.AppendLine($"### {Glyph(stage.Status)} {Escape(stage.Title)}");
            sb.AppendLine();

            if (stage.SkipReason is { } reason)
            {
                sb.AppendLine($"_{Escape(reason)}_");
                sb.AppendLine();
            }

            IEnumerable<KeyValuePair<string, string?>> evidence =
                stage.Evidence.Where(e => !string.IsNullOrWhiteSpace(e.Value));

            if (evidence.Any())
            {
                sb.AppendLine("| Evidence | Value |");
                sb.AppendLine("| --- | --- |");
                foreach ((string key, string? value) in evidence)
                {
                    sb.AppendLine($"| {Escape(key)} | {Escape(value!)} |");
                }

                sb.AppendLine();
            }

            foreach (Finding finding in stage.Findings)
            {
                sb.AppendLine($"- {SeverityGlyph(finding.Severity)} **{Escape(finding.Message)}** (`{finding.Code}`)");

                if (!string.IsNullOrWhiteSpace(finding.Detail))
                {
                    sb.AppendLine($"  - {Escape(finding.Detail)}");
                }

                foreach (string step in finding.Remediation)
                {
                    sb.AppendLine($"  - → {Escape(step)}");
                }
            }

            sb.AppendLine();
        }
    }

    private static void AppendMatrix(StringBuilder sb, AnalysisReport report)
    {
        if (report.MatrixVerdict is null && report.MatrixOutcomes.Count == 0)
        {
            return;
        }

        sb.AppendLine("## Encryption matrix");
        sb.AppendLine();

        if (report.MatrixOutcomes.Count > 0)
        {
            sb.AppendLine("| Encrypt | TrustServerCertificate | Result | Time | Detail |");
            sb.AppendLine("| --- | --- | --- | --- | --- |");

            foreach (MatrixOutcome o in report.MatrixOutcomes)
            {
                bool strict = o.Encrypt.Equals("Strict", StringComparison.OrdinalIgnoreCase);
                string detail = o.Succeeded
                    ? string.Empty
                    : $"{(o.ErrorNumber is { } n ? $"[{n}] " : string.Empty)}{o.Error}";

                sb.AppendLine(
                    $"| {o.Encrypt} | {(strict ? "n/a" : o.TrustServerCertificate.ToString().ToLowerInvariant())} " +
                    $"| {(o.Succeeded ? "succeeded" : "failed")} | {o.Elapsed.TotalMilliseconds:0} ms | {Escape(detail)} |");
            }

            sb.AppendLine();
        }

        if (report.MatrixVerdict is { } verdict)
        {
            sb.AppendLine($"{SeverityGlyph(verdict.Severity)} **{Escape(verdict.Message)}** (`{verdict.Code}`)");

            if (!string.IsNullOrWhiteSpace(verdict.Detail))
            {
                sb.AppendLine();
                sb.AppendLine(Escape(verdict.Detail));
            }

            foreach (string step in verdict.Remediation)
            {
                sb.AppendLine($"- → {Escape(step)}");
            }

            sb.AppendLine();
        }
    }

    private static void AppendTrace(StringBuilder sb, AnalysisReport report)
    {
        if (report.TraceEvents.Count == 0)
        {
            return;
        }

        sb.AppendLine("<details>");
        sb.AppendLine($"<summary>SqlClient trace ({report.TraceEvents.Count} events)</summary>");
        sb.AppendLine();
        sb.AppendLine("```");

        foreach (SqlClientTraceEvent e in report.TraceEvents)
        {
            sb.AppendLine($"{e.TimestampUtc:HH:mm:ss.fff} {e.EventName} {e.Message}");
        }

        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("</details>");
        sb.AppendLine();
    }

    private static string Glyph(StageStatus status) => status switch
    {
        StageStatus.Passed => "✅",
        StageStatus.Warning => "⚠️",
        StageStatus.Failed => "❌",
        _ => "⚪"
    };

    private static string SeverityGlyph(Severity severity) => severity switch
    {
        Severity.Info => "ℹ️",
        Severity.Warning => "⚠️",
        _ => "❌"
    };

    /// <summary>Escapes the pipe character so evidence values cannot break table layout.</summary>
    private static string Escape(string value) =>
        value.Replace("|", "\\|", StringComparison.Ordinal)
             .Replace("\r", string.Empty, StringComparison.Ordinal)
             .Replace("\n", " ", StringComparison.Ordinal);
}
