using System.Text.Json.Serialization;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Core.Rules;

/// <summary>
/// The observable facts of a server error, decoupled from <c>SqlError</c>.
/// <para>
/// <c>SqlError</c> cannot be constructed outside the driver, which would make every
/// classification rule untestable. Lifting the facts into a plain type keeps the knowledge
/// base verifiable without a live server.
/// </para>
/// </summary>
public readonly record struct SqlErrorFacts(
    int Number,
    byte State,
    byte Class,
    string Message,
    string? Server = null,
    string? Procedure = null,
    int LineNumber = 0);

/// <summary>One entry in the diagnosis knowledge base.</summary>
public sealed class DiagnosticRule
{
    /// <summary>Stable identifier surfaced to users and used to override a built-in rule.</summary>
    public string Code { get; init; } = string.Empty;

    /// <summary>Server error numbers this rule applies to.</summary>
    public IReadOnlyList<int> ErrorNumbers { get; init; } = Array.Empty<int>();

    /// <summary>
    /// Error states this rule applies to. Empty means the rule matches any state, which also
    /// makes it less specific than a state-qualified rule for the same number.
    /// </summary>
    public IReadOnlyList<int> States { get; init; } = Array.Empty<int>();

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public DiagnosticLayer Layer { get; init; } = DiagnosticLayer.Authentication;

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Severity Severity { get; init; } = Severity.Error;

    /// <summary>Supports the tokens {number}, {state}, {class}, {message}, and {server}.</summary>
    public string Message { get; init; } = string.Empty;

    public string? Detail { get; init; }

    public IReadOnlyList<string> Remediation { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> References { get; init; } = Array.Empty<string>();

    /// <summary>A state-qualified rule is preferred over a catch-all for the same error number.</summary>
    public bool IsStateQualified => States.Count > 0;

    public bool Matches(SqlErrorFacts facts) =>
        ErrorNumbers.Contains(facts.Number) &&
        (States.Count == 0 || States.Contains(facts.State));

    public Finding ToFinding(SqlErrorFacts facts) => new()
    {
        Code = Code,
        Severity = Severity,
        Layer = Layer,
        Message = Expand(Message, facts),
        Detail = Detail is null ? facts.Message : Expand(Detail, facts),
        Remediation = Remediation.Select(r => Expand(r, facts)).ToArray(),
        References = References
    };

    private static string Expand(string template, SqlErrorFacts facts) => template
        .Replace("{number}", facts.Number.ToString(), StringComparison.Ordinal)
        .Replace("{state}", facts.State.ToString(), StringComparison.Ordinal)
        .Replace("{class}", facts.Class.ToString(), StringComparison.Ordinal)
        .Replace("{message}", facts.Message, StringComparison.Ordinal)
        .Replace("{server}", facts.Server ?? string.Empty, StringComparison.Ordinal);
}
