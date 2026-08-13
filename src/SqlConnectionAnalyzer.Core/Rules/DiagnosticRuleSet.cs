using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Core.Rules;

/// <summary>Serialized shape of a rules file.</summary>
public sealed class RuleDocument
{
    public int Version { get; init; } = 1;

    public IReadOnlyList<DiagnosticRule> Rules { get; init; } = Array.Empty<DiagnosticRule>();
}

/// <summary>
/// The diagnosis knowledge base: a set of rules mapping server errors to causes and fixes.
/// <para>
/// Keeping these in data rather than a switch statement means a newly discovered error can be
/// described without recompiling, and lets an operator ship site-specific guidance
/// (internal runbook links, for example) alongside the built-in rules.
/// </para>
/// </summary>
public sealed class DiagnosticRuleSet
{
    private const string EmbeddedResourceName = "SqlConnectionAnalyzer.Core.Rules.sql-rules.json";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly Lazy<DiagnosticRuleSet> BuiltInInstance = new(LoadBuiltIn);

    private readonly List<DiagnosticRule> _rules;

    private DiagnosticRuleSet(IEnumerable<DiagnosticRule> rules) => _rules = rules.ToList();

    /// <summary>Rules compiled into the assembly, so the tool works with no external files.</summary>
    public static DiagnosticRuleSet BuiltIn => BuiltInInstance.Value;

    public IReadOnlyList<DiagnosticRule> Rules => _rules;

    public static DiagnosticRuleSet FromJson(string json)
    {
        RuleDocument? document = JsonSerializer.Deserialize<RuleDocument>(json, SerializerOptions)
            ?? throw new InvalidDataException("The rules document was empty.");

        var invalid = document.Rules
            .Where(r => string.IsNullOrWhiteSpace(r.Code) || r.ErrorNumbers.Count == 0)
            .ToList();

        if (invalid.Count > 0)
        {
            throw new InvalidDataException(
                $"{invalid.Count} rule(s) are missing a code or error numbers.");
        }

        return new DiagnosticRuleSet(document.Rules);
    }

    public static DiagnosticRuleSet LoadFromFile(string path) => FromJson(File.ReadAllText(path));

    /// <summary>
    /// Overlays another rule set on this one. Rules sharing a code replace the original, so an
    /// operator can correct built-in guidance rather than only appending to it.
    /// </summary>
    public DiagnosticRuleSet MergedWith(DiagnosticRuleSet overrides)
    {
        var byCode = _rules.ToDictionary(r => r.Code, StringComparer.OrdinalIgnoreCase);

        foreach (DiagnosticRule rule in overrides._rules)
        {
            byCode[rule.Code] = rule;
        }

        return new DiagnosticRuleSet(byCode.Values);
    }

    /// <summary>
    /// Finds the most specific rule for an error. A rule naming the exact state beats a
    /// catch-all for the same number, which is what makes the 18456 state table useful.
    /// </summary>
    public DiagnosticRule? Match(SqlErrorFacts facts) => _rules
        .Where(r => r.Matches(facts))
        .OrderByDescending(r => r.IsStateQualified)
        .ThenByDescending(r => r.States.Count > 0 ? 1 : 0)
        .FirstOrDefault();

    /// <summary>Classifies an error, falling back to a generic finding when no rule matches.</summary>
    public Finding Classify(SqlErrorFacts facts, DiagnosticLayer fallbackLayer)
    {
        DiagnosticRule? rule = Match(facts);

        if (rule is not null)
        {
            return rule.ToFinding(facts);
        }

        // A negative number is an HRESULT raised by the client — the driver, the OS security
        // stack, or a socket API — not a message the server sent back. Reporting a server
        // state and class for one would be fiction, and the state byte is always 0 there,
        // which has previously read as "state 0" rather than "not applicable".
        if (facts.Number < 0)
        {
            string hresult = $"0x{unchecked((uint)facts.Number):X8}";

            return Finding.Error(
                $"SQLCLIENT{hresult}",
                fallbackLayer,
                $"The client failed with error {facts.Number} ({hresult}) before the server reported a status.",
                facts.Message,
                "Treat this as a client-side or network failure rather than a login rejection.",
                $"Look up {hresult} as a Windows HRESULT for the underlying cause.");
        }

        return Finding.Error(
            $"SQL{facts.Number}",
            fallbackLayer,
            $"SQL Server returned error {facts.Number} (state {facts.State}, class {facts.Class}).",
            facts.Message);
    }

    private static DiagnosticRuleSet LoadBuiltIn()
    {
        Assembly assembly = typeof(DiagnosticRuleSet).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(EmbeddedResourceName)
            ?? throw new InvalidOperationException(
                $"Embedded rules resource '{EmbeddedResourceName}' was not found. "
                    + $"Available: {string.Join(", ", assembly.GetManifestResourceNames())}");

        using var reader = new StreamReader(stream);
        return FromJson(reader.ReadToEnd());
    }
}
