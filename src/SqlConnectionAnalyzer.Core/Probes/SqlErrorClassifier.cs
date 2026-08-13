using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Rules;

namespace SqlConnectionAnalyzer.Core.Probes;

/// <summary>
/// Translates SqlException error numbers and login states into precise causes.
/// <para>
/// The state byte on error 18456 is the only way to distinguish a bad password from a
/// disabled login or a missing default database, and SQL Server never reveals it to the
/// client in the message text.
/// </para>
/// <para>
/// The knowledge itself lives in <see cref="DiagnosticRuleSet"/> rather than in this class,
/// so rules are data that can be extended or corrected without recompiling.
/// </para>
/// </summary>
public static class SqlErrorClassifier
{
    private static DiagnosticRuleSet _ruleSet = DiagnosticRuleSet.BuiltIn;

    /// <summary>The active knowledge base. Replaced when the user supplies a custom rules file.</summary>
    public static DiagnosticRuleSet RuleSet
    {
        get => _ruleSet;
        set => _ruleSet = value ?? throw new ArgumentNullException(nameof(value));
    }

    public static Finding Classify(SqlError error, DiagnosticLayer fallbackLayer) =>
        Classify(ToFacts(error), fallbackLayer);

    public static Finding Classify(SqlErrorFacts facts, DiagnosticLayer fallbackLayer) =>
        _ruleSet.Classify(facts, fallbackLayer);

    public static SqlErrorFacts ToFacts(SqlError error) => new(
        error.Number,
        error.State,
        error.Class,
        error.Message,
        error.Server,
        error.Procedure,
        error.LineNumber);
}
