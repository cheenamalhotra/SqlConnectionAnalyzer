using System.Reflection;
using System.Text.RegularExpressions;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Core.Rules;

namespace SqlConnectionAnalyzer.Tests;

/// <summary>
/// A finding code is the stable identity of a diagnosis; users cite it in tickets and search
/// for it. Two stages sharing one code silently breaks that contract, and it already happened
/// once when the routing stage was added alongside the TLS stage.
/// </summary>
public class FindingCodeTests
{
    private static readonly Regex CodeLiteral = new(@"""(SCA\d{4})""", RegexOptions.Compiled);

    private static IEnumerable<string> SourceFiles()
    {
        string root = FindRepositoryRoot();
        return Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories);
    }

    [Fact]
    public void EverySraCodeIsDeclaredExactlyOnce()
    {
        var occurrences = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (string file in SourceFiles())
        {
            foreach (Match match in CodeLiteral.Matches(File.ReadAllText(file)))
            {
                string code = match.Groups[1].Value;
                if (!occurrences.TryGetValue(code, out List<string>? files))
                {
                    occurrences[code] = files = new List<string>();
                }

                string name = Path.GetFileName(file);
                if (!files.Contains(name))
                {
                    files.Add(name);
                }
            }
        }

        var duplicates = occurrences
            .Where(kv => kv.Value.Count > 1)
            .Select(kv => $"{kv.Key} in {string.Join(", ", kv.Value)}")
            .ToList();

        Assert.True(duplicates.Count == 0, $"Duplicate finding codes: {string.Join("; ", duplicates)}");
    }

    [Fact]
    public void CodesAreFoundAtAllSoTheScanIsMeaningful()
    {
        int count = SourceFiles().Sum(f => CodeLiteral.Matches(File.ReadAllText(f)).Count);

        // Guards against the scan silently passing because it found nothing.
        Assert.True(count > 50, $"Expected many finding codes, found {count}.");
    }

    [Fact]
    public void RuleCodesDoNotCollideWithStageCodes()
    {
        var stageCodes = SourceFiles()
            .SelectMany(f => CodeLiteral.Matches(File.ReadAllText(f)).Select(m => m.Groups[1].Value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (DiagnosticRule rule in DiagnosticRuleSet.BuiltIn.Rules)
        {
            Assert.DoesNotContain(rule.Code, stageCodes);
        }
    }

    private static string FindRepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);

        // Anchor on the src directory rather than a solution file name, which varies (.sln/.slnx).
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
