namespace SqlConnectionAnalyzer.Core.Model;

/// <summary>
/// Detects whether a keyword was *supplied* in a connection string, which is the test
/// Microsoft.Data.SqlClient applies when validating authentication combinations.
/// </summary>
/// <remarks>
/// Neither builder type can answer this question:
/// <list type="bullet">
///   <item><description><c>SqlConnectionStringBuilder.ContainsKey</c> returns true for every
///   known keyword, supplied or not.</description></item>
///   <item><description><c>DbConnectionStringBuilder</c> discards keywords with an empty value,
///   yet <c>Password=</c> alone is enough for SqlClient to reject the connection.</description></item>
/// </list>
/// SqlClient sets <c>_hasPasswordKeyword</c> during its own parse, so the raw text is scanned here
/// to reproduce that behaviour exactly.
/// </remarks>
public static class ConnectionStringKeywords
{
    private static readonly string[] PasswordKeywords = ["password", "pwd"];

    private static readonly string[] UserIdKeywords = ["user id", "uid", "userid"];

    public static bool HasPassword(string connectionString) =>
        ContainsAny(connectionString, PasswordKeywords);

    public static bool HasUserId(string connectionString) =>
        ContainsAny(connectionString, UserIdKeywords);

    public static bool ContainsAny(string connectionString, params string[] keywords)
    {
        foreach (string key in EnumerateKeywords(connectionString))
        {
            foreach (string candidate in keywords)
            {
                if (string.Equals(key, candidate, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Yields the keyword of every <c>key=value</c> pair. Values are skipped rather than parsed,
    /// honouring single and double quoting so that a ';' or '=' inside a password cannot be
    /// mistaken for a separator.
    /// </summary>
    public static IEnumerable<string> EnumerateKeywords(string connectionString)
    {
        if (string.IsNullOrEmpty(connectionString))
        {
            yield break;
        }

        int i = 0;
        while (i < connectionString.Length)
        {
            while (i < connectionString.Length && (char.IsWhiteSpace(connectionString[i]) || connectionString[i] == ';'))
            {
                i++;
            }

            if (i >= connectionString.Length)
            {
                yield break;
            }

            int keyStart = i;
            string? key = null;

            while (i < connectionString.Length)
            {
                if (connectionString[i] == '=')
                {
                    // A doubled '=' is an escaped literal inside the keyword, not the separator.
                    if (i + 1 < connectionString.Length && connectionString[i + 1] == '=')
                    {
                        i += 2;
                        continue;
                    }

                    key = connectionString[keyStart..i].Trim();
                    i++;
                    break;
                }

                if (connectionString[i] == ';')
                {
                    break;
                }

                i++;
            }

            if (key is null)
            {
                // A fragment with no '=' is malformed; skip it rather than guessing.
                continue;
            }

            // The keyword is already captured, so the value only needs to be stepped over.
            i = SkipValue(connectionString, i);

            if (key.Length > 0)
            {
                yield return key.Replace("==", "=");
            }
        }
    }

    private static int SkipValue(string s, int i)
    {
        while (i < s.Length && char.IsWhiteSpace(s[i]))
        {
            i++;
        }

        if (i < s.Length && (s[i] == '\'' || s[i] == '"'))
        {
            char quote = s[i++];
            while (i < s.Length)
            {
                if (s[i] == quote)
                {
                    // A doubled quote is an escaped literal within the quoted value.
                    if (i + 1 < s.Length && s[i + 1] == quote)
                    {
                        i += 2;
                        continue;
                    }

                    i++;
                    break;
                }

                i++;
            }
        }

        while (i < s.Length && s[i] != ';')
        {
            i++;
        }

        return i;
    }
}
