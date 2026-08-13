using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace SqlConnectionAnalyzer.Core.Diagnostics;

/// <summary>Removes secrets from connection strings and tokens before they reach any output.</summary>
public static class Redactor
{
    private static readonly string[] SensitiveKeys =
    {
        "Password", "PWD", "Access Token", "AccessToken", "User ID", "UID",
        "Application Key", "Client Secret"
    };

    public static string ConnectionString(string connectionString)
    {
        // Validate with the SqlClient builder so unknown keywords are still reported...
        try
        {
            _ = new SqlConnectionStringBuilder(connectionString);
        }
        catch (ArgumentException)
        {
            return "<unparsable connection string>";
        }

        // ...but render with the base builder, which keeps only the keys the user actually
        // supplied instead of expanding every SqlClient default.
        var supplied = new System.Data.Common.DbConnectionStringBuilder { ConnectionString = connectionString };

        var sb = new StringBuilder();
        foreach (string key in supplied.Keys.Cast<string>())
        {
            object? value = supplied[key];
            string rendered = IsSensitive(key) ? Mask(value?.ToString()) : value?.ToString() ?? string.Empty;
            sb.Append(key).Append('=').Append(rendered).Append(';');
        }

        return sb.ToString();
    }

    public static bool IsSensitive(string key) =>
        SensitiveKeys.Any(s => string.Equals(s, key, StringComparison.OrdinalIgnoreCase));

    /// <summary>Keeps a short prefix so the user can still tell values apart.</summary>
    public static string Mask(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Length <= 4 ? "****" : value[..2] + new string('*', 6);
    }

    /// <summary>Shows only the header and a hash suffix of a JWT so claims can be discussed safely.</summary>
    public static string Token(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return string.Empty;
        }

        string[] parts = token.Split('.');
        return parts.Length == 3
            ? $"{parts[0][..Math.Min(8, parts[0].Length)]}….<payload>.<sig> (len={token.Length})"
            : $"<opaque token len={token.Length}>";
    }

    /// <summary>
    /// Strips secret-bearing keywords out of arbitrary text such as driver trace lines.
    /// <para>
    /// SqlClient already omits the password from its own traces, but this tool promises that
    /// nothing it prints or writes contains a secret. Relying on another component's current
    /// behaviour would make that promise conditional, so the guarantee is enforced here too.
    /// </para>
    /// </summary>
    public static string FreeText(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        return SecretInText.Replace(text, m => $"{m.Groups["key"].Value}{m.Groups["sep"].Value}******");
    }

    private static readonly Regex SecretInText = new(
        @"(?<key>\b(?:password|pwd|access[ _]?token|client[ _]?secret|application[ _]?key)\b)(?<sep>\s*=\s*)[^;'""\r\n]*",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
}
