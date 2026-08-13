using System.Text;
using System.Text.Json;

namespace SqlConnectionAnalyzer.Core.Probes;

/// <summary>Claims extracted from an access token, used to explain audience or tenant mismatches.</summary>
public sealed record TokenClaims(
    string? Audience,
    string? TenantId,
    string? ObjectId,
    string? AppId,
    string? UniqueName,
    DateTimeOffset? ExpiresOn,
    DateTimeOffset? IssuedAt,
    string? Issuer)
{
    public bool IsExpired => ExpiresOn is { } exp && exp <= DateTimeOffset.UtcNow;
}

/// <summary>
/// Decodes the payload of a JWT without validating its signature. The analyzer only needs
/// the claims to explain why a server rejected a token; it never trusts the token itself.
/// </summary>
public static class JwtInspector
{
    public static bool TryDecode(string? token, out TokenClaims? claims)
    {
        claims = null;

        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        string[] parts = token.Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(Base64UrlDecode(parts[1]));
            JsonElement root = document.RootElement;

            claims = new TokenClaims(
                GetString(root, "aud"),
                GetString(root, "tid"),
                GetString(root, "oid"),
                GetString(root, "appid") ?? GetString(root, "azp"),
                GetString(root, "upn") ?? GetString(root, "unique_name") ?? GetString(root, "preferred_username"),
                GetUnixTime(root, "exp"),
                GetUnixTime(root, "iat"),
                GetString(root, "iss"));

            return true;
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return false;
        }
    }

    private static string? GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static DateTimeOffset? GetUnixTime(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement value) && value.TryGetInt64(out long seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;

    private static byte[] Base64UrlDecode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            2 => padded + "==",
            3 => padded + "=",
            0 => padded,
            _ => throw new FormatException("Invalid base64url segment length.")
        };

        return Convert.FromBase64String(padded);
    }

    /// <summary>Formats claims for report output; no secret material is included.</summary>
    public static string Describe(TokenClaims claims)
    {
        var sb = new StringBuilder();
        sb.Append("aud=").Append(claims.Audience ?? "?");
        sb.Append(", tid=").Append(claims.TenantId ?? "?");
        sb.Append(", identity=").Append(claims.UniqueName ?? claims.AppId ?? claims.ObjectId ?? "?");
        if (claims.ExpiresOn is { } exp)
        {
            sb.Append(", exp=").Append(exp.ToLocalTime().ToString("u"));
        }

        return sb.ToString();
    }
}
