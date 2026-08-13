using SqlConnectionAnalyzer.Core.Diagnostics;
using SqlConnectionAnalyzer.Core.Probes;

namespace SqlConnectionAnalyzer.Tests;

public class RedactorTests
{
    [Fact]
    public void RemovesThePasswordFromAConnectionString()
    {
        string redacted = Redactor.ConnectionString("Server=s;User ID=admin;Password=SuperSecret123;");

        Assert.DoesNotContain("SuperSecret123", redacted, StringComparison.Ordinal);
        Assert.Contains("Server", redacted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MasksShortValuesEntirely()
    {
        Assert.Equal("****", Redactor.Mask("abc"));
    }

    [Fact]
    public void KeepsAShortPrefixForLongerValues()
    {
        string masked = Redactor.Mask("SuperSecret");

        Assert.StartsWith("Su", masked, StringComparison.Ordinal);
        Assert.DoesNotContain("Secret", masked, StringComparison.Ordinal);
    }

    [Fact]
    public void NeverEmitsTheTokenPayload()
    {
        const string token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2RhdGFiYXNlLndpbmRvd3MubmV0In0.signature";

        string redacted = Redactor.Token(token);

        Assert.DoesNotContain("signature", redacted, StringComparison.Ordinal);
        Assert.Contains("<payload>", redacted, StringComparison.Ordinal);
    }
}

public class JwtInspectorTests
{
    /// <summary>Builds an unsigned JWT with the given payload for decode-only testing.</summary>
    private static string BuildToken(string payloadJson)
    {
        static string Encode(string value) =>
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return $"{Encode("{\"alg\":\"none\"}")}.{Encode(payloadJson)}.sig";
    }

    [Fact]
    public void DecodesTheStandardClaims()
    {
        long exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        string token = BuildToken(
            $"{{\"aud\":\"https://database.windows.net/\",\"tid\":\"tenant-1\",\"upn\":\"user@contoso.com\",\"exp\":{exp}}}");

        Assert.True(JwtInspector.TryDecode(token, out TokenClaims? claims));
        Assert.Equal("https://database.windows.net/", claims!.Audience);
        Assert.Equal("tenant-1", claims.TenantId);
        Assert.Equal("user@contoso.com", claims.UniqueName);
        Assert.False(claims.IsExpired);
    }

    [Fact]
    public void DetectsAnExpiredToken()
    {
        long exp = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        string token = BuildToken($"{{\"aud\":\"a\",\"exp\":{exp}}}");

        Assert.True(JwtInspector.TryDecode(token, out TokenClaims? claims));
        Assert.True(claims!.IsExpired);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    public void RejectsMalformedTokens(string? token)
    {
        Assert.False(JwtInspector.TryDecode(token, out _));
    }

    [Theory]
    [InlineData("connectionString: Server=s;Password=Sup3rSecret;Encrypt=true", "Sup3rSecret")]
    [InlineData("<api> 'Data Source=s;PWD=Hunter2;'", "Hunter2")]
    [InlineData("Client Secret = abc123xyz;", "abc123xyz")]
    [InlineData("access_token=eyJhbGciOi", "eyJhbGciOi")]
    public void StripsSecretsFromArbitraryTraceText(string input, string secret)
    {
        string redacted = Redactor.FreeText(input);

        Assert.DoesNotContain(secret, redacted, StringComparison.Ordinal);
        Assert.Contains("******", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void LeavesNonSecretTraceTextIntact()
    {
        const string line = "<sc.TdsParser.Connect|SEC> Connection established, Encrypt=Mandatory";

        Assert.Equal(line, Redactor.FreeText(line));
    }
}
