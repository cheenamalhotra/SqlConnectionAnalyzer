using System.Diagnostics;
using Microsoft.Data.SqlClient;
using SqlConnectionAnalyzer.Core.Diagnostics;

namespace SqlConnectionAnalyzer.Core;

/// <summary>Result of one encryption permutation attempt.</summary>
public sealed record MatrixOutcome(
    string Encrypt,
    bool TrustServerCertificate,
    bool Succeeded,
    TimeSpan Elapsed,
    int? ErrorNumber,
    string? Error);

/// <summary>
/// Re-attempts the connection across the encryption settings that most often decide
/// success or failure.
/// <para>
/// A single failed connection tells you something is wrong; a matrix tells you exactly which
/// setting is responsible. If every combination fails, the problem is not encryption at all.
/// If only TrustServerCertificate=true succeeds, the server certificate is untrusted and the
/// fix is a real certificate rather than a flag.
/// </para>
/// </summary>
public static class ConnectionMatrixRunner
{
    private static readonly (string Encrypt, bool Trust)[] Permutations =
    [
        ("Mandatory", false),
        ("Mandatory", true),
        ("Optional", false),
        ("Strict", false)
    ];

    public static async Task<IReadOnlyList<MatrixOutcome>> RunAsync(
        string connectionString,
        string? accessToken,
        TimeSpan attemptTimeout,
        CancellationToken cancellationToken)
    {
        var outcomes = new List<MatrixOutcome>(Permutations.Length);

        foreach ((string encrypt, bool trust) in Permutations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            outcomes.Add(await AttemptAsync(connectionString, accessToken, encrypt, trust, attemptTimeout, cancellationToken)
                .ConfigureAwait(false));
        }

        return outcomes;
    }

    private static async Task<MatrixOutcome> AttemptAsync(
        string connectionString,
        string? accessToken,
        string encrypt,
        bool trust,
        TimeSpan attemptTimeout,
        CancellationToken cancellationToken)
    {
        var builder = new SqlConnectionStringBuilder(connectionString)
        {
            Pooling = false,
            ConnectTimeout = Math.Max(5, (int)attemptTimeout.TotalSeconds)
        };

        builder["Encrypt"] = encrypt;

        // Strict (TDS 8.0) validates the certificate unconditionally, so the flag is meaningless there.
        if (!encrypt.Equals("Strict", StringComparison.OrdinalIgnoreCase))
        {
            builder.TrustServerCertificate = trust;
        }

        var sw = Stopwatch.StartNew();

        try
        {
            await using var connection = new SqlConnection(builder.ConnectionString);

            if (accessToken is not null && RequiresExplicitToken(builder))
            {
                connection.AccessToken = accessToken;
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(attemptTimeout);

            await connection.OpenAsync(timeoutCts.Token).ConfigureAwait(false);
            sw.Stop();

            return new MatrixOutcome(encrypt, trust, true, sw.Elapsed, null, null);
        }
        catch (SqlException ex)
        {
            sw.Stop();
            return new MatrixOutcome(encrypt, trust, false, sw.Elapsed, ex.Number, FirstLine(ex.Message));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            sw.Stop();
            return new MatrixOutcome(encrypt, trust, false, sw.Elapsed, null, "timed out");
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new MatrixOutcome(encrypt, trust, false, sw.Elapsed, null, FirstLine(ex.Message));
        }
    }

    /// <summary>Turns the raw matrix into the conclusion it supports.</summary>
    public static Finding Interpret(IReadOnlyList<MatrixOutcome> outcomes)
    {
        List<MatrixOutcome> succeeded = outcomes.Where(o => o.Succeeded).ToList();

        if (succeeded.Count == 0)
        {
            return Finding.Error(
                "SCA1000",
                DiagnosticLayer.Tls,
                "No encryption permutation succeeded.",
                "Because relaxing encryption changed nothing, the failure is not caused by TLS settings. "
                    + "Look at the first stage that failed instead.");
        }

        if (succeeded.Count == outcomes.Count)
        {
            return Finding.Info(
                "SCA1001",
                DiagnosticLayer.Tls,
                "Every encryption permutation succeeded, including Encrypt=Strict.",
                "The server presents a fully trusted certificate and no encryption relaxation is needed.");
        }

        bool strictWorks = succeeded.Any(o => o.Encrypt.Equals("Strict", StringComparison.OrdinalIgnoreCase));
        bool mandatoryVerifiedWorks = succeeded.Any(o =>
            o.Encrypt.Equals("Mandatory", StringComparison.OrdinalIgnoreCase) && !o.TrustServerCertificate);
        bool onlyTrustWorks = !mandatoryVerifiedWorks &&
            succeeded.Any(o => o.TrustServerCertificate || o.Encrypt.Equals("Optional", StringComparison.OrdinalIgnoreCase));

        if (mandatoryVerifiedWorks && !strictWorks)
        {
            return Finding.Warn(
                "SCA1002",
                DiagnosticLayer.Tls,
                "Encryption works with certificate validation, but Encrypt=Strict fails.",
                "The certificate is trusted for TDS 7.4 encryption, yet the server does not accept a "
                    + "TDS 8.0 strict connection.",
                "Confirm the server is SQL Server 2022 or Azure SQL, which are required for Encrypt=Strict.");
        }

        if (onlyTrustWorks)
        {
            return Finding.Error(
                "SCA1003",
                DiagnosticLayer.Tls,
                "The connection only succeeds when certificate validation is bypassed.",
                "This isolates the fault to server certificate trust: the handshake itself works, but the "
                    + "certificate is not verifiable by this client. TrustServerCertificate=true hides the "
                    + "problem and removes protection against man-in-the-middle attacks.",
                "Install a certificate whose subject or SAN matches the exact name in the connection string.",
                "Ensure the issuing CA chain is present in the client trust store.",
                "Treat TrustServerCertificate=true as a temporary diagnostic, not a fix.");
        }

        return Finding.Info(
            "SCA1004",
            DiagnosticLayer.Tls,
            $"{succeeded.Count} of {outcomes.Count} encryption permutations succeeded.",
            "Compare the successful and failing rows to identify the setting that matters.");
    }

    private static bool RequiresExplicitToken(SqlConnectionStringBuilder builder) =>
        builder.Authentication == SqlAuthenticationMethod.NotSpecified &&
        !builder.IntegratedSecurity &&
        string.IsNullOrEmpty(builder.UserID);

    private static string FirstLine(string message)
    {
        int idx = message.IndexOf('\n');
        return (idx < 0 ? message : message[..idx]).Trim();
    }
}
