# SQL Connection Analyzer

Diagnoses **Microsoft.Data.SqlClient** connectivity failures stage by stage along the
MS-TDS login flow, so a failure is attributed to one specific layer instead of a single
opaque exception.

Rather than wrapping `SqlConnection.Open()` and interpreting whatever error comes back,
the analyzer independently probes each layer — DNS, TCP, the raw TDS PRELOGIN handshake,
the TLS handshake and certificate chain, credential acquisition — and only then attempts
a real login. Because every earlier layer has already been proven healthy, the first
failing stage *is* the root cause.

New to the TDS login flow? [docs/login-flow.md](docs/login-flow.md) explains it from first
principles with diagrams, including why failures land where they do.

Runs as a console checklist or, with `--serve`, as a local web UI.

## Install

```bash
dotnet pack src/SqlConnectionAnalyzer.Cli -c Release
dotnet tool install --global --add-source ./artifacts SqlConnectionAnalyzer.Cli
```

## Usage

```bash
sqlconn-analyze "Server=myserver,1433;Database=mydb;User ID=sa;Password=…;Encrypt=Mandatory"

# Keep secrets out of shell history
export SQLCONNSTR="Server=…;Password=…"
sqlconn-analyze --verbose

# Stop before touching credentials, and emit a machine-readable report
sqlconn-analyze --no-login --json report.json
```

| Option | Purpose |
| --- | --- |
| `-c`, `--connection-string` | Connection string to analyze |
| `-t`, `--timeout <seconds>` | Per-stage probe timeout (default 15) |
| `-v`, `--verbose` | Show evidence tables and informational findings |
| `--no-login` | Stop before attempting a real login |
| `--continue-on-fatal` | Run every stage even after a fatal failure |
| `--matrix` | Retry across `Encrypt`/`TrustServerCertificate` permutations to prove which setting is at fault |
| `--trace` | Capture `Microsoft.Data.SqlClient` EventSource output |
| `--json <path>` | Write a machine-readable report |
| `--markdown <path>` | Write a Markdown report for a support ticket |
| `--rules <path>` | Overlay a custom JSON rules file on the built-in knowledge base |
| `--serve` | Open the interactive web UI instead of running once |
| `--port <number>` | Port for `--serve` (default `0`, meaning any free port) |
| `--no-browser` | Do not open a browser when using `--serve` |

Exit codes: `0` success, `1` connectivity failure, `2` usage error.

## Web UI

The same engine, with a live checklist you can click through:

```bash
sqlconn-analyze --serve
```

The tool starts a local server, prints the address, and opens a browser. Everything runs
in-process; nothing is uploaded anywhere.

The UI shows each stage as it happens rather than after the run, plus per-stage findings and
evidence, a verdict that distinguishes "connected" from "connected, but only because
validation was bypassed", a timing waterfall showing where the seconds went, the encryption
matrix, and one-click JSON or Markdown export.

Notes:

- It binds to `127.0.0.1` only. The UI accepts a connection string, so it is never exposed to
  the network.
- Secrets are redacted in the UI and in every export, exactly as in the console.
- `--serve` accepts an optional connection string to pre-fill the form.
- On a headless host, forward the port over SSH and use `--port` with `--no-browser`:

  ```bash
  ssh -L 5000:127.0.0.1:5000 user@host
  sqlconn-analyze --serve --port 5000 --no-browser
  ```

## Using the analyzer as a library

`SqlConnectionAnalyzer.Core` is UI-agnostic, so the console, the web UI, and your own code
share one implementation.

```csharp
services.AddConnectivityAnalyzer();
```

`AnalyzeAsync` returns the finished report. `AnalyzeStreamAsync` yields each stage transition
as it happens, which is what a progress bar needs:

```csharp
await foreach (AnalysisProgress progress in analyzer.AnalyzeStreamAsync(connectionString, options, ct))
{
    switch (progress)
    {
        case AnalysisProgress.StageStarted started:
            Console.WriteLine($"[{started.Index + 1}/{started.Total}] {started.Stage.Title}");
            break;

        case AnalysisProgress.Finished done:
            Console.WriteLine(done.Report.Succeeded ? "Connected." : "Failed.");
            break;
    }
}
```

Stage transitions carry an immutable `StageSnapshot` rather than the live `StageResult`. The
pipeline keeps mutating a stage while it runs, so a consumer on another thread that held the
live object would enumerate its collections mid-write. The analyzer is registered as transient
for the same reason: progress is instance-scoped, so concurrent analyses need separate
instances.

## Diagnosis knowledge base

Error classification lives in data, not in a `switch`. The built-in rules ship embedded in the
assembly (`src/SqlConnectionAnalyzer.Core/Rules/sql-rules.json`), so the tool works standalone,
and `--rules <path>` overlays your own file on top:

```jsonc
{
  "version": 1,
  "rules": [
    {
      "code": "SQL18456",              // reusing a built-in code replaces that rule
      "errorNumbers": [18456],
      "states": [8],                    // omit to match any state
      "layer": "Authentication",
      "severity": "Error",
      "message": "Login rejected by {server}. See runbook KB-4471.",
      "remediation": ["Check the shared credential in the team vault."]
    }
  ]
}
```

Rules sharing a `code` replace the built-in entry; new codes are added. A rule naming an exact
`state` always wins over a catch-all for the same error number, which is what makes the 18456
state table work. Templates support `{number}`, `{state}`, `{class}`, `{message}`, and `{server}`.

### Finding codes

`SCAnnnn` codes identify analyzer findings and `SQLnnnnn` codes identify server errors. Each
code is unique across the tool, enforced by a test — codes are cited in tickets, so one code
must mean exactly one thing.

| Range | Area |
| --- | --- |
| `SCA00xx` | Pipeline and connection string parsing |
| `SCA01xx` | Connection string validation |
| `SCA02xx` | Name resolution |
| `SCA03xx` | TCP reachability |
| `SCA04xx` | TDS Pre-Login |
| `SCA05xx` | TLS and certificates |
| `SCA06xx` | Credential acquisition |
| `SCA07xx` | LOGIN7 |
| `SCA08xx` | Resiliency and pooling |
| `SCA09xx` | Routing and redirection |
| `SCA10xx` | Encryption matrix |

## Stages

| # | Stage | What it proves |
| --- | --- | --- |
| 0 | Connection string | Keyword validity, option conflicts, `Encrypt` defaults, timeout sanity |
| 1 | Name resolution | DNS records, literal IPs, named instance lookup via SQL Browser (UDP 1434) |
| 2 | TCP reachability | A socket can be opened to each resolved address |
| 3 | TDS Pre-Login | The endpoint speaks TDS; reveals server build, `ENCRYPTION`, `FEDAUTHREQUIRED`, `INSTOPT` |
| 4 | TLS handshake | Negotiated protocol and cipher, full certificate chain, expiry, name match |
| 5 | Routing and redirection | Azure gateway Redirect range (11000–11999) is reachable; AG read-only and multi-subnet routing |
| 6 | Credential acquisition | Entra token acquisition or Kerberos ticket state, *before* login |
| 7 | LOGIN7 | Real `SqlConnection` open, with error number and state classification |
| 8 | Resiliency and pooling | Handshake cost vs pooled reuse, timeout headroom, retry and pool settings |

### Why routing is probed separately

A Redirect-policy failure is invisible at stage 2. TCP 1433 reaches the Azure gateway,
Pre-Login and TLS both succeed, and the connection only dies later when the client is told
to reconnect on a node port in the 11000–11999 range that the local firewall blocks.

Stage 5 samples that range and distinguishes a **refusal** (an RST, proving packets reach
the host and the range is open) from **silence** (the signature of a firewall dropping
packets). Both look identical to `SqlClient`, but they call for completely different fixes.

### Encryption matrix

`--matrix` re-attempts the connection across the encryption settings that most often decide
success or failure, turning "something is wrong" into a specific culprit:

- **Nothing succeeds** → the fault is not encryption; look at the first failing stage.
- **Only `TrustServerCertificate=true` succeeds** → the handshake works but the certificate
  is not verifiable. The flag hides the problem rather than fixing it.
- **Everything including `Encrypt=Strict` succeeds** → the certificate is fully trusted.

### Why the raw TDS probe matters

In TDS 7.x the TLS handshake is **tunneled inside TDS PRELOGIN packets** — the ClientHello
is wrapped in a packet with type `0x12`, and only after the handshake completes do TLS
records travel directly on the wire. `TdsSslWrapperStream` implements this framing, which
is what lets the analyzer inspect the certificate chain exactly as SqlClient sees it.

## Authentication coverage

- **SQL authentication** — credential presence and shape
- **Integrated Security** — SSPI/Kerberos to SQL Server. The expected SPN is built the way
  SqlClient's managed SNI builds it: the DNS-resolved FQDN, the `Server SPN` keyword honoured
  verbatim when set, and for a default instance on TCP *both* `MSSQLSvc/fqdn` and
  `MSSQLSvc/fqdn:1433` accepted, because SQL Server registers both and either may be the one
  in the directory. The cache is read from `klist`, whose output differs across MIT, Heimdal
  (macOS), and Windows; all three formats are parsed.
- **Microsoft Entra ID** — `Default`, `Interactive`, `DeviceCodeFlow`, `ManagedIdentity`,
  `ServicePrincipal`, `WorkloadIdentity`, `Integrated`. Tokens are acquired independently
  and their claims (`aud`, `tid`, `exp`, identity) decoded, so an audience or tenant
  mismatch is reported as such rather than as a login failure.

`Authentication=Active Directory Integrated` is **not** Kerberos to SQL Server: SqlClient calls
MSAL's Integrated Windows Authentication against Entra ID, so no `MSSQLSvc` ticket is involved.
Only `Integrated Security=true` uses SSPI/Kerberos. The analyzer keeps the two apart.

### Driver parity

Some authentication keyword combinations are rejected by `SqlConnection` with an
`ArgumentException` before any network traffic — the connection can never open:

| Combination | Result |
|---|---|
| `Authentication=*` with `Integrated Security=true` | rejected |
| `Active Directory Integrated`/`Interactive`/`Default`/`Managed Identity`/`MSI`/`Workload Identity` with `Password` | rejected |
| `Active Directory Device Code Flow` with `User ID` or `Password` | rejected |

The driver tests whether the **keyword was supplied**, not whether it holds a value, so even
`Password=` with an empty value fails. `SqlConnectionStringBuilder` does *not* apply these rules,
so the analyzer scans the raw connection string to reproduce them and fails fast.

Token resource and authority are not hardcoded by SqlClient either: the server sends them in its
`FEDAUTHINFO` login token. The analyzer probes token acquisition *before* login, so it infers the
resource from the endpoint suffix (including the US Gov, China, and Germany clouds) and treats a
missing tenant as un-probeable rather than as a fault.

`DriverParityTests` cross-checks each rejection against a real `SqlConnection`, so if the driver
relaxes a rule the test fails and tells us to relax ours too.

## Diagnosis

`SqlErrorClassifier` maps SQL Server error numbers and login states to precise causes —
including the `18456` state table (state 5 login missing, 8 bad password, 11 no CONNECT
permission, 38 default database inaccessible). SQL Server always reports state `1` to the
client, so the analyzer explains what to look for in the server error log.

## Security

Passwords, tokens, and secrets are redacted from **all** output, including JSON reports.
Only the header and length of a JWT are ever shown; signatures and payloads never are.

## Trying it out

Every scenario below is verified and fails at a *different* stage, which is the quickest way to
see whether the analyzer is isolating faults correctly.

Start a throwaway server:

```bash
docker run -d --name sqltest -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD='Str0ng!Passw0rd' \
  -p 14333:1433 mcr.microsoft.com/mssql/server:2022-latest
```

| # | Connection string | Expected failing stage |
|---|---|---|
| 1 | `127.0.0.1,14333` + `TrustServerCertificate=true` | none - succeeds with warnings |
| 2 | as 1, but `Password=WRONG` | LOGIN7 and authentication |
| 3 | as 1, without `TrustServerCertificate` | TLS handshake and certificate |
| 4 | `Server=127.0.0.1,14444` (wrong port) | TCP reachability |
| 5 | `Server=nope.invalid` | Name resolution |
| 6 | `Server=;Gibberish` | Connection string |

```bash
export SQLCONNSTR="Server=127.0.0.1,14333;User ID=sa;Password=Str0ng!Passw0rd;TrustServerCertificate=true"

sqlconn-analyze                       # 1: healthy, but reports certificate warnings
sqlconn-analyze -v                    # same, with all evidence
sqlconn-analyze --matrix              # proves which encryption setting is at fault
sqlconn-analyze --markdown report.md  # output for a support ticket
sqlconn-analyze --no-login            # stop before sending credentials
```

Scenario 1 exits 0 but the verdict is yellow: the connection works only because certificate
validation is disabled. Scenario 3 is that same server with validation left on, and it fails.
That pair is the point of the tool - it separates "connects" from "connects securely".

Scenarios 4-6 need no server at all.

Two more checks that need no SQL Server:

```bash
# A port that accepts TCP but speaks no TDS: a proxy, a health-check listener, or the wrong port.
nc -l 15999 &
sqlconn-analyze "Server=127.0.0.1,15999;User ID=sa;Password=x" -t 5

# Confirm secrets never reach disk.
sqlconn-analyze --json out.json && grep -c 'Str0ng' out.json   # expect 0
```

Clean up with `docker rm -f sqltest`.

## Development

```bash
dotnet build
dotnet test
```

Projects:

| Project | Role |
| --- | --- |
| `SqlConnectionAnalyzer.Core` | Stages, probes, rules knowledge base, report writers. No UI. |
| `SqlConnectionAnalyzer.Cli` | Console front end and the `--serve` launcher. Packs as the tool. |
| `SqlConnectionAnalyzer.Web` | Blazor components for the web UI, hosted in-process by the CLI. |
