using SqlConnectionAnalyzer.Core.Model;

namespace SqlConnectionAnalyzer.Cli;

/// <summary>Parsed command line for the analyzer.</summary>
public sealed class CommandLineOptions
{
    public string? ConnectionString { get; private set; }

    public bool Verbose { get; private set; }

    public bool NoLogin { get; private set; }

    public bool ContinueOnFatal { get; private set; }

    public bool Matrix { get; private set; }

    public bool Trace { get; private set; }

    public string? JsonPath { get; private set; }

    public string? MarkdownPath { get; private set; }

    /// <summary>Optional rules file overlaid on the built-in knowledge base.</summary>
    public string? RulesPath { get; private set; }

    public TimeSpan Timeout { get; private set; } = TimeSpan.FromSeconds(15);

    public bool ShowHelp { get; private set; }

    /// <summary>Launch the local web UI instead of running a single console analysis.</summary>
    public bool Serve { get; private set; }

    /// <summary>Port for the web UI. Zero asks the OS for a free port.</summary>
    public int Port { get; private set; }

    /// <summary>Suppress opening the default browser when serving.</summary>
    public bool NoBrowser { get; private set; }

    public string? Error { get; private set; }

    public AnalyzerOptions ToAnalyzerOptions() => new()
    {
        ProbeTimeout = Timeout,
        AttemptLogin = !NoLogin,
        ContinueOnFatal = ContinueOnFatal,
        MatrixMode = Matrix,
        CaptureEventSource = Trace
    };

    public static CommandLineOptions Parse(string[] args)
    {
        var options = new CommandLineOptions();

        if (args.Length == 0 && string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SQLCONNSTR")))
        {
            options.ShowHelp = true;
            return options;
        }

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            switch (arg)
            {
                case "-h" or "--help":
                    options.ShowHelp = true;
                    return options;

                case "-v" or "--verbose":
                    options.Verbose = true;
                    break;

                case "--no-login":
                    options.NoLogin = true;
                    break;

                case "--continue-on-fatal":
                    options.ContinueOnFatal = true;
                    break;

                case "--matrix":
                    options.Matrix = true;
                    break;

                case "--trace":
                    options.Trace = true;
                    break;

                case "--serve":
                    options.Serve = true;
                    break;

                case "--no-browser":
                    options.NoBrowser = true;
                    break;

                case "--port":
                    if (!TryTakeValue(args, ref i, out string? portText) ||
                        !int.TryParse(portText, out int port) ||
                        port is < 0 or > 65535)
                    {
                        options.Error = "Option '--port' requires a port number between 0 and 65535.";
                        return options;
                    }

                    options.Port = port;
                    break;

                case "-c" or "--connection-string":
                    if (!TryTakeValue(args, ref i, out string? connectionString))
                    {
                        options.Error = $"Option '{arg}' requires a value.";
                        return options;
                    }

                    options.ConnectionString = connectionString;
                    break;

                case "--json":
                    if (!TryTakeValue(args, ref i, out string? jsonPath))
                    {
                        options.Error = "Option '--json' requires a file path.";
                        return options;
                    }

                    options.JsonPath = jsonPath;
                    break;

                case "--markdown":
                    if (!TryTakeValue(args, ref i, out string? markdownPath))
                    {
                        options.Error = "Option '--markdown' requires a file path.";
                        return options;
                    }

                    options.MarkdownPath = markdownPath;
                    break;

                case "--rules":
                    if (!TryTakeValue(args, ref i, out string? rulesPath))
                    {
                        options.Error = "Option '--rules' requires a file path.";
                        return options;
                    }

                    options.RulesPath = rulesPath;
                    break;

                case "-t" or "--timeout":
                    if (!TryTakeValue(args, ref i, out string? timeoutText) ||
                        !int.TryParse(timeoutText, out int seconds) ||
                        seconds <= 0)
                    {
                        options.Error = "Option '--timeout' requires a positive number of seconds.";
                        return options;
                    }

                    options.Timeout = TimeSpan.FromSeconds(seconds);
                    break;

                default:
                    if (arg.StartsWith('-'))
                    {
                        options.Error = $"Unknown option '{arg}'.";
                        return options;
                    }

                    options.ConnectionString ??= arg;
                    break;
            }
        }

        options.ConnectionString ??= Environment.GetEnvironmentVariable("SQLCONNSTR");

        // The web UI collects the connection string in the browser, so it is optional there.
        if (!options.Serve && string.IsNullOrWhiteSpace(options.ConnectionString))
        {
            options.Error = "A connection string is required. Pass it as an argument, with --connection-string, or set SQLCONNSTR.";
        }

        return options;
    }

    private static bool TryTakeValue(string[] args, ref int index, out string? value)
    {
        if (index + 1 >= args.Length)
        {
            value = null;
            return false;
        }

        value = args[++index];
        return true;
    }

    public static string HelpText => """
        sqlconn-analyze - diagnose Microsoft.Data.SqlClient connectivity stage by stage.

        Usage:
          sqlconn-analyze "<connection string>" [options]

        Options:
          -c, --connection-string <value>  The connection string to analyze.
          -t, --timeout <seconds>          Per-stage probe timeout. Default 15.
          -v, --verbose                    Show evidence and informational findings.
              --no-login                   Stop before attempting a real login.
              --continue-on-fatal          Run every stage even after a fatal failure.
              --matrix                     Retry across Encrypt/TrustServerCertificate
                                           permutations to prove which setting is at fault.
              --trace                      Capture Microsoft.Data.SqlClient EventSource output.
              --json <path>                Write a machine-readable report.
              --markdown <path>            Write a Markdown report for a support ticket.
              --rules <path>               Overlay a custom JSON rules file on the built-in
                                           diagnosis knowledge base.
              --serve                      Open the interactive web UI instead of running once.
              --port <number>              Port for --serve. Default 0 (any free port).
              --no-browser                 Do not open a browser when using --serve.
          -h, --help                       Show this help.

        The connection string may also be supplied in the SQLCONNSTR environment variable,
        which avoids exposing secrets in shell history. Secrets are always redacted in output.

        Exit codes: 0 success, 1 connectivity failure, 2 usage error.
        """;
}
