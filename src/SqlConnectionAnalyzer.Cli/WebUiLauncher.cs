using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console;
using SqlConnectionAnalyzer.Web;

namespace SqlConnectionAnalyzer.Cli;

/// <summary>Starts the local web UI and reports the address it actually bound to.</summary>
internal static class WebUiLauncher
{
    public static async Task<int> RunAsync(CommandLineOptions options, CancellationToken cancellationToken)
    {
        WebApplication app = AnalyzerWebHost.Build(new WebUiOptions
        {
            Port = options.Port,
            InitialConnectionString = options.ConnectionString,
            OpenBrowser = !options.NoBrowser
        });

        try
        {
            await app.StartAsync(cancellationToken);
        }
        catch (IOException ex)
        {
            AnsiConsole.MarkupLine($"[red]Could not start the web UI: {Markup.Escape(ex.Message)}[/]");
            AnsiConsole.MarkupLine("[grey]Try a different port with --port.[/]");
            return 2;
        }

        // Port 0 means the OS chose the port, so the real address is only known after starting.
        string url = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()?.Addresses.FirstOrDefault()
            ?? $"http://127.0.0.1:{options.Port}";

        AnsiConsole.Write(new Rule("[bold]SQL connectivity analyzer[/]").LeftJustified());
        AnsiConsole.MarkupLine($"Web UI listening on [link={url}]{Markup.Escape(url)}[/]");
        AnsiConsole.MarkupLine("[grey]Bound to loopback only. Press Ctrl+C to stop.[/]");

        if (!options.NoBrowser)
        {
            TryOpenBrowser(url);
        }

        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            AnsiConsole.MarkupLine("[grey]Shutting down.[/]");
        }

        await app.StopAsync(CancellationToken.None);
        return 0;
    }

    private static void TryOpenBrowser(string url)
    {
        try
        {
            ProcessStartInfo info = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? new ProcessStartInfo(url) { UseShellExecute = true }
                : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                    ? new ProcessStartInfo("open", url)
                    : new ProcessStartInfo("xdg-open", url);

            using Process? process = Process.Start(info);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException
                                      or PlatformNotSupportedException)
        {
            // Headless hosts have no browser; the URL is already printed above.
            AnsiConsole.MarkupLine("[grey]Could not open a browser automatically.[/]");
        }
    }
}
