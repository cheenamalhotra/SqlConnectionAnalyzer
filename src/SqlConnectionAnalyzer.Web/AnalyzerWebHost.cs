using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SqlConnectionAnalyzer.Core;
using SqlConnectionAnalyzer.Web.Components;

namespace SqlConnectionAnalyzer.Web;

/// <summary>Options for the local diagnostic web UI.</summary>
public sealed record WebUiOptions
{
    /// <summary>Port to listen on. Zero asks the OS for a free port.</summary>
    public int Port { get; init; }

    /// <summary>
    /// Bind address. Defaults to loopback: the UI accepts a connection string, so it must
    /// not be reachable from the network unless the operator opts in explicitly.
    /// </summary>
    public string Host { get; init; } = "127.0.0.1";

    /// <summary>Connection string to pre-fill, so `--serve` can continue a CLI session.</summary>
    public string? InitialConnectionString { get; init; }

    public bool OpenBrowser { get; init; } = true;
}

/// <summary>Hosts the Blazor diagnostic UI in the current process.</summary>
public static class AnalyzerWebHost
{
    /// <summary>Builds the app and returns it, so callers can inspect the bound URL before running.</summary>
    public static WebApplication Build(WebUiOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = WebApplication.CreateBuilder();

        builder.Logging.ClearProviders();
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddConsole();

        builder.WebHost.UseUrls($"http://{options.Host}:{options.Port}");

        builder.Services.AddRazorComponents().AddInteractiveServerComponents();
        builder.Services.AddConnectivityAnalyzer();
        builder.Services.AddSingleton(options);

        WebApplication app = builder.Build();

        app.UseStaticFiles();
        app.UseAntiforgery();
        app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

        return app;
    }
}
