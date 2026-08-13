using Microsoft.Extensions.DependencyInjection;
using SqlConnectionAnalyzer.Core.Stages;

namespace SqlConnectionAnalyzer.Core;

/// <summary>Registers the analyzer so hosts (web, desktop, tests) resolve it identically.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the diagnostic stages and the analyzer.
    /// <para>
    /// The analyzer is registered as transient because progress notifications are
    /// instance-scoped: sharing one instance across concurrent analyses would interleave
    /// the progress of unrelated runs.
    /// </para>
    /// </summary>
    public static IServiceCollection AddConnectivityAnalyzer(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddTransient<IDiagnosticStage, ConnectionStringStage>();
        services.AddTransient<IDiagnosticStage, NameResolutionStage>();
        services.AddTransient<IDiagnosticStage, TcpReachabilityStage>();
        services.AddTransient<IDiagnosticStage, PreLoginStage>();
        services.AddTransient<IDiagnosticStage, TlsHandshakeStage>();
        services.AddTransient<IDiagnosticStage, RoutingStage>();
        services.AddTransient<IDiagnosticStage, CredentialStage>();
        services.AddTransient<IDiagnosticStage, LoginStage>();
        services.AddTransient<IDiagnosticStage, ResiliencyStage>();

        services.AddTransient<ConnectivityAnalyzer>();
        return services;
    }
}
