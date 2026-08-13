using SqlConnectionAnalyzer.Core.Stages;

namespace SqlConnectionAnalyzer.Core;

/// <summary>Builds the analyzer with the stages ordered to mirror the MS-TDS login flow.</summary>
public static class AnalyzerFactory
{
    public static IReadOnlyList<IDiagnosticStage> CreateDefaultStages() =>
    [
        new ConnectionStringStage(),
        new NameResolutionStage(),
        new TcpReachabilityStage(),
        new PreLoginStage(),
        new TlsHandshakeStage(),
        new RoutingStage(),
        new CredentialStage(),
        new LoginStage(),
        new ResiliencyStage()
    ];

    public static ConnectivityAnalyzer Create() => new(CreateDefaultStages());
}
