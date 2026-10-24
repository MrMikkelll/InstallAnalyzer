namespace InstallAnalyzer.Core.Help;

public sealed class HelpQueryRequest
{
    public required string FilePath { get; init; }
    public required string Arguments { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(12);
}

public sealed class HelpQueryResult
{
    public string StandardOutput { get; init; } = "";
    public string StandardError { get; init; } = "";
    public bool TimedOut { get; init; }
    public int? ExitCode { get; init; }
    public string? Error { get; init; }

    public static HelpQueryResult Failed(string error) => new() { Error = error };
}

public interface IHelpQueryRunner
{
    Task<HelpQueryResult> RunAsync(HelpQueryRequest request, CancellationToken cancellationToken);
}

public static class HelpSwitches
{
    public static string For(InstallerFamily family) => family switch
    {
        InstallerFamily.Squirrel => "--help",
        InstallerFamily.QtInstallerFramework => "--help",
        _ => "/?"
    };
}
