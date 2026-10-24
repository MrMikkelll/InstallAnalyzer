namespace InstallAnalyzer.Core.Help;

public sealed class HelpQueryRequest
{
    public required string FilePath { get; init; }
    public InstallerFamily Family { get; init; }
    public IReadOnlyList<string> Arguments { get; init; } = [];
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);
    public IProgress<string>? Progress { get; init; }
}

public sealed class HelpQueryResult
{
    public string StandardOutput { get; init; } = "";
    public string StandardError { get; init; } = "";
    public bool TimedOut { get; init; }
    public bool InstallerWasStopped { get; init; }
    public bool RelaxedSandbox { get; init; }
    public int? ExitCode { get; init; }
    public string? Error { get; init; }
    public string Attempted { get; init; } = "";

    public static HelpQueryResult Failed(string error) => new() { Error = error };
}

public interface IHelpQueryRunner
{
    Task<HelpQueryResult> RunAsync(HelpQueryRequest request, CancellationToken cancellationToken);
}

public static class HelpSwitches
{
    private static readonly HashSet<string> Allow = new(StringComparer.OrdinalIgnoreCase)
    {
        "/?",
        "/h",
        "/help",
        "-?",
        "-h",
        "-help",
        "--help",
        "--h",
        "--?"
    };

    public static IReadOnlyList<string> Candidates(InstallerFamily family)
    {
        string[] ordered = family switch
        {
            InstallerFamily.Squirrel or InstallerFamily.QtInstallerFramework => ["--help", "-h", "-?", "/?", "/help", "/h", "--h", "--?"],
            InstallerFamily.WixBurn => ["-?", "/?", "-help", "/help", "--help", "-h", "/h", "--h"],
            _ => ["/?", "/help", "/h", "-?", "-help", "-h", "--help", "--h", "--?"]
        };

        return ordered.Where(IsSafeProbe).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static bool IsSafeProbe(string arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments))
            return false;

        var token = arguments.Trim();
        if (token.Any(ch => char.IsWhiteSpace(ch) || ch is '"' or '\'' or '&' or '|' or '>' or '<' or '^' or ';' or '`'))
            return false;
        if (HelpTextParser.IsKnownSilent(token))
            return false;
        return Allow.Contains(token);
    }
}
