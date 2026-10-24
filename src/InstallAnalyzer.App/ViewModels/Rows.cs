using InstallAnalyzer.Core;

namespace InstallAnalyzer.App.ViewModels;

public sealed class SwitchRow
{
    public required string Flag { get; init; }
    public required string Meaning { get; init; }
    public required string Source { get; init; }
}

public sealed class PayloadRow
{
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required string CommandText { get; init; }
    public required AnalysisReport Report { get; init; }
    public bool CanOpen { get; init; }
}
