namespace InstallAnalyzer.Core;

public enum InstallerFamily
{
    Unknown = 0,
    Msi,
    Msp,
    Msix,
    InnoSetup,
    Nsis,
    InstallShield,
    WixBurn,
    Squirrel,
    AdvancedInstaller,
    InstallAware,
    QtInstallerFramework,
    SevenZipSfx,
    IExpress
}

public enum Confidence
{
    None = 0,
    Low,
    Medium,
    High
}

public enum SwitchSource
{
    BuiltIn,
    MsiProperty,
    HelpText,
    Embedded
}

public enum DetectionStrength
{
    Weak,
    Strong
}

public static class FamilyNames
{
    public static string Display(InstallerFamily family) => family switch
    {
        InstallerFamily.Msi => "Windows Installer",
        InstallerFamily.Msp => "Windows Installer patch",
        InstallerFamily.Msix => "MSIX package",
        InstallerFamily.InnoSetup => "Inno Setup",
        InstallerFamily.Nsis => "NSIS",
        InstallerFamily.InstallShield => "InstallShield",
        InstallerFamily.WixBurn => "WiX Burn",
        InstallerFamily.Squirrel => "Squirrel",
        InstallerFamily.AdvancedInstaller => "Advanced Installer",
        InstallerFamily.InstallAware => "InstallAware",
        InstallerFamily.QtInstallerFramework => "Qt Installer Framework",
        InstallerFamily.SevenZipSfx => "7-Zip SFX",
        InstallerFamily.IExpress => "IExpress",
        _ => "Unknown"
    };
}

public sealed class FileIdentity
{
    public required string Path { get; init; }
    public required string Name { get; init; }
    public long Size { get; init; }
    public string? FileVersion { get; init; }
    public string? ProductName { get; init; }
    public string? ProductVersion { get; init; }
    public string? CompanyName { get; init; }
    public string? FileDescription { get; init; }
    public string? Signer { get; init; }
}

public sealed class Detection
{
    public required InstallerFamily Family { get; init; }
    public required Confidence Confidence { get; init; }
    public required DetectionStrength Strength { get; init; }
    public required string Evidence { get; init; }
}

public sealed class SwitchFinding
{
    public required string Flag { get; init; }
    public required string Meaning { get; init; }
    public required SwitchSource Source { get; init; }
    public bool IncludedInCommand { get; set; }
}

public sealed class RecommendedCommand
{
    public required string Label { get; init; }
    public required string Text { get; init; }
    public required string TextWithLog { get; init; }
    public required bool HasLogVariant { get; init; }
    public required Confidence Confidence { get; init; }
    public required string Note { get; init; }
}

public sealed class MsiFacts
{
    public string? ProductCode { get; init; }
    public string? ProductName { get; init; }
    public string? ProductVersion { get; init; }
    public string? Manufacturer { get; init; }
    public string? UpgradeCode { get; init; }
    public IReadOnlyDictionary<string, string> PublicProperties { get; init; }
        = new Dictionary<string, string>();
    public string? ReadError { get; init; }
}

public sealed class MsixFacts
{
    public string? Name { get; init; }
    public string? Version { get; init; }
    public string? Publisher { get; init; }
}

public sealed class ChainedPackage
{
    public string? Name { get; init; }
    public string? ProductCode { get; init; }
    public string? Source { get; init; }
}

public sealed class AnalysisReport
{
    public required FileIdentity File { get; init; }
    public InstallerFamily Family { get; init; }
    public Confidence Confidence { get; init; }
    public string Evidence { get; init; } = "";
    public IReadOnlyList<Detection> Detections { get; init; } = [];
    public MsiFacts? Msi { get; init; }
    public MsixFacts? Msix { get; init; }
    public IReadOnlyList<SwitchFinding> Switches { get; init; } = [];
    public RecommendedCommand? Install { get; init; }
    public RecommendedCommand? Uninstall { get; init; }
    public string? Advisory { get; init; }
    public IReadOnlyList<AnalysisReport> Payloads { get; init; } = [];
    public IReadOnlyList<ChainedPackage> Chain { get; init; } = [];
    public string? HelpOutput { get; init; }
    public bool HelpWasEmpty { get; init; }
    public bool HelpTimedOut { get; init; }
    public string? Error { get; init; }
    public bool CanQueryHelp { get; init; }
    public bool InstallScript { get; init; }
    public bool InstallShieldMsiEngine { get; init; }
    public string? InstallDirectory { get; init; }
    public string? AlternateInstallDirectory { get; init; }
    public string? UninstallFileName { get; init; }
    public bool InstallDirectoryEmbedded { get; init; }
    public bool InstallerWasStopped { get; init; }
}
