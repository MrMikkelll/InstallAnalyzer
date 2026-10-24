using InstallAnalyzer.Core.Pe;
using InstallAnalyzer.Core.Unpack;

namespace InstallAnalyzer.Core.Inspection;

public sealed class FileInspection
{
    public required FileIdentity Identity { get; init; }
    public required IReadOnlyList<Detection> Detections { get; init; }
    public InstallerFamily Family { get; init; }
    public Confidence Confidence { get; init; }
    public string Evidence { get; init; } = "";
    public bool InstallScript { get; init; }
    public bool InstallShieldMsiEngine { get; init; }
    public bool IsPortableExecutable { get; init; }
    public MsixFacts? Msix { get; init; }
    public IReadOnlyList<BurnContainerSlice> BurnContainers { get; init; } = [];
    public IReadOnlyList<long> OleOffsets { get; init; } = [];
    public IReadOnlyList<long> ZipOffsets { get; init; } = [];
    public VersionStrings? Version { get; init; }
}
