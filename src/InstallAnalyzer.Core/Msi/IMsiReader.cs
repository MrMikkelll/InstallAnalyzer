namespace InstallAnalyzer.Core.Msi;

public interface IMsiReader
{
    bool IsAvailable { get; }

    MsiFacts Read(string path);
}

public sealed class UnavailableMsiReader : IMsiReader
{
    public bool IsAvailable => false;

    public MsiFacts Read(string path) => new()
    {
        ReadError = "Reading MSI tables uses the Windows Installer API and runs on Windows."
    };
}
