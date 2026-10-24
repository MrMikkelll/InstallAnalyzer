using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using InstallAnalyzer.Core.Msi;
using InstallAnalyzer.Core.Pe;
using InstallAnalyzer.Core.Scanning;
using InstallAnalyzer.Core.Unpack;

namespace InstallAnalyzer.Core.Inspection;

public static class SignatureDetector
{
    private sealed record Sig(
        string Id,
        string Text,
        InstallerFamily Family,
        Confidence Confidence,
        DetectionStrength Strength,
        string Evidence);

    private static readonly Sig[] Sigs =
    [
        new("inno-data", "Inno Setup Setup Data", InstallerFamily.InnoSetup, Confidence.High, DetectionStrength.Strong, "Found the Inno Setup data header."),
        new("inno-jr", "JR.Inno.Setup", InstallerFamily.InnoSetup, Confidence.High, DetectionStrength.Strong, "Found an Inno Setup marker."),
        new("nsis", "NullsoftInst", InstallerFamily.Nsis, Confidence.High, DetectionStrength.Strong, "Found the Nullsoft installer signature."),
        new("nsis-text", "Nullsoft Install System", InstallerFamily.Nsis, Confidence.High, DetectionStrength.Strong, "Found the Nullsoft installer signature."),
        new("nsis-err", "NSIS Error", InstallerFamily.Nsis, Confidence.Medium, DetectionStrength.Weak, "Found an NSIS error string."),
        new("is-engine", "ISSetup.dll", InstallerFamily.InstallShield, Confidence.High, DetectionStrength.Strong, "Found the InstallShield setup engine."),
        new("is-stream", "ISSetupStream", InstallerFamily.InstallShield, Confidence.High, DetectionStrength.Strong, "Found an InstallShield setup stream."),
        new("is-name", "InstallShield", InstallerFamily.InstallShield, Confidence.Medium, DetectionStrength.Weak, "Found an InstallShield string."),
        new("script", "InstallScript", InstallerFamily.Unknown, Confidence.None, DetectionStrength.Weak, ""),
        new("msi-api", "MsiInstallProduct", InstallerFamily.Unknown, Confidence.None, DetectionStrength.Weak, ""),
        new("wix-string", "WixBundle", InstallerFamily.WixBurn, Confidence.Medium, DetectionStrength.Weak, "Found a WiX bundle string."),
        new("squirrel", "SquirrelAwareApp", InstallerFamily.Squirrel, Confidence.High, DetectionStrength.Strong, "Found the Squirrel aware marker."),
        new("squirrel-name", "Squirrel.Windows", InstallerFamily.Squirrel, Confidence.Medium, DetectionStrength.Weak, "Found a Squirrel string."),
        new("ai", "Advanced Installer", InstallerFamily.AdvancedInstaller, Confidence.High, DetectionStrength.Strong, "Found an Advanced Installer string."),
        new("ia", "InstallAware", InstallerFamily.InstallAware, Confidence.High, DetectionStrength.Strong, "Found an InstallAware string."),
        new("qt", "Qt Installer Framework", InstallerFamily.QtInstallerFramework, Confidence.High, DetectionStrength.Strong, "Found the Qt Installer Framework."),
        new("qt-ifw", "org.qt-project.ifw", InstallerFamily.QtInstallerFramework, Confidence.High, DetectionStrength.Strong, "Found the Qt Installer Framework."),
        new("7z", ";!@Install@!UTF-8!", InstallerFamily.SevenZipSfx, Confidence.High, DetectionStrength.Strong, "Found a 7-Zip SFX config block."),
        new("7zip-app", "7-Zip Shell Extension", InstallerFamily.SevenZipSfx, Confidence.High, DetectionStrength.Strong, "Found the 7-Zip installer."),
        new("inno-x64", "ArchitecturesInstallIn64BitMode", InstallerFamily.Unknown, Confidence.None, DetectionStrength.Weak, ""),
        new("sumatra", "SumatraPDF", InstallerFamily.Unknown, Confidence.None, DetectionStrength.Weak, ""),
        new("sumatra-s", "uninstall.exe [/s]", InstallerFamily.Unknown, Confidence.None, DetectionStrength.Weak, ""),
        new("firefox-title", "Title=\"Mozilla Firefox\"", InstallerFamily.Unknown, Confidence.None, DetectionStrength.Weak, ""),
        new("iexpress", "IExpress", InstallerFamily.IExpress, Confidence.Medium, DetectionStrength.Weak, "Found an IExpress string."),
        new("pftw", "PackageForTheWeb", InstallerFamily.IExpress, Confidence.Medium, DetectionStrength.Weak, "Found a Package for the Web string."),
        new("wextract", "wextract", InstallerFamily.IExpress, Confidence.Low, DetectionStrength.Weak, "Found the IExpress extractor.")
    ];

    public static FileInspection Inspect(string path, Func<string, string?>? readSigner = null)
    {
        var info = new FileInfo(path);
        var extension = info.Extension;
        var headerLength = (int)Math.Min(512, info.Length);
        var header = new byte[headerLength];
        ScanResult scan;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            if (headerLength > 0)
                stream.ReadExactly(header);
            stream.Position = 0;
            scan = PatternScanner.Scan(stream, Patterns(), Markers(), maxMarkerHits: 24);
        }

        var matched = scan.MatchedPatternIds.ToHashSet(StringComparer.Ordinal);
        var detections = new List<Detection>();
        var isPe = header.Length >= 2 && header[0] == (byte)'M' && header[1] == (byte)'Z';
        VersionStrings? version = null;
        bool? is64Bit = null;
        var burnContainers = Array.Empty<BurnContainerSlice>();
        if (isPe && PeFile.TryOpen(path) is { } pe)
        {
            using (pe)
            {
                is64Bit = pe.Is64Bit;
                var resource = pe.ReadVersionResource();
                if (resource is not null)
                    version = VersionStrings.FromMap(VersionResourceReader.Read(resource));
                if (BurnLayout.TryRead(pe, out _, out var containers))
                {
                    burnContainers = containers.ToArray();
                    detections.Add(new Detection
                    {
                        Family = InstallerFamily.WixBurn,
                        Confidence = Confidence.High,
                        Strength = DetectionStrength.Strong,
                        Evidence = "Found the WiX Burn section."
                    });
                }
            }
        }

        var oleAtZero = header.Length >= 8 && CompoundStorage.LooksLikeOle(header);
        Guid clsid = Guid.Empty;
        if (oleAtZero)
            CompoundStorage.TryGetClsid(path, out clsid);

        if (clsid == CompoundStorage.MsiClsid)
            AddStructural(detections, InstallerFamily.Msi, "Windows Installer storage signature.");
        else if (clsid == CompoundStorage.MspClsid)
            AddStructural(detections, InstallerFamily.Msp, "Windows Installer patch storage signature.");
        else if (oleAtZero && IsExtension(extension, ".msi"))
            Add(detections, InstallerFamily.Msi, Confidence.Medium, DetectionStrength.Weak, "OLE compound file with an .msi extension.");
        else if (oleAtZero && IsExtension(extension, ".msp"))
            Add(detections, InstallerFamily.Msp, Confidence.Medium, DetectionStrength.Weak, "OLE compound file with an .msp extension.");

        var msix = header.Length >= 2 && header[0] == (byte)'P' && header[1] == (byte)'K'
            ? ReadMsix(path)
            : null;
        if (msix is not null)
            AddStructural(detections, InstallerFamily.Msix, "Found an Appx manifest.");
        else if (header.Length >= 2 && header[0] == (byte)'P' && header[1] == (byte)'K'
            && IsExtension(extension, ".msix", ".appx", ".msixbundle", ".appxbundle"))
            Add(detections, InstallerFamily.Msix, Confidence.Medium, DetectionStrength.Weak, "Package extension on a zip file.");

        foreach (var sig in Sigs)
        {
            if (!matched.Contains(sig.Id) || sig.Family == InstallerFamily.Unknown || sig.Confidence == Confidence.None)
                continue;
            if (sig.Id == "wextract" && (!isPe || matched.Contains("iexpress") || matched.Contains("pftw")))
                continue;
            detections.Add(new Detection
            {
                Family = sig.Family,
                Confidence = sig.Confidence,
                Strength = sig.Strength,
                Evidence = sig.Evidence
            });
        }

        var winner = Choose(detections);
        string? signer = null;
        if (isPe && readSigner is not null)
        {
            try
            {
                signer = readSigner(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                signer = null;
            }
        }

        return new FileInspection
        {
            Identity = new FileIdentity
            {
                Path = Path.GetFullPath(path),
                Name = info.Name,
                Size = info.Length,
                FileVersion = version?.FileVersion,
                ProductName = version?.ProductName ?? msix?.Name,
                ProductVersion = version?.ProductVersion ?? msix?.Version,
                CompanyName = version?.CompanyName,
                FileDescription = version?.FileDescription,
                Signer = signer
            },
            Detections = detections,
            Family = winner?.Family ?? InstallerFamily.Unknown,
            Confidence = winner?.Confidence ?? Confidence.None,
            Evidence = winner?.Evidence ?? (info.Length == 0
                ? "The file is empty."
                : "No installer family signature was found."),
            InstallScript = matched.Contains("script"),
            InstallShieldMsiEngine = matched.Contains("is-engine") || matched.Contains("is-stream") || matched.Contains("msi-api"),
            IsPortableExecutable = isPe,
            Is64Bit = is64Bit,
            Prefer64BitInstall = matched.Contains("inno-x64"),
            SevenZipApplication = matched.Contains("7zip-app"),
            SumatraInstaller = matched.Contains("sumatra") && matched.Contains("sumatra-s"),
            FirefoxPackage = matched.Contains("firefox-title"),
            Msix = msix,
            BurnContainers = burnContainers,
            OleOffsets = scan.MarkerOffsets.TryGetValue("ole", out var ole) ? ole : [],
            ZipOffsets = scan.MarkerOffsets.TryGetValue("zip", out var zip) ? zip : [],
            Version = version
        };
    }

    private static Detection? Choose(List<Detection> detections)
    {
        var structuralPackage = detections.FirstOrDefault(item =>
            item.Strength == DetectionStrength.Strong
            && item.Family is InstallerFamily.Msi or InstallerFamily.Msp or InstallerFamily.Msix);
        if (structuralPackage is not null)
            return structuralPackage;

        return detections
            .Where(item => item.Family != InstallerFamily.Unknown && item.Confidence != Confidence.None)
            .OrderByDescending(item => item.Confidence)
            .ThenByDescending(item => item.Strength)
            .ThenByDescending(item => Rank(item.Family))
            .FirstOrDefault();
    }

    private static int Rank(InstallerFamily family) => family switch
    {
        InstallerFamily.WixBurn => 50,
        InstallerFamily.InnoSetup => 48,
        InstallerFamily.Nsis => 47,
        InstallerFamily.InstallShield => 46,
        InstallerFamily.AdvancedInstaller => 45,
        InstallerFamily.Squirrel => 44,
        InstallerFamily.QtInstallerFramework => 43,
        InstallerFamily.InstallAware => 42,
        InstallerFamily.SevenZipSfx => 41,
        InstallerFamily.IExpress => 40,
        _ => 10
    };

    private static void AddStructural(List<Detection> detections, InstallerFamily family, string evidence) =>
        Add(detections, family, Confidence.High, DetectionStrength.Strong, evidence);

    private static void Add(
        List<Detection> detections,
        InstallerFamily family,
        Confidence confidence,
        DetectionStrength strength,
        string evidence) =>
        detections.Add(new Detection
        {
            Family = family,
            Confidence = confidence,
            Strength = strength,
            Evidence = evidence
        });

    private static bool IsExtension(string extension, params string[] expected) =>
        expected.Any(item => extension.Equals(item, StringComparison.OrdinalIgnoreCase));

    private static MsixFacts? ReadMsix(string path)
    {
        try
        {
            using var zip = ZipFile.OpenRead(path);
            var entry = zip.GetEntry("AppxManifest.xml")
                ?? zip.GetEntry("AppxMetadata/AppxBundleManifest.xml")
                ?? zip.Entries.FirstOrDefault(item =>
                    item.FullName.EndsWith("AppxManifest.xml", StringComparison.OrdinalIgnoreCase)
                    || item.FullName.EndsWith("AppxBundleManifest.xml", StringComparison.OrdinalIgnoreCase));
            if (entry is null)
                return null;

            using var reader = entry.Open();
            var document = XDocument.Load(reader);
            var identity = document.Descendants().FirstOrDefault(element => element.Name.LocalName == "Identity");
            if (identity is null)
                return new MsixFacts();

            return new MsixFacts
            {
                Name = identity.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "Name")?.Value,
                Version = identity.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "Version")?.Value,
                Publisher = identity.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == "Publisher")?.Value
            };
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.Xml.XmlException)
        {
            return null;
        }
    }

    private static IReadOnlyList<Pattern> Patterns() =>
        Sigs.Select(sig => new Pattern { Id = sig.Id, Bytes = Encoding.ASCII.GetBytes(sig.Text) }).ToArray();

    private static IReadOnlyList<Pattern> Markers() =>
    [
        new Pattern { Id = "ole", Bytes = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },
        new Pattern { Id = "zip", Bytes = [0x50, 0x4B, 0x03, 0x04] }
    ];
}
