using InstallAnalyzer.Core.Commands;
using InstallAnalyzer.Core.Inspection;
using InstallAnalyzer.Core.Help;
using InstallAnalyzer.Core.Msi;
using InstallAnalyzer.Core.Unpack;

namespace InstallAnalyzer.Core.Analysis;

public sealed class AnalyzerOptions
{
    public string? WorkingDirectory { get; init; }
    public int MaxDepth { get; init; } = 2;
    public long MaxCarveBytes { get; init; } = 512L * 1024 * 1024;
    public IMsiReader MsiReader { get; init; } = new UnavailableMsiReader();
    public Func<string, string?>? ReadSigner { get; init; }
    public IProgress<string>? Progress { get; init; }
}

public sealed class InstallerAnalyzer
{
    private readonly AnalyzerOptions _options;

    public InstallerAnalyzer(AnalyzerOptions? options = null)
    {
        _options = options ?? new AnalyzerOptions();
    }

    public AnalysisReport Analyze(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return ErrorReport(path, "File was not found.");
            if (Directory.Exists(path) && File.GetAttributes(path).HasFlag(FileAttributes.Directory))
                return ErrorReport(path, "Drop a file, not a folder.");

            var root = _options.WorkingDirectory
                ?? Path.Combine(Path.GetTempPath(), "InstallAnalyzer", Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(root);
            CleanupOldWork(root);
            var budget = _options.MaxCarveBytes;
            return Analyze(Path.GetFullPath(path), depth: 0, root, ref budget, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ErrorReport(path, "This file could not be read. " + ex.Message);
        }
    }

    public static AnalysisReport ApplyHelp(AnalysisReport report, HelpQueryResult result)
    {
        var output = (result.StandardOutput + "\n" + result.StandardError).Trim();
        var tokens = HelpTextParser.Extract(output);
        var plan = CommandBuilder.Build(new CommandInput
        {
            FilePath = report.File.Path,
            Family = report.Family,
            Confidence = report.Confidence,
            Msi = report.Msi,
            Msix = report.Msix,
            InstallScript = report.InstallScript,
            InstallShieldMsiEngine = report.InstallShieldMsiEngine,
            HelpSwitches = tokens,
            ProductCodes = ProductCodes(report).ToList(),
            InstallDirectory = report.InstallDirectory,
            AlternateInstallDirectory = report.AlternateInstallDirectory,
            UninstallFileName = report.UninstallFileName,
            InstallDirectoryEmbedded = report.InstallDirectoryEmbedded
        });

        var empty = string.IsNullOrWhiteSpace(output) && string.IsNullOrWhiteSpace(result.Error);
        return new AnalysisReport
        {
            File = report.File,
            Family = report.Family,
            Confidence = report.Confidence,
            Evidence = report.Evidence,
            Detections = report.Detections,
            Msi = report.Msi,
            Msix = report.Msix,
            Switches = plan.Switches,
            Install = plan.Install,
            Uninstall = plan.Uninstall,
            Advisory = Join(plan.Advisory, result.Error),
            Payloads = report.Payloads,
            Chain = report.Chain,
            HelpOutput = string.IsNullOrWhiteSpace(output) ? null : output,
            HelpWasEmpty = empty,
            HelpTimedOut = result.TimedOut,
            Error = report.Error,
            CanQueryHelp = report.CanQueryHelp,
            InstallScript = report.InstallScript,
            InstallShieldMsiEngine = report.InstallShieldMsiEngine,
            InstallDirectory = report.InstallDirectory,
            AlternateInstallDirectory = report.AlternateInstallDirectory,
            UninstallFileName = report.UninstallFileName,
            InstallDirectoryEmbedded = report.InstallDirectoryEmbedded,
            InstallerWasStopped = result.InstallerWasStopped
        };
    }

    private AnalysisReport Analyze(string path, int depth, string root, ref long budget, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _options.Progress?.Report("Reading " + Path.GetFileName(path) + "…");
        var inspection = SignatureDetector.Inspect(path, _options.ReadSigner);
        MsiFacts? msi = null;
        if (inspection.Family is InstallerFamily.Msi or InstallerFamily.Msp)
            msi = _options.MsiReader.Read(path);

        var payloads = new List<AnalysisReport>();
        var chain = new List<ChainedPackage>();
        if (depth < _options.MaxDepth && budget > 0)
        {
            var carved = PayloadCarver.Carve(path, Path.Combine(root, depth + "-" + Guid.NewGuid().ToString("n")), inspection, ref budget);
            foreach (var item in carved)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (item.Kind == "xml")
                {
                    chain.AddRange(BurnManifestReader.Read(item.Path));
                    continue;
                }

                payloads.Add(Analyze(item.Path, depth + 1, root, ref budget, cancellationToken));
            }
        }

        var codes = new List<string>();
        if (msi?.ProductCode is not null)
            codes.Add(msi.ProductCode);
        foreach (var package in chain)
        {
            if (package.ProductCode is not null)
                codes.Add(package.ProductCode);
        }
        foreach (var payload in payloads)
            codes.AddRange(ProductCodes(payload));

        var identity = inspection.Identity;
        if (string.IsNullOrWhiteSpace(identity.ProductName) && msi?.ProductName is not null)
        {
            identity = new FileIdentity
            {
                Path = identity.Path,
                Name = identity.Name,
                Size = identity.Size,
                FileVersion = identity.FileVersion,
                ProductName = msi.ProductName,
                ProductVersion = msi.ProductVersion ?? identity.ProductVersion,
                CompanyName = msi.Manufacturer ?? identity.CompanyName,
                FileDescription = identity.FileDescription,
                Signer = identity.Signer
            };
        }

        InstallLocation location;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            location = InstallLocationFinder.Find(stream, inspection.Family, identity.ProductName, inspection.Is64Bit);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            location = new InstallLocation();
        }

        var plan = CommandBuilder.Build(new CommandInput
        {
            FilePath = identity.Path,
            Family = inspection.Family,
            Confidence = inspection.Confidence,
            Msi = msi,
            Msix = inspection.Msix,
            InstallScript = inspection.InstallScript,
            InstallShieldMsiEngine = inspection.InstallShieldMsiEngine,
            ProductCodes = codes,
            InstallDirectory = location.Directory,
            AlternateInstallDirectory = location.AlternateDirectory,
            UninstallFileName = location.UninstallFileName,
            InstallDirectoryEmbedded = location.Embedded
        });

        return new AnalysisReport
        {
            File = identity,
            Family = inspection.Family,
            Confidence = inspection.Confidence,
            Evidence = inspection.Evidence,
            Detections = inspection.Detections,
            Msi = msi,
            Msix = inspection.Msix,
            Switches = plan.Switches,
            Install = plan.Install,
            Uninstall = plan.Uninstall,
            Advisory = plan.Advisory,
            Payloads = payloads,
            Chain = chain,
            CanQueryHelp = inspection.IsPortableExecutable,
            InstallScript = inspection.InstallScript,
            InstallShieldMsiEngine = inspection.InstallShieldMsiEngine,
            InstallDirectory = location.Directory,
            AlternateInstallDirectory = location.AlternateDirectory,
            UninstallFileName = location.UninstallFileName,
            InstallDirectoryEmbedded = location.Embedded
        };
    }

    private static IEnumerable<string> ProductCodes(AnalysisReport report)
    {
        if (report.Msi?.ProductCode is not null)
            yield return report.Msi.ProductCode;
        foreach (var package in report.Chain)
        {
            if (package.ProductCode is not null)
                yield return package.ProductCode;
        }
        foreach (var payload in report.Payloads)
        {
            foreach (var code in ProductCodes(payload))
                yield return code;
        }
    }

    private static string? Join(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left))
            return string.IsNullOrWhiteSpace(right) ? null : right;
        if (string.IsNullOrWhiteSpace(right))
            return left;
        return left + " " + right;
    }

    private static AnalysisReport ErrorReport(string path, string error) => new()
    {
        File = new FileIdentity
        {
            Path = path ?? "",
            Name = string.IsNullOrWhiteSpace(path) ? "" : Path.GetFileName(path),
            Size = 0
        },
        Evidence = error,
        Error = error,
        Advisory = error
    };

    private static void CleanupOldWork(string root)
    {
        var parent = Directory.GetParent(root)?.FullName;
        if (parent is null || !parent.EndsWith("InstallAnalyzer", StringComparison.OrdinalIgnoreCase) || !Directory.Exists(parent))
            return;

        var cutoff = DateTime.UtcNow.AddDays(-7);
        foreach (var dir in Directory.EnumerateDirectories(parent))
        {
            if (string.Equals(dir, root, StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                if (Directory.GetLastWriteTimeUtc(dir) < cutoff)
                    Directory.Delete(dir, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}
