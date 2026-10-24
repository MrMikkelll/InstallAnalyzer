namespace InstallAnalyzer.Core.Commands;

public sealed class CommandInput
{
    public required string FilePath { get; init; }
    public required InstallerFamily Family { get; init; }
    public required Confidence Confidence { get; init; }
    public MsiFacts? Msi { get; init; }
    public MsixFacts? Msix { get; init; }
    public bool InstallScript { get; init; }
    public bool InstallShieldMsiEngine { get; init; }
    public IReadOnlyList<string> HelpSwitches { get; init; } = [];
    public IReadOnlyList<string> ProductCodes { get; init; } = [];
    public string? InstallDirectory { get; init; }
    public string? AlternateInstallDirectory { get; init; }
    public string? UninstallFileName { get; init; }
    public bool InstallDirectoryEmbedded { get; init; }
    public bool SevenZipApplication { get; init; }
    public bool SumatraInstaller { get; init; }
    public bool FirefoxPackage { get; init; }
    public string? ProductName { get; init; }
}

public sealed class CommandPlan
{
    public RecommendedCommand? Install { get; init; }
    public RecommendedCommand? Uninstall { get; init; }
    public string? Advisory { get; init; }
    public IReadOnlyList<SwitchFinding> Switches { get; init; } = [];
}

public static class CommandBuilder
{
    public const string InstallLog = "%TEMP%\\InstallAnalyzer\\install.log";
    public const string UninstallLog = "%TEMP%\\InstallAnalyzer\\uninstall.log";

    public static CommandPlan Build(CommandInput input)
    {
        var switches = new List<SwitchFinding>();
        RecommendedCommand? install = null;
        RecommendedCommand? uninstall = null;
        string? advisory = null;
        var file = CommandLineText.Quote(input.FilePath);
        var confidence = input.Confidence == Confidence.None ? Confidence.Medium : input.Confidence;
        var productCode = input.ProductCodes.Select(CommandLineText.FormatProductCode).FirstOrDefault(code => code is not null)
            ?? CommandLineText.FormatProductCode(input.Msi?.ProductCode);

        switch (input.Family)
        {
            case InstallerFamily.Msi:
                install = Make("Install", $"msiexec /i {file} /qn /norestart", $"msiexec /i {file} /qn /norestart /l*v {CommandLineText.Quote(InstallLog)}", confidence, "Reboot prompts are suppressed.");
                uninstall = ProductUninstall(productCode, file, confidence, "The product code could not be read, so uninstall uses the MSI file.");
                AddBuiltIn(switches, install, ("/i", "Install the package."), ("/qn", "No user interface."), ("/norestart", "Do not reboot."));
                AddProperties(switches, input.Msi);
                break;
            case InstallerFamily.Msp:
                install = Make("Install", $"msiexec /p {file} /qn /norestart", $"msiexec /p {file} /qn /norestart /l*v {CommandLineText.Quote(InstallLog)}", confidence, "Reboot prompts are suppressed.");
                advisory = "Removing a patch needs its patch code and the product it applies to.";
                AddBuiltIn(switches, install, ("/p", "Apply the patch."), ("/qn", "No user interface."), ("/norestart", "Do not reboot."));
                break;
            case InstallerFamily.Msix:
                install = Make("Install", $"Add-AppxPackage -Path {file}", null, confidence, "MSIX install is already quiet.");
                if (!string.IsNullOrWhiteSpace(input.Msix?.Name))
                    uninstall = Make("Uninstall", $"Get-AppxPackage -Name {CommandLineText.Quote(input.Msix.Name)} | Remove-AppxPackage", null, confidence, "Removes the package with this identity name.");
                else
                    advisory = "The package identity name was not found, so there is no uninstall command yet.";
                AddBuiltIn(switches, install, ("Add-AppxPackage", "Install an MSIX or APPX package."));
                break;
            case InstallerFamily.InnoSetup:
                install = Make("Install", $"{file} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART", $"{file} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG={CommandLineText.Quote(InstallLog)}", confidence, "Reboot prompts are suppressed.");
                uninstall = FolderUninstall(input, confidence, "unins000.exe /VERYSILENT /NORESTART", "unins000.exe is created in the install directory, so this command has no full path yet.");
                AddBuiltIn(switches, install, ("/VERYSILENT", "No wizard and no progress window."), ("/SUPPRESSMSGBOXES", "Answer message boxes with the default."), ("/NORESTART", "Do not reboot."), ("/LOG", "Write an install log."), ("/DIR", "Override the install directory."), ("/TASKS", "Choose which tasks to run."));
                break;
            case InstallerFamily.Nsis:
                install = Make("Install", $"{file} /S", null, confidence, "/D=C:\\Path overrides the directory. It must be last and it must not be quoted. NSIS has no standard log switch.");
                uninstall = FolderUninstall(input, confidence, "uninstall.exe /S", "The install folder was not found, so this command has no full path yet.");
                AddBuiltIn(switches, install, ("/S", "Silent install."), ("/NCRC", "Skip the CRC check."), ("/D=", "Set the directory. Must be last and unquoted."));
                break;
            case InstallerFamily.WixBurn:
                install = Make("Install", $"{file} /install /quiet /norestart", $"{file} /install /quiet /norestart /log {CommandLineText.Quote(InstallLog)}", confidence, ChainNote("Reboot prompts are suppressed.", input.ProductCodes));
                uninstall = Make("Uninstall", $"{file} /uninstall /quiet /norestart", $"{file} /uninstall /quiet /norestart /log {CommandLineText.Quote(UninstallLog)}", confidence, ChainNote("Bundle uninstall removes the chain.", input.ProductCodes));
                AddBuiltIn(switches, install, ("/install", "Install the bundle."), ("/uninstall", "Uninstall the bundle."), ("/quiet", "No user interface."), ("/norestart", "Do not reboot."), ("/log", "Write a bundle log."), ("/layout", "Extract the bundle payloads."));
                break;
            case InstallerFamily.InstallShield:
                var scriptOnly = input.InstallScript && !input.InstallShieldMsiEngine && productCode is null;
                if (scriptOnly)
                {
                    advisory = "This looks like an InstallScript setup. Silent install needs a recorded response file: setup.exe /s /f1\"setup.iss\". No silent command is recommended until that file exists.";
                }
                else
                {
                    install = Make("Install", $"{file} /s /v\"/qn /norestart\"", $"{file} /s /v\"/qn /norestart /l*v {InstallLog}\"", confidence, input.InstallShieldMsiEngine
                        ? "Reboot prompts are suppressed. /v passes switches to the embedded Windows Installer."
                        : "Reboot prompts are suppressed. If this is a pure InstallScript setup, it needs a response file (setup.exe /s /f1\"setup.iss\") instead.");
                    uninstall = productCode is null
                        ? null
                        : ProductUninstall(productCode, file, confidence, "Uses the product code from the embedded Windows Installer package.");
                    if (productCode is null)
                        advisory = "Uninstall is registered after setup. A product code was not found in an embedded package.";
                    AddBuiltIn(switches, install, ("/s", "Silent InstallShield setup."), ("/v", "Pass Windows Installer switches."), ("/qn", "No user interface."), ("/norestart", "Do not reboot."));
                }
                break;
            case InstallerFamily.Squirrel:
                install = Make("Install", $"{file} --silent", null, confidence, "Squirrel has no standard log switch.");
                uninstall = FolderUninstall(input, confidence, "Update.exe --uninstall -s", "Update.exe lives in the application directory after install. Some packages also accept the setup executable with --uninstall -s.");
                AddBuiltIn(switches, install, ("--silent", "Silent setup."), ("--uninstall", "Uninstall flag used by some Squirrel setups."));
                break;
            case InstallerFamily.AdvancedInstaller:
                install = Make("Install", $"{file} /exenoui /qn /norestart", $"{file} /exenoui /qn /norestart /l*v {CommandLineText.Quote(InstallLog)}", confidence, "Reboot prompts are suppressed. The log switch is passed through when the package is Windows Installer based.");
                uninstall = productCode is null ? null : ProductUninstall(productCode, file, confidence, "Uses the product code from the embedded Windows Installer package.");
                if (uninstall is null)
                    advisory = "Uninstall is registered in Apps and Features. A product code was not found in an embedded package.";
                AddBuiltIn(switches, install, ("/exenoui", "Hide the EXE interface."), ("/qn", "No user interface."), ("/norestart", "Do not reboot."));
                break;
            case InstallerFamily.InstallAware:
                install = Make("Install", $"{file} /s", $"{file} /s /l={CommandLineText.Quote(InstallLog)}", confidence, "Reboot behavior depends on the package.");
                uninstall = FolderUninstall(input, confidence, "uninstall.exe /s", "The uninstaller is created in the install directory and accepts /s.");
                AddBuiltIn(switches, install, ("/s", "Silent InstallAware setup."), ("/l", "Write a log."));
                break;
            case InstallerFamily.QtInstallerFramework:
                install = Make("Install", $"{file} --accept-licenses --default-answer --confirm-command install", null, confidence, "The installer answers prompts with defaults.");
                uninstall = FolderUninstall(input, confidence, "maintenancetool.exe purge --confirm-command", "maintenancetool.exe is created in the install directory.");
                AddBuiltIn(switches, install, ("install", "Start installation."), ("--accept-licenses", "Accept licenses."), ("--default-answer", "Use default answers."), ("--confirm-command", "Do not ask for confirmation."));
                break;
            case InstallerFamily.SevenZipSfx:
                install = Make("Install", $"{file} /S", null, confidence, "/D=C:\\Path sets the output directory. It must be last and it is not quoted. This extracts files; it may not be a full installer.");
                if (input.FirefoxPackage)
                {
                    uninstall = Make("Uninstall", $"{CommandLineText.Quote(@"C:\Program Files\Mozilla Firefox\uninstall\helper.exe")} /S", null, Confidence.Medium, "Firefox removes itself through helper.exe in the install folder.");
                }
                else if (input.SevenZipApplication)
                {
                    var sevenZip = input.InstallDirectory ?? @"C:\Program Files\7-Zip";
                    uninstall = Make("Uninstall", $"{CommandLineText.Quote(CommandLineText.WindowsCombine(sevenZip, "Uninstall.exe"))} /S", null, confidence, "7-Zip registers Uninstall.exe in its install folder.");
                }
                else
                {
                    advisory = "7-Zip SFX modules usually have no uninstaller.";
                }
                AddBuiltIn(switches, install, ("/S", "Silent extract."), ("/D=", "Output directory. Must be last and unquoted."));
                break;
            case InstallerFamily.IExpress:
                install = Make("Install", $"{file} /Q", null, confidence, "/T sets a temp folder and /C runs a command.");
                advisory = "IExpress packages do not have a standard uninstall command.";
                AddBuiltIn(switches, install, ("/Q", "Suppress prompts."), ("/T", "Extract to a folder."), ("/C", "Run a command after extract."));
                break;
            default:
                if (input.SevenZipApplication || input.ProductName?.StartsWith("7-Zip", StringComparison.OrdinalIgnoreCase) == true)
                {
                    install = Make("Install", $"{file} /S", null, Confidence.Medium, "The 7-Zip installer accepts /S.");
                    var sevenZip = input.InstallDirectory ?? @"C:\Program Files\7-Zip";
                    uninstall = Make("Uninstall", $"{CommandLineText.Quote(CommandLineText.WindowsCombine(sevenZip, "Uninstall.exe"))} /S", null, Confidence.Medium, "7-Zip registers Uninstall.exe in its install folder.");
                    AddBuiltIn(switches, install, ("/S", "Silent install."));
                }
                else if (input.SumatraInstaller)
                {
                    install = Make("Install", $"{file} -s", null, Confidence.High, "SumatraPDF installs quietly with -s.");
                    uninstall = Make("Uninstall", $"{CommandLineText.Quote(@"C:\Program Files\SumatraPDF\uninstall.exe")} /s", null, Confidence.Medium, "The uninstaller accepts /s.");
                }
                else
                {
                    advisory = "No reliable silent command was found for this file. Query help tries help switches in a sandbox and does not install the file.";
                }
                break;
        }

        if (input.Msi?.ReadError is { Length: > 0 } readError)
            advisory = string.IsNullOrWhiteSpace(advisory) ? readError : advisory + " " + readError;

        ApplyHelp(input, file, switches, ref install);
        MarkIncluded(switches, install);
        return new CommandPlan
        {
            Install = install,
            Uninstall = uninstall,
            Advisory = string.IsNullOrWhiteSpace(advisory) ? null : Note(advisory),
            Switches = switches
        };
    }

    private static void ApplyHelp(CommandInput input, string file, List<SwitchFinding> switches, ref RecommendedCommand? install)
    {
        if (input.HelpSwitches.Count == 0)
            return;

        foreach (var flag in input.HelpSwitches)
        {
            switches.Add(new SwitchFinding
            {
                Flag = flag,
                Meaning = Help.HelpTextParser.IsKnownSilent(flag)
                    ? "Silent-related switch from help text."
                    : "Switch found in help text.",
                Source = SwitchSource.HelpText
            });
        }

        if (install is not null)
            return;

        var trigger = Help.HelpTextParser.BestTrigger(input.HelpSwitches);
        if (trigger is null)
            return;

        var parts = new List<string> { file, trigger };
        foreach (var companion in new[] { "/SUPPRESSMSGBOXES", "/NORESTART" })
        {
            var found = input.HelpSwitches.FirstOrDefault(flag => flag.Equals(companion, StringComparison.OrdinalIgnoreCase));
            if (found is not null)
                parts.Add(found);
        }

        install = Make("Install", string.Join(' ', parts), null, Confidence.Low, "Taken from the installer's help text.");
    }

    private static RecommendedCommand FolderUninstall(CommandInput input, Confidence confidence, string relative, string missingNote)
    {
        var fileName = string.IsNullOrWhiteSpace(input.UninstallFileName) ? FirstToken(relative) : input.UninstallFileName;
        var arguments = ArgumentsAfterFile(relative);
        if (string.IsNullOrWhiteSpace(input.InstallDirectory) || string.IsNullOrWhiteSpace(fileName))
            return Make("Uninstall", relative, null, confidence, missingNote);

        var command = CommandLineText.Quote(CommandLineText.WindowsCombine(input.InstallDirectory, fileName));
        if (!string.IsNullOrWhiteSpace(arguments))
            command += " " + arguments;
        var level = input.InstallDirectoryEmbedded ? confidence : Confidence.Medium;
        return Make("Uninstall", command, null, level, LocationNote(input, fileName, arguments));
    }

    private static string LocationNote(CommandInput input, string fileName, string arguments)
    {
        var note = input.InstallDirectoryEmbedded
            ? "The folder was read from the installer."
            : "The folder name comes from the product name.";
        if (!string.IsNullOrWhiteSpace(input.AlternateInstallDirectory))
        {
            var alternate = CommandLineText.Quote(CommandLineText.WindowsCombine(input.AlternateInstallDirectory, fileName));
            if (!string.IsNullOrWhiteSpace(arguments))
                alternate += " " + arguments;
            note += " The other common folder uses " + alternate + ".";
        }

        return note;
    }

    private static string FirstToken(string command)
    {
        var token = command.Split(' ', 2)[0].Trim('"');
        return token;
    }

    private static string ArgumentsAfterFile(string command)
    {
        var split = command.Split(' ', 2);
        return split.Length == 2 ? split[1].Trim() : "";
    }

    private static RecommendedCommand ProductUninstall(string? productCode, string file, Confidence confidence, string missingNote)
    {
        if (productCode is not null)
            return Make("Uninstall", $"msiexec /x {productCode} /qn /norestart", $"msiexec /x {productCode} /qn /norestart /l*v {CommandLineText.Quote(UninstallLog)}", confidence, "Uses the product code. Reboot prompts are suppressed.");
        return Make("Uninstall", $"msiexec /x {file} /qn /norestart", $"msiexec /x {file} /qn /norestart /l*v {CommandLineText.Quote(UninstallLog)}", Confidence.Medium, missingNote);
    }

    private static RecommendedCommand Make(string label, string text, string? withLog, Confidence confidence, string note) =>
        new()
        {
            Label = label,
            Text = text,
            TextWithLog = withLog ?? text,
            HasLogVariant = withLog is not null && !string.Equals(withLog, text, StringComparison.Ordinal),
            Confidence = confidence,
            Note = Note(note)
        };

    private static string Note(string text)
    {
        var trimmed = text.Trim();
        return trimmed.Contains("Try this in a VM.", StringComparison.Ordinal)
            ? trimmed
            : trimmed + " Try this in a VM.";
    }

    private static string ChainNote(string text, IReadOnlyList<string> codes)
    {
        var formatted = codes.Select(CommandLineText.FormatProductCode).Where(code => code is not null).Distinct().Take(6).ToArray();
        if (formatted.Length == 0)
            return text;
        return text + " Packaged product codes: " + string.Join(", ", formatted) + ".";
    }

    private static void AddBuiltIn(List<SwitchFinding> switches, RecommendedCommand? command, params (string Flag, string Meaning)[] items)
    {
        foreach (var (flag, meaning) in items)
        {
            switches.Add(new SwitchFinding
            {
                Flag = flag,
                Meaning = meaning,
                Source = SwitchSource.BuiltIn,
                IncludedInCommand = command is not null && ContainsFlag(command.Text, flag)
            });
        }
    }

    private static void AddProperties(List<SwitchFinding> switches, MsiFacts? msi)
    {
        if (msi is null)
            return;
        foreach (var pair in msi.PublicProperties)
        {
            switches.Add(new SwitchFinding
            {
                Flag = pair.Key + "=" + pair.Value,
                Meaning = "Public property from the MSI.",
                Source = SwitchSource.MsiProperty
            });
        }
    }

    private static void MarkIncluded(List<SwitchFinding> switches, RecommendedCommand? install)
    {
        if (install is null)
            return;
        foreach (var item in switches)
            item.IncludedInCommand = ContainsFlag(install.Text, item.Flag) || ContainsFlag(install.TextWithLog, item.Flag);
    }

    private static bool ContainsFlag(string command, string flag)
    {
        var index = 0;
        while ((index = command.IndexOf(flag, index, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var beforeOk = index == 0 || char.IsWhiteSpace(command[index - 1]) || command[index - 1] == '"';
            var after = index + flag.Length;
            var afterOk = after >= command.Length || char.IsWhiteSpace(command[after]) || command[after] == '"';
            if (beforeOk && afterOk)
                return true;
            index += Math.Max(flag.Length, 1);
        }

        return false;
    }
}
