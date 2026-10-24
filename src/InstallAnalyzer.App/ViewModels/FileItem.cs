using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using InstallAnalyzer.Core;
using InstallAnalyzer.Core.Help;

namespace InstallAnalyzer.App.ViewModels;

public partial class FileItem : ObservableObject
{
    private readonly Action<FileItem> _select;

    public FileItem(AnalysisReport report, Action<FileItem> select)
    {
        _select = select;
        Load(report);
    }

    public AnalysisReport Source { get; private set; } = null!;
    public ObservableCollection<SwitchRow> Switches { get; } = [];
    public ObservableCollection<PayloadRow> Payloads { get; } = [];

    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _filePath = "";
    [ObservableProperty] private string _sizeText = "";
    [ObservableProperty] private string _productLine = "";
    [ObservableProperty] private string _publisher = "";
    [ObservableProperty] private string _familyText = "";
    [ObservableProperty] private string _confidenceText = "";
    [ObservableProperty] private string _evidence = "";
    [ObservableProperty] private string _installText = "";
    [ObservableProperty] private string _installLogText = "";
    [ObservableProperty] private string _installNote = "";
    [ObservableProperty] private string _installConfidence = "";
    [ObservableProperty] private string _uninstallText = "";
    [ObservableProperty] private string _uninstallLogText = "";
    [ObservableProperty] private string _uninstallNote = "";
    [ObservableProperty] private string _uninstallConfidence = "";
    [ObservableProperty] private string _advisory = "";
    [ObservableProperty] private string _helpOutput = "";
    [ObservableProperty] private string _helpMessage = "";
    [ObservableProperty] private string _helpArgument = "/?";
    [ObservableProperty] private bool _hasInstall;
    [ObservableProperty] private bool _hasInstallLog;
    [ObservableProperty] private bool _hasUninstall;
    [ObservableProperty] private bool _hasUninstallLog;
    [ObservableProperty] private bool _hasAdvisory;
    [ObservableProperty] private bool _hasHelpOutput;
    [ObservableProperty] private bool _hasHelpMessage;
    [ObservableProperty] private bool _canQueryHelp;
    [ObservableProperty] private bool _hasSwitches;
    [ObservableProperty] private bool _hasPayloads;
    [ObservableProperty] private bool _isSelected;
    [ObservableProperty] private InstallerFamily _family;

    public void Load(AnalysisReport report)
    {
        Source = report;
        FilePath = report.File.Path;
        Name = string.IsNullOrWhiteSpace(report.File.Name) ? "Installer" : report.File.Name;
        SizeText = FormatSize(report.File.Size);
        var product = string.Join(" ", new[] { report.File.ProductName, report.Msi?.ProductVersion ?? report.File.ProductVersion }
            .Where(part => !string.IsNullOrWhiteSpace(part)));
        ProductLine = string.IsNullOrWhiteSpace(product) ? Name : product;
        Publisher = report.File.CompanyName
            ?? report.Msi?.Manufacturer
            ?? report.Msix?.Publisher
            ?? report.File.Signer
            ?? "";
        Family = report.Family;
        FamilyText = FamilyNames.Display(report.Family);
        ConfidenceText = report.Confidence == Confidence.None ? "No confidence" : report.Confidence + " confidence";
        Evidence = report.Evidence;
        HasInstall = report.Install is not null;
        InstallText = report.Install?.Text ?? "";
        InstallLogText = report.Install?.TextWithLog ?? "";
        InstallNote = report.Install?.Note ?? "";
        InstallConfidence = report.Install is null ? "" : report.Install.Confidence + " confidence";
        HasInstallLog = report.Install?.HasLogVariant == true;
        HasUninstall = report.Uninstall is not null;
        UninstallText = report.Uninstall?.Text ?? "";
        UninstallLogText = report.Uninstall?.TextWithLog ?? "";
        UninstallNote = report.Uninstall?.Note ?? "";
        UninstallConfidence = report.Uninstall is null ? "" : report.Uninstall.Confidence + " confidence";
        HasUninstallLog = report.Uninstall?.HasLogVariant == true;
        Advisory = report.Error ?? report.Advisory ?? "";
        HasAdvisory = Advisory.Length > 0;
        HelpOutput = report.HelpOutput ?? "";
        HasHelpOutput = HelpOutput.Length > 0;
        HelpMessage = HelpMessageFor(report);
        HasHelpMessage = HelpMessage.Length > 0;
        CanQueryHelp = report.CanQueryHelp && report.Error is null;
        HelpArgument = HelpSwitches.For(report.Family);

        Switches.Clear();
        foreach (var item in report.Switches)
        {
            Switches.Add(new SwitchRow
            {
                Flag = item.Flag,
                Meaning = item.Meaning,
                Source = item.Source switch
                {
                    SwitchSource.MsiProperty => "MSI property",
                    SwitchSource.HelpText => "Help text",
                    SwitchSource.Embedded => "Embedded",
                    _ => "Built in"
                }
            });
        }

        Payloads.Clear();
        foreach (var payload in report.Payloads)
        {
            Payloads.Add(new PayloadRow
            {
                Title = payload.File.Name,
                Detail = FamilyNames.Display(payload.Family) + (payload.Msi?.ProductCode is { } code ? " · " + code : ""),
                CommandText = payload.Install?.Text ?? payload.Advisory ?? "",
                Report = payload,
                CanOpen = true
            });
        }

        foreach (var package in report.Chain)
        {
            if (payloadsAlreadyListed(package))
                continue;
            Payloads.Add(new PayloadRow
            {
                Title = package.Name ?? package.Source ?? "Chained package",
                Detail = package.ProductCode ?? "WiX Burn chain",
                CommandText = "",
                Report = report,
                CanOpen = false
            });
        }

        HasSwitches = Switches.Count > 0;
        HasPayloads = Payloads.Count > 0;
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private void Select() => _select(this);

    private bool payloadsAlreadyListed(ChainedPackage package) =>
        package.ProductCode is not null && Payloads.Any(row => row.Detail.Contains(package.ProductCode, StringComparison.OrdinalIgnoreCase));

    private static string HelpMessageFor(AnalysisReport report)
    {
        if (report.HelpWasEmpty && report.HelpTimedOut)
            return "The process was stopped after 12 seconds and did not write help text. Graphical installers often show a dialog instead of console output.";
        if (report.HelpWasEmpty)
            return "The installer did not write help text. Graphical installers often show a dialog instead of console output.";
        if (report.HelpTimedOut)
            return "The process was stopped after 12 seconds.";
        return "";
    }

    private static string FormatSize(long size)
    {
        if (size < 1024)
            return size + " B";
        if (size < 1024 * 1024)
            return $"{size / 1024.0:0.#} KB";
        if (size < 1024L * 1024 * 1024)
            return $"{size / (1024.0 * 1024):0.#} MB";
        return $"{size / (1024.0 * 1024 * 1024):0.#} GB";
    }
}
