using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using InstallAnalyzer.Core.Analysis;
using InstallAnalyzer.Core.Help;
using InstallAnalyzer.Core.Msi;

namespace InstallAnalyzer.App.ViewModels;

public partial class MainWindowViewModel : ObservableObject
{
    private readonly InstallerAnalyzer _analyzer;
    private readonly IHelpQueryRunner _help;
    private readonly IUserIO _io;

    public MainWindowViewModel(IMsiReader msiReader, Func<string, string?>? readSigner, IHelpQueryRunner help, IUserIO io)
    {
        _help = help;
        _io = io;
        _analyzer = new InstallerAnalyzer(new AnalyzerOptions
        {
            MsiReader = msiReader,
            ReadSigner = readSigner,
            Progress = new Progress<string>(text => BusyText = text)
        });
    }

    public ObservableCollection<FileItem> Files { get; } = [];

    [ObservableProperty] private FileItem? _selected;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _busyText = "";
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private bool _showHelpConfirm;

    public bool HasSelection => Selected is not null;
    public bool ShowEmpty => !HasSelection && !IsBusy;

    partial void OnSelectedChanged(FileItem? value)
    {
        foreach (var file in Files)
            file.IsSelected = ReferenceEquals(file, value);
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(ShowEmpty));
        ShowHelpConfirm = false;
    }

    partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(ShowEmpty));

    [RelayCommand]
    private async Task BrowseAsync()
    {
        if (IsBusy)
            return;
        var files = await _io.PickFilesAsync();
        await AddFilesAsync(files);
    }

    public async Task AddFilesAsync(IReadOnlyList<string> paths)
    {
        if (IsBusy || paths.Count == 0)
            return;

        IsBusy = true;
        try
        {
            var index = 0;
            foreach (var path in paths)
            {
                index++;
                BusyText = paths.Count == 1
                    ? "Reading " + Path.GetFileName(path) + "…"
                    : $"Reading {index} of {paths.Count}…";
                var report = await Task.Run(() => _analyzer.Analyze(path));
                var item = new FileItem(report, Select);
                Files.Add(item);
                Selected = item;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    [RelayCommand]
    private void Select(FileItem item) => Selected = item;

    public void OpenPayload(PayloadRow row)
    {
        if (ReferenceEquals(row.Report, Selected?.Source))
            return;
        var existing = Files.FirstOrDefault(file =>
            string.Equals(file.FilePath, row.Report.File.Path, StringComparison.OrdinalIgnoreCase));
        if (existing is null)
        {
            existing = new FileItem(row.Report, Select);
            Files.Add(existing);
        }

        Selected = existing;
    }

    [RelayCommand]
    private void AskHelp()
    {
        if (Selected?.CanQueryHelp == true && !IsBusy)
            ShowHelpConfirm = true;
    }

    [RelayCommand]
    private void CancelHelp() => ShowHelpConfirm = false;

    [RelayCommand]
    private async Task ConfirmHelpAsync()
    {
        if (Selected is null)
            return;
        var item = Selected;
        ShowHelpConfirm = false;
        IsBusy = true;
        BusyText = "Querying help…";
        try
        {
            var result = await _help.RunAsync(new HelpQueryRequest
            {
                FilePath = item.FilePath,
                Arguments = item.HelpArgument,
                Timeout = TimeSpan.FromSeconds(12)
            }, CancellationToken.None);
            item.Load(InstallerAnalyzer.ApplyHelp(item.Source, result));
            StatusText = result.Error ?? "";
        }
        finally
        {
            IsBusy = false;
            BusyText = "";
        }
    }

    [RelayCommand]
    private Task CopyInstallAsync() => CopyAsync(Selected?.InstallText, "Copied the install command.");

    [RelayCommand]
    private Task CopyInstallLogAsync() => CopyAsync(Selected?.InstallLogText, "Copied the install command with a log.");

    [RelayCommand]
    private Task CopyUninstallAsync() => CopyAsync(Selected?.UninstallText, "Copied the uninstall command.");

    [RelayCommand]
    private Task CopyUninstallLogAsync() => CopyAsync(Selected?.UninstallLogText, "Copied the uninstall command with a log.");

    private async Task CopyAsync(string? text, string confirmation)
    {
        if (string.IsNullOrWhiteSpace(text))
            return;
        await _io.SetClipboardAsync(text);
        StatusText = confirmation;
    }
}

public interface IUserIO
{
    Task<IReadOnlyList<string>> PickFilesAsync();
    Task SetClipboardAsync(string text);
}
