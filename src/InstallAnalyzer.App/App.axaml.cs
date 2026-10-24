using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using InstallAnalyzer.App.ViewModels;
using InstallAnalyzer.Core.Analysis;
using InstallAnalyzer.Core.Help;
using InstallAnalyzer.Core.Msi;
using InstallAnalyzer.Windows;

namespace InstallAnalyzer.App;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = new MainWindow();
            IMsiReader msi = OperatingSystem.IsWindows() ? new WindowsMsiReader() : new UnavailableMsiReader();
            IHelpQueryRunner help = OperatingSystem.IsWindows() ? new WindowsHelpQuery() : new UnavailableHelpQuery();
            Func<string, string?>? signer = OperatingSystem.IsWindows() ? AuthenticodeInspector.GetSigner : null;
            window.DataContext = new MainWindowViewModel(msi, signer, help, new WindowUserIO(window));
            desktop.MainWindow = window;
        }

        base.OnFrameworkInitializationCompleted();
    }
}

public sealed class UnavailableHelpQuery : IHelpQueryRunner
{
    public Task<HelpQueryResult> RunAsync(HelpQueryRequest request, CancellationToken cancellationToken) =>
        Task.FromResult(HelpQueryResult.Failed("Help query runs on Windows."));
}
