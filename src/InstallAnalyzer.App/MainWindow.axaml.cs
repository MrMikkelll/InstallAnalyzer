using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Platform.Storage;
using InstallAnalyzer.App.ViewModels;

namespace InstallAnalyzer.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DragDrop.SetAllowDrop(this, true);
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DropEvent, OnDrop);
    }

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = e.Data.Contains(DataFormats.Files) ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private async void OnDrop(object? sender, DragEventArgs e)
    {
        if (DataContext is not MainWindowViewModel viewModel)
            return;
        var items = e.Data.GetFiles();
        if (items is null)
            return;
        var paths = new List<string>();
        foreach (var item in items)
        {
            if (item.Path.IsAbsoluteUri && item.Path.IsFile)
                paths.Add(item.Path.LocalPath);
        }

        await viewModel.AddFilesAsync(paths);
    }

    private void OpenPayloadClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (sender is Button { DataContext: PayloadRow row } && DataContext is MainWindowViewModel viewModel)
            viewModel.OpenPayload(row);
    }
}

public sealed class WindowUserIO : IUserIO
{
    private readonly Window _window;

    public WindowUserIO(Window window) => _window = window;

    public async Task<IReadOnlyList<string>> PickFilesAsync()
    {
        var files = await _window.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Choose installers",
            AllowMultiple = true,
            FileTypeFilter =
            [
                new FilePickerFileType("Installers")
                {
                    Patterns = ["*.msi", "*.msp", "*.exe", "*.msix", "*.appx", "*.msixbundle", "*.appxbundle"]
                },
                new FilePickerFileType("All files") { Patterns = ["*.*"] }
            ]
        });

        return files
            .Select(file => file.Path.IsFile ? file.Path.LocalPath : "")
            .Where(path => path.Length > 0)
            .ToList();
    }

    public async Task SetClipboardAsync(string text)
    {
        var clipboard = TopLevel.GetTopLevel(_window)?.Clipboard;
        if (clipboard is not null)
            await clipboard.SetTextAsync(text);
    }
}
