using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using HpsBrowser.ViewModels;

namespace HpsBrowser;

public sealed partial class MainWindow : Window
{
    public MainWindow() : this(new MainViewModel())
    {
    }

    public MainWindow(MainViewModel vm)
    {
        InitializeComponent();
        vm.AttachOwner(this);
        DataContext = vm;
        Closing += (_, _) =>
        {
            if (DataContext is MainViewModel viewModel)
            {
                viewModel.SealDatabaseOnShutdown();
            }
        };
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    private void OnBrowserUrlKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
        {
            return;
        }

        if (DataContext is MainViewModel vm && vm.NavigateCommand.CanExecute(null))
        {
            vm.NavigateCommand.Execute(null);
        }
    }

    private async void OnCopyUploadHashClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel vm)
        {
            return;
        }
        var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clipboard is null)
        {
            vm.UploadStatus = "Ãrea de transferÃªncia indisponÃ­vel.";
            return;
        }

        var textBox = this.FindControl<TextBox>("UploadHashTextBox");
        var text = textBox?.SelectedText;
        if (string.IsNullOrWhiteSpace(text))
        {
            text = textBox?.Text;
        }
        text = text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        try
        {
            await clipboard.SetTextAsync(text);
            vm.UploadStatus = "Hash copiado para a Ã¡rea de transferÃªncia.";
        }
        catch (Exception ex)
        {
            vm.UploadStatus = $"Falha ao copiar hash: {ex.Message}";
        }
        e.Handled = true;
    }

    private async void OnUploadHashKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.C || !e.KeyModifiers.HasFlag(KeyModifiers.Control))
        {
            return;
        }

        if (sender is not TextBox textBox)
        {
            return;
        }
        var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clipboard is null)
        {
            if (DataContext is MainViewModel vmNoClipboard)
            {
                vmNoClipboard.UploadStatus = "Ãrea de transferÃªncia indisponÃ­vel.";
            }
            return;
        }

        var text = string.IsNullOrWhiteSpace(textBox.SelectedText) ? textBox.Text : textBox.SelectedText;
        text = text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        try
        {
            await clipboard.SetTextAsync(text);
            if (DataContext is MainViewModel vm)
            {
                vm.UploadStatus = "Hash copiado para a Ã¡rea de transferÃªncia.";
            }
        }
        catch (Exception ex)
        {
            if (DataContext is MainViewModel vmError)
            {
                vmError.UploadStatus = $"Falha ao copiar hash: {ex.Message}";
            }
        }
        e.Handled = true;
    }

    private async void OnHelpClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel vm)
        {
            return;
        }

        var topic = (sender as Control)?.Tag?.ToString() ?? string.Empty;
        await vm.ShowHelpAsync(topic);
        e.Handled = true;
    }
}
