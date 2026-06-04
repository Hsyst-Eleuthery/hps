using Avalonia.Controls;
using Avalonia.Interactivity;
using HpsBrowser.Services;

namespace HpsBrowser.Views;

public sealed partial class ContractWindow : Window
{
    public ContractWindow()
    {
        InitializeComponent();
        ConfirmButton.Click += OnConfirm;
        CancelButton.Click += OnCancel;
    }

    public void SetContent(string title, string contractText)
    {
        Title = title;
        TitleText.Text = title;
        ContractText.Text = contractText;
    }

    public void SetReadOnlyContent(string title, string content, string closeText = "Fechar")
    {
        SetContent(title, content);
        ContractText.IsReadOnly = true;
        ConfirmButton.IsVisible = false;
        CancelButton.Content = closeText;
    }

    private void OnConfirm(object? sender, RoutedEventArgs e)
    {
        Close(new ContractDialogResult(true, ContractText.Text ?? string.Empty));
    }

    private void OnCancel(object? sender, RoutedEventArgs e)
    {
        Close(new ContractDialogResult(false, ContractText.Text ?? string.Empty));
    }
}
