using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;

namespace HpsBrowser.Views;

public partial class PromptWindow : Window
{
    private bool _requestTextInput;
    public string InputText => InputTextBox.Text?.Trim() ?? string.Empty;

    public PromptWindow()
    {
        InitializeComponent();
        ConfirmButton.Click += OnConfirm;
        CancelButton.Click += OnCancel;
    }

    public void SetContent(string title, string message, string confirmText, string cancelText, bool requestTextInput = false, string? defaultText = null)
    {
        Title = title;
        MessageText.Text = message;
        ConfirmButton.Content = confirmText;
        CancelButton.Content = cancelText;
        CancelButton.IsVisible = !string.IsNullOrWhiteSpace(cancelText);
        ConfirmButton.HorizontalAlignment = CancelButton.IsVisible ? HorizontalAlignment.Stretch : HorizontalAlignment.Right;
        _requestTextInput = requestTextInput;
        InputTextBox.IsVisible = requestTextInput;
        InputTextBox.Text = defaultText ?? string.Empty;
    }

    private void OnConfirm(object? sender, RoutedEventArgs e)
    {
        if (_requestTextInput && string.IsNullOrWhiteSpace(InputText))
        {
            MessageText.Text = "Informe um valor para continuar.";
            return;
        }
        Close(true);
    }

    private void OnCancel(object? sender, RoutedEventArgs e)
    {
        Close(false);
    }
}
