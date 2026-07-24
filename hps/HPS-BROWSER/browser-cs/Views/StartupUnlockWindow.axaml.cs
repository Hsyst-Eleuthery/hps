using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace HpsBrowser.Views;

public sealed record StartupUnlockResult(string Username, string Passphrase);

public partial class StartupUnlockWindow : Window
{
    private readonly bool _isSetupMode;
    public Func<string, string, Task<string?>>? SubmitAsync { get; set; }
    public StartupUnlockResult? Result { get; private set; }

    public StartupUnlockWindow() : this(false)
    {
    }

    public StartupUnlockWindow(bool isSetupMode)
    {
        _isSetupMode = isSetupMode;
        InitializeComponent();
        IntroTextBlock.Text = _isSetupMode
            ? "Primeiro acesso: informe usuario e senha para gerar chave mestra e chaves derivadas."
            : "Informe usuario e senha para desbloquear as chaves e abrir o browser.";
        Title = _isSetupMode ? "Setup Inicial de Chaves" : "Unlock de Chaves";
        ConfirmButton.Content = _isSetupMode ? "Gerar Chaves" : "Entrar";
        ConfirmButton.Click += OnConfirm;
        CancelButton.Click += OnCancel;
    }

    private async void OnConfirm(object? sender, RoutedEventArgs e)
    {
        var username = UsernameTextBox.Text?.Trim() ?? string.Empty;
        var passphrase = PassphraseTextBox.Text ?? string.Empty;
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(passphrase))
        {
            ErrorTextBlock.Text = "Usuario e senha sao obrigatorios.";
            ErrorTextBlock.IsVisible = true;
            return;
        }

        if (SubmitAsync is not null)
        {
            ConfirmButton.IsEnabled = false;
            CancelButton.IsEnabled = false;
            ErrorTextBlock.IsVisible = false;
            var error = await SubmitAsync(username, passphrase);
            ConfirmButton.IsEnabled = true;
            CancelButton.IsEnabled = true;
            if (!string.IsNullOrWhiteSpace(error))
            {
                ErrorTextBlock.Text = error;
                ErrorTextBlock.IsVisible = true;
                PassphraseTextBox.Text = string.Empty;
                return;
            }
        }

        Result = new StartupUnlockResult(username, passphrase);
        Close();
    }

    private void OnCancel(object? sender, RoutedEventArgs e)
    {
        Result = null;
        Close();
    }
}
