using HpsMobile.Services;

namespace HpsMobile.Views;

public partial class SettingsPage : ContentPage
{
    public SettingsPage()
    {
        InitializeComponent();
        LoadSettings();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        UpdateConnectionStatus();
        UpdateKeyInfo();
    }

    private void LoadSettings()
    {
        AutoSignSwitch.IsToggled = Preferences.Get("auto_sign", false);
    }

    private void UpdateConnectionStatus()
    {
        if (SessionState.IsLoggedIn && SessionState.Socket.IsConnected)
        {
            ConnectionStatusLabel.Text = "Conectado";
            ConnectionStatusLabel.TextColor = Color.FromArgb("#34D399");
            UserInfoLabel.Text = $"Usuario: {SessionState.Username}";
            ServerInfoLabel.Text = $"Servidor: {SessionState.ServerAddress}";
        }
        else
        {
            ConnectionStatusLabel.Text = "Desconectado";
            ConnectionStatusLabel.TextColor = Color.FromArgb("#F87171");
            UserInfoLabel.Text = "";
            ServerInfoLabel.Text = "";
        }
    }

    private void UpdateKeyInfo()
    {
        var cryptoDir = Path.Combine(FileSystem.AppDataDirectory, ".hps_keys");
        if (Directory.Exists(cryptoDir))
        {
            var keyFiles = Directory.GetFiles(cryptoDir, "*.hps*").Length;
            KeyInfoLabel.Text = $"{keyFiles} arquivos de chave encontrados\nLocal: {cryptoDir}";
        }
        else
        {
            KeyInfoLabel.Text = "Nenhuma chave local encontrada";
        }
    }

    private async void OnDisconnectClicked(object? sender, EventArgs e)
    {
        var confirmed = await DisplayAlertAsync("Desconectar",
            "Tem certeza que deseja sair da rede?", "Sim", "Nao");
        if (!confirmed) return;

        SessionState.IsLoggedIn = false;
        await SessionState.Socket.DisconnectAsync();

        Application.Current!.Windows[0].Page = new NavigationPage(new LoginPage())
        {
            BarBackgroundColor = Color.FromArgb("#1A0A2E"),
            BarTextColor = Colors.White
        };
    }

    private void OnAutoSignToggled(object? sender, ToggledEventArgs e)
    {
        Preferences.Set("auto_sign", e.Value);
    }

    private async void OnExportKeysClicked(object? sender, EventArgs e)
    {
        try
        {
            var cryptoDir = Path.Combine(FileSystem.AppDataDirectory, ".hps_keys");
            if (!Directory.Exists(cryptoDir))
            {
                await DisplayAlertAsync("Exportar", "Nenhuma chave para exportar.", "OK");
                return;
            }

            var exportPath = Path.Combine(FileSystem.AppDataDirectory, "hps_keys_export");
            Directory.CreateDirectory(exportPath);
            foreach (var file in Directory.GetFiles(cryptoDir))
                File.Copy(file, Path.Combine(exportPath, Path.GetFileName(file)), true);

            await DisplayAlertAsync("Chaves Exportadas",
                $"Chaves exportadas para:\n{exportPath}\n\nCompartilhe apenas a chave PUBLICA!", "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlertAsync("Erro", $"Falha ao exportar: {ex.Message}", "OK");
        }
    }
}
