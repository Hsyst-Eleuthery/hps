namespace HpsMobile.Views;

public partial class BanPage : ContentPage
{
    public BanPage(int durationSeconds, string reason)
    {
        InitializeComponent();

        ReasonLabel.Text = string.IsNullOrWhiteSpace(reason) ? "Razao nao especificada" : reason;

        if (durationSeconds > 0)
        {
            var ts = TimeSpan.FromSeconds(durationSeconds);
            var remaining = ts.Days > 0
                ? $"{ts.Days}d {ts.Hours}h {ts.Minutes}m"
                : ts.Hours > 0
                    ? $"{ts.Hours}h {ts.Minutes}m"
                    : $"{ts.Minutes}min";
            DurationLabel.Text = $"Duracao restante: {remaining}";
        }
        else
        {
            DurationLabel.IsVisible = false;
        }
    }

    private async void OnDismissClicked(object? sender, EventArgs e)
    {
        var app = Application.Current;
        if (app?.Windows.Count > 0)
            app.Windows[0].Page?.Navigation.RemovePage(this);
        if (Shell.Current != null)
            await Shell.Current.GoToAsync("//login");
    }
}
