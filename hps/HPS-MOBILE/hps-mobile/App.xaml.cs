using HpsMobile.Views;

namespace HpsMobile;

public partial class App : Application
{
    private static bool _banHandlerRegistered;

    public App()
    {
        try
        {
            InitializeComponent();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[FATAL] App init error: {ex}");
            throw;
        }
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        try
        {
            if (!_banHandlerRegistered)
            {
                _banHandlerRegistered = true;
                Services.SessionState.Socket.Banned += OnBanned;
            }

            var page = new LoginPage
            {
                BackgroundColor = Color.FromArgb("#1A0A2E")
            };
            return new Window(page);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[FATAL] CreateWindow error: {ex}");
            throw;
        }
    }

    private static async void OnBanned(object? sender, (int Duration, string Reason) args)
    {
        try
        {
            var app = Application.Current;
            if (app?.Windows.Count == 0) return;
            var currentPage = app!.Windows[0].Page;
            if (currentPage == null) return;

            var (duration, reason) = args;
            var banPage = new BanPage(duration, reason);

            if (MainThread.IsMainThread)
                await currentPage.Navigation.PushModalAsync(banPage);
            else
                MainThread.BeginInvokeOnMainThread(async () =>
                {
                    await currentPage.Navigation.PushModalAsync(banPage);
                });
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[BAN] Error showing ban page: {ex}");
        }
    }
}
