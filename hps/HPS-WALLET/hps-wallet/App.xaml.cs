using HpsWallet.Views;

namespace HpsWallet;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        return new Window(new NavigationPage(new LoginPage())
        {
            BarBackgroundColor = Color.FromArgb("#1A0A2E"),
            BarTextColor = Colors.White
        });
    }
}
