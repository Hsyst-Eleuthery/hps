using CommunityToolkit.Maui;
using HpsWallet.Services;
using HpsWallet.Views;
using ZXing.Net.Maui.Controls;

namespace HpsWallet;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>().UseMauiCommunityToolkit().UseBarcodeReader();
        builder.Services.AddSingleton<HpsSocketService>();
        builder.Services.AddTransient<LoginPage>();
        builder.Services.AddTransient<WalletMainPage>();
        return builder.Build();
    }
}
