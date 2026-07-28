using Android.App;
using Android.Content.PM;
using Android.OS;
using Android.Widget;

namespace HpsMobile;

[Activity(
    Theme = "@style/Maui.SplashTheme",
    MainLauncher = true,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode |
    ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        try
        {
            base.OnCreate(savedInstanceState);
        }
        catch (System.Exception ex)
        {
            Android.Util.Log.Error("HpsMobile", $"MainActivity.OnCreate CRASH: {ex}");
        }

        ShowPreviousCrash();
    }

    private void ShowPreviousCrash()
    {
        try
        {
            var dir = global::Android.App.Application.Context?.FilesDir?.AbsolutePath;
            if (dir == null) return;
            var crashFile = new Java.IO.File(dir, "hps_crash.log");
            if (!crashFile.Exists()) return;
            var content = System.IO.File.ReadAllText(crashFile.AbsolutePath);
            Toast.MakeText(this, $"Crash anterior:\n{content}", ToastLength.Long)?.Show();
            crashFile.Delete();
        }
        catch { }
    }
}
