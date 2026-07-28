using Android.App;
using Android.Runtime;

namespace HpsMobile;

[Application]
public class MainApplication : MauiApplication
{
    public static string? StartupCrash { get; private set; }

    public MainApplication(IntPtr handle, JniHandleOwnership ownership) : base(handle, ownership)
    {
        AndroidEnvironment.UnhandledExceptionRaiser += OnAndroidException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            var ex = args.ExceptionObject as System.Exception;
            LogCrash($"AppDomain: {ex}");
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            LogCrash($"TaskScheduler: {args.Exception}");
        };
    }

    private static void OnAndroidException(object? sender, RaiseThrowableEventArgs e)
    {
        LogCrash($"Android: {e.Exception}");
    }

    private static void LogCrash(string msg)
    {
        Android.Util.Log.Error("HpsMobile", msg);
        try
        {
            var dir = global::Android.App.Application.Context?.FilesDir?.AbsolutePath;
            if (dir != null)
                System.IO.File.AppendAllText(System.IO.Path.Combine(dir, "hps_crash.log"),
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {msg}\n");
        }
        catch { }
    }

    protected override MauiApp CreateMauiApp()
    {
        try
        {
            return MauiProgram.CreateMauiApp();
        }
        catch (System.Exception ex)
        {
            var msg = $"CreateMauiApp CRASH: {ex}";
            Android.Util.Log.Error("HpsMobile", msg);
            LogCrash(msg);
            StartupCrash = msg;
            throw;
        }
    }
}
