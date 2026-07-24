using Android.App;
using Android.Runtime;

namespace HpsMobile;

[Application]
public class MainApplication : MauiApplication
{
    public MainApplication(IntPtr handle, JniHandleOwnership ownership) : base(handle, ownership)
    {
    }

    protected override MauiApp CreateMauiApp()
    {
        try
        {
            return MauiProgram.CreateMauiApp();
        }
        catch (System.Exception ex)
        {
            Android.Util.Log.Error("HpsMobile", $"CreateMauiApp CRASH: {ex}");
            throw;
        }
    }
}
