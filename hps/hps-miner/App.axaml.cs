using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;

namespace HpsMiner;

public sealed class App : Application
{
    public App()
    {
        Dispatcher.UIThread.UnhandledException += (_, args) =>
        {
            LogException("[UIThread]", args.Exception);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            LogException("[UnhandledException]", args.ExceptionObject);
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            LogException("[UnobservedTaskException]", args.Exception);
            args.SetObserved();
        };
    }

    private static void LogException(string source, object exceptionObject)
    {
        try
        {
            var text = $"{DateTime.UtcNow:O} {source} {exceptionObject}{Environment.NewLine}";
            Console.Error.WriteLine(text);
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".hps_miner");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "crash.log"), text);
        }
        catch
        {
            // Do not throw from logger.
        }
    }

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
