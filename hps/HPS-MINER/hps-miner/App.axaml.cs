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
            var crashLogPath = Path.Combine(dir, "crash.log");

            if (File.Exists(crashLogPath) || Directory.Exists(crashLogPath))
            {
                var info = new FileInfo(crashLogPath);
                if (info.Exists && (info.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    Console.Error.WriteLine("[CrashLog] Ignorado: crash.log e um symlink.");
                    return;
                }
                var dirInfo = new DirectoryInfo(crashLogPath);
                if (dirInfo.Exists && (dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    Console.Error.WriteLine("[CrashLog] Ignorado: crash.log e um diretorio symlink.");
                    return;
                }
            }

            Directory.CreateDirectory(dir);
            File.AppendAllText(crashLogPath, text);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Crash log error: {ex}");
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
