using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using HpsBrowser.ViewModels;
using HpsBrowser.Views;

namespace HpsBrowser;

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
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".hps_browser");
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
            var vm = new MainViewModel();
            var isSetupMode = !vm.HasAnyLocalKeyMaterial();
            var flowWindow = new StartupFlowWindow(isSetupMode);
            var isOpeningUnlockWindow = false;
            var isTransitioningToMainWindow = false;

            flowWindow.RequestUnlock += async (_, _) =>
            {
                if (isOpeningUnlockWindow || isTransitioningToMainWindow)
                {
                    return;
                }

                isOpeningUnlockWindow = true;
                try
                {
                    var unlockWindow = new StartupUnlockWindow(isSetupMode);
                    unlockWindow.SubmitAsync = (username, passphrase) =>
                    {
                        return Task.FromResult(vm.TryUnlockAtStartup(username, passphrase, out var error)
                            ? null
                            : error);
                    };

                    await unlockWindow.ShowDialog(flowWindow);
                    if (unlockWindow.Result is null)
                    {
                        return;
                    }

                    isTransitioningToMainWindow = true;
                    flowWindow.MarkCompleted();
                    var mainWindow = new MainWindow(vm);
                    desktop.MainWindow = mainWindow;
                    mainWindow.Show();
                    flowWindow.Close();
                }
                finally
                {
                    isOpeningUnlockWindow = false;
                }
            };

            flowWindow.Closed += (_, _) =>
            {
                if (!isTransitioningToMainWindow)
                {
                    desktop.Shutdown();
                }
            };

            desktop.MainWindow = flowWindow;
        }

        base.OnFrameworkInitializationCompleted();
    }
}
