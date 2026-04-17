using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.ReactiveUI;
using HpsMiner.Cli;

namespace HpsMiner;

internal sealed class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Any(IsCliFlag))
        {
            EnsureConsoleForCli();
            RunCli(args).GetAwaiter().GetResult();
            return;
        }

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    private static async Task RunCli(string[] args)
    {
        await CliRunner.RunAsync(args);
    }

    private static bool IsCliFlag(string arg)
    {
        if (string.IsNullOrWhiteSpace(arg))
        {
            return false;
        }
        var normalized = arg.Trim();
        return string.Equals(normalized, "--cli", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(normalized, "-cli", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(normalized, "/cli", StringComparison.OrdinalIgnoreCase);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace()
            .UseReactiveUI();

    private static void EnsureConsoleForCli()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const int AttachParentProcess = -1;
        if (!AttachConsole(AttachParentProcess))
        {
            _ = AllocConsole();
        }

        try
        {
            Console.SetIn(new StreamReader(Console.OpenStandardInput()));
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
        }
        catch
        {
            // Keep default streams if rebinding fails.
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AllocConsole();
}
