using System.Threading;
using Avalonia.Controls;
using HpsBrowser.Services;

namespace HpsMiner.Cli;

public sealed class CliPromptService : IPromptService
{
    private static string? ReadLineWithTimeout(int timeoutMs = 30000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        var readTask = Task.Run(() => Console.ReadLine());
        var completed = Task.WhenAny(readTask, Task.Delay(timeoutMs, cts.Token)).GetAwaiter().GetResult();
        if (completed == readTask && readTask.IsCompletedSuccessfully)
        {
            return readTask.Result;
        }
        return null;
    }

    public Task AlertAsync(Window owner, string title, string message, string closeText = "Fechar")
    {
        Console.WriteLine($"\n[{title}]");
        Console.WriteLine(message);
        Console.Write($"{closeText}...");
        ReadLineWithTimeout(30000);
        return Task.CompletedTask;
    }

    public Task<bool> ConfirmAsync(Window owner, string title, string message, string confirmText, string cancelText)
    {
        Console.WriteLine($"\n[{title}]");
        Console.WriteLine(message);
        Console.Write($"{confirmText}? (y/N): ");
        var input = ReadLineWithTimeout(30000);
        var ok = string.Equals(input?.Trim(), "y", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(input?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
        return Task.FromResult(ok);
    }

    public Task<string?> PromptTextAsync(Window owner, string title, string message, string confirmText, string cancelText, string? defaultValue = null)
    {
        Console.WriteLine($"\n[{title}]");
        Console.WriteLine(message);
        if (!string.IsNullOrWhiteSpace(defaultValue))
        {
            Console.Write($"Valor [{defaultValue}]: ");
            var value = ReadLineWithTimeout(30000);
            if (string.IsNullOrWhiteSpace(value))
            {
                return Task.FromResult<string?>(defaultValue);
            }
            return Task.FromResult<string?>(value.Trim());
        }

        Console.Write("Valor: ");
        return Task.FromResult<string?>(ReadLineWithTimeout(30000)?.Trim());
    }
}
