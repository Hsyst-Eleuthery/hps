using Avalonia.Controls;
using HpsBrowser.Services;

namespace HpsMiner.Cli;

public sealed class CliPromptService : IPromptService
{
    public Task AlertAsync(Window owner, string title, string message, string closeText = "Fechar")
    {
        Console.WriteLine($"\n[{title}]");
        Console.WriteLine(message);
        Console.Write($"{closeText}...");
        Console.ReadLine();
        return Task.CompletedTask;
    }

    public Task<bool> ConfirmAsync(Window owner, string title, string message, string confirmText, string cancelText)
    {
        Console.WriteLine($"\n[{title}]");
        Console.WriteLine(message);
        Console.Write($"{confirmText}? (y/N): ");
        var input = Console.ReadLine();
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
            var value = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(value))
            {
                return Task.FromResult<string?>(defaultValue);
            }
            return Task.FromResult<string?>(value.Trim());
        }

        Console.Write("Valor: ");
        return Task.FromResult<string?>(Console.ReadLine()?.Trim());
    }
}
