using Avalonia.Controls;
using HpsBrowser.Services;

namespace HpsMiner.Cli;

public sealed class CliContractDialogService : IContractDialogService
{
    public Task<ContractDialogResult> ShowAsync(Window owner, string title, string contractText, Func<string, string>? signer = null)
    {
        Console.WriteLine($"\n[{title}]");
        Console.WriteLine(contractText);
        Console.Write("Aceitar contrato? (y/N): ");
        var input = Console.ReadLine();
        var accepted = string.Equals(input?.Trim(), "y", StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(input?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
        var text = contractText;
        if (accepted && signer is not null)
        {
            text = signer(contractText);
        }
        return Task.FromResult(new ContractDialogResult(accepted, text));
    }
}
