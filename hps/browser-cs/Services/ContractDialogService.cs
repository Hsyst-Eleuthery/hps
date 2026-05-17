using Avalonia.Controls;
using HpsBrowser.Views;

namespace HpsBrowser.Services;

public sealed record ContractDialogResult(bool Accepted, string Text);

public interface IContractDialogService
{
    Task<ContractDialogResult> ShowAsync(Window owner, string title, string contractText, Func<string, string>? signer = null);
}

public sealed class ContractDialogService : IContractDialogService
{
    public async Task<ContractDialogResult> ShowAsync(Window owner, string title, string contractText, Func<string, string>? signer = null)
    {
        var window = new ContractReviewWindow();
        window.SetContent(title, contractText, signer);
        var result = await window.ShowDialog<ContractDialogResult>(owner);
        return result;
    }
}
