using Avalonia.Controls;
using HpsBrowser.Views;

namespace HpsBrowser.Services;

public interface IPromptService
{
    Task<bool> ConfirmAsync(Window owner, string title, string message, string confirmText, string cancelText);
    Task<string?> PromptTextAsync(Window owner, string title, string message, string confirmText, string cancelText, string? defaultValue = null);
    Task AlertAsync(Window owner, string title, string message, string closeText = "Fechar");
}

public sealed class PromptService : IPromptService
{
    public async Task<bool> ConfirmAsync(Window owner, string title, string message, string confirmText, string cancelText)
    {
        var window = new PromptWindow();
        window.SetContent(title, message, confirmText, cancelText);
        var result = await window.ShowDialog<bool>(owner);
        return result;
    }

    public async Task<string?> PromptTextAsync(Window owner, string title, string message, string confirmText, string cancelText, string? defaultValue = null)
    {
        var window = new PromptWindow();
        window.SetContent(title, message, confirmText, cancelText, requestTextInput: true, defaultText: defaultValue);
        var result = await window.ShowDialog<bool>(owner);
        return result ? window.InputText : null;
    }

    public async Task AlertAsync(Window owner, string title, string message, string closeText = "Fechar")
    {
        var window = new PromptWindow();
        window.SetContent(title, message, closeText, string.Empty);
        await window.ShowDialog<bool>(owner);
    }
}
