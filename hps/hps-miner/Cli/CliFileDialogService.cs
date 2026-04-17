using Avalonia.Controls;
using HpsBrowser.Services;

namespace HpsMiner.Cli;

public sealed class CliFileDialogService : IFileDialogService
{
    public Task<string?> OpenFileAsync(Window owner, string title, string? initialDirectory = null)
    {
        return Task.FromResult<string?>(null);
    }

    public Task<string?> SaveFileAsync(Window owner, string title, string? initialDirectory = null, string? defaultFileName = null)
    {
        return Task.FromResult<string?>(null);
    }
}
