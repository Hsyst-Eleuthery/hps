using Avalonia.Controls;

namespace HpsBrowser.Services;

public interface IFileDialogService
{
    Task<string?> OpenFileAsync(Window owner, string title, string? initialDirectory = null);
    Task<string?> SaveFileAsync(Window owner, string title, string? initialDirectory = null, string? defaultFileName = null);
}

public sealed class FileDialogService : IFileDialogService
{
    public async Task<string?> OpenFileAsync(Window owner, string title, string? initialDirectory = null)
    {
        var dialog = new OpenFileDialog
        {
            Title = title,
            AllowMultiple = false,
            Directory = initialDirectory
        };

        var result = await dialog.ShowAsync(owner);
        return result?.FirstOrDefault();
    }

    public async Task<string?> SaveFileAsync(Window owner, string title, string? initialDirectory = null, string? defaultFileName = null)
    {
        var dialog = new SaveFileDialog
        {
            Title = title,
            Directory = initialDirectory,
            InitialFileName = defaultFileName
        };

        return await dialog.ShowAsync(owner);
    }
}
