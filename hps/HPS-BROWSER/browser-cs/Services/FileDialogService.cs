using Avalonia.Controls;
using Avalonia.Platform.Storage;

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
        var options = new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false
        };

        if (initialDirectory is not null)
        {
            var folder = await owner.StorageProvider.TryGetFolderFromPathAsync(initialDirectory);
            if (folder is not null)
                options.SuggestedStartLocation = folder;
        }

        var files = await owner.StorageProvider.OpenFilePickerAsync(options);
        return files?.Count >= 1 ? files[0].TryGetLocalPath() : null;
    }

    public async Task<string?> SaveFileAsync(Window owner, string title, string? initialDirectory = null, string? defaultFileName = null)
    {
        var options = new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = defaultFileName
        };

        if (initialDirectory is not null)
        {
            var folder = await owner.StorageProvider.TryGetFolderFromPathAsync(initialDirectory);
            if (folder is not null)
                options.SuggestedStartLocation = folder;
        }

        var file = await owner.StorageProvider.SaveFilePickerAsync(options);
        return file?.TryGetLocalPath();
    }
}
