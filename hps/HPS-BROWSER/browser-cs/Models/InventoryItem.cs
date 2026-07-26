using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class InventoryItem : INotifyPropertyChanged
{
    private string _contentHash = string.Empty;
    private string _title = string.Empty;
    private string _description = string.Empty;
    private string _mimeType = string.Empty;
    private long _size;
    private string _owner = string.Empty;
    private string _source = string.Empty;
    private bool _isPublic = true;

    public string ContentHash
    {
        get => _contentHash;
        set => SetProperty(ref _contentHash, value);
    }

    public string Title
    {
        get => _title;
        set => SetProperty(ref _title, value);
    }

    public string Description
    {
        get => _description;
        set => SetProperty(ref _description, value);
    }

    public string MimeType
    {
        get => _mimeType;
        set => SetProperty(ref _mimeType, value);
    }

    public long Size
    {
        get => _size;
        set => SetProperty(ref _size, value);
    }

    public string Owner
    {
        get => _owner;
        set => SetProperty(ref _owner, value);
    }

    public string Source
    {
        get => _source;
        set => SetProperty(ref _source, value);
    }

    public bool IsPublic
    {
        get => _isPublic;
        set => SetProperty(ref _isPublic, value);
    }

    public string SizeLabel => Size <= 0 ? "-" : $"{Size / 1024d:0.##} KB";

    public event PropertyChangedEventHandler? PropertyChanged;

    private void SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
