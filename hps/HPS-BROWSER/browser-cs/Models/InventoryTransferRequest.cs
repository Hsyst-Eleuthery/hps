using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class InventoryTransferRequest : INotifyPropertyChanged
{
    private string _transferId = string.Empty;
    private string _requester = string.Empty;
    private string _contentHash = string.Empty;
    private string _title = string.Empty;
    private string _description = string.Empty;
    private string _mimeType = string.Empty;
    private long _size;

    public string TransferId
    {
        get => _transferId;
        set => SetProperty(ref _transferId, value);
    }

    public string Requester
    {
        get => _requester;
        set => SetProperty(ref _requester, value);
    }

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
