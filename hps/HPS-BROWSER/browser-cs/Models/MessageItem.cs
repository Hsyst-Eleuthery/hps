using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class MessageItem : INotifyPropertyChanged
{
    private string _peerUser = string.Empty;
    private string _senderUser = string.Empty;
    private string _direction = string.Empty;
    private string _fileName = string.Empty;
    private string _preview = string.Empty;
    private double _timestamp;

    public string PeerUser { get => _peerUser; set => SetProperty(ref _peerUser, value); }
    public string SenderUser { get => _senderUser; set => SetProperty(ref _senderUser, value); }
    public string Direction { get => _direction; set => SetProperty(ref _direction, value); }
    public string FileName { get => _fileName; set => SetProperty(ref _fileName, value); }
    public string Preview { get => _preview; set => SetProperty(ref _preview, value); }
    public double Timestamp { get => _timestamp; set => SetProperty(ref _timestamp, value); }

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
