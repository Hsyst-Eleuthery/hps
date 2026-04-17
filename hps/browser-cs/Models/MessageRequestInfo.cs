using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class MessageRequestInfo : INotifyPropertyChanged
{
    private string _requestId = string.Empty;
    private string _peerUser = string.Empty;
    private string _displayName = string.Empty;
    private string _sender = string.Empty;
    private string _receiver = string.Empty;
    private double _createdAt;

    public string RequestId { get => _requestId; set => SetProperty(ref _requestId, value); }
    public string PeerUser { get => _peerUser; set => SetProperty(ref _peerUser, value); }
    public string DisplayName { get => _displayName; set => SetProperty(ref _displayName, value); }
    public string Sender { get => _sender; set => SetProperty(ref _sender, value); }
    public string Receiver { get => _receiver; set => SetProperty(ref _receiver, value); }
    public double CreatedAt { get => _createdAt; set => SetProperty(ref _createdAt, value); }

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
