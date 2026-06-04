using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class MessageContactInfo : INotifyPropertyChanged
{
    private string _peerUser = string.Empty;
    private string _displayName = string.Empty;
    private double _approvedAt;
    private double _lastMessageAt;
    private string _initiator = string.Empty;

    public string PeerUser { get => _peerUser; set => SetProperty(ref _peerUser, value); }
    public string DisplayName { get => _displayName; set => SetProperty(ref _displayName, value); }
    public double ApprovedAt { get => _approvedAt; set => SetProperty(ref _approvedAt, value); }
    public double LastMessageAt { get => _lastMessageAt; set => SetProperty(ref _lastMessageAt, value); }
    public string Initiator { get => _initiator; set => SetProperty(ref _initiator, value); }

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
