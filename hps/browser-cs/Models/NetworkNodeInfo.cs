using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class NetworkNodeInfo : INotifyPropertyChanged
{
    private string _nodeId = string.Empty;
    private string _username = string.Empty;
    private string _address = string.Empty;
    private string _nodeType = string.Empty;
    private int _reputation = 100;
    private string _status = "Desconhecido";

    public string NodeId
    {
        get => _nodeId;
        set => SetProperty(ref _nodeId, value);
    }

    public string Username
    {
        get => _username;
        set => SetProperty(ref _username, value);
    }

    public string Address
    {
        get => _address;
        set => SetProperty(ref _address, value);
    }

    public string NodeType
    {
        get => _nodeType;
        set => SetProperty(ref _nodeType, value);
    }

    public int Reputation
    {
        get => _reputation;
        set => SetProperty(ref _reputation, value);
    }

    public string Status
    {
        get => _status;
        set => SetProperty(ref _status, value);
    }

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
