using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class ServerInfo : INotifyPropertyChanged
{
    private string _address = string.Empty;
    private string _status = "Desconhecido";
    private int _reputation = 100;
    private bool _useSsl;

    public string Address
    {
        get => _address;
        set => SetProperty(ref _address, value);
    }

    public string Status
    {
        get => _status;
        set => SetProperty(ref _status, value);
    }

    public int Reputation
    {
        get => _reputation;
        set => SetProperty(ref _reputation, value);
    }

    public bool UseSsl
    {
        get => _useSsl;
        set => SetProperty(ref _useSsl, value);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public override string ToString()
    {
        return Address;
    }

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
