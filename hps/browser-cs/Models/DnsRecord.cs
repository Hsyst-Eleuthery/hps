using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class DnsRecord : INotifyPropertyChanged
{
    private string _domain = string.Empty;
    private string _contentHash = string.Empty;
    private string _username = string.Empty;
    private bool _verified;
    private string _ddnsHash = string.Empty;

    public string Domain
    {
        get => _domain;
        set => SetProperty(ref _domain, value);
    }

    public string ContentHash
    {
        get => _contentHash;
        set => SetProperty(ref _contentHash, value);
    }

    public string Username
    {
        get => _username;
        set => SetProperty(ref _username, value);
    }

    public bool Verified
    {
        get => _verified;
        set => SetProperty(ref _verified, value);
    }

    public string DdnsHash
    {
        get => _ddnsHash;
        set => SetProperty(ref _ddnsHash, value);
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
