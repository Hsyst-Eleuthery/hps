using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class ContractInfo : INotifyPropertyChanged
{
    private string _contractId = string.Empty;
    private string _actionType = string.Empty;
    private string _contentHash = string.Empty;
    private string _domain = string.Empty;
    private string _username = string.Empty;
    private string _verified = string.Empty;
    private string _contractContent = string.Empty;
    private string _signature = string.Empty;
    private string _contractTitle = string.Empty;
    private double _timestamp;
    private bool _integrityOk = true;
    private string _violationReason = string.Empty;
    private bool _isPendingTransfer;
    private bool _isContractViolation;

    public string ContractId
    {
        get => _contractId;
        set => SetProperty(ref _contractId, value);
    }

    public string ActionType
    {
        get => _actionType;
        set => SetProperty(ref _actionType, value);
    }

    public string ContentHash
    {
        get => _contentHash;
        set => SetProperty(ref _contentHash, value);
    }

    public string Domain
    {
        get => _domain;
        set => SetProperty(ref _domain, value);
    }

    public string Username
    {
        get => _username;
        set => SetProperty(ref _username, value);
    }

    public string Verified
    {
        get => _verified;
        set => SetProperty(ref _verified, value);
    }

    public string ContractContent
    {
        get => _contractContent;
        set => SetProperty(ref _contractContent, value);
    }

    public string Signature
    {
        get => _signature;
        set => SetProperty(ref _signature, value);
    }

    public string ContractTitle
    {
        get => _contractTitle;
        set => SetProperty(ref _contractTitle, value);
    }

    public double Timestamp
    {
        get => _timestamp;
        set => SetProperty(ref _timestamp, value);
    }

    public bool IntegrityOk
    {
        get => _integrityOk;
        set => SetProperty(ref _integrityOk, value);
    }

    public string ViolationReason
    {
        get => _violationReason;
        set => SetProperty(ref _violationReason, value);
    }

    public bool IsPendingTransfer
    {
        get => _isPendingTransfer;
        set => SetProperty(ref _isPendingTransfer, value);
    }

    public bool IsContractViolation
    {
        get => _isContractViolation;
        set => SetProperty(ref _isContractViolation, value);
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
