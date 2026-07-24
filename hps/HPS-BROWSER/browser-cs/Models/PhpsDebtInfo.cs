using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace HpsBrowser.Models;

public sealed class PhpsDebtInfo : INotifyPropertyChanged
{
    private string _debtId = string.Empty;
    private string _reason = string.Empty;
    private string _targetType = string.Empty;
    private string _targetId = string.Empty;
    private int _principal;
    private int _payoutTotal;
    private int _reservedAmount;
    private string _creditorUsername = string.Empty;
    private string _status = string.Empty;
    private double _createdAt;

    public string DebtId { get => _debtId; set => SetProperty(ref _debtId, value); }
    public string Reason { get => _reason; set => SetProperty(ref _reason, value); }
    public string TargetType { get => _targetType; set => SetProperty(ref _targetType, value); }
    public string TargetId { get => _targetId; set => SetProperty(ref _targetId, value); }
    public int Principal { get => _principal; set => SetProperty(ref _principal, value); }
    public int PayoutTotal { get => _payoutTotal; set => SetProperty(ref _payoutTotal, value); }
    public int ReservedAmount { get => _reservedAmount; set => SetProperty(ref _reservedAmount, value); }
    public string CreditorUsername { get => _creditorUsername; set => SetProperty(ref _creditorUsername, value); }
    public string Status { get => _status; set => SetProperty(ref _status, value); }
    public double CreatedAt { get => _createdAt; set => SetProperty(ref _createdAt, value); }
    public int ExpectedGain => PayoutTotal - Principal;

    public event PropertyChangedEventHandler? PropertyChanged;

    private void SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        if (propertyName is nameof(PayoutTotal) or nameof(Principal))
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ExpectedGain)));
        }
    }
}
