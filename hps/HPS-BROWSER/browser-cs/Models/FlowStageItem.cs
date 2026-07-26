using HpsBrowser.ViewModels;
using System.Windows.Input;

namespace HpsBrowser.Models;

public sealed class FlowStageItem : ViewModelBase
{
    private string _marker = "[ ]";
    private string _title = string.Empty;
    private string _detail = string.Empty;
    private bool _isCompleted;
    private bool _isActive;
    private bool _isDimmed = true;
    private bool _isPendingUserAction;
    private bool _blinkVisible = true;
    private ICommand? _actionCommand;
    private double _opacity = 0.45;
    private string _pendingLabel = string.Empty;

    public string Marker
    {
        get => _marker;
        set => SetProperty(ref _marker, value);
    }

    public string Title
    {
        get => _title;
        set => SetProperty(ref _title, value);
    }

    public string Detail
    {
        get => _detail;
        set => SetProperty(ref _detail, value);
    }

    public bool IsCompleted
    {
        get => _isCompleted;
        set => SetProperty(ref _isCompleted, value);
    }

    public bool IsActive
    {
        get => _isActive;
        set => SetProperty(ref _isActive, value);
    }

    public bool IsDimmed
    {
        get => _isDimmed;
        set => SetProperty(ref _isDimmed, value);
    }

    public bool IsPendingUserAction
    {
        get => _isPendingUserAction;
        set => SetProperty(ref _isPendingUserAction, value);
    }

    public bool BlinkVisible
    {
        get => _blinkVisible;
        set => SetProperty(ref _blinkVisible, value);
    }

    public ICommand? ActionCommand
    {
        get => _actionCommand;
        set => SetProperty(ref _actionCommand, value);
    }

    public double Opacity
    {
        get => _opacity;
        set => SetProperty(ref _opacity, value);
    }

    public string PendingLabel
    {
        get => _pendingLabel;
        set => SetProperty(ref _pendingLabel, value);
    }
}
