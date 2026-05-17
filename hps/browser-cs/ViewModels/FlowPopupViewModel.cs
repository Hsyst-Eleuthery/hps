using System;
using Avalonia.Threading;
using HpsBrowser.Commands;
using System.Windows.Input;

namespace HpsBrowser.ViewModels;

public sealed class FlowPopupViewModel : ViewModelBase
{
    private string _title;
    private string _status;
    private string _details;
    private string _log = string.Empty;
    private bool _isBusy;
    private bool _isCompleted;
    private bool _completedVisible;
    private readonly DispatcherTimer? _completedTimer;
    private readonly Action _closeAction;

    public FlowPopupViewModel(string title, string status, string details, bool useUiDispatcher, Action closeAction)
    {
        _title = title;
        _status = status;
        _details = details;
        _isBusy = true;
        _closeAction = closeAction;
        CloseCommand = new RelayCommand(() => _closeAction());
        if (useUiDispatcher)
        {
            _completedTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(0.8)
            };
            _completedTimer.Tick += (_, _) => CompletedVisible = !CompletedVisible;
        }
    }

    public ICommand CloseCommand { get; }

    public string Title
    {
        get => _title;
        set => SetProperty(ref _title, value);
    }

    public string Status
    {
        get => _status;
        set => SetProperty(ref _status, value);
    }

    public string Details
    {
        get => _details;
        set => SetProperty(ref _details, value);
    }

    public string Log
    {
        get => _log;
        set => SetProperty(ref _log, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetProperty(ref _isBusy, value);
    }

    public bool IsCompleted
    {
        get => _isCompleted;
        set => SetProperty(ref _isCompleted, value);
    }

    public bool CompletedVisible
    {
        get => _completedVisible;
        set => SetProperty(ref _completedVisible, value);
    }

    public string CompletedText => "CONCLUÍDO";

    public void AppendLog(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        var line = $"[{DateTime.Now:HH:mm:ss}] {message.Trim()}";
        if (string.IsNullOrWhiteSpace(Log))
        {
            Log = line;
        }
        else
        {
            Log += "\n" + line;
        }

        const int maxLen = 8000;
        if (Log.Length > maxLen)
        {
            Log = Log[^maxLen..];
        }
    }

    public void MarkDone()
    {
        IsBusy = false;
        IsCompleted = true;
        CompletedVisible = true;
        _completedTimer?.Start();
    }

    public void ResetCompletion()
    {
        IsBusy = true;
        IsCompleted = false;
        CompletedVisible = false;
        _completedTimer?.Stop();
    }
}
