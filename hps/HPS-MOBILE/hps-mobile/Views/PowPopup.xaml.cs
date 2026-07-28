using CommunityToolkit.Maui.Views;

namespace HpsMobile.Views;

public partial class PowPopup : Popup
{
    private readonly CancellationTokenSource _cts = new();
    private readonly System.Timers.Timer _uiTimer;
    private DateTime _startTime;
    private long _attempts;
    private double _elapsedSeconds;

    public PowPopup(string actionType, int targetBits)
    {
        InitializeComponent();
        BitsLabel.Text = targetBits.ToString();
        AppendLog($"Iniciando PoW para {actionType} com {targetBits} bits...");

        _uiTimer = new System.Timers.Timer(250);
        _uiTimer.Elapsed += (_, _) => MainThread.BeginInvokeOnMainThread(() =>
        {
            _elapsedSeconds = (DateTime.UtcNow - _startTime).TotalSeconds;
            ElapsedLabel.Text = $"{_elapsedSeconds:0.0}s";
        });

        Opened += (_, _) =>
        {
            _startTime = DateTime.UtcNow;
            _uiTimer.Start();
        };
    }

    public CancellationToken Token => _cts.Token;

    public void UpdateProgress(long attemptCount, double hashrate)
    {
        _attempts = attemptCount;
        MainThread.BeginInvokeOnMainThread(() =>
        {
            HashrateLabel.Text = $"{hashrate:0} H/s";
            AttemptsLabel.Text = attemptCount.ToString("N0");
        });
    }

    public void SetStatus(string status, bool isComplete = false)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            StatusLabel.Text = status;
            if (isComplete)
            {
                CancelButton.IsVisible = false;
                CloseButton.IsVisible = true;
            }
        });
    }

    public void AppendLog(string msg)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var current = LogLabel.Text;
            if (string.IsNullOrEmpty(current))
                LogLabel.Text = $"[{timestamp}] {msg}";
            else
            {
                var lines = (current + $"\n[{timestamp}] {msg}").Trim('\n');
                var allLines = lines.Split('\n');
                if (allLines.Length > 30)
                    lines = string.Join("\n", allLines[^30..]);
                LogLabel.Text = lines;
            }
        });
    }

    public void MarkComplete(long elapsedSeconds)
    {
        _uiTimer.Stop();
        MainThread.BeginInvokeOnMainThread(() =>
        {
            ElapsedLabel.Text = $"{elapsedSeconds:0.0}s";
            StatusLabel.Text = "Solucao encontrada!";
            CancelButton.IsVisible = false;
            CloseButton.IsVisible = true;
        });
    }

    public async void AutoClose(int delayMs = 1200)
    {
        MarkComplete(0);
        await Task.Delay(delayMs);
        _cts.Dispose();
        await CloseAsync();
    }

    private async void OnCancelClicked(object? sender, EventArgs e)
    {
        _uiTimer.Stop();
        _cts.Cancel();
        await CloseAsync();
    }

    private async void OnCloseClicked(object? sender, EventArgs e)
    {
        _uiTimer.Stop();
        _cts.Dispose();
        await CloseAsync();
    }
}
