namespace HpsBrowser.Models;

public sealed class ApiAppVersionInfo
{
    public string AppName { get; set; } = string.Empty;
    public string ContentHash { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string VersionLabel { get; set; } = string.Empty;
    public string TimestampText { get; set; } = string.Empty;
    public bool IsLatest { get; set; }
    public bool IsCurrent { get; set; }
}
