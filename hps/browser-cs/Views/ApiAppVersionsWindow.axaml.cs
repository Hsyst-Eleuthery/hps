using System.Collections.ObjectModel;
using Avalonia.Controls;
using HpsBrowser.Models;

namespace HpsBrowser.Views;

public sealed record ApiAppVersionsDialogResult(string SelectedHash, bool ProceedCurrent);

public sealed partial class ApiAppVersionsWindow : Window
{
    public ObservableCollection<ApiAppVersionInfo> Versions { get; } = new();

    public ApiAppVersionInfo? SelectedVersion { get; set; }

    public string CurrentHash { get; private set; } = string.Empty;
    public string LatestHash { get; private set; } = string.Empty;

    public ApiAppVersionsWindow()
    {
        InitializeComponent();
        DataContext = this;
        OpenSelectedButton.Click += (_, _) =>
        {
            var selected = SelectedVersion?.ContentHash ?? string.Empty;
            Close(new ApiAppVersionsDialogResult(selected, false));
        };
        ProceedCurrentButton.Click += (_, _) => Close(new ApiAppVersionsDialogResult(string.Empty, true));
        CancelButton.Click += (_, _) => Close(new ApiAppVersionsDialogResult(string.Empty, false));
    }

    public void SetContent(string appName, IEnumerable<ApiAppVersionInfo> versions, string currentHash, string latestHash)
    {
        Title = string.IsNullOrWhiteSpace(appName) ? "Versoes do API App" : $"Versoes do API App - {appName}";
        CurrentHash = currentHash ?? string.Empty;
        LatestHash = latestHash ?? string.Empty;
        Versions.Clear();
        foreach (var version in versions)
        {
            Versions.Add(version);
        }
    }
}
