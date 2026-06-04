using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace HpsBrowser.Views;

public sealed partial class PowMonitorWindow : Window
{
    public PowMonitorWindow()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
