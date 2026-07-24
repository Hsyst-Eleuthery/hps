using System;
using System.IO;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using HpsBrowser.ViewModels;

namespace HpsMiner;

public sealed partial class MainWindow : Window
{
    private static readonly string MinerCryptoDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".hps_miner");

    public MainWindow()
    {
        InitializeComponent();
        var vm = new MainViewModel(cryptoDirOverride: MinerCryptoDir, minerMode: true);
        vm.ShowTourOnStartup = false;
        vm.AttachOwner(this);
        DataContext = vm;
        Closing += (_, _) =>
        {
            if (DataContext is MainViewModel viewModel)
            {
                viewModel.SealDatabaseOnShutdown();
            }
        };
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
