using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;

namespace HpsBrowser.Views;

public partial class StartupFlowWindow : Window
{
    private readonly DispatcherTimer _blinkTimer;

    public event EventHandler? RequestUnlock;

    public StartupFlowWindow(bool isSetupMode)
    {
        InitializeComponent();
        IntroTextBlock.Text = isSetupMode
            ? "Primeiro acesso detectado. Siga as etapas para gerar e carregar suas chaves."
            : "Siga as etapas para desbloquear suas chaves e abrir o browser.";
        ProgressTitleTextBlock.Text = isSetupMode ? "Etapas da geração segura" : "Etapas da abertura segura";
        StepOneButton.Content = isSetupMode ? "[..] Gerar sua chave mestra" : "[..] Informar usuário e senha";
        StepTwoButton.Content = isSetupMode ? "[ ] Gerar chave de assinatura" : "[ ] Desbloquear chave mestra";
        StepThreeButton.Content = isSetupMode ? "[ ] Carregar chave de criptografia e descriptografia" : "[ ] Carregar chaves operacionais";

        StepOneButton.Click += OnRequestUnlock;
        CancelButton.Click += OnCancel;

        _blinkTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(650) };
        _blinkTimer.Tick += (_, _) => StepOneHintTextBlock.IsVisible = !StepOneHintTextBlock.IsVisible;
        _blinkTimer.Start();
    }

    private void OnRequestUnlock(object? sender, RoutedEventArgs e)
    {
        RequestUnlock?.Invoke(this, EventArgs.Empty);
    }

    public void MarkCompleted()
    {
        _blinkTimer.Stop();
        StepOneHintTextBlock.IsVisible = false;
        StepOneButton.Content = StepOneButton.Content?.ToString()?.Replace("[..]", "[OK]") ?? "[OK]";
        StepTwoButton.Content = StepTwoButton.Content?.ToString()?.Replace("[ ]", "[OK]") ?? "[OK]";
        StepThreeButton.Content = StepThreeButton.Content?.ToString()?.Replace("[ ]", "[OK]") ?? "[OK]";
        StepOneButton.Opacity = 1.0;
        StepTwoButton.Opacity = 1.0;
        StepThreeButton.Opacity = 1.0;
        ProgressStatusTextBlock.Text = "Etapas concluídas. Abrindo o browser.";
    }

    private void OnCancel(object? sender, RoutedEventArgs e)
    {
        Close();
    }
}
