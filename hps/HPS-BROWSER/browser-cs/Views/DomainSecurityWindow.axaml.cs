using Avalonia.Controls;
using Avalonia.Media;
using HpsBrowser.Models;

namespace HpsBrowser.Views;

public sealed partial class DomainSecurityWindow : Window
{
    public DomainSecurityWindow()
    {
        InitializeComponent();
        CloseButton.Click += (_, _) => Close();
    }

    public void SetContent(DomainSecurityInfo info)
    {
        DomainText.Text = info.Domain;
        HashText.Text = info.ContentHash;
        UserText.Text = info.Username;
        OwnerText.Text = string.IsNullOrWhiteSpace(info.OriginalOwner) ? info.Username : info.OriginalOwner;
        CertifierText.Text = info.Certifier;
        SignatureText.Text = info.Signature;

        if (info.Verified)
        {
            StatusText.Text = "DOMÍNIO VERIFICADO";
            StatusText.Foreground = Brushes.Green;
        }
        else
        {
            StatusText.Text = "DOMÍNIO SEM GARANTIA";
            StatusText.Foreground = Brushes.Red;
        }

        ContractsText.Text = info.Contracts.Count == 0
            ? "Nenhum contrato encontrado."
            : string.Join("\n", info.Contracts);
    }
}
