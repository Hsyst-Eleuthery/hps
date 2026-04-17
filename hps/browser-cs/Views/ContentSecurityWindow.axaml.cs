using Avalonia.Controls;
using Avalonia.Media;
using HpsBrowser.Models;

namespace HpsBrowser.Views;

public sealed partial class ContentSecurityWindow : Window
{
    public ContentSecurityWindow()
    {
        InitializeComponent();
        CloseButton.Click += (_, _) => Close();
    }

    public void SetContent(ContentSecurityInfo info, int sizeBytes)
    {
        TitleText.Text = info.Title;
        DescriptionText.Text = info.Description;
        AuthorText.Text = info.Username;
        OwnerText.Text = string.IsNullOrWhiteSpace(info.OriginalOwner) ? info.Username : info.OriginalOwner;
        HashText.Text = info.ContentHash;
        MimeText.Text = info.MimeType;
        SizeText.Text = $"{sizeBytes} bytes";
        ReputationText.Text = info.Reputation.ToString();
        PublicKeyText.Text = info.PublicKey;
        SignatureText.Text = info.Signature;

        if (!info.SignatureValid)
        {
            StatusText.Text = "CONTEÚDO NÃO VERIFICADO";
            StatusText.Foreground = Brushes.OrangeRed;
        }
        else
        {
            StatusText.Text = "CONTEÚDO VERIFICADO";
            StatusText.Foreground = Brushes.Green;
        }

        if (!string.IsNullOrWhiteSpace(info.Certifier))
        {
            CertifierText.Text = $"Certificador: {info.Certifier}";
        }
        else
        {
            CertifierText.Text = string.Empty;
        }

        ContractsText.Text = info.Contracts.Count == 0
            ? "Nenhum contrato encontrado."
            : string.Join("\n", info.Contracts);
    }
}
