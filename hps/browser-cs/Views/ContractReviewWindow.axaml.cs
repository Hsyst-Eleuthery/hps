using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Interactivity;
using HpsBrowser.Services;

namespace HpsBrowser.Views;

public sealed partial class ContractReviewWindow : Window
{
    private string _templateText = string.Empty;
    private bool _signed;
    private Func<string, string>? _signer;

    public ContractReviewWindow()
    {
        InitializeComponent();
        ConfirmButton.Click += OnConfirm;
        CancelButton.Click += OnCancel;
        ContractText.TextChanged += (_, _) => UpdateDiff();
    }

    public void SetContent(string title, string contractText, Func<string, string>? signer)
    {
        Title = title;
        TitleText.Text = title;
        _templateText = contractText ?? string.Empty;
        _signer = signer;
        _signed = false;
        ContractText.IsReadOnly = false;
        ConfirmButton.Content = "Confirmar";
        ContractText.Text = _templateText;
        UpdateDiff();
    }

    private void UpdateDiff()
    {
        var current = ContractText.Text ?? string.Empty;
        HashText.Text = ComputeSha256Hex(current);
        SummaryText.Text = ExtractContractSummary(current);
        DiffText.Text = BuildDiff(_templateText, current);
    }

    private void OnConfirm(object? sender, RoutedEventArgs e)
    {
        var current = (ContractText.Text ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(current))
        {
            StatusText.Text = "O contrato não pode ficar vazio.";
            return;
        }
        if (AcceptCheck.IsChecked != true)
        {
            StatusText.Text = "Confirme que leu e concorda com o contrato.";
            return;
        }
        if (_signer is not null && !_signed)
        {
            try
            {
                var signedText = _signer(current);
                ContractText.Text = signedText;
                ContractText.IsReadOnly = true;
                _signed = true;
                ConfirmButton.Content = "Continuar";
                StatusText.Text = "Contrato assinado. Revise e confirme para continuar.";
                UpdateDiff();
                return;
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Falha ao assinar contrato: {ex.Message}";
                return;
            }
        }

        Close(new ContractDialogResult(true, ContractText.Text ?? string.Empty));
    }

    private void OnCancel(object? sender, RoutedEventArgs e)
    {
        Close(new ContractDialogResult(false, ContractText.Text ?? string.Empty));
    }

    private static string ComputeSha256Hex(string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string ExtractContractSummary(string contractText)
    {
        string? action = null;
        string? user = null;
        string? targetType = null;
        string? targetId = null;
        string? domain = null;
        string? contentHash = null;
        string? transferTo = null;
        string? app = null;
        string? title = null;
        var currentSection = string.Empty;

        foreach (var rawLine in contractText.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("### ") && line.EndsWith(":"))
            {
                currentSection = line[4..^1].ToLowerInvariant();
                continue;
            }
            if (line.StartsWith("### :END "))
            {
                currentSection = string.Empty;
                continue;
            }
            if (!line.StartsWith("# "))
            {
                continue;
            }

            if (currentSection == "details")
            {
                if (line.StartsWith("# ACTION:"))
                {
                    action = line.Split(":", 2)[1].Trim();
                }
                else if (line.StartsWith("# TARGET_TYPE:"))
                {
                    targetType = line.Split(":", 2)[1].Trim();
                }
                else if (line.StartsWith("# TARGET_ID:"))
                {
                    targetId = line.Split(":", 2)[1].Trim();
                }
                else if (line.StartsWith("# DOMAIN:"))
                {
                    domain = line.Split(":", 2)[1].Trim();
                }
                else if (line.StartsWith("# CONTENT_HASH:"))
                {
                    contentHash = line.Split(":", 2)[1].Trim();
                }
                else if (line.StartsWith("# TRANSFER_TO:"))
                {
                    transferTo = line.Split(":", 2)[1].Trim();
                }
                else if (line.StartsWith("# APP:"))
                {
                    app = line.Split(":", 2)[1].Trim();
                }
                else if (line.StartsWith("# TITLE:"))
                {
                    title = line.Split(":", 2)[1].Trim();
                }
            }
            else if (currentSection == "start" && line.StartsWith("# USER:"))
            {
                user = line.Split(":", 2)[1].Trim();
            }
        }

        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(action))
        {
            lines.Add($"Ação: {action}");
        }
        if (!string.IsNullOrWhiteSpace(user))
        {
            lines.Add($"Usuário: {user}");
        }
        if (!string.IsNullOrWhiteSpace(targetType) && !string.IsNullOrWhiteSpace(targetId))
        {
            lines.Add($"Alvo: {targetType} {targetId}");
        }
        else if (!string.IsNullOrWhiteSpace(domain))
        {
            lines.Add($"Alvo: domain {domain}");
        }
        else if (!string.IsNullOrWhiteSpace(contentHash))
        {
            lines.Add($"Alvo: content {contentHash}");
        }
        if (!string.IsNullOrWhiteSpace(transferTo))
        {
            lines.Add($"Transferir para: {transferTo}");
        }
        if (!string.IsNullOrWhiteSpace(app))
        {
            lines.Add($"App: {app}");
        }
        if (!string.IsNullOrWhiteSpace(title))
        {
            lines.Add($"Título: {title}");
        }
        return lines.Count == 0 ? "Sem detalhes adicionais." : string.Join("\n", lines);
    }

    private static string BuildDiff(string templateText, string currentText)
    {
        var templateLines = templateText.Split('\n');
        var currentLines = currentText.Split('\n');
        var max = Math.Max(templateLines.Length, currentLines.Length);
        var sb = new StringBuilder();
        for (var i = 0; i < max; i++)
        {
            var t = i < templateLines.Length ? templateLines[i] : string.Empty;
            var c = i < currentLines.Length ? currentLines[i] : string.Empty;
            if (t == c)
            {
                sb.AppendLine($" {t}");
            }
            else
            {
                if (!string.IsNullOrEmpty(t))
                {
                    sb.AppendLine($"-{t}");
                }
                if (!string.IsNullOrEmpty(c))
                {
                    sb.AppendLine($"+{c}");
                }
            }
        }
        var diffText = sb.ToString().Trim();
        return string.IsNullOrWhiteSpace(diffText) ? "Sem alterações" : diffText;
    }
}
