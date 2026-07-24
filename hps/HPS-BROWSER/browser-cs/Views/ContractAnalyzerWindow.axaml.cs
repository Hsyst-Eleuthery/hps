using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Media;
using HpsBrowser.Models;

namespace HpsBrowser.Views;

public sealed partial class ContractAnalyzerWindow : Window
{
    private Action? _accept;
    private Action? _reject;
    private Action? _renounce;

    public ContractAnalyzerWindow()
    {
        InitializeComponent();
        CloseButton.Click += (_, _) => Close();
        AcceptButton.Click += (_, _) => { _accept?.Invoke(); Close(); };
        RejectButton.Click += (_, _) => { _reject?.Invoke(); Close(); };
        RenounceButton.Click += (_, _) => { _renounce?.Invoke(); Close(); };
    }

    public void SetContent(ContractInfo contract, object? pendingTransfer, Action? accept, Action? reject, Action? renounce)
    {
        TitleText.Text = "Analisador de Contratos";
        ContractText.Text = contract.ContractContent ?? string.Empty;
        SummaryText.Text = ExtractContractSummary(contract.ContractContent ?? string.Empty);

        var integrityOk = contract.IntegrityOk && !contract.IsContractViolation;
        if (integrityOk)
        {
            StatusText.Text = "Contrato verificado";
            StatusText.Foreground = Brushes.Green;
            ReasonText.Text = string.Empty;
        }
        else
        {
            StatusText.Text = "Contrato adulterado ou inválido";
            StatusText.Foreground = Brushes.Red;
            ReasonText.Text = string.IsNullOrWhiteSpace(contract.ViolationReason)
                ? "Motivo: contrato inválido"
                : $"Motivo: {contract.ViolationReason}";
        }

        _accept = accept;
        _reject = reject;
        _renounce = renounce;

        var showPendingActions = pendingTransfer is not null;
        AcceptButton.IsVisible = showPendingActions;
        RejectButton.IsVisible = showPendingActions;
        RenounceButton.IsVisible = showPendingActions;
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
}
