namespace HpsWallet.Models;

public class WalletTransactionItem
{
    public string Icon { get; set; } = "";
    public string Description { get; set; } = "";
    public string Date { get; set; } = "";
    public string Amount { get; set; } = "";
    public Color AmountColor { get; set; } = Colors.White;
}

public class PendingTransferItem
{
    public string TransferId { get; set; } = "";
    public string FromUser { get; set; } = "";
    public int RawAmount { get; set; }
    public string Status { get; set; } = "pending";
    public string ContractText { get; set; } = "";
    public string CreatedAt { get; set; } = "";
    public bool IsIncoming { get; set; } = true;

    // Display properties used by XAML bindings
    public string Description =>
        IsIncoming
            ? $"[Pendente] De: {FromUser} - {RawAmount} $HPS"
            : $"[Pendente] Para: {FromUser} - {RawAmount} $HPS";
    public string Date => CreatedAt;
    public string Amount => $"{(IsIncoming ? "+" : "-")}{RawAmount} $HPS";
    public Color AmountColor => IsIncoming ? Colors.LimeGreen : Colors.OrangeRed;
}
