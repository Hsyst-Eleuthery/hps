namespace HpsMobile.Models;

public class TransactionItem
{
    public string Description { get; set; } = "";
    public string Date { get; set; } = "";
    public string Amount { get; set; } = "";
    public Color AmountColor { get; set; } = Colors.White;
}

public class PendingTransferItem
{
    public string TransferId { get; set; } = "";
    public string FromUser { get; set; } = "";
    public int Amount { get; set; }
    public string Status { get; set; } = "pending";
    public string CreatedAt { get; set; } = "";
    public bool IsIncoming { get; set; } = true;
    public string Description => IsIncoming
        ? $"Recebendo {Amount} $HPS de {FromUser}"
        : $"Enviando {Amount} $HPS para {FromUser}";
    public string Date => CreatedAt;
    public string AmountDisplay => IsIncoming ? $"+{Amount} $HPS" : $"-{Amount} $HPS";
    public Color AmountColor => IsIncoming ? Colors.LimeGreen : Colors.OrangeRed;
}
