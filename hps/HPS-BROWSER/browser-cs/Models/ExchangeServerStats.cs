namespace HpsBrowser.Models;

public sealed class ExchangeServerStats
{
    public string Server { get; set; } = string.Empty;
    public string TotalMinted { get; set; } = "0";
    public string Multiplier { get; set; } = "1.00";
    public string ExchangeFeeRate { get; set; } = "0.00";
    public string UpdatedAt { get; set; } = string.Empty;
}
