namespace HpsBrowser.Models;

public sealed class Voucher
{
    public string VoucherId { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Owner { get; set; } = string.Empty;
    public int Value { get; set; }
    public string Reason { get; set; } = string.Empty;
    public double IssuedAt { get; set; }
    public Dictionary<string, object> Payload { get; set; } = new();
    public string IssuerSignature { get; set; } = string.Empty;
    public string OwnerSignature { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public bool Invalidated { get; set; }
    public string DisplayStatus { get; set; } = string.Empty;
    public bool IsUsable { get; set; } = true;
}
