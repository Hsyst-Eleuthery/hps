namespace HpsBrowser.Models;

public sealed class DkvhpsVoucherInfo
{
    public string VoucherId { get; set; } = string.Empty;
    public string LineageRootVoucherId { get; set; } = string.Empty;
    public string LineageParentVoucherId { get; set; } = string.Empty;
    public string LineageParentHash { get; set; } = string.Empty;
    public int LineageDepth { get; set; }
    public string LineageOrigin { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public bool Invalidated { get; set; }
    public int Value { get; set; }
    public string VoucherHash { get; set; } = string.Empty;
    public string LineageHash { get; set; } = string.Empty;
    public string VoucherOwnerEncrypted { get; set; } = string.Empty;
    public string LineageOwnerEncrypted { get; set; } = string.Empty;
    public string VoucherKey { get; set; } = string.Empty;
    public string LineageKey { get; set; } = string.Empty;
    public bool DkvhpsPresent { get; set; }
    public bool VoucherHashVerified { get; set; }
    public bool LineageHashVerified { get; set; }
    public string VoucherHashStatus { get; set; } = string.Empty;
    public string LineageHashStatus { get; set; } = string.Empty;
    public string IntegritySummary { get; set; } = string.Empty;
}

public sealed class DkvhpsLineageInfo
{
    public string LineageRootVoucherId { get; set; } = string.Empty;
    public int VoucherCount { get; set; }
    public int TotalValue { get; set; }
    public string ActiveVoucherId { get; set; } = string.Empty;
    public string ActiveStatus { get; set; } = string.Empty;
    public string LineageOrigin { get; set; } = string.Empty;
    public string LineageKey { get; set; } = string.Empty;
    public bool LineageHashVerified { get; set; }
    public string IntegritySummary { get; set; } = string.Empty;
    public string DisplaySummary { get; set; } = string.Empty;
    public List<DkvhpsVoucherInfo> Vouchers { get; set; } = [];
}
