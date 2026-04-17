namespace Hps.Cli.Native.Storage;

public sealed class NativeState
{
    public string SessionId { get; set; } = Guid.NewGuid().ToString("D");
    public string ClientIdentifier { get; set; } = string.Empty;
    public string CurrentUser { get; set; } = string.Empty;
    public string CurrentServer { get; set; } = string.Empty;
    public int Reputation { get; set; } = 100;
    public string Username { get; set; } = string.Empty;
    public Dictionary<string, long> Stats { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<KnownServerRecord> KnownServers { get; set; } = [];
    public Dictionary<string, ContentCacheRecord> ContentCache { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, DdnsRecord> DdnsCache { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, ContractRecord> ContractsCache { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, VoucherRecord> VoucherCache { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, MessageContactRecord> MessageContacts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<MessageRequestRecord> IncomingMessageRequests { get; set; } = [];
    public List<MessageRequestRecord> OutgoingMessageRequests { get; set; } = [];
    public Dictionary<string, MessageRecord> MessageRecords { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public int MessagePowBundleRemaining { get; set; }
    public int MessagePowBundleSize { get; set; } = 5;
    public List<HistoryRecord> History { get; set; } = [];
    public string LastExchangeTokenJson { get; set; } = string.Empty;
    public string LastExchangeSignature { get; set; } = string.Empty;
    public string LastExchangeServer { get; set; } = string.Empty;
}

public sealed class HistoryRecord
{
    public string Command { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public bool Success { get; set; }
    public string Result { get; set; } = string.Empty;
}

public sealed class KnownServerRecord
{
    public string ServerAddress { get; set; } = string.Empty;
    public int Reputation { get; set; } = 100;
    public DateTimeOffset LastConnected { get; set; } = DateTimeOffset.UtcNow;
    public bool IsActive { get; set; } = true;
    public bool UseSsl { get; set; }
}

public sealed class ContentCacheRecord
{
    public string ContentHash { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string MimeType { get; set; } = "application/octet-stream";
    public long Size { get; set; }
    public DateTimeOffset LastAccessed { get; set; } = DateTimeOffset.UtcNow;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public bool Verified { get; set; }
}

public sealed class DdnsRecord
{
    public string Domain { get; set; } = string.Empty;
    public string DdnsHash { get; set; } = string.Empty;
    public string ContentHash { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public bool Verified { get; set; }
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string Signature { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
}

public sealed class ContractRecord
{
    public string ContractId { get; set; } = string.Empty;
    public string ActionType { get; set; } = string.Empty;
    public string ContentHash { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public bool Verified { get; set; }
    public string ContractContent { get; set; } = string.Empty;
}

public sealed class VoucherRecord
{
    public string VoucherId { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public bool IsLocalIssuer { get; set; }
    public string Owner { get; set; } = string.Empty;
    public long Value { get; set; }
    public string Reason { get; set; } = string.Empty;
    public DateTimeOffset IssuedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Payload { get; set; } = string.Empty;
    public string Signatures { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public bool Invalidated { get; set; }
    public string IntegrityHash { get; set; } = string.Empty;
    public bool IntegrityVerified { get; set; }
}

public sealed class MessageContactRecord
{
    public string PeerUser { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public DateTimeOffset ApprovedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastMessageAt { get; set; } = DateTimeOffset.UtcNow;
    public string Initiator { get; set; } = string.Empty;
}

public sealed class MessageRequestRecord
{
    public string RequestId { get; set; } = string.Empty;
    public string PeerUser { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Sender { get; set; } = string.Empty;
    public string Receiver { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class MessageRecord
{
    public string MessageId { get; set; } = string.Empty;
    public string PeerUser { get; set; } = string.Empty;
    public string SenderUser { get; set; } = string.Empty;
    public string Direction { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Preview { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
}
