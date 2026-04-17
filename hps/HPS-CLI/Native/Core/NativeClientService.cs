using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hps.Cli.Native.Storage;
using Hps.Cli.Native.Net;

namespace Hps.Cli.Native.Core;

public sealed class NativeClientService
{
    private const int AesNonceSize = 12;
    private const int AesTagSize = 16;
    private static readonly byte[] EncMagic = Encoding.ASCII.GetBytes("HPS2ENC1");
    private sealed class VoucherFileEnvelope
    {
        public int Version { get; set; }
        public string Scheme { get; set; } = string.Empty;
        public string VoucherHash { get; set; } = string.Empty;
        public string LineageHash { get; set; } = string.Empty;
        public string VoucherOwnerEncrypted { get; set; } = string.Empty;
        public string LineageOwnerEncrypted { get; set; } = string.Empty;
        public string LineageNonce { get; set; } = string.Empty;
        public string Ciphertext { get; set; } = string.Empty;
    }

    private sealed class VoucherInnerEnvelope
    {
        public string VoucherNonce { get; set; } = string.Empty;
        public string Ciphertext { get; set; } = string.Empty;
    }

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
        public long Value { get; set; }
        public string VoucherHash { get; set; } = string.Empty;
        public string LineageHash { get; set; } = string.Empty;
        public string VoucherOwnerEncrypted { get; set; } = string.Empty;
        public string LineageOwnerEncrypted { get; set; } = string.Empty;
        public string VoucherKey { get; set; } = string.Empty;
        public string LineageKey { get; set; } = string.Empty;
        public bool VoucherHashVerified { get; set; }
        public bool LineageHashVerified { get; set; }
        public string StoragePath { get; set; } = string.Empty;
    }

    public sealed class DkvhpsLineageInfo
    {
        public string LineageRootVoucherId { get; set; } = string.Empty;
        public int VoucherCount { get; set; }
        public long TotalValue { get; set; }
        public string ActiveVoucherId { get; set; } = string.Empty;
        public string ActiveStatus { get; set; } = string.Empty;
        public string LineageOrigin { get; set; } = string.Empty;
        public string LineageKey { get; set; } = string.Empty;
        public bool LineageHashVerified { get; set; }
        public List<DkvhpsVoucherInfo> Vouchers { get; set; } = [];
    }

    private readonly NativeContext _ctx;
    private NativeState _state;
    private const int MaxHistoryItems = 5000;

    public NativeClientService(NativeContext ctx)
    {
        _ctx = ctx;
        _state = _ctx.StateStore.Load();
        if (string.IsNullOrWhiteSpace(_state.SessionId))
        {
            _state.SessionId = Guid.NewGuid().ToString("D");
        }
        if (string.IsNullOrWhiteSpace(_state.ClientIdentifier))
        {
            _state.ClientIdentifier = GenerateClientIdentifier(_state.SessionId);
        }
        Save();
    }

    public IReadOnlyList<string> ListKnownServers() =>
        _state.KnownServers.Where(s => s.IsActive).Select(s => s.ServerAddress).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    public string GetCurrentServer() => _state.CurrentServer;

    public string RequireCurrentServer() => _state.CurrentServer;

    public string CurrentUser => _state.CurrentUser;
    public string ClientIdentifier => _state.ClientIdentifier;
    public string CurrentPublicKeyBase64 => _ctx.KeyManager.ExportPublicKeyBase64();
    public string LastExchangeTokenJson => _state.LastExchangeTokenJson;
    public string LastExchangeSignature => _state.LastExchangeSignature;
    public bool IsCryptoUnlocked => _ctx.KeyManager.IsUnlocked;

    public void AddKnownServer(string server)
    {
        server = NormalizeServer(server);
        if (string.IsNullOrWhiteSpace(server))
        {
            return;
        }

        var existing = _state.KnownServers.FirstOrDefault(s => s.ServerAddress.Equals(server, StringComparison.OrdinalIgnoreCase));
        if (existing is null)
        {
            _state.KnownServers.Add(new KnownServerRecord
            {
                ServerAddress = server,
                LastConnected = DateTimeOffset.UtcNow,
                IsActive = true,
                UseSsl = server.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            });
        }
        else
        {
            existing.IsActive = true;
            existing.LastConnected = DateTimeOffset.UtcNow;
        }
        Save();
    }

    public bool SetCurrentServer(string serverOrIndex)
    {
        if (int.TryParse(serverOrIndex, out var idx))
        {
            var list = ListKnownServers();
            if (idx < 1 || idx > list.Count)
            {
                return false;
            }
            _state.CurrentServer = list[idx - 1];
            Save();
            return true;
        }

        var normalized = NormalizeServer(serverOrIndex);
        if (!ListKnownServers().Any(s => s.Equals(normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }
        _state.CurrentServer = normalized;
        Save();
        return true;
    }

    public bool RemoveKnownServer(string serverOrIndex)
    {
        if (int.TryParse(serverOrIndex, out var idx))
        {
            var list = _state.KnownServers.Where(x => x.IsActive).ToList();
            if (idx < 1 || idx > list.Count)
            {
                return false;
            }
            list[idx - 1].IsActive = false;
            Save();
            return true;
        }

        var normalized = NormalizeServer(serverOrIndex);
        var found = _state.KnownServers.FirstOrDefault(s => s.ServerAddress.Equals(normalized, StringComparison.OrdinalIgnoreCase));
        if (found is null)
        {
            return false;
        }
        found.IsActive = false;
        Save();
        return true;
    }

    public void SaveSession(string? currentUser, string? currentServer, int reputation, string? username, Dictionary<string, long>? stats)
    {
        _state.CurrentUser = currentUser ?? string.Empty;
        _state.CurrentServer = currentServer ?? string.Empty;
        _state.Reputation = reputation;
        _state.Username = username ?? string.Empty;
        if (stats is not null)
        {
            _state.Stats = new Dictionary<string, long>(stats, StringComparer.OrdinalIgnoreCase);
        }
        Save();
    }

    public void Logout()
    {
        _state.CurrentUser = string.Empty;
        _state.Username = string.Empty;
        Save();
    }

    public IReadOnlyDictionary<string, long> GetStats() => new Dictionary<string, long>(_state.Stats, StringComparer.OrdinalIgnoreCase);

    public void IncrementStat(string key, long amount = 1)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return;
        }
        _state.Stats.TryGetValue(key, out var current);
        _state.Stats[key] = current + amount;
        Save();
    }

    public void SetCurrentUser(string username)
    {
        _state.CurrentUser = (username ?? string.Empty).Trim();
        _state.Username = _state.CurrentUser;
        Save();
    }

    public void UnlockCrypto(string username, string passphrase, bool createIfMissing)
    {
        if (createIfMissing)
        {
            _ctx.KeyManager.UnlockOrCreate(username, passphrase);
        }
        else
        {
            _ctx.KeyManager.UnlockExisting(username, passphrase);
        }
        if (!string.IsNullOrWhiteSpace(username))
        {
            _state.CurrentUser = username.Trim();
            _state.Username = _state.CurrentUser;
        }
        var storageKey = _ctx.KeyManager.GetStorageKeyCopy();
        try
        {
            var loaded = _ctx.StateStore.LoadWithStorageKey(storageKey);
            if (!string.IsNullOrWhiteSpace(_state.CurrentUser))
            {
                loaded.CurrentUser = _state.CurrentUser;
                loaded.Username = _state.Username;
            }
            if (!string.IsNullOrWhiteSpace(_state.CurrentServer))
            {
                loaded.CurrentServer = _state.CurrentServer;
            }
            if (!string.IsNullOrWhiteSpace(_state.ClientIdentifier))
            {
                loaded.ClientIdentifier = _state.ClientIdentifier;
            }
            _state = loaded;
            _ctx.StateStore.SaveEncrypted(_state, storageKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(storageKey);
        }
        EncryptLegacyLocalFiles();
    }

    public IReadOnlyList<HistoryRecord> GetHistory(int limit)
    {
        if (limit <= 0)
        {
            limit = 50;
        }
        return _state.History
            .OrderByDescending(x => x.Timestamp)
            .Take(limit)
            .ToList();
    }

    public void AddHistory(string command, bool success, string result = "")
    {
        _state.History.Add(new HistoryRecord
        {
            Command = command ?? "",
            Timestamp = DateTimeOffset.UtcNow,
            Success = success,
            Result = result ?? ""
        });
        if (_state.History.Count > MaxHistoryItems)
        {
            var remove = _state.History.Count - MaxHistoryItems;
            _state.History.RemoveRange(0, remove);
        }
        Save();
    }

    public IReadOnlyList<VoucherRecord> ListVouchers(int limit = 100)
    {
        if (limit <= 0)
        {
            limit = 100;
        }
        return _state.VoucherCache.Values
            .OrderByDescending(v => v.IssuedAt)
            .Take(limit)
            .ToList();
    }

    public IReadOnlyList<VoucherRecord> ListSpendableVouchers(string currentServer, int limit = 100)
    {
        if (limit <= 0)
        {
            limit = 100;
        }
        return _state.VoucherCache.Values
            .Where(v => IsVoucherSpendableOnServer(v, currentServer))
            .OrderByDescending(v => v.IssuedAt)
            .Take(limit)
            .ToList();
    }

    public IReadOnlyList<DkvhpsLineageInfo> ListDkvhpsLineages()
    {
        return _state.VoucherCache.Values
            .Select(BuildDkvhpsVoucherInfo)
            .Where(info => info is not null)
            .Cast<DkvhpsVoucherInfo>()
            .GroupBy(info => string.IsNullOrWhiteSpace(info.LineageRootVoucherId) ? info.VoucherId : info.LineageRootVoucherId, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var vouchers = group
                    .OrderBy(info => info.LineageDepth)
                    .ThenBy(info => info.VoucherId, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                var active = vouchers
                    .Where(info => !info.Invalidated &&
                                   !string.Equals(info.Status, "spent", StringComparison.OrdinalIgnoreCase) &&
                                   !string.Equals(info.Status, "ghosted", StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(info => info.LineageDepth)
                    .ThenByDescending(info => info.VoucherId, StringComparer.OrdinalIgnoreCase)
                    .FirstOrDefault() ?? vouchers.Last();
                return new DkvhpsLineageInfo
                {
                    LineageRootVoucherId = group.Key,
                    VoucherCount = vouchers.Count,
                    TotalValue = vouchers.Sum(info => info.Value),
                    ActiveVoucherId = active?.VoucherId ?? string.Empty,
                    ActiveStatus = active?.Status ?? string.Empty,
                    LineageOrigin = vouchers.FirstOrDefault()?.LineageOrigin ?? string.Empty,
                    LineageKey = active?.LineageKey ?? vouchers.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.LineageKey))?.LineageKey ?? string.Empty,
                    LineageHashVerified = vouchers.All(info => info.LineageHashVerified || string.IsNullOrWhiteSpace(info.LineageHash)),
                    Vouchers = vouchers
                };
            })
            .OrderByDescending(info => info.Vouchers.Max(v => v.LineageDepth))
            .ThenBy(info => info.LineageRootVoucherId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public DkvhpsLineageInfo? GetDkvhpsLineage(string lineageOrVoucherId)
    {
        if (string.IsNullOrWhiteSpace(lineageOrVoucherId))
        {
            return null;
        }
        lineageOrVoucherId = lineageOrVoucherId.Trim();
        return ListDkvhpsLineages().FirstOrDefault(info =>
            info.LineageRootVoucherId.Equals(lineageOrVoucherId, StringComparison.OrdinalIgnoreCase) ||
            info.Vouchers.Any(v => v.VoucherId.Equals(lineageOrVoucherId, StringComparison.OrdinalIgnoreCase)));
    }

    public bool IsVoucherSpendableOnServer(VoucherRecord? voucher, string currentServer)
    {
        if (voucher is null)
        {
            return false;
        }
        if (voucher.IsLocalIssuer)
        {
            return true;
        }
        return string.Equals(NormalizeServerIdentity(voucher.Issuer), NormalizeServerIdentity(currentServer), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeServerIdentity(string value)
    {
        var raw = (value ?? string.Empty).Trim().TrimEnd('/');
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) &&
            !Uri.TryCreate("http://" + raw, UriKind.Absolute, out uri))
        {
            return raw.ToLowerInvariant();
        }

        if (uri.IsDefaultPort)
        {
            return uri.Host.ToLowerInvariant();
        }

        return $"{uri.Host}:{uri.Port}".ToLowerInvariant();
    }

    public IReadOnlyList<ContentCacheRecord> ListContentCache(int limit = 200)
    {
        if (limit <= 0)
        {
            limit = 200;
        }
        return _state.ContentCache.Values
            .OrderByDescending(c => c.LastAccessed)
            .Take(limit)
            .ToList();
    }

    public IReadOnlyList<MessageContactRecord> ListMessageContacts()
    {
        return _state.MessageContacts.Values
            .OrderByDescending(x => x.LastMessageAt)
            .ThenByDescending(x => x.ApprovedAt)
            .ToList();
    }

    public IReadOnlyList<MessageRequestRecord> ListIncomingMessageRequests()
    {
        return _state.IncomingMessageRequests
            .OrderByDescending(x => x.CreatedAt)
            .ToList();
    }

    public IReadOnlyList<MessageRequestRecord> ListOutgoingMessageRequests()
    {
        return _state.OutgoingMessageRequests
            .OrderByDescending(x => x.CreatedAt)
            .ToList();
    }

    public IReadOnlyList<MessageRecord> ListMessageRecords(string peerUser)
    {
        var normalized = (peerUser ?? string.Empty).Trim();
        return _state.MessageRecords.Values
            .Where(x => string.Equals(x.PeerUser, normalized, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Timestamp)
            .ToList();
    }

    public MessageRequestRecord? FindIncomingMessageRequest(string requestId)
    {
        var normalized = (requestId ?? string.Empty).Trim();
        return _state.IncomingMessageRequests.FirstOrDefault(x => x.RequestId.Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    public (int Remaining, int BundleSize) GetMessageBundleInfo()
    {
        return (_state.MessagePowBundleRemaining, _state.MessagePowBundleSize <= 0 ? 5 : _state.MessagePowBundleSize);
    }

    public void ReplaceMessageState(
        IEnumerable<MessageContactRecord> contacts,
        IEnumerable<MessageRequestRecord> incoming,
        IEnumerable<MessageRequestRecord> outgoing,
        int bundleRemaining,
        int bundleSize)
    {
        _state.MessageContacts = contacts
            .Where(x => !string.IsNullOrWhiteSpace(x.PeerUser))
            .ToDictionary(x => x.PeerUser, x => x, StringComparer.OrdinalIgnoreCase);
        _state.IncomingMessageRequests = incoming
            .Where(x => !string.IsNullOrWhiteSpace(x.RequestId))
            .OrderByDescending(x => x.CreatedAt)
            .ToList();
        _state.OutgoingMessageRequests = outgoing
            .Where(x => !string.IsNullOrWhiteSpace(x.RequestId))
            .OrderByDescending(x => x.CreatedAt)
            .ToList();
        _state.MessagePowBundleRemaining = Math.Max(0, bundleRemaining);
        _state.MessagePowBundleSize = bundleSize <= 0 ? 5 : bundleSize;
        Save();
    }

    public void SaveMessageRecord(MessageRecord record)
    {
        if (string.IsNullOrWhiteSpace(record.MessageId))
        {
            return;
        }

        _state.MessageRecords[record.MessageId] = record;
        if (!string.IsNullOrWhiteSpace(record.PeerUser))
        {
            if (!_state.MessageContacts.TryGetValue(record.PeerUser, out var contact))
            {
                contact = new MessageContactRecord
                {
                    PeerUser = record.PeerUser,
                    DisplayName = record.PeerUser,
                    ApprovedAt = record.Timestamp,
                    Initiator = record.Direction.Equals("out", StringComparison.OrdinalIgnoreCase) ? CurrentUser : record.PeerUser
                };
            }

            contact.LastMessageAt = record.Timestamp;
            if (string.IsNullOrWhiteSpace(contact.DisplayName))
            {
                contact.DisplayName = record.PeerUser;
            }
            _state.MessageContacts[record.PeerUser] = contact;
        }
        Save();
    }

    public void SaveContentToStorage(string contentHash, byte[] content, ContentCacheRecord? metadata = null)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }

        _ctx.Paths.EnsureDirectories();
        var fileName = $"{contentHash}.dat";
        var filePath = Path.Combine(_ctx.Paths.ContentDir, fileName);
        File.WriteAllBytes(filePath, EncryptForLocalStorage(content));

        var rec = metadata ?? new ContentCacheRecord();
        rec.ContentHash = contentHash;
        rec.FilePath = filePath;
        rec.FileName = fileName;
        rec.Size = content.LongLength;
        rec.LastAccessed = DateTimeOffset.UtcNow;
        if (string.IsNullOrWhiteSpace(rec.MimeType))
        {
            rec.MimeType = "application/octet-stream";
        }
        _state.ContentCache[contentHash] = rec;
        Save();
    }

    public void SaveDns(string domain, string contentHash)
    {
        domain = (domain ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }
        _state.DdnsCache.TryGetValue(domain, out var existing);
        _state.DdnsCache[domain] = new DdnsRecord
        {
            Domain = domain,
            ContentHash = contentHash,
            DdnsHash = existing?.DdnsHash ?? string.Empty,
            Username = existing?.Username ?? string.Empty,
            Verified = existing?.Verified ?? false,
            Timestamp = DateTimeOffset.UtcNow,
            Signature = existing?.Signature ?? string.Empty,
            PublicKey = existing?.PublicKey ?? string.Empty
        };
        Save();
    }

    public (byte[] Content, ContentCacheRecord Metadata)? LoadCachedContent(string contentHash)
    {
        if (!_state.ContentCache.TryGetValue(contentHash, out var rec))
        {
            return null;
        }
        if (!File.Exists(rec.FilePath))
        {
            return null;
        }
        rec.LastAccessed = DateTimeOffset.UtcNow;
        _state.ContentCache[contentHash] = rec;
        Save();
        return (DecryptFromLocalStorage(File.ReadAllBytes(rec.FilePath)), rec);
    }

    public string SaveDdnsToStorage(string domain, byte[] ddnsContent, DdnsRecord? metadata = null)
    {
        domain = (domain ?? string.Empty).Trim().ToLowerInvariant();
        var ddnsHash = Convert.ToHexString(SHA256.HashData(ddnsContent)).ToLowerInvariant();
        var filePath = Path.Combine(_ctx.Paths.DdnsDir, $"{ddnsHash}.ddns");
        File.WriteAllBytes(filePath, EncryptForLocalStorage(ddnsContent));

        if (!string.IsNullOrWhiteSpace(domain))
        {
            var rec = metadata ?? new DdnsRecord();
            rec.Domain = domain;
            rec.DdnsHash = ddnsHash;
            rec.Timestamp = DateTimeOffset.UtcNow;
            _state.DdnsCache[domain] = rec;
            Save();
        }
        return ddnsHash;
    }

    public DdnsRecord? GetDdnsRecord(string domain)
    {
        domain = (domain ?? string.Empty).Trim().ToLowerInvariant();
        return string.IsNullOrWhiteSpace(domain) ? null : _state.DdnsCache.GetValueOrDefault(domain);
    }

    public byte[]? LoadDdnsContent(string domain)
    {
        var record = GetDdnsRecord(domain);
        if (record is null || string.IsNullOrWhiteSpace(record.DdnsHash))
        {
            return null;
        }
        var filePath = Path.Combine(_ctx.Paths.DdnsDir, $"{record.DdnsHash}.ddns");
        if (!File.Exists(filePath))
        {
            return null;
        }
        return DecryptFromLocalStorage(File.ReadAllBytes(filePath));
    }

    public void SaveContractToStorage(ContractRecord contract)
    {
        if (string.IsNullOrWhiteSpace(contract.ContractId))
        {
            return;
        }
        _ctx.Paths.EnsureDirectories();
        if (!string.IsNullOrWhiteSpace(contract.ContractContent))
        {
            var path = Path.Combine(_ctx.Paths.ContractsDir, $"{contract.ContractId}.contract");
            var plain = Encoding.UTF8.GetBytes(contract.ContractContent);
            File.WriteAllBytes(path, EncryptForLocalStorage(plain));
            CryptographicOperations.ZeroMemory(plain);
        }
        _state.ContractsCache[contract.ContractId] = contract;
        Save();
    }

    public ContractRecord? GetContractRecord(string contractId)
    {
        if (string.IsNullOrWhiteSpace(contractId))
        {
            return null;
        }
        if (!_state.ContractsCache.TryGetValue(contractId, out var rec))
        {
            return null;
        }
        if (string.IsNullOrWhiteSpace(rec.ContractContent))
        {
            var path = Path.Combine(_ctx.Paths.ContractsDir, $"{contractId}.contract");
            rec.ContractContent = ReadTextFileFromStorage(path);
        }
        return rec;
    }

    public void SaveVoucher(VoucherRecord voucher)
    {
        if (string.IsNullOrWhiteSpace(voucher.VoucherId))
        {
            return;
        }
        SaveVoucherInternal(voucher, persistState: true);
    }

    private void SaveVoucherInternal(VoucherRecord voucher, bool persistState)
    {
        if (string.IsNullOrWhiteSpace(voucher.VoucherId))
        {
            return;
        }
        _ctx.Paths.EnsureDirectories();
        var path = BuildVoucherStoragePath(voucher);
        var raw = JsonSerializer.Serialize(voucher, new JsonSerializerOptions { WriteIndented = true });
        var plain = Encoding.UTF8.GetBytes(raw);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? _ctx.Paths.VouchersDir);
            File.WriteAllBytes(path, EncryptForLocalStorage(ProtectVoucherWithDkvhps(voucher, plain)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
        var legacyPath = Path.Combine(_ctx.Paths.VouchersDir, $"{voucher.VoucherId}.hps");
        if (!string.Equals(path, legacyPath, StringComparison.OrdinalIgnoreCase) && File.Exists(legacyPath))
        {
            try
            {
                File.Delete(legacyPath);
            }
            catch
            {
            }
        }
        _state.VoucherCache[voucher.VoucherId] = voucher;
        if (persistState)
        {
            Save();
        }
    }

    public string ReadTextFileFromStorage(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return string.Empty;
        }
        try
        {
            var raw = File.ReadAllBytes(filePath);
            var plain = DecryptFromLocalStorage(raw);
            var text = Encoding.UTF8.GetString(plain);
            CryptographicOperations.ZeroMemory(plain);
            return text;
        }
        catch
        {
            try
            {
                return File.ReadAllText(filePath, Encoding.UTF8);
            }
            catch
            {
                return string.Empty;
            }
        }
    }

    public void ApplySyncSnapshot(SyncSnapshot snapshot)
    {
        foreach (var row in snapshot.Dns)
        {
            var domain = GetValue(row, "domain");
            var hash = GetValue(row, "content_hash");
            if (!string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(hash))
            {
                SaveDns(domain, hash);
                var ddnsHash = GetValue(row, "ddns_hash");
                if (!string.IsNullOrWhiteSpace(ddnsHash))
                {
                    _state.DdnsCache[domain.Trim().ToLowerInvariant()] = new DdnsRecord
                    {
                        Domain = domain.Trim().ToLowerInvariant(),
                        ContentHash = hash,
                        DdnsHash = ddnsHash,
                        Username = GetValue(row, "username"),
                        Verified = GetBool(row, "verified"),
                        Timestamp = DateTimeOffset.UtcNow,
                        Signature = GetValue(row, "signature"),
                        PublicKey = GetValue(row, "public_key")
                    };
                }
            }
        }

        foreach (var row in snapshot.Contracts)
        {
            var id = GetValue(row, "contract_id");
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }
            SaveContractToStorage(new ContractRecord
            {
                ContractId = id,
                ActionType = GetValue(row, "action_type"),
                ContentHash = GetValue(row, "content_hash"),
                Domain = GetValue(row, "domain"),
                Username = GetValue(row, "username"),
                Signature = GetValue(row, "signature"),
                ContractContent = GetValue(row, "contract_content"),
                Verified = GetBool(row, "verified"),
                Timestamp = DateTimeOffset.UtcNow
            });
        }
        Save();
    }

    public (bool Ok, string Error) VerifyVoucherSignatures(JsonElement voucherElement)
    {
        try
        {
            if (!voucherElement.TryGetProperty("payload", out var payload) ||
                !voucherElement.TryGetProperty("signatures", out var signatures))
            {
                return (false, "voucher payload/signatures missing");
            }
            var payloadRaw = payload.GetRawText();
            var payloadObj = JsonSerializer.Deserialize<Dictionary<string, object?>>(payloadRaw) ?? [];
            var ownerKey = GetString(payloadObj, "owner_public_key");
            var issuerKey = GetString(payloadObj, "issuer_public_key");
            if (string.IsNullOrWhiteSpace(ownerKey) || string.IsNullOrWhiteSpace(issuerKey))
            {
                return (false, "voucher public keys missing");
            }

            var canonical = CanonicalJson(payloadObj);
            var ownerSig = signatures.TryGetProperty("owner", out var os) ? os.GetString() ?? string.Empty : string.Empty;
            var issuerSig = signatures.TryGetProperty("issuer", out var isg) ? isg.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(ownerSig) || string.IsNullOrWhiteSpace(issuerSig))
            {
                return (false, "voucher signatures missing");
            }

            var ownerOk = _ctx.KeyManager.VerifySignature(canonical, Convert.FromBase64String(ownerSig), ownerKey);
            var issuerOk = _ctx.KeyManager.VerifySignature(canonical, Convert.FromBase64String(issuerSig), issuerKey);
            return ownerOk && issuerOk ? (true, string.Empty) : (false, "voucher signature invalid");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    public (bool Ok, string VoucherId, string Error) SaveVoucherFromJson(string jsonText)
    {
        try
        {
            var node = JsonNode.Parse(jsonText);
            if (node is null)
            {
                return (false, string.Empty, "json vazio");
            }
            var voucherId = node["payload"]?["voucher_id"]?.GetValue<string>() ?? node["voucher_id"]?.GetValue<string>() ?? "";
            if (string.IsNullOrWhiteSpace(voucherId))
            {
                return (false, string.Empty, "voucher_id ausente");
            }
            var rec = new VoucherRecord
            {
                VoucherId = voucherId,
                Issuer = node["payload"]?["issuer"]?.GetValue<string>() ?? "",
                IsLocalIssuer = false,
                Owner = node["payload"]?["owner"]?.GetValue<string>() ?? "",
                Value = node["payload"]?["value"]?.GetValue<long>() ?? 0,
                Reason = node["payload"]?["reason"]?.GetValue<string>() ?? "",
                IssuedAt = DateTimeOffset.UtcNow,
                Payload = node["payload"]?.ToJsonString() ?? "",
                Signatures = node["signatures"]?.ToJsonString() ?? "",
                Status = node["status"]?.GetValue<string>() ?? "unknown",
                Invalidated = node["invalidated"]?.GetValue<bool>() ?? false,
                IntegrityHash = node["integrity"]?["hash"]?.GetValue<string>() ?? "",
                IntegrityVerified = node["integrity"]?["verified"]?.GetValue<bool>() ?? false
            };
            SaveVoucher(rec);
            return (true, voucherId, string.Empty);
        }
        catch (Exception ex)
        {
            return (false, string.Empty, ex.Message);
        }
    }

    public (bool Ok, string VoucherId, string Error) SaveVoucherFromText(string rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return (false, string.Empty, "conteudo vazio");
        }
        var trimmed = rawText.TrimStart();
        if (trimmed.StartsWith("# HSYST P2P SERVICE", StringComparison.Ordinal))
        {
            var parsed = ParseHpsVoucherHsyst(rawText);
            if (parsed is null)
            {
                return (false, string.Empty, "formato .hps invalido");
            }
            var json = JsonSerializer.Serialize(parsed);
            return SaveVoucherFromJson(json);
        }
        return SaveVoucherFromJson(rawText);
    }

    public byte[] SignContent(byte[] content) => _ctx.KeyManager.SignBytes(content);

    public string PublicKeyBase64() => _ctx.KeyManager.ExportPublicKeyBase64();

    public string SignCanonicalPayloadBase64(Dictionary<string, object?> payload)
    {
        var canonical = CanonicalJson(payload);
        return Convert.ToBase64String(_ctx.KeyManager.SignPayload(canonical));
    }

    public string InferIssuerFromVouchers(IEnumerable<string> voucherIds, string fallback)
    {
        foreach (var id in voucherIds)
        {
            if (_state.VoucherCache.TryGetValue(id, out var v) && !string.IsNullOrWhiteSpace(v.Issuer))
            {
                return v.Issuer;
            }
        }
        return fallback;
    }

    public void SaveLastExchangeToken(string server, string tokenJson, string signature)
    {
        _state.LastExchangeServer = server ?? string.Empty;
        _state.LastExchangeTokenJson = tokenJson ?? string.Empty;
        _state.LastExchangeSignature = signature ?? string.Empty;
        Save();
    }

    public string BuildContractTemplate(string actionType, IReadOnlyDictionary<string, string> details)
    {
        var user = string.IsNullOrWhiteSpace(_state.CurrentUser) ? "unknown" : _state.CurrentUser;
        var lines = new List<string>
        {
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            $"# ACTION: {actionType}"
        };
        foreach (var kv in details)
        {
            lines.Add($"# {kv.Key.ToUpperInvariant()}: {kv.Value}");
        }
        lines.Add("### :END DETAILS");
        lines.Add("### START:");
        lines.Add($"# USER: {user}");
        lines.Add("# SIGNATURE: ");
        lines.Add("### :END START");
        lines.Add("## :END CONTRACT");
        return string.Join("\n", lines) + "\n";
    }

    public string SignContractTemplate(string contractTemplate)
    {
        var trimmed = (contractTemplate ?? string.Empty).TrimEnd('\r', '\n');
        var lines = trimmed.Split('\n').ToList();
        var signatureIndex = lines.FindIndex(line => line.TrimStart().StartsWith("# SIGNATURE:", StringComparison.Ordinal));
        if (signatureIndex < 0)
        {
            throw new InvalidOperationException("linha de assinatura nao encontrada no contrato");
        }

        var userIndex = lines.FindIndex(line => line.TrimStart().StartsWith("# USER:", StringComparison.Ordinal));
        if (userIndex >= 0 && !string.IsNullOrWhiteSpace(_state.CurrentUser))
        {
            lines[userIndex] = "# USER: " + _state.CurrentUser;
        }

        var signedLines = new List<string>(lines.Count);
        for (var i = 0; i < lines.Count; i++)
        {
            if (i == signatureIndex)
            {
                continue;
            }
            signedLines.Add(lines[i]);
        }

        var signedText = string.Join("\n", signedLines);
        if (!ValidateContractTextAllowed(signedText, new[] { ExtractAction(signedText) }, out var err))
        {
            throw new InvalidOperationException(err);
        }
        var signature = Convert.ToBase64String(_ctx.KeyManager.SignPayload(signedText));
        lines[signatureIndex] = "# SIGNATURE: " + signature;
        return string.Join("\n", lines).TrimEnd() + "\n";
    }

    public bool VerifyContractSignatureWithKey(string contractText, string publicKeyPemOrBase64)
    {
        try
        {
            var normalized = NormalizeContractWithoutSignature(contractText, out var signatureB64);
            if (string.IsNullOrWhiteSpace(signatureB64))
            {
                return false;
            }
            var signature = Convert.FromBase64String(signatureB64);
            return _ctx.KeyManager.VerifySignature(normalized, signature, publicKeyPemOrBase64);
        }
        catch
        {
            return false;
        }
    }

    public Dictionary<string, string> ExtractContractDetailsMap(string contractText)
    {
        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(contractText))
        {
            return details;
        }
        var lines = contractText.Split('\n');
        var inDetails = false;
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line == "### DETAILS:")
            {
                inDetails = true;
                continue;
            }
            if (line == "### :END DETAILS")
            {
                break;
            }
            if (!inDetails)
            {
                continue;
            }
            if (!line.StartsWith("# ", StringComparison.Ordinal))
            {
                continue;
            }
            var value = line[2..];
            var idx = value.IndexOf(':');
            if (idx <= 0)
            {
                continue;
            }
            var key = value[..idx].Trim();
            var val = value[(idx + 1)..].Trim();
            details[key] = val;
        }
        return details;
    }

    public bool ValidateContractTextAllowed(string contractText, IReadOnlyCollection<string> allowedActions, out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(contractText) || !contractText.StartsWith("# HSYST P2P SERVICE", StringComparison.Ordinal))
        {
            error = "cabecalho HSYST nao encontrado";
            return false;
        }
        if (!contractText.Contains("## :END CONTRACT", StringComparison.Ordinal))
        {
            error = "final do contrato nao encontrado";
            return false;
        }
        var action = ExtractAction(contractText);
        if (string.IsNullOrWhiteSpace(action))
        {
            error = "acao nao informada no contrato";
            return false;
        }
        if (allowedActions.Count > 0 && !allowedActions.Contains(action, StringComparer.OrdinalIgnoreCase))
        {
            error = $"acao invalida no contrato (permitido: {string.Join(", ", allowedActions)})";
            return false;
        }
        var user = ExtractStartUser(contractText);
        if (string.IsNullOrWhiteSpace(user))
        {
            error = "usuario nao informado no contrato";
            return false;
        }
        if (!string.IsNullOrWhiteSpace(_state.CurrentUser) && !user.Equals(_state.CurrentUser, StringComparison.Ordinal))
        {
            error = "usuario do contrato nao corresponde ao usuario logado";
            return false;
        }
        return true;
    }

    public string CreateDdnsFile(string domain, string contentHash)
    {
        var lines = new[]
        {
            "# HSYST P2P SERVICE",
            "### START:",
            "# VERSION: 1.0",
            "# TYPE: DDNS",
            "# DOMAIN SYSTEM: HSYST",
            "### :END START",
            "### DNS:",
            $"# DNAME: {domain} = {contentHash}",
            "### :END DNS"
        };
        return string.Join("\n", lines) + "\n";
    }

    public IReadOnlyList<DdnsRecord> ListDdns(int limit = 200)
    {
        if (limit <= 0)
        {
            limit = 200;
        }
        return _state.DdnsCache.Values
            .OrderByDescending(x => x.Timestamp)
            .Take(limit)
            .ToList();
    }

    public IReadOnlyList<ContractRecord> ListContracts(int limit = 200)
    {
        if (limit <= 0)
        {
            limit = 200;
        }
        return _state.ContractsCache.Values
            .OrderByDescending(x => x.Timestamp)
            .Take(limit)
            .ToList();
    }

    public int SaveWalletSync(JsonElement vouchers)
    {
        if (vouchers.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }
        var count = 0;
        var expectedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in vouchers.EnumerateArray())
        {
            var voucherId = item.TryGetProperty("voucher_id", out var id) ? id.GetString() ?? "" : "";
            if (string.IsNullOrWhiteSpace(voucherId))
            {
                continue;
            }
            var rec = new VoucherRecord
            {
                VoucherId = voucherId,
                Issuer = item.TryGetProperty("issuer", out var issuer) ? issuer.GetString() ?? "" : "",
                IsLocalIssuer = item.TryGetProperty("is_local_issuer", out var isLocalIssuer) && isLocalIssuer.ValueKind == JsonValueKind.True,
                Owner = item.TryGetProperty("owner", out var owner) ? owner.GetString() ?? "" : "",
                Value = item.TryGetProperty("value", out var value) && value.TryGetInt64(out var v) ? v : 0,
                Reason = item.TryGetProperty("reason", out var reason) ? reason.GetString() ?? "" : "",
                IssuedAt = item.TryGetProperty("issued_at", out var ts) && ts.TryGetDouble(out var d)
                    ? DateTimeOffset.FromUnixTimeMilliseconds((long)(d * 1000.0))
                    : DateTimeOffset.UtcNow,
                Payload = item.TryGetProperty("payload", out var payload) ? payload.ToString() : "",
                Signatures = JsonSerializer.Serialize(new Dictionary<string, string>
                {
                    ["issuer"] = item.TryGetProperty("issuer_signature", out var isg) ? isg.GetString() ?? "" : "",
                    ["owner"] = item.TryGetProperty("owner_signature", out var osg) ? osg.GetString() ?? "" : ""
                }),
                Status = item.TryGetProperty("status", out var status) ? status.GetString() ?? "" : "",
                Invalidated = item.TryGetProperty("invalidated", out var invalidated) && invalidated.ValueKind == JsonValueKind.True
            };
            SaveVoucherInternal(rec, persistState: false);
            expectedFiles.Add(BuildVoucherStoragePath(rec));
            count++;
        }
        if (count > 0)
        {
            foreach (var file in Directory.EnumerateFiles(_ctx.Paths.VouchersDir, "*.hps", SearchOption.AllDirectories))
            {
                if (!expectedFiles.Contains(file))
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch
                    {
                    }
                }
            }
            Save();
        }
        return count;
    }

    public string FormatHpsVoucherHsyst(JsonElement voucherElement)
    {
        var payload = voucherElement.TryGetProperty("payload", out var p) ? p : default;
        var signatures = voucherElement.TryGetProperty("signatures", out var s) ? s : default;
        var integrity = voucherElement.TryGetProperty("integrity", out var i) ? i : default;
        string GetPayload(string key, string fallback = "") =>
            payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(key, out var e) ? e.ToString() : fallback;
        string GetSig(string key, string fallback = "") =>
            signatures.ValueKind == JsonValueKind.Object && signatures.TryGetProperty(key, out var e) ? e.ToString() : fallback;
        string GetIntegrity(string key, string fallback = "") =>
            integrity.ValueKind == JsonValueKind.Object && integrity.TryGetProperty(key, out var e) ? e.ToString() : fallback;

        var pow = payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty("pow", out var powElement)
            ? powElement.GetRawText() : "{}";
        var conditions = payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty("conditions", out var conditionsElement)
            ? conditionsElement.GetRawText() : "{}";
        var dkvhps = payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty("dkvhps", out var dkvhpsElement)
            ? dkvhpsElement.GetRawText() : "{}";

        var lines = new[]
        {
            "# HSYST P2P SERVICE",
            "## HPS VOUCHER:",
            "### DETAILS:",
            $"# VERSION: {GetPayload("version", "1")}",
            $"# VOUCHER_ID: {GetPayload("voucher_id")}",
            $"# VALUE: {GetPayload("value", "0")}",
            $"# ISSUER: {GetPayload("issuer")}",
            $"# ISSUER_PUBLIC_KEY: {GetPayload("issuer_public_key")}",
            $"# OWNER: {GetPayload("owner")}",
            $"# OWNER_PUBLIC_KEY: {GetPayload("owner_public_key")}",
            $"# REASON: {GetPayload("reason")}",
            $"# ISSUED_AT: {GetPayload("issued_at", "0")}",
            $"# POW: {pow}",
            $"# CONDITIONS: {conditions}",
            $"# DKVHPS: {dkvhps}",
            $"# LINEAGE_ROOT_VOUCHER_ID: {GetPayload("lineage_root_voucher_id")}",
            $"# LINEAGE_PARENT_VOUCHER_ID: {GetPayload("lineage_parent_voucher_id")}",
            $"# LINEAGE_PARENT_HASH: {GetPayload("lineage_parent_hash")}",
            $"# LINEAGE_DEPTH: {GetPayload("lineage_depth", "0")}",
            $"# LINEAGE_ORIGIN: {GetPayload("lineage_origin")}",
            "### :END DETAILS",
            "### SIGNATURES:",
            $"# OWNER: {GetSig("owner")}",
            $"# ISSUER: {GetSig("issuer")}",
            $"# INTEGRITY_HASH: {GetIntegrity("hash")}",
            $"# INTEGRITY_ALGO: {GetIntegrity("algo", "sha256")}",
            "### :END SIGNATURES",
            "## :END HPS VOUCHER"
        };
        return string.Join("\n", lines) + "\n";
    }

    public Dictionary<string, object?>? ParseHpsVoucherHsyst(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || !text.StartsWith("# HSYST P2P SERVICE", StringComparison.Ordinal))
        {
            return null;
        }
        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var signatures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var section = "";
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("### ", StringComparison.Ordinal))
            {
                if (line.EndsWith(":", StringComparison.Ordinal))
                {
                    section = line[4..^1].Trim().ToLowerInvariant();
                }
                else if (line.StartsWith("### :END", StringComparison.Ordinal))
                {
                    section = "";
                }
                continue;
            }
            if (!line.StartsWith("# ", StringComparison.Ordinal))
            {
                continue;
            }
            var body = line[2..];
            var idx = body.IndexOf(':');
            if (idx <= 0)
            {
                continue;
            }
            var key = body[..idx].Trim().ToLowerInvariant();
            var val = body[(idx + 1)..].Trim();
            if (section == "details")
            {
                details[key] = val;
            }
            else if (section == "signatures")
            {
                signatures[key] = val;
            }
        }
        if (details.Count == 0)
        {
            return null;
        }
        Dictionary<string, object?> ParseJsonObj(string raw)
        {
            try
            {
                return JsonSerializer.Deserialize<Dictionary<string, object?>>(raw) ?? new Dictionary<string, object?>();
            }
            catch
            {
                return new Dictionary<string, object?>();
            }
        }
        var payload = new Dictionary<string, object?>
        {
            ["voucher_type"] = "HPS",
            ["version"] = ParseInt(details, "version", 1),
            ["voucher_id"] = Get(details, "voucher_id"),
            ["value"] = ParseLong(details, "value", 0),
            ["issuer"] = Get(details, "issuer"),
            ["issuer_public_key"] = Get(details, "issuer_public_key"),
            ["owner"] = Get(details, "owner"),
            ["owner_public_key"] = Get(details, "owner_public_key"),
            ["reason"] = Get(details, "reason"),
            ["issued_at"] = ParseDouble(details, "issued_at", 0),
            ["pow"] = ParseJsonObj(Get(details, "pow", "{}")),
            ["conditions"] = ParseJsonObj(Get(details, "conditions", "{}")),
            ["dkvhps"] = ParseJsonObj(Get(details, "dkvhps", "{}")),
            ["lineage_root_voucher_id"] = Get(details, "lineage_root_voucher_id"),
            ["lineage_parent_voucher_id"] = Get(details, "lineage_parent_voucher_id"),
            ["lineage_parent_hash"] = Get(details, "lineage_parent_hash"),
            ["lineage_depth"] = ParseLong(details, "lineage_depth", 0),
            ["lineage_origin"] = Get(details, "lineage_origin")
        };
        return new Dictionary<string, object?>
        {
            ["voucher_type"] = "HPS",
            ["payload"] = payload,
            ["signatures"] = new Dictionary<string, object?>
            {
                ["owner"] = Get(signatures, "owner"),
                ["issuer"] = Get(signatures, "issuer")
            },
            ["integrity"] = new Dictionary<string, object?>
            {
                ["hash"] = Get(signatures, "integrity_hash"),
                ["algo"] = Get(signatures, "integrity_algo", "sha256")
            }
        };
    }

    public string CanonicalJson(object payload)
    {
        var raw = JsonSerializer.Serialize(payload);
        using var doc = JsonDocument.Parse(raw);
        return CanonicalizeElement(doc.RootElement);
    }

    private static string CanonicalizeElement(JsonElement e)
    {
        return e.ValueKind switch
        {
            JsonValueKind.Object => "{" + string.Join(",", e.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal)
                .Select(p => JsonSerializer.Serialize(p.Name) + ":" + CanonicalizeElement(p.Value))) + "}",
            JsonValueKind.Array => "[" + string.Join(",", e.EnumerateArray().Select(CanonicalizeElement)) + "]",
            _ => e.GetRawText()
        };
    }

    private static string GetString(Dictionary<string, object?> map, string key)
    {
        if (!map.TryGetValue(key, out var val) || val is null)
        {
            return string.Empty;
        }
        return val.ToString() ?? string.Empty;
    }

    private static string NormalizeServer(string server)
    {
        server = (server ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(server))
        {
            return string.Empty;
        }
        if (!server.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !server.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return "http://" + server;
        }
        return server;
    }

    private static string GenerateClientIdentifier(string sessionId)
    {
        var machine = Environment.MachineName + ":" + Environment.UserName;
        var machineId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(machine))).ToLowerInvariant();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(machineId + sessionId))).ToLowerInvariant();
    }

    private DkvhpsVoucherInfo? BuildDkvhpsVoucherInfo(VoucherRecord voucher)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(voucher.Payload))
            {
                return null;
            }
            using var payloadDoc = JsonDocument.Parse(voucher.Payload);
            if (payloadDoc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            var payload = payloadDoc.RootElement;
            if (!payload.TryGetProperty("dkvhps", out var dkvhps) || dkvhps.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            var voucherOwnerEncrypted = dkvhps.TryGetProperty("voucher_owner_encrypted", out var voucherOwnerEncryptedElement) ? voucherOwnerEncryptedElement.GetString() ?? string.Empty : string.Empty;
            var lineageOwnerEncrypted = dkvhps.TryGetProperty("lineage_owner_encrypted", out var lineageOwnerEncryptedElement) ? lineageOwnerEncryptedElement.GetString() ?? string.Empty : string.Empty;
            var voucherKey = _ctx.KeyManager.IsUnlocked ? _ctx.KeyManager.DecryptOaepBase64(voucherOwnerEncrypted) : string.Empty;
            var lineageKey = _ctx.KeyManager.IsUnlocked ? _ctx.KeyManager.DecryptOaepBase64(lineageOwnerEncrypted) : string.Empty;
            var voucherHash = dkvhps.TryGetProperty("voucher_hash", out var voucherHashElement) ? voucherHashElement.GetString() ?? string.Empty : string.Empty;
            var lineageHash = dkvhps.TryGetProperty("lineage_hash", out var lineageHashElement) ? lineageHashElement.GetString() ?? string.Empty : string.Empty;
            return new DkvhpsVoucherInfo
            {
                VoucherId = voucher.VoucherId,
                LineageRootVoucherId = payload.TryGetProperty("lineage_root_voucher_id", out var rootElement) ? rootElement.GetString() ?? voucher.VoucherId : voucher.VoucherId,
                LineageParentVoucherId = payload.TryGetProperty("lineage_parent_voucher_id", out var parentElement) ? parentElement.GetString() ?? string.Empty : string.Empty,
                LineageParentHash = payload.TryGetProperty("lineage_parent_hash", out var parentHashElement) ? parentHashElement.GetString() ?? string.Empty : string.Empty,
                LineageDepth = payload.TryGetProperty("lineage_depth", out var depthElement) ? ParseIntJson(depthElement) : 0,
                LineageOrigin = payload.TryGetProperty("lineage_origin", out var originElement) ? originElement.GetString() ?? string.Empty : string.Empty,
                Status = voucher.Status,
                Invalidated = voucher.Invalidated,
                Value = voucher.Value,
                VoucherHash = voucherHash,
                LineageHash = lineageHash,
                VoucherOwnerEncrypted = voucherOwnerEncrypted,
                LineageOwnerEncrypted = lineageOwnerEncrypted,
                VoucherKey = voucherKey,
                LineageKey = lineageKey,
                VoucherHashVerified = string.IsNullOrWhiteSpace(voucherKey) ? false : string.Equals(HashDisclosureKey(voucherKey), voucherHash, StringComparison.OrdinalIgnoreCase),
                LineageHashVerified = string.IsNullOrWhiteSpace(lineageKey) ? false : string.Equals(HashDisclosureKey(lineageKey), lineageHash, StringComparison.OrdinalIgnoreCase),
                StoragePath = BuildVoucherStoragePath(voucher)
            };
        }
        catch
        {
            return null;
        }
    }

    private static string HashDisclosureKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static int ParseIntJson(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Number)
        {
            if (element.TryGetInt32(out var i))
            {
                return i;
            }
            if (element.TryGetDouble(out var d))
            {
                return (int)d;
            }
        }
        if (element.ValueKind == JsonValueKind.String && int.TryParse(element.GetString(), out var parsed))
        {
            return parsed;
        }
        return 0;
    }

    private static string? TryReadString(JsonElement payload, string property)
    {
        return payload.TryGetProperty(property, out var element) ? element.GetString() : null;
    }

    private string BuildVoucherStoragePath(VoucherRecord voucher)
    {
        var lineageRoot = voucher.VoucherId;
        try
        {
            if (!string.IsNullOrWhiteSpace(voucher.Payload))
            {
                using var payloadDoc = JsonDocument.Parse(voucher.Payload);
                if (payloadDoc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    lineageRoot = TryReadString(payloadDoc.RootElement, "lineage_root_voucher_id") ?? voucher.VoucherId;
                }
            }
        }
        catch
        {
        }
        if (string.IsNullOrWhiteSpace(lineageRoot))
        {
            lineageRoot = voucher.VoucherId;
        }
        return Path.Combine(_ctx.Paths.VouchersDir, lineageRoot, $"{voucher.VoucherId}.hps");
    }

    private byte[] ProtectVoucherWithDkvhps(VoucherRecord voucher, byte[] plain)
    {
        try
        {
            if (!_ctx.KeyManager.IsUnlocked || string.IsNullOrWhiteSpace(voucher.Payload))
            {
                return plain;
            }
            using var payloadDoc = JsonDocument.Parse(voucher.Payload);
            if (payloadDoc.RootElement.ValueKind != JsonValueKind.Object ||
                !payloadDoc.RootElement.TryGetProperty("dkvhps", out var dkvhps) ||
                dkvhps.ValueKind != JsonValueKind.Object)
            {
                return plain;
            }
            var voucherOwnerEncrypted = dkvhps.TryGetProperty("voucher_owner_encrypted", out var voucherEncElement) ? voucherEncElement.GetString() ?? string.Empty : string.Empty;
            var lineageOwnerEncrypted = dkvhps.TryGetProperty("lineage_owner_encrypted", out var lineageEncElement) ? lineageEncElement.GetString() ?? string.Empty : string.Empty;
            var voucherKeySecret = _ctx.KeyManager.DecryptOaepBase64(voucherOwnerEncrypted);
            var lineageKeySecret = _ctx.KeyManager.DecryptOaepBase64(lineageOwnerEncrypted);
            if (string.IsNullOrWhiteSpace(voucherKeySecret) || string.IsNullOrWhiteSpace(lineageKeySecret))
            {
                return plain;
            }

            var voucherKey = SHA256.HashData(Encoding.UTF8.GetBytes("voucher:" + voucherKeySecret));
            var lineageKey = SHA256.HashData(Encoding.UTF8.GetBytes("lineage:" + lineageKeySecret));
            try
            {
                var voucherCipher = EncryptWithAesKey(voucherKey, plain, out var voucherNonce);
                var innerPayload = JsonSerializer.SerializeToUtf8Bytes(new VoucherInnerEnvelope
                {
                    VoucherNonce = Convert.ToBase64String(voucherNonce),
                    Ciphertext = Convert.ToBase64String(voucherCipher)
                });
                var lineageCipher = EncryptWithAesKey(lineageKey, innerPayload, out var lineageNonce);
                return JsonSerializer.SerializeToUtf8Bytes(new VoucherFileEnvelope
                {
                    Version = 1,
                    Scheme = "hps-voucher-dkvhps",
                    VoucherHash = dkvhps.TryGetProperty("voucher_hash", out var voucherHashElement) ? voucherHashElement.GetString() ?? string.Empty : string.Empty,
                    LineageHash = dkvhps.TryGetProperty("lineage_hash", out var lineageHashElement) ? lineageHashElement.GetString() ?? string.Empty : string.Empty,
                    VoucherOwnerEncrypted = voucherOwnerEncrypted,
                    LineageOwnerEncrypted = lineageOwnerEncrypted,
                    LineageNonce = Convert.ToBase64String(lineageNonce),
                    Ciphertext = Convert.ToBase64String(lineageCipher)
                });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(voucherKey);
                CryptographicOperations.ZeroMemory(lineageKey);
            }
        }
        catch
        {
            return plain;
        }
    }

    private static byte[] EncryptWithAesKey(byte[] key, byte[] plain, out byte[] nonce)
    {
        nonce = RandomNumberGenerator.GetBytes(AesNonceSize);
        var cipher = new byte[plain.Length];
        var tag = new byte[AesTagSize];
        using (var aes = new AesGcm(key, AesTagSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag);
        }
        var output = new byte[nonce.Length + tag.Length + cipher.Length];
        Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, output, nonce.Length, tag.Length);
        Buffer.BlockCopy(cipher, 0, output, nonce.Length + tag.Length, cipher.Length);
        return output;
    }

    private byte[] EncryptForLocalStorage(byte[] plain)
    {
        var key = _ctx.KeyManager.GetStorageKeyCopy();
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(AesNonceSize);
            var cipher = new byte[plain.Length];
            var tag = new byte[AesTagSize];
            try
            {
                using (var aes = new AesGcm(key, AesTagSize))
                {
                    aes.Encrypt(nonce, plain, cipher, tag);
                }

                var output = new byte[EncMagic.Length + nonce.Length + tag.Length + cipher.Length];
                Buffer.BlockCopy(EncMagic, 0, output, 0, EncMagic.Length);
                Buffer.BlockCopy(nonce, 0, output, EncMagic.Length, nonce.Length);
                Buffer.BlockCopy(tag, 0, output, EncMagic.Length + nonce.Length, tag.Length);
                Buffer.BlockCopy(cipher, 0, output, EncMagic.Length + nonce.Length + tag.Length, cipher.Length);
                return output;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonce);
                CryptographicOperations.ZeroMemory(cipher);
                CryptographicOperations.ZeroMemory(tag);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private byte[] DecryptFromLocalStorage(byte[] input)
    {
        if (input.Length <= EncMagic.Length + AesNonceSize + AesTagSize)
        {
            return input;
        }
        for (var i = 0; i < EncMagic.Length; i++)
        {
            if (input[i] != EncMagic[i])
            {
                return input;
            }
        }

        var key = _ctx.KeyManager.GetStorageKeyCopy();
        var nonce = new byte[AesNonceSize];
        var tag = new byte[AesTagSize];
        var cipherOffset = EncMagic.Length + AesNonceSize + AesTagSize;
        var cipherLength = input.Length - cipherOffset;
        var cipher = new byte[cipherLength];
        var plain = new byte[cipherLength];
        try
        {
            Buffer.BlockCopy(input, EncMagic.Length, nonce, 0, AesNonceSize);
            Buffer.BlockCopy(input, EncMagic.Length + AesNonceSize, tag, 0, AesTagSize);
            Buffer.BlockCopy(input, cipherOffset, cipher, 0, cipherLength);
            using var aes = new AesGcm(key, AesTagSize);
            aes.Decrypt(nonce, cipher, tag, plain);
            return plain;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(cipher);
        }
    }

    private void EncryptLegacyLocalFiles()
    {
        if (!_ctx.KeyManager.IsUnlocked)
        {
            return;
        }
        EncryptLegacyFilesInDirectory(_ctx.Paths.ContentDir, "*.dat");
        EncryptLegacyFilesInDirectory(_ctx.Paths.DdnsDir, "*.ddns");
        EncryptLegacyFilesInDirectory(_ctx.Paths.ContractsDir, "*.contract");
        EncryptLegacyFilesInDirectory(_ctx.Paths.VouchersDir, "*.hps");
    }

    private void EncryptLegacyFilesInDirectory(string directory, string pattern)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }
        foreach (var file in Directory.EnumerateFiles(directory, pattern, SearchOption.TopDirectoryOnly))
        {
            try
            {
                var raw = File.ReadAllBytes(file);
                if (IsEncryptedPayload(raw))
                {
                    continue;
                }
                File.WriteAllBytes(file, EncryptForLocalStorage(raw));
            }
            catch
            {
            }
        }
    }

    private static bool IsEncryptedPayload(byte[] input)
    {
        if (input.Length < EncMagic.Length)
        {
            return false;
        }
        for (var i = 0; i < EncMagic.Length; i++)
        {
            if (input[i] != EncMagic[i])
            {
                return false;
            }
        }
        return true;
    }

    private static string ExtractAction(string contractText)
    {
        foreach (var raw in (contractText ?? "").Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("# ACTION:", StringComparison.OrdinalIgnoreCase))
            {
                return line.Split(':', 2)[1].Trim();
            }
        }
        return string.Empty;
    }

    private static string ExtractStartUser(string contractText)
    {
        var inStart = false;
        foreach (var raw in (contractText ?? "").Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line == "### START:")
            {
                inStart = true;
                continue;
            }
            if (line == "### :END START")
            {
                inStart = false;
                continue;
            }
            if (inStart && line.StartsWith("# USER:", StringComparison.OrdinalIgnoreCase))
            {
                return line.Split(':', 2)[1].Trim();
            }
        }
        return string.Empty;
    }

    private static string Get(Dictionary<string, string> map, string key, string fallback = "")
    {
        return map.TryGetValue(key, out var v) ? v : fallback;
    }

    private static int ParseInt(Dictionary<string, string> map, string key, int fallback)
    {
        if (!map.TryGetValue(key, out var v) || !int.TryParse(v, out var n))
        {
            return fallback;
        }
        return n;
    }

    private static long ParseLong(Dictionary<string, string> map, string key, long fallback)
    {
        if (!map.TryGetValue(key, out var v) || !long.TryParse(v, out var n))
        {
            return fallback;
        }
        return n;
    }

    private static double ParseDouble(Dictionary<string, string> map, string key, double fallback)
    {
        if (!map.TryGetValue(key, out var v) || !double.TryParse(v, out var n))
        {
            return fallback;
        }
        return n;
    }

    private static string NormalizeContractWithoutSignature(string contractText) =>
        NormalizeContractWithoutSignature(contractText, out _);

    private static string NormalizeContractWithoutSignature(string contractText, out string signatureB64)
    {
        signatureB64 = string.Empty;
        var lines = (contractText ?? string.Empty).Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var clean = new List<string>(lines.Length);
        foreach (var line in lines)
        {
            var t = line.Trim();
            if (t.StartsWith("# SIGNATURE:", StringComparison.OrdinalIgnoreCase))
            {
                var idx = line.IndexOf(':');
                if (idx >= 0 && idx + 1 < line.Length)
                {
                    signatureB64 = line[(idx + 1)..].Trim();
                }
                continue;
            }
            clean.Add(line);
        }
        return string.Join("\n", clean).TrimEnd();
    }

    private static string GetValue(Dictionary<string, object?> map, string key)
    {
        if (!map.TryGetValue(key, out var v) || v is null)
        {
            return string.Empty;
        }
        return v.ToString() ?? string.Empty;
    }

    private static bool GetBool(Dictionary<string, object?> map, string key)
    {
        if (!map.TryGetValue(key, out var v) || v is null)
        {
            return false;
        }
        if (v is bool b)
        {
            return b;
        }
        if (v is long l)
        {
            return l != 0;
        }
        if (v is int i)
        {
            return i != 0;
        }
        return string.Equals(v.ToString(), "true", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(v.ToString(), "1", StringComparison.OrdinalIgnoreCase);
    }

    private void Save()
    {
        if (_ctx.KeyManager.IsUnlocked)
        {
            var key = _ctx.KeyManager.GetStorageKeyCopy();
            try
            {
                _ctx.StateStore.SaveEncrypted(_state, key);
                return;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
        _ctx.StateStore.Save(_state);
    }
}
