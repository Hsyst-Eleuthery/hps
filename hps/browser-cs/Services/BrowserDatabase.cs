using Microsoft.Data.Sqlite;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using HpsBrowser.Models;

namespace HpsBrowser.Services;

public sealed class BrowserDatabase
{
    private readonly string _dbPath;
    private string? _connectionString;
    private SqliteConnection? _rootConnection;

    public BrowserDatabase(string dbPath)
    {
        _dbPath = dbPath;
    }

    public string DbPath => _dbPath;

    public void Initialize(byte[]? seedBytes = null)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_dbPath) ?? ".");

        if (_rootConnection is null)
        {
            var builder = new SqliteConnectionStringBuilder
            {
                DataSource = $"browser-{Guid.NewGuid():N}",
                Mode = SqliteOpenMode.Memory,
                Cache = SqliteCacheMode.Shared
            };
            _connectionString = builder.ToString();
            _rootConnection = new SqliteConnection(_connectionString);
            _rootConnection.Open();
        }

        if (seedBytes is not null && seedBytes.Length > 0)
        {
            DeserializeMemoryDatabase(seedBytes);
        }

        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS browser_network_nodes (
    node_id TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    node_type TEXT NOT NULL,
    reputation INTEGER DEFAULT 100,
    status TEXT NOT NULL,
    last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS browser_dns_records (
    domain TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    username TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    timestamp REAL NOT NULL,
    ddns_hash TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS browser_known_servers (
    server_address TEXT PRIMARY KEY,
    reputation INTEGER DEFAULT 100,
    last_connected REAL NOT NULL,
    is_active INTEGER DEFAULT 1,
    use_ssl INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS browser_content_cache (
    content_hash TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    last_accessed REAL NOT NULL,
    title TEXT,
    description TEXT,
    username TEXT,
    signature TEXT,
    public_key TEXT,
    verified INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS browser_ddns_cache (
    domain TEXT PRIMARY KEY,
    ddns_hash TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    username TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    timestamp REAL NOT NULL,
    signature TEXT DEFAULT '',
    public_key TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS browser_contracts_cache (
    contract_id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    content_hash TEXT,
    domain TEXT,
    username TEXT NOT NULL,
    signature TEXT,
    timestamp REAL NOT NULL,
    verified INTEGER DEFAULT 0,
    contract_content TEXT
);
CREATE TABLE IF NOT EXISTS browser_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS browser_inventory_visibility (
    content_hash TEXT PRIMARY KEY,
    is_public INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS browser_published_content (
    content_hash TEXT PRIMARY KEY,
    published_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS browser_reports (
    report_id TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    reported_user TEXT NOT NULL,
    reporter_user TEXT NOT NULL,
    timestamp REAL NOT NULL,
    status TEXT NOT NULL,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS browser_hps_vouchers (
    voucher_id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    owner TEXT NOT NULL,
    value INTEGER NOT NULL,
    reason TEXT NOT NULL,
    issued_at REAL NOT NULL,
    payload TEXT NOT NULL,
    issuer_signature TEXT NOT NULL,
    owner_signature TEXT NOT NULL,
    status TEXT NOT NULL,
    invalidated INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS browser_server_economy (
    server_address TEXT PRIMARY KEY,
    multiplier REAL NOT NULL,
    total_minted REAL NOT NULL,
    custody_balance REAL NOT NULL,
    owner_balance REAL NOT NULL,
    rebate_balance REAL NOT NULL,
    exchange_fee_rate REAL NOT NULL,
    exchange_fee_min REAL NOT NULL,
    last_report_ts REAL NOT NULL,
    report_payload TEXT,
    report_signature TEXT
);
CREATE TABLE IF NOT EXISTS browser_message_records (
    message_id TEXT PRIMARY KEY,
    peer_user TEXT NOT NULL,
    sender_user TEXT NOT NULL,
    direction TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    preview TEXT NOT NULL,
    timestamp REAL NOT NULL
);
";
        cmd.ExecuteNonQuery();
    }

    public SqliteConnection OpenConnection()
    {
        return new SqliteConnection(_connectionString ?? $"Data Source={_dbPath}");
    }

    public byte[] ExportPlaintextBytes()
    {
        if (_rootConnection is null)
        {
            return Array.Empty<byte>();
        }

        return SerializeMemoryDatabase();
    }

    public void Close()
    {
        _rootConnection?.Close();
        _rootConnection?.Dispose();
        _rootConnection = null;
        _connectionString = null;
    }

    public void RunInTransaction(Action<SqliteConnection> action)
    {
        using var conn = OpenConnection();
        conn.Open();
        using var tx = conn.BeginTransaction();
        action(conn);
        tx.Commit();
    }

    public T RunInTransaction<T>(Func<SqliteConnection, T> action)
    {
        using var conn = OpenConnection();
        conn.Open();
        using var tx = conn.BeginTransaction();
        var result = action(conn);
        tx.Commit();
        return result;
    }

    public string? LoadSetting(string key)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM browser_settings WHERE key = $key";
        cmd.Parameters.AddWithValue("$key", key);
        return cmd.ExecuteScalar() as string;
    }

    public int LoadSettingInt(string key, int defaultValue)
    {
        var value = LoadSetting(key);
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        return int.TryParse(value, out var parsed) ? parsed : defaultValue;
    }

    public void SaveSetting(string key, string value)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO browser_settings (key, value) VALUES ($key, $value)
ON CONFLICT(key) DO UPDATE SET value=excluded.value;
";
        cmd.Parameters.AddWithValue("$key", key);
        cmd.Parameters.AddWithValue("$value", value);
        cmd.ExecuteNonQuery();
    }

    public void ReplaceMessageContacts(IEnumerable<MessageContactInfo> contacts)
    {
    }

    public List<MessageContactInfo> LoadMessageContacts()
    {
        return new List<MessageContactInfo>();
    }

    public void SaveMessageRecord(string messageId, string peerUser, string senderUser, string direction, string fileName, string filePath, string preview, double timestamp)
    {
        using var conn = OpenConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO browser_message_records
(message_id, peer_user, sender_user, direction, file_name, file_path, preview, timestamp)
VALUES ($id, $peer, $sender, $direction, $file, $path, $preview, $timestamp);";
        cmd.Parameters.AddWithValue("$id", messageId);
        cmd.Parameters.AddWithValue("$peer", peerUser);
        cmd.Parameters.AddWithValue("$sender", senderUser);
        cmd.Parameters.AddWithValue("$direction", direction);
        cmd.Parameters.AddWithValue("$file", fileName);
        cmd.Parameters.AddWithValue("$path", filePath);
        cmd.Parameters.AddWithValue("$preview", preview);
        cmd.Parameters.AddWithValue("$timestamp", timestamp);
        cmd.ExecuteNonQuery();
    }

    public List<MessageItem> LoadMessageRecords(string peerUser)
    {
        var results = new List<MessageItem>();
        using var conn = OpenConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT peer_user, sender_user, direction, file_name, preview, timestamp
            FROM browser_message_records WHERE peer_user = $peer ORDER BY timestamp ASC";
        cmd.Parameters.AddWithValue("$peer", peerUser);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add(new MessageItem
            {
                PeerUser = reader.IsDBNull(0) ? string.Empty : reader.GetString(0),
                SenderUser = reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                Direction = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                FileName = reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                Preview = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
                Timestamp = reader.IsDBNull(5) ? 0 : reader.GetDouble(5)
            });
        }
        return results;
    }

    public void EnsureInventoryVisibility(string contentHash, bool isPublicDefault = true)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }
        using var conn = OpenConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR IGNORE INTO browser_inventory_visibility (content_hash, is_public)
VALUES ($hash, $public);
";
        cmd.Parameters.AddWithValue("$hash", contentHash);
        cmd.Parameters.AddWithValue("$public", isPublicDefault ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    public void SaveInventoryVisibility(string contentHash, bool isPublic)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }
        using var conn = OpenConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO browser_inventory_visibility (content_hash, is_public)
VALUES ($hash, $public)
ON CONFLICT(content_hash) DO UPDATE SET is_public=excluded.is_public;
";
        cmd.Parameters.AddWithValue("$hash", contentHash);
        cmd.Parameters.AddWithValue("$public", isPublic ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    public Dictionary<string, bool> LoadInventoryVisibility()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        using var conn = OpenConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT content_hash, is_public FROM browser_inventory_visibility";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var hash = reader.GetString(0);
            var isPublic = !reader.IsDBNull(1) && reader.GetInt32(1) == 1;
            results[hash] = isPublic;
        }
        return results;
    }

    public void MarkContentPublished(string contentHash)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }

        using var conn = OpenConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO browser_published_content (content_hash, published_at)
VALUES ($hash, $publishedAt)
ON CONFLICT(content_hash) DO UPDATE SET published_at=excluded.published_at;
";
        cmd.Parameters.AddWithValue("$hash", contentHash);
        cmd.Parameters.AddWithValue("$publishedAt", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    public HashSet<string> LoadPublishedContentHashes()
    {
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var conn = OpenConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT content_hash FROM browser_published_content";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            if (!reader.IsDBNull(0))
            {
                results.Add(reader.GetString(0));
            }
        }

        return results;
    }

    public List<(string address, bool useSsl)> LoadKnownServers()
    {
        var results = new List<(string, bool)>();
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT server_address, use_ssl FROM browser_known_servers WHERE is_active = 1";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var address = reader.GetString(0);
            var useSsl = reader.GetInt32(1) == 1;
            results.Add((address, useSsl));
        }

        return results;
    }

    public List<(string domain, string contentHash, string username, bool verified, string ddnsHash)> LoadDnsRecords()
    {
        var results = new List<(string, string, string, bool, string)>();
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT domain, content_hash, username, verified, ddns_hash FROM browser_dns_records ORDER BY timestamp DESC";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var domain = reader.GetString(0);
            var contentHash = reader.GetString(1);
            var username = reader.GetString(2);
            var verified = reader.GetInt32(3) == 1;
            var ddnsHash = reader.GetString(4);
            results.Add((domain, contentHash, username, verified, ddnsHash));
        }

        return results;
    }

    public void SaveDnsRecord(string domain, string contentHash, string username, bool verified)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO browser_dns_records
(domain, content_hash, username, verified, timestamp, ddns_hash)
VALUES (
    $domain,
    $content_hash,
    $username,
    $verified,
    $timestamp,
    COALESCE((SELECT ddns_hash FROM browser_dns_records WHERE domain = $domain), '')
);
";
        cmd.Parameters.AddWithValue("$domain", domain);
        cmd.Parameters.AddWithValue("$content_hash", contentHash);
        cmd.Parameters.AddWithValue("$username", username);
        cmd.Parameters.AddWithValue("$verified", verified ? 1 : 0);
        cmd.Parameters.AddWithValue("$timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    public void SaveDdnsRecord(string domain, string ddnsHash, string contentHash, string username, bool verified, string signature, string publicKey)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO browser_ddns_cache
(domain, ddns_hash, content_hash, username, verified, timestamp, signature, public_key)
VALUES ($domain, $ddns_hash, $content_hash, $username, $verified, $timestamp, $signature, $public_key);
";
        cmd.Parameters.AddWithValue("$domain", domain);
        cmd.Parameters.AddWithValue("$ddns_hash", ddnsHash);
        cmd.Parameters.AddWithValue("$content_hash", contentHash);
        cmd.Parameters.AddWithValue("$username", username);
        cmd.Parameters.AddWithValue("$verified", verified ? 1 : 0);
        cmd.Parameters.AddWithValue("$timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.Parameters.AddWithValue("$signature", signature);
        cmd.Parameters.AddWithValue("$public_key", publicKey);
        cmd.ExecuteNonQuery();

        using var dnsCmd = conn.CreateCommand();
        dnsCmd.CommandText = @"
INSERT OR REPLACE INTO browser_dns_records
(domain, content_hash, username, verified, timestamp, ddns_hash)
VALUES ($domain, $content_hash, $username, $verified, $timestamp, $ddns_hash);
";
        dnsCmd.Parameters.AddWithValue("$domain", domain);
        dnsCmd.Parameters.AddWithValue("$content_hash", contentHash);
        dnsCmd.Parameters.AddWithValue("$username", username);
        dnsCmd.Parameters.AddWithValue("$verified", verified ? 1 : 0);
        dnsCmd.Parameters.AddWithValue("$timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        dnsCmd.Parameters.AddWithValue("$ddns_hash", ddnsHash);
        dnsCmd.ExecuteNonQuery();
    }

    public (string filePath, string title, string description, string mimeType, string username, string signature, string publicKey, bool verified)? LoadContentMetadata(string contentHash)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT file_path, title, description, mime_type, username, signature, public_key, verified
FROM browser_content_cache
WHERE content_hash = $hash
";
        cmd.Parameters.AddWithValue("$hash", contentHash);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var filePath = reader.GetString(0);
        var title = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
        var description = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
        var mimeType = reader.IsDBNull(3) ? "application/octet-stream" : reader.GetString(3);
        var username = reader.IsDBNull(4) ? string.Empty : reader.GetString(4);
        var signature = reader.IsDBNull(5) ? string.Empty : reader.GetString(5);
        var publicKey = reader.IsDBNull(6) ? string.Empty : reader.GetString(6);
        var verified = !reader.IsDBNull(7) && reader.GetInt32(7) == 1;

        return (filePath, title, description, mimeType, username, signature, publicKey, verified);
    }

    public List<Voucher> LoadLocalVouchers()
    {
        var results = new List<Voucher>();
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT voucher_id, issuer, owner, value, reason, issued_at, payload,
       issuer_signature, owner_signature, status, invalidated
FROM browser_hps_vouchers
ORDER BY issued_at DESC;
";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var payloadJson = reader.GetString(6);
            var payload = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson) ?? new Dictionary<string, object>();
            results.Add(new Voucher
            {
                VoucherId = reader.GetString(0),
                Issuer = reader.GetString(1),
                Owner = reader.GetString(2),
                Value = reader.GetInt32(3),
                Reason = reader.GetString(4),
                IssuedAt = reader.GetDouble(5),
                Payload = payload,
                IssuerSignature = reader.GetString(7),
                OwnerSignature = reader.GetString(8),
                Status = reader.GetString(9),
                Invalidated = reader.GetInt32(10) == 1
            });
        }

        return results;
    }

    public void SaveVoucherRecord(Voucher voucher)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO browser_hps_vouchers
(voucher_id, issuer, owner, value, reason, issued_at, payload,
 issuer_signature, owner_signature, status, invalidated)
VALUES ($id, $issuer, $owner, $value, $reason, $issued_at, $payload,
        $issuer_sig, $owner_sig, $status, $invalidated);
";
        cmd.Parameters.AddWithValue("$id", voucher.VoucherId);
        cmd.Parameters.AddWithValue("$issuer", voucher.Issuer);
        cmd.Parameters.AddWithValue("$owner", voucher.Owner);
        cmd.Parameters.AddWithValue("$value", voucher.Value);
        cmd.Parameters.AddWithValue("$reason", voucher.Reason);
        cmd.Parameters.AddWithValue("$issued_at", voucher.IssuedAt);
        cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(voucher.Payload));
        cmd.Parameters.AddWithValue("$issuer_sig", voucher.IssuerSignature);
        cmd.Parameters.AddWithValue("$owner_sig", voucher.OwnerSignature);
        cmd.Parameters.AddWithValue("$status", voucher.Status);
        cmd.Parameters.AddWithValue("$invalidated", voucher.Invalidated ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    public void ReplaceVoucherRecords(string issuer, IEnumerable<Voucher> vouchers)
    {
        var normalizedIssuer = (issuer ?? string.Empty).Trim();
        using var conn = OpenConnection();
        conn.Open();

        using var tx = conn.BeginTransaction();
        using (var deleteCmd = conn.CreateCommand())
        {
            deleteCmd.CommandText = @"
DELETE FROM browser_hps_vouchers
WHERE lower(trim(issuer)) = lower(trim($issuer))
  AND lower(trim(COALESCE(status, ''))) <> 'ghosted';
";
            deleteCmd.Parameters.AddWithValue("$issuer", normalizedIssuer);
            deleteCmd.ExecuteNonQuery();
        }

        foreach (var voucher in vouchers)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
INSERT OR REPLACE INTO browser_hps_vouchers
(voucher_id, issuer, owner, value, reason, issued_at, payload,
 issuer_signature, owner_signature, status, invalidated)
VALUES ($id, $issuer, $owner, $value, $reason, $issued_at, $payload,
        $issuer_sig, $owner_sig, $status, $invalidated);
";
            cmd.Parameters.AddWithValue("$id", voucher.VoucherId);
            cmd.Parameters.AddWithValue("$issuer", voucher.Issuer);
            cmd.Parameters.AddWithValue("$owner", voucher.Owner);
            cmd.Parameters.AddWithValue("$value", voucher.Value);
            cmd.Parameters.AddWithValue("$reason", voucher.Reason);
            cmd.Parameters.AddWithValue("$issued_at", voucher.IssuedAt);
            cmd.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(voucher.Payload));
            cmd.Parameters.AddWithValue("$issuer_sig", voucher.IssuerSignature);
            cmd.Parameters.AddWithValue("$owner_sig", voucher.OwnerSignature);
            cmd.Parameters.AddWithValue("$status", voucher.Status);
            cmd.Parameters.AddWithValue("$invalidated", voucher.Invalidated ? 1 : 0);
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
    }

    public void UpdateVoucherStatus(IEnumerable<string> voucherIds, string status, bool invalidated)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var tx = conn.BeginTransaction();
        foreach (var id in voucherIds)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
UPDATE browser_hps_vouchers
SET status = $status, invalidated = $invalidated
WHERE voucher_id = $id;
";
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$invalidated", invalidated ? 1 : 0);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public void SaveContractRecord(ContractInfo contract)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO browser_contracts_cache
(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
VALUES ($id, $action, $hash, $domain, $user, $sig, $ts, $verified, $content);
";
        cmd.Parameters.AddWithValue("$id", contract.ContractId);
        cmd.Parameters.AddWithValue("$action", contract.ActionType);
        cmd.Parameters.AddWithValue("$hash", contract.ContentHash);
        cmd.Parameters.AddWithValue("$domain", contract.Domain);
        cmd.Parameters.AddWithValue("$user", contract.Username);
        cmd.Parameters.AddWithValue("$sig", contract.Signature);
        cmd.Parameters.AddWithValue("$ts", contract.Timestamp);
        cmd.Parameters.AddWithValue("$verified", contract.Verified == "Sim" ? 1 : 0);
        cmd.Parameters.AddWithValue("$content", contract.ContractContent);
        cmd.ExecuteNonQuery();
    }

    public ContractInfo? LoadContractRecord(string contractId)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT action_type, content_hash, domain, username, signature, timestamp, verified, contract_content
FROM browser_contracts_cache
WHERE contract_id = $id
";
        cmd.Parameters.AddWithValue("$id", contractId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new ContractInfo
        {
            ContractId = contractId,
            ActionType = reader.IsDBNull(0) ? string.Empty : reader.GetString(0),
            ContentHash = reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
            Domain = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
            Username = reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
            Signature = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
            Timestamp = reader.IsDBNull(5) ? 0 : reader.GetDouble(5),
            Verified = reader.IsDBNull(6) || reader.GetInt32(6) == 0 ? "Não" : "Sim",
            ContractContent = reader.IsDBNull(7) ? string.Empty : reader.GetString(7),
            ContractTitle = reader.IsDBNull(7) ? string.Empty : ExtractContractTitle(reader.GetString(7))
        };
    }

    private static string ExtractContractTitle(string contractText)
    {
        if (string.IsNullOrWhiteSpace(contractText))
        {
            return string.Empty;
        }

        var lines = contractText.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');
        var keys = new[] { "TITLE", "FILE_NAME", "APP", "APP_NAME", "DOMAIN" };
        foreach (var key in keys)
        {
            var prefix = "# " + key + ":";
            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (!line.StartsWith(prefix, StringComparison.Ordinal))
                {
                    continue;
                }

                var parts = line.Split(':', 2);
                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                {
                    return parts[1].Trim();
                }
            }
        }

        return string.Empty;
    }

    public List<(string contentHash, string fileName, long size)> LoadContentSummaries()
    {
        var results = new List<(string, string, long)>();
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT content_hash, file_name, size FROM browser_content_cache";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var hash = reader.GetString(0);
            var fileName = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
            var size = reader.IsDBNull(2) ? 0 : reader.GetInt64(2);
            results.Add((hash, fileName, size));
        }

        return results;
    }

    public List<(string contentHash, string title, string description, string mimeType, long size, string username, bool isPublic)> LoadInventoryItems()
    {
        var results = new List<(string, string, string, string, long, string, bool)>();
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT c.content_hash,
       COALESCE(c.title, ''),
       COALESCE(c.description, ''),
       COALESCE(c.mime_type, ''),
       COALESCE(c.size, 0),
       COALESCE(c.username, ''),
       COALESCE(v.is_public, 1)
FROM browser_content_cache c
LEFT JOIN browser_inventory_visibility v
  ON v.content_hash = c.content_hash
ORDER BY c.last_accessed DESC;
";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var hash = reader.GetString(0);
            var title = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
            var description = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
            var mime = reader.IsDBNull(3) ? string.Empty : reader.GetString(3);
            var size = reader.IsDBNull(4) ? 0 : reader.GetInt64(4);
            var username = reader.IsDBNull(5) ? string.Empty : reader.GetString(5);
            var isPublic = !reader.IsDBNull(6) && reader.GetInt32(6) == 1;
            results.Add((hash, title, description, mime, size, username, isPublic));
        }

        return results;
    }

    public List<(string domain, string ddnsHash)> LoadDdnsSummaries()
    {
        var results = new List<(string, string)>();
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT domain, ddns_hash FROM browser_ddns_cache";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var domain = reader.GetString(0);
            var ddnsHash = reader.GetString(1);
            results.Add((domain, ddnsHash));
        }

        return results;
    }

    public List<(string contractId, string contentHash, string domain)> LoadContractSummaries()
    {
        var results = new List<(string, string, string)>();
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT contract_id, content_hash, domain FROM browser_contracts_cache";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var id = reader.GetString(0);
            var hash = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
            var domain = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
            results.Add((id, hash, domain));
        }

        return results;
    }

    public (string ddnsHash, string contentHash, string username, bool verified, string signature, string publicKey)? LoadDdnsRecord(string domain)
    {
        using var conn = OpenConnection();
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT ddns_hash, content_hash, username, verified, signature, public_key
FROM browser_ddns_cache
WHERE domain = $domain
";
        cmd.Parameters.AddWithValue("$domain", domain);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return (
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetInt32(3) == 1,
            reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
            reader.IsDBNull(5) ? string.Empty : reader.GetString(5)
        );
    }

    public void SaveKnownServers(IEnumerable<(string address, bool useSsl)> servers)
    {
        using var conn = OpenConnection();
        conn.Open();
        using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA busy_timeout = 5000;";
            pragma.ExecuteNonQuery();
        }

        using var tx = conn.BeginTransaction();
        using (var clearCmd = conn.CreateCommand())
        {
            clearCmd.CommandText = "DELETE FROM browser_known_servers";
            clearCmd.ExecuteNonQuery();
        }
        foreach (var (address, useSsl) in servers)
        {
            var normalized = (address ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(normalized))
            {
                continue;
            }
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
INSERT OR REPLACE INTO browser_known_servers
(server_address, last_connected, is_active, use_ssl)
VALUES ($address, $last_connected, 1, $use_ssl);
";
            cmd.Parameters.AddWithValue("$address", normalized);
            cmd.Parameters.AddWithValue("$last_connected", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            cmd.Parameters.AddWithValue("$use_ssl", useSsl ? 1 : 0);
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public static string CanonicalizePayload(JsonElement payload)
    {
        return CanonicalizeJson(payload);
    }

    private static string CanonicalizeJson(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => CanonicalizeObject(element),
            JsonValueKind.Array => "[" + string.Join(",", element.EnumerateArray().Select(CanonicalizeJson)) + "]",
            JsonValueKind.String => JsonSerializer.Serialize(element.GetString()),
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            _ => element.GetRawText()
        };
    }

    private static string CanonicalizeObject(JsonElement element)
    {
        var properties = element.EnumerateObject()
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .Select(p => $"{JsonSerializer.Serialize(p.Name)}:{CanonicalizeJson(p.Value)}");
        return "{" + string.Join(",", properties) + "}";
    }

    private byte[] SerializeMemoryDatabase()
    {
        if (_rootConnection is null)
        {
            return Array.Empty<byte>();
        }

        var dbHandle = GetNativeDatabaseHandle(_rootConnection);
        long size = 0;
        var buffer = NativeMethods.sqlite3_serialize(dbHandle, "main", out size, 0);
        if (buffer == IntPtr.Zero || size <= 0)
        {
            return Array.Empty<byte>();
        }

        var managed = new byte[checked((int)size)];
        try
        {
            Marshal.Copy(buffer, managed, 0, checked((int)size));
            return managed;
        }
        finally
        {
            NativeMethods.sqlite3_free(buffer);
        }
    }

    private void DeserializeMemoryDatabase(byte[] seedBytes)
    {
        if (_rootConnection is null || seedBytes.Length == 0)
        {
            return;
        }

        var dbHandle = GetNativeDatabaseHandle(_rootConnection);
        var nativeBuffer = NativeMethods.sqlite3_malloc64((ulong)seedBytes.Length);
        if (nativeBuffer == IntPtr.Zero)
        {
            throw new InvalidOperationException("Falha ao alocar buffer nativo para o banco em memoria.");
        }

        try
        {
            Marshal.Copy(seedBytes, 0, nativeBuffer, seedBytes.Length);
            var rc = NativeMethods.sqlite3_deserialize(
                dbHandle,
                "main",
                nativeBuffer,
                seedBytes.Length,
                seedBytes.Length,
                NativeMethods.SQLITE_DESERIALIZE_FREEONCLOSE);

            if (rc != 0)
            {
                throw new InvalidOperationException($"Falha ao carregar snapshot SQLite em memoria (rc={rc}).");
            }

            nativeBuffer = IntPtr.Zero;
        }
        finally
        {
            if (nativeBuffer != IntPtr.Zero)
            {
                NativeMethods.sqlite3_free(nativeBuffer);
            }
        }
    }

    private static IntPtr GetNativeDatabaseHandle(SqliteConnection connection)
    {
        var handle = connection.Handle ?? throw new InvalidOperationException("Handle SQLite indisponivel.");
        var handleType = handle.GetType();

        var ptrProperty = handleType.GetProperty("ptr", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (ptrProperty?.PropertyType == typeof(IntPtr))
        {
            return (IntPtr)(ptrProperty.GetValue(handle) ?? IntPtr.Zero);
        }

        var toIntPtrMethod = handleType.GetMethod("ToIntPtr", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (toIntPtrMethod?.ReturnType == typeof(IntPtr))
        {
            return (IntPtr)(toIntPtrMethod.Invoke(handle, null) ?? IntPtr.Zero);
        }

        var ptrField = handleType.GetField("_p", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (ptrField?.FieldType == typeof(IntPtr))
        {
            return (IntPtr)(ptrField.GetValue(handle) ?? IntPtr.Zero);
        }

        throw new InvalidOperationException($"Nao foi possivel obter o ponteiro nativo do SQLite ({handleType.FullName}).");
    }

    private static class NativeMethods
    {
        internal const uint SQLITE_DESERIALIZE_FREEONCLOSE = 1;

        [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sqlite3_malloc64(ulong size);

        [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sqlite3_free(IntPtr ptr);

        [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sqlite3_serialize(
            IntPtr db,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string schema,
            out long size,
            uint flags);

        [DllImport("e_sqlite3", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_deserialize(
            IntPtr db,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string schema,
            IntPtr data,
            long size,
            long bufferSize,
            uint flags);
    }
}

