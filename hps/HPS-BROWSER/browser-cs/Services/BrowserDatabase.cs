using System.Security.Cryptography;
using System.Text.Json;
using HpsBrowser.Models;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace HpsBrowser.Services;

public sealed class BrowserDatabase : IDisposable
{
    static BrowserDatabase()
    {
        Batteries_V2.Init();
    }

    private readonly string _dbPath;
    private SqliteConnection? _connection;
    private string? _connectionString;
    private byte[]? _encryptionKey;

    public BrowserDatabase(string dbPath)
    {
        _dbPath = dbPath;
    }

    public string DbPath => _dbPath;

    public void SetEncryptionKey(byte[] key)
    {
        _encryptionKey = key;
    }

    public void Initialize(byte[]? seedBytes = null)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_dbPath) ?? ".");

        if (!File.Exists(_dbPath) && seedBytes is not null && seedBytes.Length > 0)
        {
            throw new InvalidOperationException("Legacy encrypted snapshot import is not supported without an existing local database file.");
        }

        _connectionString = BuildConnectionString(encrypted: true);
        if (_encryptionKey != null && _encryptionKey.Length > 0 && File.Exists(_dbPath))
        {
            try
            {
                using var verifyConnection = new SqliteConnection(_connectionString);
                verifyConnection.Open();
                using var verifyCommand = verifyConnection.CreateCommand();
                verifyCommand.CommandText = "SELECT COUNT(*) FROM sqlite_master;";
                _ = Convert.ToInt32(verifyCommand.ExecuteScalar());
            }
            catch (SqliteException)
            {
                MigrateLegacyPlaintextDatabaseToEncrypted();
            }
        }

        _connection = new SqliteConnection(_connectionString);
        _connection.Open();
        RemoveLegacyEncryptedSnapshot();

        using var cmd = _connection.CreateCommand();
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
    ddns_hash TEXT DEFAULT ''
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
    timestamp REAL NOT NULL,
    verified INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS browser_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS browser_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    title TEXT,
    visited_at REAL NOT NULL,
    username TEXT
);
CREATE TABLE IF NOT EXISTS browser_message_contacts (
    username TEXT PRIMARY KEY,
    last_message_at REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS browser_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp REAL NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0
);
";
        cmd.ExecuteNonQuery();

        EnsureColumn("browser_content_cache", "signature", "TEXT");
        EnsureColumn("browser_content_cache", "public_key", "TEXT");
        EnsureColumn("browser_content_cache", "verified", "INTEGER DEFAULT 0");
        EnsureColumn("browser_content_cache", "is_public", "INTEGER DEFAULT 1");
        EnsureColumn("browser_dns_records", "ddns_hash", "TEXT DEFAULT ''");
    }

    private string BuildConnectionString(bool encrypted)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate
        };

        if (encrypted && _encryptionKey != null && _encryptionKey.Length > 0)
        {
            builder.Password = Convert.ToBase64String(_encryptionKey);
        }

        return builder.ToString();
    }

    private void MigrateLegacyPlaintextDatabaseToEncrypted()
    {
        if (_encryptionKey == null || _encryptionKey.Length == 0 || !File.Exists(_dbPath))
        {
            return;
        }

        using var plaintextConnection = new SqliteConnection(BuildConnectionString(encrypted: false));
        plaintextConnection.Open();

        using (var verifyCommand = plaintextConnection.CreateCommand())
        {
            verifyCommand.CommandText = "SELECT COUNT(*) FROM sqlite_master;";
            _ = Convert.ToInt32(verifyCommand.ExecuteScalar());
        }

        var quotedPassword = Convert.ToBase64String(_encryptionKey).Replace("'", "''", StringComparison.Ordinal);
        using (var rekeyCommand = plaintextConnection.CreateCommand())
        {
            rekeyCommand.CommandText = $"PRAGMA rekey = '{quotedPassword}';";
            rekeyCommand.ExecuteNonQuery();
        }

        plaintextConnection.Close();
        RemoveLegacyEncryptedSnapshot();
    }

    private void RemoveLegacyEncryptedSnapshot()
    {
        var encPath = _dbPath + ".enc";
        if (File.Exists(encPath))
        {
            File.Delete(encPath);
        }
    }

    private void EnsureColumn(string tableName, string columnName, string columnSql)
    {
        var conn = GetConnection();
        using var checkCmd = conn.CreateCommand();
        checkCmd.CommandText = $"PRAGMA table_info({tableName})";
        using var reader = checkCmd.ExecuteReader();
        while (reader.Read())
        {
            if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }

        using var alterCmd = conn.CreateCommand();
        alterCmd.CommandText = $"ALTER TABLE {tableName} ADD COLUMN {columnName} {columnSql}";
        alterCmd.ExecuteNonQuery();
    }

    private SqliteConnection GetConnection()
    {
        if (_connection != null)
            return _connection;
        if (_connectionString == null)
            throw new InvalidOperationException("Database not initialized");
        _connection = new SqliteConnection(_connectionString);
        _connection.Open();
        return _connection;
    }

    public void Close()
    {
        _connection?.Close();
        _connection?.Dispose();
        _connection = null;
        _connectionString = null;
    }

    public void Dispose()
    {
        Close();
    }

    public void SealEncrypted()
    {
    }

    public string? LoadSetting(string key)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM browser_settings WHERE key = $key";
        cmd.Parameters.AddWithValue("$key", key);
        return cmd.ExecuteScalar() as string;
    }

    public int LoadSettingInt(string key, int defaultValue)
    {
        var val = LoadSetting(key);
        return int.TryParse(val, out var result) ? result : defaultValue;
    }

    public bool LoadSettingBool(string key, bool defaultValue)
    {
        var val = LoadSetting(key);
        return bool.TryParse(val, out var result) ? result : defaultValue;
    }

    public void SaveSetting(string key, string value)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO browser_settings (key, value) VALUES ($key, $value)";
        cmd.Parameters.AddWithValue("$key", key);
        cmd.Parameters.AddWithValue("$value", value);
        cmd.ExecuteNonQuery();
    }

    public void SaveSettingInt(string key, int value)
    {
        SaveSetting(key, value.ToString());
    }

    public void SaveSettingBool(string key, bool value)
    {
        SaveSetting(key, value.ToString());
    }

    public SqliteConnection OpenConnection()
    {
        return GetConnection();
    }

    public void EnsureInventoryVisibility(string contentHash, bool visible)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE browser_content_cache SET verified = $verified WHERE content_hash = $contentHash";
        cmd.Parameters.AddWithValue("$verified", visible ? 1 : 0);
        cmd.Parameters.AddWithValue("$contentHash", contentHash);
        cmd.ExecuteNonQuery();
    }

    public void SaveDdnsRecord(string domain, string ddnsHash, string contentHash, string username, bool verified, string signature, string publicKey)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO browser_dns_records
(domain, content_hash, username, verified, timestamp, ddns_hash)
VALUES ($domain, $contentHash, $username, $verified, $timestamp, $ddnsHash)";
        cmd.Parameters.AddWithValue("$domain", domain);
        cmd.Parameters.AddWithValue("$ddnsHash", ddnsHash);
        cmd.Parameters.AddWithValue("$contentHash", contentHash);
        cmd.Parameters.AddWithValue("$username", username);
        cmd.Parameters.AddWithValue("$verified", verified ? 1 : 0);
        cmd.Parameters.AddWithValue("$timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    public (string FilePath, string Title, string Description, string MimeType, long Size, double LastAccessed, string Username, bool Verified, string Signature, string PublicKey)? LoadContentMetadata(string contentHash)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT file_path, title, description, mime_type, size, last_accessed, username, verified, signature, public_key FROM browser_content_cache WHERE content_hash = $contentHash";
        cmd.Parameters.AddWithValue("$contentHash", contentHash);
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            var signature = reader.IsDBNull(8) ? "" : reader.GetString(8);
            var publicKey = reader.IsDBNull(9) ? "" : reader.GetString(9);
            return (reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4), reader.GetDouble(5), reader.GetString(6), reader.GetInt32(7) == 1, signature, publicKey);
        }
        return null;
    }

public HpsBrowser.Models.ContractInfo? LoadContractRecord(string contentHash)
    {
        var json = LoadSetting($"contract_{contentHash}");
        if (string.IsNullOrEmpty(json)) return null;
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<HpsBrowser.Models.ContractInfo>(json);
        }
        catch { return null; }
    }

    public void SaveContractRecord(HpsBrowser.Models.ContractInfo contract)
    {
        SaveSetting($"contract_{contract.ContractId}", System.Text.Json.JsonSerializer.Serialize(contract));
    }

    public List<(string Address, bool UseSsl, int Reputation)> LoadKnownServers()
    {
        var results = new List<(string, bool, int)>();
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT server_address, use_ssl, reputation FROM browser_known_servers WHERE is_active = 1 ORDER BY reputation DESC LIMIT 20";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add((reader.GetString(0), reader.GetInt32(1) == 1, reader.GetInt32(2)));
        }
return results;
    }

    public void SaveKnownServers(List<(string Address, bool UseSsl, int Reputation)> servers)
    {
        var conn = GetConnection();
        using var clearCmd = conn.CreateCommand();
        clearCmd.CommandText = "DELETE FROM browser_known_servers";
        clearCmd.ExecuteNonQuery();
        foreach (var (address, useSsl, reputation) in servers)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO browser_known_servers (server_address, use_ssl, reputation, last_connected, is_active) VALUES ($address, $useSsl, $reputation, $lastConnected, 1)";
            cmd.Parameters.AddWithValue("$address", address);
            cmd.Parameters.AddWithValue("$useSsl", useSsl ? 1 : 0);
            cmd.Parameters.AddWithValue("$reputation", reputation);
            cmd.Parameters.AddWithValue("$lastConnected", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            cmd.ExecuteNonQuery();
        }
    }

    public List<(string ContentHash, string Title, string Description, string MimeType, long Size, string Owner, bool IsPublic)> LoadInventoryItems()
    {
        var results = new List<(string, string, string, string, long, string, bool)>();
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT content_hash, title, description, mime_type, size, username, is_public FROM browser_content_cache WHERE verified = 1 ORDER BY last_accessed DESC LIMIT 100";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4), reader.GetString(5), reader.GetInt32(6) == 1));
        }
        return results;
    }

    public byte[] ExportPlaintextBytes()
    {
        return Array.Empty<byte>();
    }

    public void SaveInventoryVisibility(string contentHash, bool isPublic)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE browser_content_cache SET verified = $verified WHERE content_hash = $contentHash";
        cmd.Parameters.AddWithValue("$verified", isPublic ? 1 : 0);
        cmd.Parameters.AddWithValue("$contentHash", contentHash);
        cmd.ExecuteNonQuery();
    }

    public void UpdateVoucherStatus(string voucherId, string status, string? claimedAt = null)
    {
        var conn = GetConnection();
        var existing = LoadSetting($"voucher_{voucherId}");
        if (!string.IsNullOrEmpty(existing))
        {
            try
            {
                var voucher = System.Text.Json.JsonSerializer.Deserialize<HpsBrowser.Models.Voucher>(existing);
                if (voucher != null)
                {
                    voucher.Status = status;
                    SaveSetting($"voucher_{voucherId}", System.Text.Json.JsonSerializer.Serialize(voucher));
                }
            }
            catch { }
        }
    }

    public List<HpsBrowser.Models.DnsRecord> LoadDnsRecords()
    {
        var results = new List<HpsBrowser.Models.DnsRecord>();
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT domain, content_hash, username, verified, ddns_hash FROM browser_dns_records";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add(new HpsBrowser.Models.DnsRecord
            {
                Domain = reader.GetString(0),
                ContentHash = reader.GetString(1),
                Username = reader.GetString(2),
                Verified = reader.GetInt32(3) == 1,
                DdnsHash = reader.GetString(4)
            });
        }
        return results;
    }

    public List<HpsBrowser.Models.Voucher> LoadLocalVouchers()
    {
        var results = new List<HpsBrowser.Models.Voucher>();
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key, value FROM browser_settings WHERE key LIKE 'voucher_%'";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var json = reader.GetString(1);
            try
            {
                var voucher = System.Text.Json.JsonSerializer.Deserialize<HpsBrowser.Models.Voucher>(json);
                if (voucher != null) results.Add(voucher);
            }
            catch { }
        }
        return results;
    }

    public void ReplaceVoucherRecords(string serverAddress, List<HpsBrowser.Models.Voucher> vouchers)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        var serverPrefix = string.IsNullOrWhiteSpace(serverAddress)
            ? "voucher_noserver_"
            : $"voucher_{serverAddress}_";
        cmd.CommandText = "DELETE FROM browser_settings WHERE key LIKE @pattern";
        cmd.Parameters.AddWithValue("@pattern", $"{serverPrefix}%");
        cmd.ExecuteNonQuery();
        foreach (var v in vouchers)
        {
            var newKey = $"{serverPrefix}{v.VoucherId}";
            cmd.Parameters.Clear();
            cmd.CommandText = "DELETE FROM browser_settings WHERE key = @oldKey";
            cmd.Parameters.AddWithValue("@oldKey", $"voucher_{v.VoucherId}");
            cmd.ExecuteNonQuery();
            cmd.Parameters.Clear();
            cmd.CommandText = "INSERT INTO browser_settings (key, value) VALUES ($key, $value)";
            cmd.Parameters.AddWithValue("$key", newKey);
            cmd.Parameters.AddWithValue("$value", System.Text.Json.JsonSerializer.Serialize(v));
            cmd.ExecuteNonQuery();
            cmd.Parameters.Clear();
        }
    }

    public void MarkContentPublished(string contentHash)
    {
        SaveSetting($"published_{contentHash}", "1");
    }

    public List<string> LoadPublishedContentHashes()
    {
        var result = new List<string>();
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key FROM browser_settings WHERE key LIKE 'published_%'";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var key = reader.GetString(0);
            if (key.StartsWith("published_"))
            {
                result.Add(key.Substring(10));
            }
        }
        return result;
    }

    public static string CanonicalizePayload(JsonElement payload)
    {
        return CanonicalizeJson(payload);
    }

    private static string CanonicalizeObject(JsonElement element)
    {
        var properties = element.EnumerateObject()
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .Select(p => $"{JsonSerializer.Serialize(p.Name)}:{CanonicalizeJson(p.Value)}");
        return "{" + string.Join(",", properties) + "}";
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

    public List<MessageContact> LoadMessageContacts()
    {
        var result = new List<MessageContact>();
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT username, last_message_at FROM browser_message_contacts ORDER BY last_message_at DESC LIMIT 50";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new MessageContact
            {
                Username = reader.GetString(0),
                LastMessageAt = reader.GetDouble(1)
            });
        }
        return result;
    }

    public List<MessageRecord> LoadMessageRecords(string contactUsername, int limit = 100)
    {
        var result = new List<MessageRecord>();
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, from_user, to_user, content, timestamp, is_read FROM browser_messages WHERE from_user = $user OR to_user = $user ORDER BY timestamp DESC LIMIT $limit";
        cmd.Parameters.AddWithValue("$user", contactUsername);
        cmd.Parameters.AddWithValue("$limit", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new MessageRecord
            {
                FromUser = reader.GetString(1),
                ToUser = reader.GetString(2),
                Content = reader.GetString(3),
                Timestamp = reader.GetDouble(4),
                IsRead = reader.GetInt32(5) == 1
            });
        }
        return result;
    }

    public void SaveMessageRecord(string fromUser, string toUser, string content, double timestamp, bool isRead)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO browser_messages (from_user, to_user, content, timestamp, is_read) VALUES ($from, $to, $content, $ts, $isRead)";
        cmd.Parameters.AddWithValue("$from", fromUser);
        cmd.Parameters.AddWithValue("$to", toUser);
        cmd.Parameters.AddWithValue("$content", content);
        cmd.Parameters.AddWithValue("$ts", timestamp);
        cmd.Parameters.AddWithValue("$isRead", isRead ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    public void SaveDnsRecord(string domain, string contentHash, string username, bool verified, double? timestamp = null)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO browser_dns_records (domain, content_hash, username, verified, timestamp, ddns_hash) VALUES ($domain, $contentHash, $username, $verified, $timestamp, '')";
        cmd.Parameters.AddWithValue("$domain", domain);
        cmd.Parameters.AddWithValue("$contentHash", contentHash);
        cmd.Parameters.AddWithValue("$username", username);
        cmd.Parameters.AddWithValue("$verified", verified ? 1 : 0);
        cmd.Parameters.AddWithValue("$timestamp", timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.ExecuteNonQuery();
    }

    public (string domain, string ddnsHash, string contentHash, string username, bool verified, string signature, string publicKey)? LoadDdnsRecord(string domain)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT signature, public_key FROM browser_content_cache WHERE content_hash = (SELECT ddns_hash FROM browser_dns_records WHERE domain = $domain AND ddns_hash != '' LIMIT 1)";
        cmd.Parameters.AddWithValue("$domain", domain);
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            var signature = reader.IsDBNull(0) ? "" : reader.GetString(0);
            var publicKey = reader.IsDBNull(1) ? "" : reader.GetString(1);
            return (domain, "", "", "", false, signature, publicKey);
        }
        return null;
    }

    public List<(string ContentHash, string ActionType, double Timestamp)> LoadContractSummaries()
    {
        var result = new List<(string, string, double)>();
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key, value FROM browser_settings WHERE key LIKE 'contract_%'";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var json = reader.GetString(1);
            try
            {
                var c = System.Text.Json.JsonSerializer.Deserialize<HpsBrowser.Models.ContractInfo>(json);
                if (c != null) result.Add((c.ContentHash, c.ActionType, c.Timestamp));
            }
            catch { }
        }
        return result;
    }

    public void ReplaceMessageContacts(List<MessageContactInfo> contacts)
    {
        var conn = GetConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM browser_message_contacts";
        cmd.ExecuteNonQuery();
        foreach (var contact in contacts)
        {
            cmd.CommandText = "INSERT INTO browser_message_contacts (username, last_message_at) VALUES ($user, $ts)";
            cmd.Parameters.AddWithValue("$user", contact.PeerUser);
            cmd.Parameters.AddWithValue("$ts", contact.LastMessageAt);
            cmd.ExecuteNonQuery();
            cmd.Parameters.Clear();
        }
    }

    public static string CanonicalizePayload(byte[] payload) => Convert.ToBase64String(payload);
    public static string CanonicalizeJson(string json) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));
    public static string CanonicalizeObject(object o) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(o)));
}

public class MessageContact
{
    public string Username { get; set; } = "";
    public double LastMessageAt { get; set; }
}

public class MessageRecord
{
    public string FromUser { get; set; } = "";
    public string ToUser { get; set; } = "";
    public string Content { get; set; } = "";
    public double Timestamp { get; set; }
    public bool IsRead { get; set; }
}
