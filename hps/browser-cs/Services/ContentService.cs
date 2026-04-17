using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using System.Text.Json;
using HpsBrowser.Models;

namespace HpsBrowser.Services;

public sealed class ContentService
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

    private readonly BrowserDatabase _database;
    private readonly string _cryptoDir;
    private byte[]? _storageKey;
    private string _defaultPublicKeyPem = string.Empty;

    public ContentService(BrowserDatabase database, string cryptoDir)
    {
        _database = database;
        _cryptoDir = cryptoDir;
    }

    public sealed record LocalContent(string FilePath, byte[] Data, string Title, string Description, string MimeType);

    public void SetStorageKey(byte[] storageKey)
    {
        ClearStorageKey();
        _storageKey = storageKey.ToArray();
    }

    public void SetDefaultPublicKey(string publicKeyPem)
    {
        _defaultPublicKeyPem = publicKeyPem ?? string.Empty;
    }

    public void ClearStorageKey()
    {
        if (_storageKey is not null)
        {
            CryptographicOperations.ZeroMemory(_storageKey);
            _storageKey = null;
        }
    }

    public string ComputeSha256HexBytes(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public string GuessMimeType(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        return extension switch
        {
            ".txt" => "text/plain",
            ".html" => "text/html",
            ".htm" => "text/html",
            ".json" => "application/json",
            ".png" => "image/png",
            ".jpg" => "image/jpeg",
            ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".pdf" => "application/pdf",
            _ => "application/octet-stream"
        };
    }

    public byte[] CombineBytes(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }

    public string BuildContractTemplate(string actionType, IDictionary<string, string> details)
    {
        var contractDetails = new Dictionary<string, string>(details, StringComparer.OrdinalIgnoreCase);
        if (!contractDetails.ContainsKey("PUBLIC_KEY") && !string.IsNullOrWhiteSpace(_defaultPublicKeyPem))
        {
            contractDetails["PUBLIC_KEY"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(_defaultPublicKeyPem));
        }
        var lines = new List<string>
        {
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            $"# ACTION: {actionType}"
        };

        foreach (var (key, value) in contractDetails)
        {
            lines.Add($"# {key}: {value}");
        }

        lines.Add("### :END DETAILS");
        lines.Add("### START:");
        lines.Add("# USER: ");
        lines.Add("# SIGNATURE: ");
        lines.Add("### :END START");
        lines.Add("## :END CONTRACT");

        return string.Join("\n", lines) + "\n";
    }

    public string ApplyContractSignature(string contractText, RSA privateKey, string username)
    {
        if (string.IsNullOrWhiteSpace(contractText))
        {
            return contractText;
        }

        const string signaturePlaceholder = "# SIGNATURE:";
        const string userPlaceholder = "# USER:";

        var trimmed = contractText.TrimEnd('\r', '\n');
        var lines = trimmed.Split('\n').ToList();
        var signatureIndex = lines.FindIndex(line => line.TrimStart().StartsWith(signaturePlaceholder, StringComparison.Ordinal));
        if (signatureIndex < 0)
        {
            return contractText;
        }

        var userIndex = lines.FindIndex(line => line.TrimStart().StartsWith(userPlaceholder, StringComparison.Ordinal));
        if (userIndex >= 0)
        {
            lines[userIndex] = $"{userPlaceholder} {username}";
        }

        var signedLines = new List<string>();
        for (var i = 0; i < lines.Count; i++)
        {
            if (i == signatureIndex)
            {
                continue;
            }
            signedLines.Add(lines[i]);
        }

        var signedText = string.Join("\n", signedLines);
        var signature = CryptoUtils.SignPayload(privateKey, signedText);
        var signatureB64 = Convert.ToBase64String(signature);
        lines[signatureIndex] = $"{signaturePlaceholder} {signatureB64}";

        return string.Join("\n", lines).TrimEnd() + "\n";
    }

    public byte[] CreateDdnsFile(string domain, string contentHash, string username, string publicKeyPem)
    {
        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyPem));
        var text = $"# HSYST P2P SERVICE\n### START:\n# USER: {username}\n# KEY: {publicKeyB64}\n# CONTENT_HASH: {contentHash}\n### :END START\n### DNS:\n# DNAME: {domain} = {contentHash}\n### :END DNS\n";
        return Encoding.UTF8.GetBytes(text);
    }

    public byte[] SignDdnsPayload(byte[] ddnsContent, RSA privateKey)
    {
        var marker = Encoding.UTF8.GetBytes("### :END START");
        var index = IndexOf(ddnsContent, marker);
        var signedPortion = ddnsContent;
        if (index >= 0)
        {
            signedPortion = ddnsContent[(index + marker.Length)..];
        }
        return privateKey.SignData(signedPortion, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public void SaveContentToStorage(string contentHash, byte[] content, string title, string description, string mimeType, string signature, string publicKey, string username)
    {
        if (_storageKey is null)
        {
            throw new InvalidOperationException("Chave de armazenamento local não carregada.");
        }

        var contentDir = Path.Combine(_cryptoDir, "content");
        Directory.CreateDirectory(contentDir);
        var filePath = Path.Combine(contentDir, $"{contentHash}.dat");
        File.WriteAllBytes(filePath, EncryptForLocalStorage(content));

        using var conn = _database.OpenConnection();
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO browser_content_cache
(content_hash, file_path, file_name, mime_type, size, last_accessed, title, description, username, signature, public_key, verified)
VALUES ($hash, $path, $name, $mime, $size, $ts, $title, $desc, $user, $sig, $pub, 1);
";
        cmd.Parameters.AddWithValue("$hash", contentHash);
        cmd.Parameters.AddWithValue("$path", filePath);
        cmd.Parameters.AddWithValue("$name", Path.GetFileName(filePath));
        cmd.Parameters.AddWithValue("$mime", mimeType);
        cmd.Parameters.AddWithValue("$size", content.Length);
        cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        cmd.Parameters.AddWithValue("$title", title);
        cmd.Parameters.AddWithValue("$desc", description);
        cmd.Parameters.AddWithValue("$user", username);
        cmd.Parameters.AddWithValue("$sig", signature);
        cmd.Parameters.AddWithValue("$pub", publicKey);
        cmd.ExecuteNonQuery();

        _database.EnsureInventoryVisibility(contentHash, true);
    }

    public void SaveDdnsToStorage(string domain, byte[] ddnsContent, string ddnsHash, string contentHash, string username, string signature, string publicKey)
    {
        if (_storageKey is null)
        {
            throw new InvalidOperationException("Chave de armazenamento local não carregada.");
        }

        var ddnsDir = Path.Combine(_cryptoDir, "ddns");
        Directory.CreateDirectory(ddnsDir);
        var filePath = Path.Combine(ddnsDir, $"{ddnsHash}.ddns");
        File.WriteAllBytes(filePath, EncryptForLocalStorage(ddnsContent));
        _database.SaveDdnsRecord(domain, ddnsHash, contentHash, username, true, signature, publicKey);
    }

    public byte[]? TryLoadDdnsContent(string ddnsHash)
    {
        if (string.IsNullOrWhiteSpace(ddnsHash))
        {
            return null;
        }

        var ddnsPath = Path.Combine(_cryptoDir, "ddns", $"{ddnsHash}.ddns");
        if (!File.Exists(ddnsPath))
        {
            return null;
        }

        try
        {
            return DecryptFromLocalStorage(File.ReadAllBytes(ddnsPath));
        }
        catch
        {
            return null;
        }
    }

    public void SyncVouchersToStorage(IEnumerable<Voucher> vouchers, RSA privateKey)
    {
        if (_storageKey is null)
        {
            throw new InvalidOperationException("Chave de armazenamento local não carregada.");
        }

        var voucherDir = Path.Combine(_cryptoDir, "vouchers");
        Directory.CreateDirectory(voucherDir);
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var voucher in vouchers)
        {
            if (string.IsNullOrWhiteSpace(voucher.VoucherId))
            {
                continue;
            }

            var lineageRoot = voucher.Payload.TryGetValue("lineage_root_voucher_id", out var lineageRootRaw)
                ? Convert.ToString(lineageRootRaw) ?? string.Empty
                : string.Empty;
            if (string.IsNullOrWhiteSpace(lineageRoot))
            {
                lineageRoot = voucher.VoucherId;
            }
            var lineageDir = Path.Combine(voucherDir, lineageRoot);
            Directory.CreateDirectory(lineageDir);
            var voucherFile = Path.Combine(lineageDir, $"{voucher.VoucherId}.hps");
            expected.Add(voucherFile);
            var payload = new
            {
                voucher_id = voucher.VoucherId,
                issuer = voucher.Issuer,
                owner = voucher.Owner,
                value = voucher.Value,
                reason = voucher.Reason,
                issued_at = voucher.IssuedAt,
                payload = voucher.Payload,
                signatures = new Dictionary<string, string>
                {
                    ["issuer"] = voucher.IssuerSignature,
                    ["owner"] = voucher.OwnerSignature
                },
                status = voucher.Status,
                invalidated = voucher.Invalidated
            };
            var raw = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
            File.WriteAllBytes(voucherFile, EncryptForLocalStorage(ProtectVoucherWithDkvhps(voucher, raw, privateKey)));
        }

        foreach (var file in Directory.EnumerateFiles(voucherDir, "*.hps", SearchOption.AllDirectories))
        {
            if (!expected.Contains(file))
            {
                File.Delete(file);
            }
        }
        foreach (var dir in Directory.EnumerateDirectories(voucherDir))
        {
            if (!Directory.EnumerateFileSystemEntries(dir).Any())
            {
                Directory.Delete(dir);
            }
        }
    }

    public string SaveMessageFileToStorage(string localUser, string peerUser, string fileName, byte[] messageContent)
    {
        if (_storageKey is null)
        {
            throw new InvalidOperationException("Chave de armazenamento local não carregada.");
        }

        var localSegment = SanitizePathSegment(localUser);
        var peerSegment = SanitizePathSegment(peerUser);
        if (string.IsNullOrWhiteSpace(localSegment))
        {
            localSegment = "default";
        }
        if (string.IsNullOrWhiteSpace(peerSegment))
        {
            peerSegment = "unknown";
        }

        var fileSegment = SanitizePathSegment(fileName);
        if (string.IsNullOrWhiteSpace(fileSegment))
        {
            fileSegment = $"message-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}.hps";
        }

        var directory = Path.Combine(_cryptoDir, "messages", localSegment, peerSegment);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, fileSegment);
        File.WriteAllBytes(path, EncryptForLocalStorage(messageContent));
        return path;
    }

    private byte[] ProtectVoucherWithDkvhps(Voucher voucher, byte[] plain, RSA privateKey)
    {
        if (!voucher.Payload.TryGetValue("dkvhps", out var dkvhpsRaw) || dkvhpsRaw is not Dictionary<string, object> dkvhps)
        {
            return plain;
        }

        var voucherEncrypted = dkvhps.TryGetValue("voucher_owner_encrypted", out var voucherEncRaw) ? Convert.ToString(voucherEncRaw) ?? string.Empty : string.Empty;
        var lineageEncrypted = dkvhps.TryGetValue("lineage_owner_encrypted", out var lineageEncRaw) ? Convert.ToString(lineageEncRaw) ?? string.Empty : string.Empty;
        var voucherSecret = CryptoUtils.DecryptOaepBase64(privateKey, voucherEncrypted);
        var lineageSecret = CryptoUtils.DecryptOaepBase64(privateKey, lineageEncrypted);
        if (string.IsNullOrWhiteSpace(voucherSecret) || string.IsNullOrWhiteSpace(lineageSecret))
        {
            return plain;
        }

        var voucherKey = SHA256.HashData(Encoding.UTF8.GetBytes($"voucher:{voucherSecret}"));
        var lineageKey = SHA256.HashData(Encoding.UTF8.GetBytes($"lineage:{lineageSecret}"));
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
            VoucherHash = dkvhps.TryGetValue("voucher_hash", out var voucherHashRaw) ? Convert.ToString(voucherHashRaw) ?? string.Empty : string.Empty,
            LineageHash = dkvhps.TryGetValue("lineage_hash", out var lineageHashRaw) ? Convert.ToString(lineageHashRaw) ?? string.Empty : string.Empty,
            VoucherOwnerEncrypted = voucherEncrypted,
            LineageOwnerEncrypted = lineageEncrypted,
            LineageNonce = Convert.ToBase64String(lineageNonce),
            Ciphertext = Convert.ToBase64String(lineageCipher)
        });
    }

    public LocalContent? TryLoadLocalContent(string contentHash)
    {
        var metadata = _database.LoadContentMetadata(contentHash);
        if (metadata is null)
        {
            return null;
        }

        var (filePath, title, description, mimeType, _, _, _, _) = metadata.Value;
        if (!File.Exists(filePath))
        {
            return null;
        }

        try
        {
            var data = DecryptFromLocalStorage(File.ReadAllBytes(filePath));
            return new LocalContent(filePath, data, title, description, mimeType);
        }
        catch
        {
            return null;
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
        if (_storageKey is null)
        {
            throw new InvalidOperationException("Storage key missing.");
        }

        var nonce = RandomNumberGenerator.GetBytes(AesNonceSize);
        var cipher = new byte[plain.Length];
        var tag = new byte[AesTagSize];
        try
        {
            using (var aes = new AesGcm(_storageKey, AesTagSize))
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

    private byte[] DecryptFromLocalStorage(byte[] input)
    {
        if (input.Length <= EncMagic.Length + AesNonceSize + AesTagSize)
        {
            throw new InvalidDataException("Arquivo local não está no formato HPS2ENC1.");
        }

        for (var i = 0; i < EncMagic.Length; i++)
        {
            if (input[i] != EncMagic[i])
            {
                throw new InvalidDataException("Arquivo local não está no formato HPS2ENC1.");
            }
        }

        if (_storageKey is null)
        {
            throw new InvalidOperationException("Chave de armazenamento local não carregada.");
        }

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
            using var aes = new AesGcm(_storageKey, AesTagSize);
            aes.Decrypt(nonce, cipher, tag, plain);
            return plain;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(cipher);
        }
    }

    private static string SanitizePathSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var invalidChars = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            builder.Append(invalidChars.Contains(ch) ? '_' : ch);
        }
        return builder.ToString().Trim();
    }

    private static int IndexOf(byte[] buffer, byte[] pattern)
    {
        for (var i = 0; i <= buffer.Length - pattern.Length; i++)
        {
            var match = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return i;
            }
        }
        return -1;
    }
}

