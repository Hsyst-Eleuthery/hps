using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HpsBrowser.Services;

public sealed class CryptoService
{
    private const int AesKeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 210000;

    private readonly string _cryptoDir;
    private static readonly byte[] DbMagic = Encoding.ASCII.GetBytes("HPSDBENC1");

    public CryptoService(string cryptoDir)
    {
        _cryptoDir = cryptoDir;
        Directory.CreateDirectory(_cryptoDir);
    }

    public bool UserKeyMaterialExists(string username)
    {
        var normalized = NormalizeUsername(username);
        if (normalized.Length == 0)
        {
            return false;
        }

        return File.Exists(GetMasterKeyPath(normalized)) &&
               File.Exists(GetLoginKeyPath(normalized)) &&
               File.Exists(GetLocalKeyPath(normalized));
    }

    public bool AnyUserKeyMaterialExists()
    {
        return Directory.EnumerateFiles(_cryptoDir, "*.masterkey.hps", SearchOption.TopDirectoryOnly).Any();
    }

    public (RSA loginPrivateKey, string loginPublicKeyPem, string localPublicKeyPem) LoadOrCreateKeys(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);

        if (UserKeyMaterialExists(normalized))
        {
            return LoadExistingKeys(normalized, passphrase);
        }

        return GenerateAndPersistKeys(normalized, passphrase);
    }

    public (RSA loginPrivateKey, string loginPublicKeyPem, string localPublicKeyPem) GenerateAndPersistKeys(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);

        var masterKey = RandomNumberGenerator.GetBytes(AesKeySizeBytes);
        try
        {
            var loginKey = RSA.Create(4096);
            var localKey = RSA.Create(4096);

            var loginPrivatePem = loginKey.ExportRSAPrivateKeyPem();
            var loginPublicPem = loginKey.ExportSubjectPublicKeyInfoPem();
            var localPrivatePem = localKey.ExportRSAPrivateKeyPem();
            var localPublicPem = localKey.ExportSubjectPublicKeyInfoPem();

            WriteMasterKeyFile(normalized, passphrase, masterKey);
            WriteEncryptedKeyFile(GetLoginKeyPath(normalized), "login", loginPrivatePem, loginPublicPem, masterKey);
            WriteEncryptedKeyFile(GetLocalKeyPath(normalized), "local", localPrivatePem, localPublicPem, masterKey);

            loginKey.ImportFromPem(loginPrivatePem.ToCharArray());
            return (loginKey, loginPublicPem, localPublicPem);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    public void ExportKeys(string outputPath, string publicKeyPem, RSA privateKey)
    {
        var builder = new StringBuilder();
        builder.AppendLine(privateKey.ExportRSAPrivateKeyPem());
        builder.AppendLine(publicKeyPem);
        File.WriteAllText(outputPath, builder.ToString(), Encoding.UTF8);
    }

    public void ExportEncryptedKeyBundle(string username, string outputPath)
    {
        var normalized = NormalizeUsername(username);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new InvalidOperationException("Usuário obrigatório para exportar as chaves.");
        }

        var masterPath = GetMasterKeyPath(normalized);
        var loginPath = GetLoginKeyPath(normalized);
        var localPath = GetLocalKeyPath(normalized);
        if (!File.Exists(masterPath) || !File.Exists(loginPath) || !File.Exists(localPath))
        {
            throw new InvalidOperationException("Conjunto de chaves local incompleto para exportação.");
        }

        var bundle = new KeyBundleEnvelope
        {
            Version = 1,
            Username = normalized,
            MasterKeyFile = Convert.ToBase64String(File.ReadAllBytes(masterPath)),
            LoginKeyFile = Convert.ToBase64String(File.ReadAllBytes(loginPath)),
            LocalKeyFile = Convert.ToBase64String(File.ReadAllBytes(localPath))
        };
        File.WriteAllText(outputPath, SerializeKeyBundleEnvelope(bundle), Encoding.UTF8);
    }

    public (RSA privateKey, string publicKeyPem) ImportKeys(string inputPath)
    {
        var raw = File.ReadAllText(inputPath, Encoding.UTF8);
        var rsa = RSA.Create();
        rsa.ImportFromPem(raw.ToCharArray());
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();
        return (rsa, publicPem);
    }

    public void ImportEncryptedKeyBundle(string username, string inputPath, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);
        if (!File.Exists(inputPath))
        {
            throw new FileNotFoundException("Arquivo de importação não encontrado.", inputPath);
        }

        var raw = File.ReadAllText(inputPath, Encoding.UTF8);
        var bundle = DeserializeKeyBundleEnvelope(raw)
            ?? throw new InvalidOperationException("Pacote de chaves inválido.");
        if (bundle.Version <= 0 ||
            string.IsNullOrWhiteSpace(bundle.MasterKeyFile) ||
            string.IsNullOrWhiteSpace(bundle.LoginKeyFile) ||
            string.IsNullOrWhiteSpace(bundle.LocalKeyFile))
        {
            throw new InvalidOperationException("Pacote de chaves inválido.");
        }

        var masterPath = GetMasterKeyPath(normalized);
        var loginPath = GetLoginKeyPath(normalized);
        var localPath = GetLocalKeyPath(normalized);

        var oldMaster = File.Exists(masterPath) ? File.ReadAllBytes(masterPath) : null;
        var oldLogin = File.Exists(loginPath) ? File.ReadAllBytes(loginPath) : null;
        var oldLocal = File.Exists(localPath) ? File.ReadAllBytes(localPath) : null;

        try
        {
            File.WriteAllBytes(masterPath, Convert.FromBase64String(bundle.MasterKeyFile));
            File.WriteAllBytes(loginPath, Convert.FromBase64String(bundle.LoginKeyFile));
            File.WriteAllBytes(localPath, Convert.FromBase64String(bundle.LocalKeyFile));

            var (loginKey, _, _) = LoadExistingKeys(normalized, passphrase);
            loginKey.Dispose();
            var storageKey = DeriveLocalStorageKey(normalized, passphrase);
            CryptographicOperations.ZeroMemory(storageKey);
        }
        catch
        {
            RestoreFileOrDelete(masterPath, oldMaster);
            RestoreFileOrDelete(loginPath, oldLogin);
            RestoreFileOrDelete(localPath, oldLocal);
            throw;
        }
        finally
        {
            ZeroOptional(oldMaster);
            ZeroOptional(oldLogin);
            ZeroOptional(oldLocal);
        }
    }

    public void OverwriteLoginKey(string username, string passphrase, RSA privateKey)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);

        var masterKey = DecryptMasterKey(normalized, passphrase);
        try
        {
            var privatePem = privateKey.ExportRSAPrivateKeyPem();
            var publicPem = privateKey.ExportSubjectPublicKeyInfoPem();
            WriteEncryptedKeyFile(GetLoginKeyPath(normalized), "login", privatePem, publicPem, masterKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    public byte[] DeriveLocalStorageKey(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);

        var masterKey = DecryptMasterKey(normalized, passphrase);
        try
        {
            var localEnvelope = DeserializeEncryptedKeyEnvelope(File.ReadAllText(GetLocalKeyPath(normalized), Encoding.UTF8))
                ?? throw new InvalidOperationException("Arquivo de chave local inválido.");
            var localPrivatePem = DecryptPrivatePem(localEnvelope, masterKey);
            var localPrivateBytes = Encoding.UTF8.GetBytes(localPrivatePem);
            try
            {
                return SHA256.HashData(localPrivateBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(localPrivateBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    public byte[]? ReadEncryptedDatabaseSnapshot(string dbPath, byte[] key)
    {
        var encPath = dbPath + ".enc";
        if (!File.Exists(encPath))
        {
            return null;
        }

        var raw = File.ReadAllBytes(encPath);
        return DecryptDatabaseBlob(raw, key);
    }

    public void WriteEncryptedDatabaseSnapshot(string dbPath, byte[] key, byte[] plain)
    {
        var encPath = dbPath + ".enc";
        var cipher = EncryptDatabaseBlob(plain, key);
        var tempPath = encPath + ".new";
        File.WriteAllBytes(tempPath, cipher);
        if (File.Exists(encPath))
        {
            File.Delete(encPath);
        }
        File.Move(tempPath, encPath);
    }

    private static byte[] EncryptDatabaseBlob(byte[] plain, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSizeBytes];
        try
        {
            using (var aes = new AesGcm(key, TagSizeBytes))
            {
                aes.Encrypt(nonce, plain, cipher, tag);
            }

            var output = new byte[DbMagic.Length + nonce.Length + tag.Length + cipher.Length];
            Buffer.BlockCopy(DbMagic, 0, output, 0, DbMagic.Length);
            Buffer.BlockCopy(nonce, 0, output, DbMagic.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, output, DbMagic.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(cipher, 0, output, DbMagic.Length + nonce.Length + tag.Length, cipher.Length);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static byte[] DecryptDatabaseBlob(byte[] input, byte[] key)
    {
        if (input.Length <= DbMagic.Length + NonceSizeBytes + TagSizeBytes)
        {
            return input.ToArray();
        }

        for (var i = 0; i < DbMagic.Length; i++)
        {
            if (input[i] != DbMagic[i])
            {
                return input.ToArray();
            }
        }

        var nonce = new byte[NonceSizeBytes];
        var tag = new byte[TagSizeBytes];
        var cipherOffset = DbMagic.Length + NonceSizeBytes + TagSizeBytes;
        var cipherLength = input.Length - cipherOffset;
        var cipher = new byte[cipherLength];
        var plain = new byte[cipherLength];
        try
        {
            Buffer.BlockCopy(input, DbMagic.Length, nonce, 0, NonceSizeBytes);
            Buffer.BlockCopy(input, DbMagic.Length + NonceSizeBytes, tag, 0, TagSizeBytes);
            Buffer.BlockCopy(input, cipherOffset, cipher, 0, cipherLength);
            using var aes = new AesGcm(key, TagSizeBytes);
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

    private (RSA loginPrivateKey, string loginPublicKeyPem, string localPublicKeyPem) LoadExistingKeys(string username, string passphrase)
    {
        var masterKey = DecryptMasterKey(username, passphrase);
        try
        {
            var loginEnvelope = DeserializeEncryptedKeyEnvelope(File.ReadAllText(GetLoginKeyPath(username), Encoding.UTF8))
                ?? throw new InvalidOperationException("Arquivo de chave de login inválido.");
            var localEnvelope = DeserializeEncryptedKeyEnvelope(File.ReadAllText(GetLocalKeyPath(username), Encoding.UTF8))
                ?? throw new InvalidOperationException("Arquivo de chave local inválido.");

            var loginPrivatePem = DecryptPrivatePem(loginEnvelope, masterKey);
            var loginKey = RSA.Create();
            loginKey.ImportFromPem(loginPrivatePem.ToCharArray());

            return (loginKey, loginEnvelope.PublicKeyPem ?? string.Empty, localEnvelope.PublicKeyPem ?? string.Empty);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    private void WriteMasterKeyFile(string username, string passphrase, byte[] masterKey)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var derived = DeriveAesKey(passphrase, salt, Pbkdf2Iterations);
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        try
        {
            var payloadBytes = Encoding.UTF8.GetBytes(Convert.ToBase64String(masterKey));
            var cipher = new byte[payloadBytes.Length];
            var tag = new byte[TagSizeBytes];
            using (var aes = new AesGcm(derived, TagSizeBytes))
            {
                aes.Encrypt(nonce, payloadBytes, cipher, tag);
            }

            var envelope = new MasterKeyEnvelope
            {
                Version = 1,
                Kdf = "PBKDF2-SHA256",
                Iterations = Pbkdf2Iterations,
                Salt = Convert.ToBase64String(salt),
                Nonce = Convert.ToBase64String(nonce),
                Tag = Convert.ToBase64String(tag),
                Ciphertext = Convert.ToBase64String(cipher)
            };

            File.WriteAllText(GetMasterKeyPath(username), SerializeMasterKeyEnvelope(envelope), Encoding.UTF8);
            CryptographicOperations.ZeroMemory(payloadBytes);
            CryptographicOperations.ZeroMemory(cipher);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private void WriteEncryptedKeyFile(string path, string keyType, string privatePem, string publicPem, byte[] masterKey)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var base64PrivatePem = Convert.ToBase64String(Encoding.UTF8.GetBytes(privatePem));
        var plain = Encoding.UTF8.GetBytes(base64PrivatePem);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSizeBytes];
        try
        {
            using (var aes = new AesGcm(masterKey, TagSizeBytes))
            {
                aes.Encrypt(nonce, plain, cipher, tag);
            }

            var envelope = new EncryptedKeyEnvelope
            {
                Version = 1,
                KeyType = keyType,
                PublicKeyPem = publicPem,
                Nonce = Convert.ToBase64String(nonce),
                Tag = Convert.ToBase64String(tag),
                Ciphertext = Convert.ToBase64String(cipher)
            };

            File.WriteAllText(path, SerializeEncryptedKeyEnvelope(envelope), Encoding.UTF8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(cipher);
        }
    }

    private byte[] DecryptMasterKey(string username, string passphrase)
    {
        var envelope = DeserializeMasterKeyEnvelope(File.ReadAllText(GetMasterKeyPath(username), Encoding.UTF8))
            ?? throw new InvalidOperationException("Arquivo de chave mestre inválido.");

        var salt = Convert.FromBase64String(envelope.Salt ?? string.Empty);
        var nonce = Convert.FromBase64String(envelope.Nonce ?? string.Empty);
        var tag = Convert.FromBase64String(envelope.Tag ?? string.Empty);
        var cipher = Convert.FromBase64String(envelope.Ciphertext ?? string.Empty);
        var derived = DeriveAesKey(passphrase, salt, envelope.Iterations <= 0 ? Pbkdf2Iterations : envelope.Iterations);
        var plain = new byte[cipher.Length];
        try
        {
            using (var aes = new AesGcm(derived, TagSizeBytes))
            {
                aes.Decrypt(nonce, cipher, tag, plain);
            }

            var masterB64 = Encoding.UTF8.GetString(plain);
            var masterKey = Convert.FromBase64String(masterB64);
            return masterKey;
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("Senha da chave inválida ou arquivo corrompido.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(derived);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static string DecryptPrivatePem(EncryptedKeyEnvelope envelope, byte[] masterKey)
    {
        var nonce = Convert.FromBase64String(envelope.Nonce ?? string.Empty);
        var tag = Convert.FromBase64String(envelope.Tag ?? string.Empty);
        var cipher = Convert.FromBase64String(envelope.Ciphertext ?? string.Empty);
        var plain = new byte[cipher.Length];
        try
        {
            using (var aes = new AesGcm(masterKey, TagSizeBytes))
            {
                aes.Decrypt(nonce, cipher, tag, plain);
            }

            var privateB64 = Encoding.UTF8.GetString(plain);
            var privateBytes = Convert.FromBase64String(privateB64);
            var privatePem = Encoding.UTF8.GetString(privateBytes);
            CryptographicOperations.ZeroMemory(privateBytes);
            return privatePem;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static byte[] DeriveAesKey(string passphrase, byte[] salt, int iterations)
    {
        return Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, AesKeySizeBytes);
    }

    private static string NormalizeUsername(string username)
    {
        return (username ?? string.Empty).Trim().ToLowerInvariant();
    }

    private static void ValidateInputs(string normalizedUsername, string passphrase)
    {
        if (string.IsNullOrWhiteSpace(normalizedUsername))
        {
            throw new InvalidOperationException("Usuário obrigatório para carregar as chaves.");
        }
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new InvalidOperationException("Senha da chave obrigatória.");
        }
    }

    private string GetMasterKeyPath(string normalizedUsername) => Path.Combine(_cryptoDir, normalizedUsername + ".masterkey.hps");

    private string GetLoginKeyPath(string normalizedUsername) => Path.Combine(_cryptoDir, normalizedUsername + ".login.hps.key");

    private string GetLocalKeyPath(string normalizedUsername) => Path.Combine(_cryptoDir, normalizedUsername + ".local.hps.key");

    private static void RestoreFileOrDelete(string path, byte[]? oldContent)
    {
        if (oldContent is null)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
            return;
        }

        File.WriteAllBytes(path, oldContent);
    }

    private static void ZeroOptional(byte[]? buffer)
    {
        if (buffer is not null)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static string SerializeMasterKeyEnvelope(MasterKeyEnvelope envelope) =>
        SerializeHpsEnvelope("MASTER KEY", new Dictionary<string, string?>
        {
            ["VERSION"] = envelope.Version.ToString(),
            ["KDF"] = envelope.Kdf,
            ["ITERATIONS"] = envelope.Iterations.ToString(),
            ["SALT"] = envelope.Salt,
            ["NONCE"] = envelope.Nonce,
            ["TAG"] = envelope.Tag,
            ["CIPHERTEXT"] = envelope.Ciphertext
        });

    private static string SerializeEncryptedKeyEnvelope(EncryptedKeyEnvelope envelope) =>
        SerializeHpsEnvelope("ENCRYPTED KEY", new Dictionary<string, string?>
        {
            ["VERSION"] = envelope.Version.ToString(),
            ["KEY_TYPE"] = envelope.KeyType,
            ["PUBLIC_KEY_PEM_B64"] = string.IsNullOrWhiteSpace(envelope.PublicKeyPem) ? string.Empty : Convert.ToBase64String(Encoding.UTF8.GetBytes(envelope.PublicKeyPem)),
            ["NONCE"] = envelope.Nonce,
            ["TAG"] = envelope.Tag,
            ["CIPHERTEXT"] = envelope.Ciphertext
        });

    private static string SerializeKeyBundleEnvelope(KeyBundleEnvelope envelope) =>
        SerializeHpsEnvelope("KEY BUNDLE", new Dictionary<string, string?>
        {
            ["VERSION"] = envelope.Version.ToString(),
            ["USERNAME"] = envelope.Username,
            ["MASTER_KEY_FILE"] = envelope.MasterKeyFile,
            ["LOGIN_KEY_FILE"] = envelope.LoginKeyFile,
            ["LOCAL_KEY_FILE"] = envelope.LocalKeyFile
        });

    private static MasterKeyEnvelope? DeserializeMasterKeyEnvelope(string raw)
    {
        if (TryParseHpsEnvelope(raw, out _, out var fields))
        {
            return new MasterKeyEnvelope
            {
                Version = ParseIntField(fields, "VERSION"),
                Kdf = GetField(fields, "KDF"),
                Iterations = ParseIntField(fields, "ITERATIONS"),
                Salt = GetField(fields, "SALT"),
                Nonce = GetField(fields, "NONCE"),
                Tag = GetField(fields, "TAG"),
                Ciphertext = GetField(fields, "CIPHERTEXT")
            };
        }
        return JsonSerializer.Deserialize<MasterKeyEnvelope>(raw);
    }

    private static EncryptedKeyEnvelope? DeserializeEncryptedKeyEnvelope(string raw)
    {
        if (TryParseHpsEnvelope(raw, out _, out var fields))
        {
            var publicKeyPemB64 = GetField(fields, "PUBLIC_KEY_PEM_B64");
            return new EncryptedKeyEnvelope
            {
                Version = ParseIntField(fields, "VERSION"),
                KeyType = GetField(fields, "KEY_TYPE"),
                PublicKeyPem = string.IsNullOrWhiteSpace(publicKeyPemB64) ? string.Empty : Encoding.UTF8.GetString(Convert.FromBase64String(publicKeyPemB64)),
                Nonce = GetField(fields, "NONCE"),
                Tag = GetField(fields, "TAG"),
                Ciphertext = GetField(fields, "CIPHERTEXT")
            };
        }
        return JsonSerializer.Deserialize<EncryptedKeyEnvelope>(raw);
    }

    private static KeyBundleEnvelope? DeserializeKeyBundleEnvelope(string raw)
    {
        if (TryParseHpsEnvelope(raw, out _, out var fields))
        {
            return new KeyBundleEnvelope
            {
                Version = ParseIntField(fields, "VERSION"),
                Username = GetField(fields, "USERNAME"),
                MasterKeyFile = GetField(fields, "MASTER_KEY_FILE"),
                LoginKeyFile = GetField(fields, "LOGIN_KEY_FILE"),
                LocalKeyFile = GetField(fields, "LOCAL_KEY_FILE")
            };
        }
        return JsonSerializer.Deserialize<KeyBundleEnvelope>(raw);
    }

    private static string SerializeHpsEnvelope(string kind, IDictionary<string, string?> fields)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# HPS P2P SERVICE");
        builder.AppendLine($"# {kind}:");
        foreach (var pair in fields)
        {
            builder.AppendLine($"## {pair.Key} = {pair.Value ?? string.Empty}");
        }
        builder.AppendLine($"# :END {kind}");
        return builder.ToString();
    }

    private static bool TryParseHpsEnvelope(string raw, out string kind, out Dictionary<string, string> fields)
    {
        kind = string.Empty;
        fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = raw.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        foreach (var lineRaw in lines)
        {
            var line = lineRaw.Trim();
            if (line.StartsWith("# ") && line.EndsWith(":") && !line.StartsWith("## ", StringComparison.Ordinal))
            {
                kind = line[2..^1].Trim();
                continue;
            }
            if (!line.StartsWith("## ", StringComparison.Ordinal))
            {
                continue;
            }
            var body = line[3..];
            var parts = body.Split('=', 2);
            if (parts.Length != 2)
            {
                continue;
            }
            fields[parts[0].Trim()] = parts[1].Trim();
        }
        return fields.Count > 0;
    }

    private static string GetField(Dictionary<string, string> fields, string key) =>
        fields.TryGetValue(key, out var value) ? value : string.Empty;

    private static int ParseIntField(Dictionary<string, string> fields, string key) =>
        fields.TryGetValue(key, out var value) && int.TryParse(value, out var parsed) ? parsed : 0;

    private sealed class MasterKeyEnvelope
    {
        public int Version { get; set; }
        public string? Kdf { get; set; }
        public int Iterations { get; set; }
        public string? Salt { get; set; }
        public string? Nonce { get; set; }
        public string? Tag { get; set; }
        public string? Ciphertext { get; set; }
    }

    private sealed class EncryptedKeyEnvelope
    {
        public int Version { get; set; }
        public string? KeyType { get; set; }
        public string? PublicKeyPem { get; set; }
        public string? Nonce { get; set; }
        public string? Tag { get; set; }
        public string? Ciphertext { get; set; }
    }

    private sealed class KeyBundleEnvelope
    {
        public int Version { get; set; }
        public string? Username { get; set; }
        public string? MasterKeyFile { get; set; }
        public string? LoginKeyFile { get; set; }
        public string? LocalKeyFile { get; set; }
    }
}

