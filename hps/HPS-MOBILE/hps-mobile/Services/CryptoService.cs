using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HpsMobile.Services;

public sealed class CryptoService
{
    private const int AesKeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 210000;
    private const string KeyDomainPrefix = "hps-mobile-local-storage"; // A7: Domain separation for key derivation

    private readonly string _cryptoDir;

    public CryptoService()
    {
        _cryptoDir = Path.Combine(FileSystem.AppDataDirectory, ".hps_keys");
        Directory.CreateDirectory(_cryptoDir);
    }

    public bool AnyUserKeyMaterialExists()
    {
        return Directory.EnumerateFiles(_cryptoDir, "*.masterkey.hps", SearchOption.TopDirectoryOnly).Any();
    }

    public bool UserKeyMaterialExists(string username)
    {
        var normalized = NormalizeUsername(username);
        if (normalized.Length == 0) return false;
        return File.Exists(GetMasterKeyPath(normalized)) &&
               File.Exists(GetLoginKeyPath(normalized)) &&
               File.Exists(GetLocalKeyPath(normalized));
    }

    public (RSA loginPrivateKey, string loginPublicKeyPem, string localPublicKeyPem) LoadOrCreateKeys(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);
        if (UserKeyMaterialExists(normalized))
            return LoadExistingKeys(normalized, passphrase);
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
            return (loginKey, loginPublicPem, localPublicPem);
        }
        finally { CryptographicOperations.ZeroMemory(masterKey); }
    }

    public byte[] DeriveLocalStorageKey(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);
        var masterKey = DecryptMasterKey(normalized, passphrase);
        try
        {
            var localEnvelope = DeserializeEncryptedKeyEnvelope(File.ReadAllText(GetLocalKeyPath(normalized), Encoding.UTF8))
                ?? throw new InvalidOperationException("Arquivo de chave local invalido.");
            var localPrivatePem = DecryptPrivatePem(localEnvelope, masterKey);
            var localPrivateBytes = Encoding.UTF8.GetBytes(localPrivatePem);
            try
            {
                // A7: Add domain prefix for key derivation to prevent cross-context key reuse
                var domainBytes = Encoding.UTF8.GetBytes(KeyDomainPrefix);
                var combined = new byte[domainBytes.Length + localPrivateBytes.Length];
                System.Buffer.BlockCopy(domainBytes, 0, combined, 0, domainBytes.Length);
                System.Buffer.BlockCopy(localPrivateBytes, 0, combined, domainBytes.Length, localPrivateBytes.Length);
                return SHA256.HashData(combined);
            }
            finally { CryptographicOperations.ZeroMemory(localPrivateBytes); }
        }
        finally { CryptographicOperations.ZeroMemory(masterKey); }
    }

    private (RSA loginPrivateKey, string loginPublicKeyPem, string localPublicKeyPem) LoadExistingKeys(string username, string passphrase)
    {
        var masterKey = DecryptMasterKey(username, passphrase);
        try
        {
            var loginEnvelope = DeserializeEncryptedKeyEnvelope(File.ReadAllText(GetLoginKeyPath(username), Encoding.UTF8))
                ?? throw new InvalidOperationException("Arquivo de chave de login invalido.");
            var localEnvelope = DeserializeEncryptedKeyEnvelope(File.ReadAllText(GetLocalKeyPath(username), Encoding.UTF8))
                ?? throw new InvalidOperationException("Arquivo de chave local invalido.");
            var loginPrivatePem = DecryptPrivatePem(loginEnvelope, masterKey);
            var loginKey = RSA.Create();
            loginKey.ImportFromPem(loginPrivatePem.ToCharArray());
            return (loginKey, loginEnvelope.PublicKeyPem ?? string.Empty, localEnvelope.PublicKeyPem ?? string.Empty);
        }
        finally { CryptographicOperations.ZeroMemory(masterKey); }
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
                aes.Encrypt(nonce, payloadBytes, cipher, tag);
            var envelope = new MasterKeyEnvelope
            {
                Version = 1, Kdf = "PBKDF2-SHA256", Iterations = Pbkdf2Iterations,
                Salt = Convert.ToBase64String(salt), Nonce = Convert.ToBase64String(nonce),
                Tag = Convert.ToBase64String(tag), Ciphertext = Convert.ToBase64String(cipher)
            };
            File.WriteAllText(GetMasterKeyPath(username), JsonSerializer.Serialize(envelope), Encoding.UTF8);
            CryptographicOperations.ZeroMemory(payloadBytes); CryptographicOperations.ZeroMemory(cipher);
        }
        finally { CryptographicOperations.ZeroMemory(salt); CryptographicOperations.ZeroMemory(derived); CryptographicOperations.ZeroMemory(nonce); }
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
                aes.Encrypt(nonce, plain, cipher, tag);
            var envelope = new EncryptedKeyEnvelope
            {
                Version = 1, KeyType = keyType, PublicKeyPem = publicPem,
                Nonce = Convert.ToBase64String(nonce), Tag = Convert.ToBase64String(tag),
                Ciphertext = Convert.ToBase64String(cipher)
            };
            File.WriteAllText(path, JsonSerializer.Serialize(envelope), Encoding.UTF8);
        }
        finally { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(plain); CryptographicOperations.ZeroMemory(cipher); }
    }

    private byte[] DecryptMasterKey(string username, string passphrase)
    {
        var envelope = DeserializeMasterKeyEnvelope(File.ReadAllText(GetMasterKeyPath(username), Encoding.UTF8))
            ?? throw new InvalidOperationException("Arquivo de chave mestre invalido.");
        var salt = Convert.FromBase64String(envelope.Salt ?? string.Empty);
        var nonce = Convert.FromBase64String(envelope.Nonce ?? string.Empty);
        var tag = Convert.FromBase64String(envelope.Tag ?? string.Empty);
        var cipher = Convert.FromBase64String(envelope.Ciphertext ?? string.Empty);
        var iters = envelope.Iterations <= 0 ? Pbkdf2Iterations : envelope.Iterations;
        // Enforce minimum iterations to prevent downgrade attacks
        const int minIterations = 100000;
        if (iters < minIterations) iters = minIterations;
        var derived = DeriveAesKey(passphrase, salt, iters);
        var plain = new byte[cipher.Length];
        try
        {
            using (var aes = new AesGcm(derived, TagSizeBytes))
                aes.Decrypt(nonce, cipher, tag, plain);
            var masterB64 = Encoding.UTF8.GetString(plain);
            return Convert.FromBase64String(masterB64);
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("Senha da chave invalida ou arquivo corrompido.");
        }
        finally { CryptographicOperations.ZeroMemory(salt); CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(tag); CryptographicOperations.ZeroMemory(cipher); CryptographicOperations.ZeroMemory(derived); CryptographicOperations.ZeroMemory(plain); }
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
                aes.Decrypt(nonce, cipher, tag, plain);
            var privateB64 = Encoding.UTF8.GetString(plain);
            var privateBytes = Convert.FromBase64String(privateB64);
            var privatePem = Encoding.UTF8.GetString(privateBytes);
            CryptographicOperations.ZeroMemory(privateBytes);
            return privatePem;
        }
        finally { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(tag); CryptographicOperations.ZeroMemory(cipher); CryptographicOperations.ZeroMemory(plain); }
    }

    private static byte[] DeriveAesKey(string passphrase, byte[] salt, int iterations)
    {
        return Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, AesKeySizeBytes);
    }

    private static string NormalizeUsername(string username)
    {
        var normalized = (username ?? string.Empty).Trim().ToLowerInvariant();
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(normalized.Length);
        foreach (var c in normalized)
        {
            if (Array.IndexOf(invalid, c) >= 0 || c == '.' || c == '/' || c == '\\')
                sb.Append('_');
            else
                sb.Append(c);
        }
        return sb.ToString();
    }

    private static void ValidateInputs(string normalizedUsername, string passphrase)
    {
        if (string.IsNullOrWhiteSpace(normalizedUsername)) throw new InvalidOperationException("Usuario obrigatorio para carregar as chaves.");
        if (string.IsNullOrWhiteSpace(passphrase)) throw new InvalidOperationException("Senha da chave obrigatoria.");
    }

    private string GetMasterKeyPath(string u) => Path.Combine(_cryptoDir, $"{u}.masterkey.hps");
    private string GetLoginKeyPath(string u) => Path.Combine(_cryptoDir, $"{u}.login.hps.key");
    private string GetLocalKeyPath(string u) => Path.Combine(_cryptoDir, $"{u}.local.hps.key");

    private static MasterKeyEnvelope? DeserializeMasterKeyEnvelope(string raw)
    {
        try { return JsonSerializer.Deserialize<MasterKeyEnvelope>(raw); }
        catch { return null; }
    }

    private static EncryptedKeyEnvelope? DeserializeEncryptedKeyEnvelope(string raw)
    {
        try { return JsonSerializer.Deserialize<EncryptedKeyEnvelope>(raw); }
        catch { return null; }
    }

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
}
