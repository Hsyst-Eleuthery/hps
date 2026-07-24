using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HpsWallet.Services;

public sealed class CryptoService
{
    private const int AesKeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 210000;

    private readonly string _cryptoDir;

    public CryptoService()
    {
        _cryptoDir = Path.Combine(FileSystem.AppDataDirectory, ".hps_keys");
        Directory.CreateDirectory(_cryptoDir);
    }

    public bool UserKeyMaterialExists(string username)
    {
        var normalized = NormalizeUsername(username);
        return File.Exists(GetMasterKeyPath(normalized)) &&
               File.Exists(GetLoginKeyPath(normalized)) &&
               File.Exists(GetLocalKeyPath(normalized));
    }

    public (RSA loginPrivateKey, string loginPublicKeyPem) LoadOrCreateKeys(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        if (UserKeyMaterialExists(normalized))
            return LoadExistingKeys(normalized, passphrase);
        return GenerateAndPersistKeys(normalized, passphrase);
    }

    private (RSA loginPrivateKey, string loginPublicKeyPem) GenerateAndPersistKeys(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
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

            return (loginKey, loginPublicPem);
        }
        finally { CryptographicOperations.ZeroMemory(masterKey); }
    }

    private (RSA loginPrivateKey, string loginPublicKeyPem) LoadExistingKeys(string username, string passphrase)
    {
        var masterKey = DecryptMasterKey(username, passphrase);
        try
        {
            var loginEnvelope = DeserializeEncryptedKeyEnvelope(File.ReadAllText(GetLoginKeyPath(username), Encoding.UTF8));
            if (loginEnvelope == null) throw new InvalidOperationException("Arquivo de chave de login invalido.");

            var loginPrivatePem = DecryptPrivatePem(loginEnvelope, masterKey);
            var loginKey = RSA.Create();
            try
            {
                loginKey.ImportFromPem(loginPrivatePem.ToCharArray());
            }
            catch (CryptographicException)
            {
                loginKey.Dispose();
                var b64 = loginPrivatePem
                    .Replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .Replace("-----END RSA PRIVATE KEY-----", "")
                    .Replace("\r", "").Replace("\n", "").Trim();
                var der = Convert.FromBase64String(b64);
                loginKey = RSA.Create();
                loginKey.ImportRSAPrivateKey(der, out _);
            }
            // Normalize key to platform-independent RSA instance
            try
            {
                var pars = loginKey.ExportParameters(true);
                var normalized = RSA.Create();
                normalized.ImportParameters(pars);
                loginKey.Dispose();
                loginKey = normalized;
            }
            catch { /* Keep original key if normalization fails */ }
            return (loginKey, loginEnvelope.PublicKeyPem ?? string.Empty);
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
        var envelope = DeserializeMasterKeyEnvelope(File.ReadAllText(GetMasterKeyPath(username), Encoding.UTF8));
        if (envelope == null) throw new InvalidOperationException("Arquivo de chave mestre invalido.");

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
        finally { CryptographicOperations.ZeroMemory(plain); }
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
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private static byte[] DeriveAesKey(string passphrase, byte[] salt, int iterations)
    {
        return Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, AesKeySizeBytes);
    }

    private static string NormalizeUsername(string username)
    {
        var normalized = (username ?? string.Empty).Trim().ToLowerInvariant();
        // Sanitize path traversal characters to prevent writing outside .hps_keys directory
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
