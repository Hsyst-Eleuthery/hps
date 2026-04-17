using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Hps.Cli.Native.Crypto;

public sealed class HpsKeyVault
{
    private const int AesKeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 210000;

    private readonly string _cryptoDir;

    public HpsKeyVault(string cryptoDir)
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

    public bool AnyUserKeyMaterialExists() =>
        Directory.EnumerateFiles(_cryptoDir, "*.masterkey.hps", SearchOption.TopDirectoryOnly).Any();

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

    public (RSA loginPrivateKey, string loginPublicKeyPem, string localPublicKeyPem) LoadExistingKeys(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);
        if (!UserKeyMaterialExists(normalized))
        {
            throw new InvalidOperationException("Conjunto de chaves local inexistente.");
        }

        var masterKey = DecryptMasterKey(normalized, passphrase);
        try
        {
            var loginEnvelope = JsonSerializer.Deserialize<EncryptedKeyEnvelope>(File.ReadAllText(GetLoginKeyPath(normalized), Encoding.UTF8))
                ?? throw new InvalidOperationException("Arquivo de chave de login inválido.");
            var localEnvelope = JsonSerializer.Deserialize<EncryptedKeyEnvelope>(File.ReadAllText(GetLocalKeyPath(normalized), Encoding.UTF8))
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
        var json = JsonSerializer.Serialize(bundle);
        File.WriteAllText(outputPath, json, Encoding.UTF8);
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
        var bundle = JsonSerializer.Deserialize<KeyBundleEnvelope>(raw)
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

    public void ImportLegacyLoginPrivateKey(string username, string passphrase, string loginPrivateKeyPem)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);
        if (string.IsNullOrWhiteSpace(loginPrivateKeyPem))
        {
            throw new InvalidOperationException("Conteudo PEM vazio.");
        }

        using var loginKey = RSA.Create();
        loginKey.ImportFromPem(loginPrivateKeyPem.ToCharArray());
        var loginPublicPem = loginKey.ExportSubjectPublicKeyInfoPem();

        using var localKey = RSA.Create(4096);
        var localPrivatePem = localKey.ExportRSAPrivateKeyPem();
        var localPublicPem = localKey.ExportSubjectPublicKeyInfoPem();

        var masterPath = GetMasterKeyPath(normalized);
        var loginPath = GetLoginKeyPath(normalized);
        var localPath = GetLocalKeyPath(normalized);
        var oldMaster = File.Exists(masterPath) ? File.ReadAllBytes(masterPath) : null;
        var oldLogin = File.Exists(loginPath) ? File.ReadAllBytes(loginPath) : null;
        var oldLocal = File.Exists(localPath) ? File.ReadAllBytes(localPath) : null;
        var masterKey = RandomNumberGenerator.GetBytes(AesKeySizeBytes);
        try
        {
            WriteMasterKeyFile(normalized, passphrase, masterKey);
            WriteEncryptedKeyFile(loginPath, "login", loginPrivateKeyPem, loginPublicPem, masterKey);
            WriteEncryptedKeyFile(localPath, "local", localPrivatePem, localPublicPem, masterKey);

            var test = DeriveLocalStorageKey(normalized, passphrase);
            CryptographicOperations.ZeroMemory(test);
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
            CryptographicOperations.ZeroMemory(masterKey);
            ZeroOptional(oldMaster);
            ZeroOptional(oldLogin);
            ZeroOptional(oldLocal);
        }
    }

    public byte[] DeriveLocalStorageKey(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        ValidateInputs(normalized, passphrase);

        var masterKey = DecryptMasterKey(normalized, passphrase);
        try
        {
            var localEnvelope = JsonSerializer.Deserialize<EncryptedKeyEnvelope>(File.ReadAllText(GetLocalKeyPath(normalized), Encoding.UTF8))
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

            File.WriteAllText(GetMasterKeyPath(username), JsonSerializer.Serialize(envelope), Encoding.UTF8);
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

            File.WriteAllText(path, JsonSerializer.Serialize(envelope), Encoding.UTF8);
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
        var envelope = JsonSerializer.Deserialize<MasterKeyEnvelope>(File.ReadAllText(GetMasterKeyPath(username), Encoding.UTF8))
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

    private static byte[] DeriveAesKey(string passphrase, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, AesKeySizeBytes);

    private static string NormalizeUsername(string username) =>
        (username ?? string.Empty).Trim().ToLowerInvariant();

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
