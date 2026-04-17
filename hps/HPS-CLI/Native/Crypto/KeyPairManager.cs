using System.Security.Cryptography;
using System.Text;

namespace Hps.Cli.Native.Crypto;

public sealed class KeyPairManager : IDisposable
{
    private readonly Native.Storage.NativePaths _paths;
    private readonly HpsKeyVault _vault;

    private RSA? _loginPrivateKey;
    private string _loginPublicPem = string.Empty;
    private string _localPublicPem = string.Empty;
    private byte[]? _storageKey;
    private string _activeUsername = string.Empty;

    public KeyPairManager(Native.Storage.NativePaths paths)
    {
        _paths = paths;
        _vault = new HpsKeyVault(_paths.RootDir);
    }

    public string ActiveUsername => _activeUsername;
    public bool IsUnlocked => _loginPrivateKey is not null && _storageKey is not null;

    public bool UserKeyMaterialExists(string username) => _vault.UserKeyMaterialExists(username);
    public bool AnyUserKeyMaterialExists() => _vault.AnyUserKeyMaterialExists();

    public void ExportEncryptedKeyBundle(string username, string outputPath) =>
        _vault.ExportEncryptedKeyBundle(username, outputPath);

    public void ImportEncryptedKeyBundle(string username, string inputPath, string passphrase) =>
        _vault.ImportEncryptedKeyBundle(username, inputPath, passphrase);

    public void ImportLegacyPrivateKeyPem(string username, string passphrase, string privateKeyPem) =>
        _vault.ImportLegacyLoginPrivateKey(username, passphrase, privateKeyPem);

    public KeyPairState UnlockOrCreate(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new InvalidOperationException("Usuário obrigatório.");
        }
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new InvalidOperationException("Senha obrigatória.");
        }

        ClearUnlocked();
        var (loginPrivate, loginPublicPem, localPublicPem) = _vault.LoadOrCreateKeys(normalized, passphrase);
        _loginPrivateKey = loginPrivate;
        _loginPublicPem = loginPublicPem;
        _localPublicPem = localPublicPem;
        _storageKey = _vault.DeriveLocalStorageKey(normalized, passphrase);
        _activeUsername = normalized;
        return new KeyPairState(loginPublicPem, localPublicPem, "vault");
    }

    public KeyPairState UnlockExisting(string username, string passphrase)
    {
        var normalized = NormalizeUsername(username);
        if (!UserKeyMaterialExists(normalized))
        {
            throw new InvalidOperationException("Conjunto de chaves não encontrado para o usuário.");
        }

        ClearUnlocked();
        var (loginPrivate, loginPublicPem, localPublicPem) = _vault.LoadExistingKeys(normalized, passphrase);
        _loginPrivateKey = loginPrivate;
        _loginPublicPem = loginPublicPem;
        _localPublicPem = localPublicPem;
        _storageKey = _vault.DeriveLocalStorageKey(normalized, passphrase);
        _activeUsername = normalized;
        return new KeyPairState(loginPublicPem, localPublicPem, "vault");
    }

    public string ExportPublicKeyBase64()
    {
        EnsureUnlocked();
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(_loginPublicPem));
    }

    public string ExportLoginPrivateKeyPem()
    {
        EnsureUnlocked();
        return _loginPrivateKey!.ExportRSAPrivateKeyPem();
    }

    public byte[] SignPayload(string payloadUtf8)
    {
        EnsureUnlocked();
        var data = Encoding.UTF8.GetBytes(payloadUtf8);
        return _loginPrivateKey!.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public byte[] SignBytes(byte[] data)
    {
        EnsureUnlocked();
        return _loginPrivateKey!.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public string DecryptOaepBase64(string ciphertextBase64)
    {
        EnsureUnlocked();
        if (string.IsNullOrWhiteSpace(ciphertextBase64))
        {
            return string.Empty;
        }
        try
        {
            var ciphertext = Convert.FromBase64String(ciphertextBase64);
            var plain = _loginPrivateKey!.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            return string.Empty;
        }
    }

    public bool VerifySignature(string payloadUtf8, byte[] signature, string publicKeyPemOrBase64)
    {
        var data = Encoding.UTF8.GetBytes(payloadUtf8);
        return VerifySignature(data, signature, publicKeyPemOrBase64);
    }

    public bool VerifySignature(byte[] payload, byte[] signature, string publicKeyPemOrBase64)
    {
        var pem = NormalizePublicPem(publicKeyPemOrBase64);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public byte[] GetStorageKeyCopy()
    {
        EnsureUnlocked();
        return _storageKey!.ToArray();
    }

    public void Dispose()
    {
        ClearUnlocked();
    }

    public void Lock() => ClearUnlocked();

    private void EnsureUnlocked()
    {
        if (!IsUnlocked)
        {
            throw new InvalidOperationException("Cofre criptográfico não desbloqueado. Use `keys unlock`.");
        }
    }

    private void ClearUnlocked()
    {
        _loginPrivateKey?.Dispose();
        _loginPrivateKey = null;
        _loginPublicPem = string.Empty;
        _localPublicPem = string.Empty;
        _activeUsername = string.Empty;
        if (_storageKey is not null)
        {
            CryptographicOperations.ZeroMemory(_storageKey);
            _storageKey = null;
        }
    }

    private static string NormalizeUsername(string username) =>
        (username ?? string.Empty).Trim().ToLowerInvariant();

    private static string NormalizePublicPem(string publicKeyPemOrBase64)
    {
        if (publicKeyPemOrBase64.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
        {
            return publicKeyPemOrBase64;
        }
        var bytes = Convert.FromBase64String(publicKeyPemOrBase64);
        return Encoding.UTF8.GetString(bytes);
    }
}

public readonly record struct KeyPairState(string LoginPublicKeyPem, string LocalPublicKeyPem, string Source);
