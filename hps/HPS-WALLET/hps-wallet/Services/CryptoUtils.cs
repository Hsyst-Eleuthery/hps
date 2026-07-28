using System.Security.Cryptography;
using System.Text;

namespace HpsWallet.Services;

public static class CryptoUtils
{
    public static string NormalizePublicKey(string? keyValue)
    {
        if (string.IsNullOrWhiteSpace(keyValue)) return string.Empty;
        var trimmed = keyValue.Trim();
        if (trimmed.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase)) return trimmed;
        try
        {
            var decoded = Convert.FromBase64String(trimmed);
            var decodedText = Encoding.UTF8.GetString(decoded).Trim();
            if (decodedText.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase)) return decodedText;
        }
        catch { }
        return trimmed;
    }

    public static RSA? LoadPublicKey(string publicKeyValue)
    {
        var normalized = NormalizePublicKey(publicKeyValue);
        if (string.IsNullOrWhiteSpace(normalized)) return null;
        try
        {
            var der = DecodeDerFromPem(normalized);
            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(der, out _);
            return rsa;
        }
        catch { return null; }
    }

    private static byte[] DecodeDerFromPem(string pem)
    {
        if (pem.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
        {
            var b64 = pem
                .Replace("-----BEGIN PUBLIC KEY-----", "")
                .Replace("-----END PUBLIC KEY-----", "")
                .Replace("-----BEGIN CERTIFICATE-----", "")
                .Replace("-----END CERTIFICATE-----", "")
                .Replace("\r", "")
                .Replace("\n", "")
                .Trim();
            return Convert.FromBase64String(b64);
        }
        return Convert.FromBase64String(pem);
    }

    public static ECDsa? LoadECDsaPublicKey(string publicKeyValue)
    {
        var normalized = NormalizePublicKey(publicKeyValue);
        if (string.IsNullOrWhiteSpace(normalized)) return null;
        try
        {
            var der = DecodeDerFromPem(normalized);
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(der, out _);
            return ecdsa;
        }
        catch { return null; }
    }

    public static bool VerifyServerSignature(string serverPem, string serverPublicKeyB64, string challenge, byte[] signatureBytes)
    {
        var data = Encoding.UTF8.GetBytes(challenge);
        var hash = SHA256.HashData(data);

        using var ecdsaKey = LoadECDsaPublicKey(serverPem) ?? LoadECDsaPublicKey(serverPublicKeyB64);
        if (ecdsaKey != null)
        {
            try { if (ecdsaKey.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256)) return true; } catch { }
            try { if (ecdsaKey.VerifyHash(hash, signatureBytes)) return true; } catch { }
            try
            {
                var p1363Sig = DerToIeeeP1363(signatureBytes, 32);
                if (p1363Sig != null)
                {
                    if (ecdsaKey.VerifyData(data, p1363Sig, HashAlgorithmName.SHA256)) return true;
                    if (ecdsaKey.VerifyHash(hash, p1363Sig)) return true;
                }
            }
            catch { }
        }

        using var rsaKey = LoadPublicKey(serverPem) ?? LoadPublicKey(serverPublicKeyB64);
        if (rsaKey != null)
        {
            try { if (rsaKey.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) return true; } catch { }
        }
        return false;
    }

    private static byte[]? DerToIeeeP1363(byte[] derSig, int keySizeBytes)
    {
        var idx = 0;
        if (idx >= derSig.Length || derSig[idx++] != 0x30) return null;
        _ = derSig[idx++];

        if (idx >= derSig.Length || derSig[idx++] != 0x02) return null;
        var rLen = derSig[idx++];
        var rBytes = new byte[keySizeBytes];
        var rCopyLen = Math.Min(rLen, keySizeBytes);
        Array.Copy(derSig, idx + Math.Max(0, rLen - keySizeBytes), rBytes, Math.Max(0, keySizeBytes - rLen), rCopyLen);
        idx += rLen;

        if (idx >= derSig.Length || derSig[idx++] != 0x02) return null;
        var sLen = derSig[idx++];
        var sBytes = new byte[keySizeBytes];
        var sCopyLen = Math.Min(sLen, keySizeBytes);
        Array.Copy(derSig, idx + Math.Max(0, sLen - keySizeBytes), sBytes, Math.Max(0, keySizeBytes - sLen), sCopyLen);

        var result = new byte[keySizeBytes * 2];
        Array.Copy(rBytes, 0, result, 0, keySizeBytes);
        Array.Copy(sBytes, 0, result, keySizeBytes, keySizeBytes);
        return result;
    }

    public static byte[] SignPayload(RSA privateKey, string payload)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        try
        {
            return privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (CryptographicException)
        {
            try
            {
                var pars = privateKey.ExportParameters(true);
                using var fresh = RSA.Create();
                fresh.ImportParameters(pars);
                return fresh.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }
            catch (CryptographicException)
            {
                return privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }

    public static bool VerifySignature(RSA publicKey, string payload, byte[] signature)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        return publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
