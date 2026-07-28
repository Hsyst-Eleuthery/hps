using System.Security.Cryptography;
using System.Text;

namespace HpsBrowser.Services;

public static class CryptoUtils
{
    public static string LastVerifyDiag { get; private set; } = "";
    public static string NormalizePublicKey(string? keyValue)
    {
        if (string.IsNullOrWhiteSpace(keyValue))
        {
            return string.Empty;
        }

        var trimmed = keyValue.Trim();
        if (trimmed.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed;
        }

        try
        {
            var decoded = Convert.FromBase64String(trimmed);
            var decodedText = Encoding.UTF8.GetString(decoded).Trim();
            if (decodedText.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
            {
                return decodedText;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[Crypto] Public key normalization failed: {ex.Message}");
        }

        return trimmed;
    }

    public static RSA? LoadPublicKey(string publicKeyValue)
    {
        var normalized = NormalizePublicKey(publicKeyValue);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }

        try
        {
            var rsa = RSA.Create();
            if (normalized.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
            {
                rsa.ImportFromPem(normalized.ToCharArray());
                return rsa;
            }

            var decoded = Convert.FromBase64String(normalized);
            rsa.ImportSubjectPublicKeyInfo(decoded, out _);
            return rsa;
        }
        catch
        {
            return null;
        }
    }

    public static ECDsa? LoadECDsaPublicKey(string publicKeyValue)
    {
        var normalized = NormalizePublicKey(publicKeyValue);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }

        // Method 1: ImportFromPem
        try
        {
            var ecdsa = ECDsa.Create();
            if (normalized.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
            {
                ecdsa.ImportFromPem(normalized.ToCharArray());
                return ecdsa;
            }

            var decoded = Convert.FromBase64String(normalized);
            ecdsa.ImportSubjectPublicKeyInfo(decoded, out _);
            return ecdsa;
        }
        catch
        {
            // Fall through to manual extraction
        }

        // Method 2: Manual PEM → DER extraction + ImportSubjectPublicKeyInfo
        try
        {
            var derBytes = ExtractSubjectPublicKeyInfoDer(normalized);
            if (derBytes != null)
            {
                var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(derBytes, out _);
                return ecdsa;
            }
        }
        catch
        {
            // Fall through
        }

        // Method 3: Try raw base64 decode of the original input
        try
        {
            var rawBytes = Convert.FromBase64String(publicKeyValue?.Trim() ?? "");
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(rawBytes, out _);
            return ecdsa;
        }
        catch
        {
            return null;
        }
    }

    private static byte[]? ExtractSubjectPublicKeyInfoDer(string pem)
    {
        const string header = "-----BEGIN PUBLIC KEY-----";
        const string footer = "-----END PUBLIC KEY-----";
        var startIdx = pem.IndexOf(header, StringComparison.Ordinal);
        var endIdx = pem.IndexOf(footer, StringComparison.Ordinal);
        if (startIdx < 0 || endIdx < 0 || endIdx <= startIdx) return null;
        var b64 = pem[(startIdx + header.Length)..endIdx]
            .Replace("\n", "").Replace("\r", "").Replace(" ", "");
        return Convert.FromBase64String(b64);
    }

    public static string DecryptOaepBase64(RSA privateKey, string ciphertextBase64, string label = "hps-dkvhps")
    {
        if (string.IsNullOrWhiteSpace(ciphertextBase64))
        {
            throw new ArgumentException("Ciphertext is empty.", nameof(ciphertextBase64));
        }

        var ciphertext = Convert.FromBase64String(ciphertextBase64);
        var plain = privateKey.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(plain);
    }

    public static byte[] DecryptOaepToBytes(RSA privateKey, string ciphertextBase64)
    {
        if (string.IsNullOrWhiteSpace(ciphertextBase64))
        {
            throw new ArgumentException("Ciphertext is empty.", nameof(ciphertextBase64));
        }

        var ciphertext = Convert.FromBase64String(ciphertextBase64);
        return privateKey.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] SignPayload(RSA privateKey, string payload)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        return privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static bool VerifySignature(RSA publicKey, string payload, byte[] signature)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        return publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static bool VerifySignature(RSA publicKey, byte[] payload, byte[] signature)
    {
        return publicKey.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static bool VerifyServerSignature(string serverPem, string serverPublicKeyB64, string challenge, byte[] signatureBytes)
    {
        var data = Encoding.UTF8.GetBytes(challenge);
        var hash = SHA256.HashData(data);

        // Try ECDsa verification (server uses ECDSA P-256)
        using var ecdsaKey = LoadECDsaPublicKey(serverPem) ?? LoadECDsaPublicKey(serverPublicKeyB64);
        if (ecdsaKey != null)
        {
            // Method 1: VerifyData (hashes internally)
            try
            {
                if (ecdsaKey.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256))
                    return true;
            }
            catch { }

            // Method 2: VerifyHash (pre-computed hash, DER signature)
            try
            {
                if (ecdsaKey.VerifyHash(hash, signatureBytes))
                    return true;
            }
            catch { }

            // Method 3: Try IEEE P1363 format (raw r||s, 64 bytes)
            try
            {
                if (signatureBytes.Length == 64)
                {
                    if (ecdsaKey.VerifyHash(hash, signatureBytes))
                        return true;
                }
            }
            catch { }

            // Method 4: Try converting DER to IEEE P1363 and verify
            try
            {
                var p1363Sig = DerToIeeeP1363(signatureBytes, 32);
                if (p1363Sig != null)
                {
                    // Try VerifyData (preferred - self-test proved it works)
                    if (ecdsaKey.VerifyData(data, p1363Sig, HashAlgorithmName.SHA256))
                        return true;
                    // Fallback to VerifyHash
                    if (ecdsaKey.VerifyHash(hash, p1363Sig))
                        return true;
                }
            }
            catch { }
        }

        // Fallback: try RSA verification (for backward compatibility)
        using var rsaKey = LoadPublicKey(serverPem) ?? LoadPublicKey(serverPublicKeyB64);
        if (rsaKey != null)
        {
            try
            {
                if (rsaKey.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                    return true;
            }
            catch { }
        }

        var sigHex = signatureBytes.Length >= 4 ? $"{signatureBytes[0]:X2}{signatureBytes[1]:X2}..{signatureBytes[^1]:X2}" : "?";
        var chalPreview = challenge.Length > 8 ? challenge[..8] : challenge;

        // Method 5: Self-test — verify .NET ECDsa works on this platform
        try
        {
            using var testKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var testData = Encoding.UTF8.GetBytes("self-test-challenge");
            var testSig = testKey.SignData(testData, HashAlgorithmName.SHA256);
            var testPem = testKey.ExportSubjectPublicKeyInfoPem();
            using var testLoad = ECDsa.Create();
            testLoad.ImportFromPem(testPem);
            var testOk = testLoad.VerifyData(testData, testSig, HashAlgorithmName.SHA256);
            LastVerifyDiag = $"selftest={(testOk ? "OK" : "FAIL")} ecdsa={ecdsaKey != null}({ecdsaKey?.KeySize}) sig={signatureBytes.Length}b[{sigHex}] chal={challenge.Length}b[{chalPreview}]";
            return false;
        }
        catch (Exception ex)
        {
            LastVerifyDiag = $"selftest=ERR({ex.Message[..Math.Min(40, ex.Message.Length)]}) sig={signatureBytes.Length}b[{sigHex}]";
            return false;
        }
    }

    private static byte[]? DerToIeeeP1363(byte[] derSig, int keySizeBytes)
    {
        // Parse DER SEQUENCE { INTEGER r, INTEGER s } → raw r||s
        // Handles leading zero bytes in DER integers (when high bit is set)
        var idx = 0;
        if (idx >= derSig.Length || derSig[idx++] != 0x30) return null;
        var seqLen = derSig[idx++];

        // Read r
        if (idx >= derSig.Length || derSig[idx++] != 0x02) return null;
        var rLen = derSig[idx++];
        var rBytes = new byte[keySizeBytes];
        var rOffset = Math.Max(0, keySizeBytes - rLen); // handles rLen > keySizeBytes (leading zero)
        var rCopyLen = Math.Min(rLen, keySizeBytes);
        var rSrcOffset = Math.Max(0, rLen - keySizeBytes);
        Array.Copy(derSig, idx + rSrcOffset, rBytes, rOffset, rCopyLen);
        idx += rLen;

        // Read s
        if (idx >= derSig.Length || derSig[idx++] != 0x02) return null;
        var sLen = derSig[idx++];
        var sBytes = new byte[keySizeBytes];
        var sOffset = Math.Max(0, keySizeBytes - sLen);
        var sCopyLen = Math.Min(sLen, keySizeBytes);
        var sSrcOffset = Math.Max(0, sLen - keySizeBytes);
        Array.Copy(derSig, idx + sSrcOffset, sBytes, sOffset, sCopyLen);
        idx += sLen;

        // Concatenate r||s
        var result = new byte[keySizeBytes * 2];
        Array.Copy(rBytes, 0, result, 0, keySizeBytes);
        Array.Copy(sBytes, 0, result, keySizeBytes, keySizeBytes);
        return result;
    }
}
