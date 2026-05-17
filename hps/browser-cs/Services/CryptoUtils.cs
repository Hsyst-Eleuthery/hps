using System.Security.Cryptography;
using System.Text;
using System.Numerics;

namespace HpsBrowser.Services;

public static class CryptoUtils
{
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
        catch
        {
            // Ignore invalid base64.
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

    public static string DecryptOaepBase64(RSA privateKey, string ciphertextBase64, string label = "hps-dkvhps")
    {
        if (string.IsNullOrWhiteSpace(ciphertextBase64))
        {
            return string.Empty;
        }

        try
        {
            var ciphertext = Convert.FromBase64String(ciphertextBase64);
            var plain = privateKey.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            return string.Empty;
        }
    }

    public static byte[] SignPayload(RSA privateKey, string payload)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        return privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static byte[] SignPayloadPssMax(RSA privateKey, string payload)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        var hash = SHA256.HashData(data);
        var padding = GetPssPaddingMax(privateKey, HashAlgorithmName.SHA256);
        return privateKey.SignHash(hash, HashAlgorithmName.SHA256, padding);
    }

    public static bool VerifySignature(RSA publicKey, string payload, byte[] signature)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        return publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static bool VerifySignaturePssMax(RSA publicKey, string payload, byte[] signature)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        var hash = SHA256.HashData(data);
        var padding = GetPssPaddingMax(publicKey, HashAlgorithmName.SHA256);
        return publicKey.VerifyHash(hash, signature, HashAlgorithmName.SHA256, padding);
    }

    public static bool VerifySignaturePssMax(RSA publicKey, byte[] payload, byte[] signature)
    {
        var hash = SHA256.HashData(payload);
        var padding = GetPssPaddingMax(publicKey, HashAlgorithmName.SHA256);
        return publicKey.VerifyHash(hash, signature, HashAlgorithmName.SHA256, padding);
    }

    public static bool VerifySignaturePssHashLen(RSA publicKey, string payload, byte[] signature)
    {
        var data = Encoding.UTF8.GetBytes(payload);
        var hash = SHA256.HashData(data);
        var padding = CreatePssPadding(GetHashSize(HashAlgorithmName.SHA256));
        return publicKey.VerifyHash(hash, signature, HashAlgorithmName.SHA256, padding);
    }

    public static bool VerifySignaturePssAuto(RSA publicKey, string payload, byte[] signature)
    {
        try
        {
            var data = Encoding.UTF8.GetBytes(payload);
            var mHash = SHA256.HashData(data);
            var hashLen = mHash.Length;

            var parameters = publicKey.ExportParameters(false);
            if (parameters.Modulus is null || parameters.Exponent is null)
            {
                return false;
            }

            var modBits = parameters.Modulus.Length * 8;
            var emBits = modBits - 1;
            var emLen = (emBits + 7) / 8;
            if (signature.Length != parameters.Modulus.Length)
            {
                return false;
            }

            var sigInt = new BigInteger(signature, isUnsigned: true, isBigEndian: true);
            var modInt = new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true);
            var expInt = new BigInteger(parameters.Exponent, isUnsigned: true, isBigEndian: true);
            var emInt = BigInteger.ModPow(sigInt, expInt, modInt);
            var em = emInt.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (em.Length < emLen)
            {
                var padded = new byte[emLen];
                Buffer.BlockCopy(em, 0, padded, emLen - em.Length, em.Length);
                em = padded;
            }
            if (em.Length != emLen)
            {
                return false;
            }

            if (em[^1] != 0xBC)
            {
                return false;
            }

            var hLen = hashLen;
            if (emLen < hLen+2)
            {
                return false;
            }

            var maskedDbLen = emLen - hLen - 1;
            var maskedDb = new byte[maskedDbLen];
            Buffer.BlockCopy(em, 0, maskedDb, 0, maskedDbLen);
            var h = new byte[hLen];
            Buffer.BlockCopy(em, maskedDbLen, h, 0, hLen);

            var leftBits = 8 * emLen - emBits;
            if (leftBits > 0)
            {
                var mask = (byte)(0xFF >> leftBits);
                if ((maskedDb[0] & ~mask) != 0)
                {
                    return false;
                }
            }

            var dbMask = Mgf1(h, maskedDbLen);
            var db = new byte[maskedDbLen];
            for (var i = 0; i < maskedDbLen; i++)
            {
                db[i] = (byte)(maskedDb[i] ^ dbMask[i]);
            }

            if (leftBits > 0)
            {
                var mask = (byte)(0xFF >> leftBits);
                db[0] &= mask;
            }

            var index = 0;
            while (index < db.Length && db[index] == 0x00)
            {
                index++;
            }
            if (index >= db.Length || db[index] != 0x01)
            {
                return false;
            }

            var salt = db[(index + 1)..];
            var mPrime = new byte[8 + hLen + salt.Length];
            Buffer.BlockCopy(mHash, 0, mPrime, 8, hLen);
            Buffer.BlockCopy(salt, 0, mPrime, 8 + hLen, salt.Length);
            var hPrime = SHA256.HashData(mPrime);
            return CryptographicOperations.FixedTimeEquals(h, hPrime);
        }
        catch
        {
            return false;
        }
    }

    public static bool VerifySignature(RSA publicKey, byte[] payload, byte[] signature)
    {
        return publicKey.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    private static RSASignaturePadding GetPssPaddingMax(RSA key, HashAlgorithmName hashAlgorithm)
    {
        var hashSize = GetHashSize(hashAlgorithm);
        var modulusSize = key.KeySize / 8;
        var maxSalt = Math.Max(0, modulusSize - hashSize - 2);
        var createPss = typeof(RSASignaturePadding).GetMethod("CreatePss", new[] { typeof(int) });
        if (createPss is not null)
        {
            try
            {
                return (RSASignaturePadding)createPss.Invoke(null, new object[] { maxSalt })!;
            }
            catch
            {
                // Fall back to default.
            }
        }
        return RSASignaturePadding.Pss;
    }

    private static RSASignaturePadding CreatePssPadding(int saltLength)
    {
        var createPss = typeof(RSASignaturePadding).GetMethod("CreatePss", new[] { typeof(int) });
        if (createPss is not null)
        {
            try
            {
                return (RSASignaturePadding)createPss.Invoke(null, new object[] { saltLength })!;
            }
            catch
            {
                // Ignore.
            }
        }
        return RSASignaturePadding.Pss;
    }

    private static int GetHashSize(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            return 32;
        }
        if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            return 48;
        }
        if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            return 64;
        }
        if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
            return 20;
        }
        return 32;
    }

    private static byte[] Mgf1(byte[] seed, int maskLen)
    {
        var hLen = 32;
        var count = (int)Math.Ceiling(maskLen / (double)hLen);
        var output = new byte[maskLen];
        var counter = new byte[4];
        var offset = 0;
        for (var i = 0; i < count; i++)
        {
            counter[0] = (byte)((i >> 24) & 0xFF);
            counter[1] = (byte)((i >> 16) & 0xFF);
            counter[2] = (byte)((i >> 8) & 0xFF);
            counter[3] = (byte)(i & 0xFF);
            var data = new byte[seed.Length + 4];
            Buffer.BlockCopy(seed, 0, data, 0, seed.Length);
            Buffer.BlockCopy(counter, 0, data, seed.Length, 4);
            var hash = SHA256.HashData(data);
            var toCopy = Math.Min(hLen, maskLen - offset);
            Buffer.BlockCopy(hash, 0, output, offset, toCopy);
            offset += toCopy;
        }
        return output;
    }
}
