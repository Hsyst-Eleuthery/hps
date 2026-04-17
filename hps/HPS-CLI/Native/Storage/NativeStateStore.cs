using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

namespace Hps.Cli.Native.Storage;

public sealed class NativeStateStore
{
    private static readonly byte[] StateMagic = Encoding.ASCII.GetBytes("HPSCLIST1");
    private const int AesNonceSize = 12;
    private const int AesTagSize = 16;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly NativePaths _paths;

    public NativeStateStore(NativePaths paths)
    {
        _paths = paths;
    }

    public NativeState Load()
    {
        _paths.EnsureDirectories();
        if (!File.Exists(_paths.StateFile))
        {
            return new NativeState();
        }

        var data = File.ReadAllBytes(_paths.StateFile);
        if (LooksEncrypted(data))
        {
            return new NativeState();
        }
        var raw = Encoding.UTF8.GetString(data);
        var state = DeserializeState(raw);
        state.History ??= [];
        return state;
    }

    public NativeState LoadWithStorageKey(byte[] storageKey)
    {
        _paths.EnsureDirectories();
        if (!File.Exists(_paths.StateFile))
        {
            return new NativeState();
        }

        var data = File.ReadAllBytes(_paths.StateFile);
        if (!LooksEncrypted(data))
        {
            var plain = Encoding.UTF8.GetString(data);
            var statePlain = DeserializeState(plain);
            statePlain.History ??= [];
            return statePlain;
        }

        var plainJson = DecryptState(data, storageKey);
        var state = DeserializeState(plainJson);
        state.KnownServers ??= [];
        state.Stats ??= new(StringComparer.OrdinalIgnoreCase);
        state.ContentCache ??= new(StringComparer.OrdinalIgnoreCase);
        state.DdnsCache ??= new(StringComparer.OrdinalIgnoreCase);
        state.ContractsCache ??= new(StringComparer.OrdinalIgnoreCase);
        state.VoucherCache ??= new(StringComparer.OrdinalIgnoreCase);
        state.MessageContacts ??= new(StringComparer.OrdinalIgnoreCase);
        state.IncomingMessageRequests ??= [];
        state.OutgoingMessageRequests ??= [];
        state.MessageRecords ??= new(StringComparer.OrdinalIgnoreCase);
        state.History ??= [];
        return state;
    }

    public void Save(NativeState state)
    {
        _paths.EnsureDirectories();
        var raw = JsonSerializer.Serialize(state, JsonOptions);
        File.WriteAllText(_paths.StateFile, raw);
    }

    public void SaveEncrypted(NativeState state, byte[] storageKey)
    {
        _paths.EnsureDirectories();
        var raw = JsonSerializer.Serialize(state, JsonOptions);
        var enc = EncryptState(raw, storageKey);
        File.WriteAllBytes(_paths.StateFile, enc);
    }

    private static NativeState DeserializeState(string raw)
    {
        var state = JsonSerializer.Deserialize<NativeState>(raw, JsonOptions) ?? new NativeState();
        state.KnownServers ??= [];
        state.Stats ??= new(StringComparer.OrdinalIgnoreCase);
        state.ContentCache ??= new(StringComparer.OrdinalIgnoreCase);
        state.DdnsCache ??= new(StringComparer.OrdinalIgnoreCase);
        state.ContractsCache ??= new(StringComparer.OrdinalIgnoreCase);
        state.VoucherCache ??= new(StringComparer.OrdinalIgnoreCase);
        state.MessageContacts ??= new(StringComparer.OrdinalIgnoreCase);
        state.IncomingMessageRequests ??= [];
        state.OutgoingMessageRequests ??= [];
        state.MessageRecords ??= new(StringComparer.OrdinalIgnoreCase);
        state.History ??= [];
        return state;
    }

    private static bool LooksEncrypted(byte[] data)
    {
        if (data.Length < StateMagic.Length + AesNonceSize + AesTagSize)
        {
            return false;
        }
        for (var i = 0; i < StateMagic.Length; i++)
        {
            if (data[i] != StateMagic[i])
            {
                return false;
            }
        }
        return true;
    }

    private static byte[] EncryptState(string json, byte[] key)
    {
        var plain = Encoding.UTF8.GetBytes(json);
        var nonce = RandomNumberGenerator.GetBytes(AesNonceSize);
        var tag = new byte[AesTagSize];
        var cipher = new byte[plain.Length];
        try
        {
            using (var aes = new AesGcm(key, AesTagSize))
            {
                aes.Encrypt(nonce, plain, cipher, tag);
            }
            var output = new byte[StateMagic.Length + nonce.Length + tag.Length + cipher.Length];
            Buffer.BlockCopy(StateMagic, 0, output, 0, StateMagic.Length);
            Buffer.BlockCopy(nonce, 0, output, StateMagic.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, output, StateMagic.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(cipher, 0, output, StateMagic.Length + nonce.Length + tag.Length, cipher.Length);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(cipher);
        }
    }

    private static string DecryptState(byte[] input, byte[] key)
    {
        var nonce = new byte[AesNonceSize];
        var tag = new byte[AesTagSize];
        var cipherOffset = StateMagic.Length + AesNonceSize + AesTagSize;
        var cipher = new byte[input.Length - cipherOffset];
        var plain = new byte[cipher.Length];
        try
        {
            Buffer.BlockCopy(input, StateMagic.Length, nonce, 0, AesNonceSize);
            Buffer.BlockCopy(input, StateMagic.Length + AesNonceSize, tag, 0, AesTagSize);
            Buffer.BlockCopy(input, cipherOffset, cipher, 0, cipher.Length);
            using var aes = new AesGcm(key, AesTagSize);
            aes.Decrypt(nonce, cipher, tag, plain);
            return Encoding.UTF8.GetString(plain);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}
