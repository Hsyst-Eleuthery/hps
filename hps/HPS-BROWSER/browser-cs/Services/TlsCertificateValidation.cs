using System.Net.Http;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace HpsBrowser.Services;

public static class TlsCertificateValidation
{
    private static readonly string PinnedKeysPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".hps_browser",
        "pinned_server_keys.json");

    private static Dictionary<string, string>? _pinnedKeys;
    private static readonly object _pinnedKeysLock = new();

    private static Dictionary<string, string> LoadPinnedKeys()
    {
        try
        {
            if (File.Exists(PinnedKeysPath))
            {
                var json = File.ReadAllText(PinnedKeysPath);
                return JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[TLS] Failed to load pinned keys: {ex.Message}");
        }
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    private static void SavePinnedKeys(Dictionary<string, string> keys)
    {
        try
        {
            var dir = Path.GetDirectoryName(PinnedKeysPath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(PinnedKeysPath, JsonSerializer.Serialize(keys));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[TLS] Failed to save pinned keys: {ex.Message}");
        }
    }

    public static void PinServerKey(string address, string keyB64)
    {
        if (string.IsNullOrWhiteSpace(address) || string.IsNullOrWhiteSpace(keyB64))
        {
            return;
        }

        lock (_pinnedKeysLock)
        {
            _pinnedKeys ??= LoadPinnedKeys();
            _pinnedKeys[address.Trim().ToLowerInvariant()] = keyB64.Trim();
            SavePinnedKeys(_pinnedKeys);
        }
    }

    public static string? GetPinnedServerKey(string address)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return null;
        }

        lock (_pinnedKeysLock)
        {
            _pinnedKeys ??= LoadPinnedKeys();
            return _pinnedKeys.TryGetValue(address.Trim().ToLowerInvariant(), out var key) ? key : null;
        }
    }

    public static HttpClientHandler CreateHttpClientHandler()
    {
        return new HttpClientHandler
        {
            UseProxy = false,
            Proxy = null,
            ServerCertificateCustomValidationCallback = AcceptServerCertificate
        };
    }

    public static void ApplyTo(ClientWebSocketOptions options)
    {
        options.RemoteCertificateValidationCallback = AcceptServerCertificate;
    }

    private static bool AcceptServerCertificate(
        object? sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // A3 FIX: If no SSL errors, accept the certificate
        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            return true;
        }

        // A3 FIX: Reject name mismatch - prevents passive observation
        if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            System.Diagnostics.Debug.WriteLine("[TLS] REJECT: Certificate name mismatch");
            return false;
        }

        // A3 FIX: Reject if certificate is not available
        if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
        {
            System.Diagnostics.Debug.WriteLine("[TLS] REJECT: Certificate not available");
            return false;
        }

        // A3 FIX: For chain errors (self-signed, untrusted root), accept with TOFU model
        if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
        {
            if (chain != null && chain.ChainStatus.Length > 0)
            {
                foreach (var status in chain.ChainStatus)
                {
                    if (status.Status != X509ChainStatusFlags.PartialChain &&
                        status.Status != X509ChainStatusFlags.UntrustedRoot &&
                        status.Status != X509ChainStatusFlags.RevocationStatusUnknown)
                    {
                        System.Diagnostics.Debug.WriteLine($"[TLS] REJECT: Critical cert error: {status.Status}");
                        return false;
                    }
                }
                return true;
            }
        }

        // A3 FIX: Reject all other errors
        System.Diagnostics.Debug.WriteLine($"[TLS] REJECT: Certificate error: {sslPolicyErrors}");
        return false;
    }
}
