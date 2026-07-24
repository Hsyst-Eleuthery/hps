using System.Security.Cryptography;

namespace HpsWallet.Services;

public static class SessionState
{
    private static readonly object _lock = new();
    public static HpsSocketService Socket { get; set; } = new();
    public static HpsServerService Server { get; set; } = new();
    
    // C5 FIX: Private key is now private with secure accessor
    private static RSA? _privateKey;
    
    public static RSA? GetPrivateKey()
    {
        lock (_lock) { return _privateKey; }
    }
    
    public static void SetPrivateKey(RSA? value)
    {
        lock (_lock)
        {
            if (_privateKey != null && _privateKey != value)
            {
                // C5 FIX: Zero private key material before dispose
                try
                {
                    var keyData = _privateKey.ExportRSAPrivateKey();
                    CryptographicOperations.ZeroMemory(keyData);
                }
                catch { /* Key may not be exportable */ }
                _privateKey.Dispose();
                _privateKey = null;
            }
            _privateKey = value;
        }
    }
    
    public static void ClearPrivateKey()
    {
        lock (_lock)
        {
            if (_privateKey != null)
            {
                // C5 FIX: Zero private key material before dispose
                try
                {
                    var keyData = _privateKey.ExportRSAPrivateKey();
                    CryptographicOperations.ZeroMemory(keyData);
                }
                catch { /* Key may not be exportable */ }
                _privateKey.Dispose();
                _privateKey = null;
            }
        }
    }
    
    private static string _username = string.Empty;
    public static string Username
    {
        get { lock (_lock) { return _username; } }
        set { lock (_lock) { _username = value; } }
    }
    public static string PublicKeyPem { get; set; } = string.Empty;
    public static string ServerAddress { get; set; } = string.Empty;
    public static bool UseSsl { get; set; }
    private static bool _isLoggedIn;
    public static bool IsLoggedIn
    {
        get { lock (_lock) { return _isLoggedIn; } }
        set { lock (_lock) { _isLoggedIn = value; } }
    }
    public static string PendingUsageContractText { get; set; } = string.Empty;
}
