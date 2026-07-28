namespace HpsWallet.Services;

/// <summary>
/// Secure storage helper for sensitive data.
/// Uses SecureStorage on Android/iOS, falls back to Preferences on other platforms.
/// </summary>
public static class SecureStorageHelper
{
    private const string CertHashKey = "wallet_server_cert_hash_secure";
    private const string ClientIdKey = "wallet_client_id_secure";
    private const string UsernameKey = "wallet_username_secure";

    public static async Task SetCertHashAsync(string hash)
    {
        try
        {
            await SecureStorage.SetAsync(CertHashKey, hash);
        }
        catch
        {
            Preferences.Set("wallet_server_cert_hash", hash);
        }
    }

    public static async Task<string> GetCertHashAsync()
    {
        try
        {
            return await SecureStorage.GetAsync(CertHashKey) ?? string.Empty;
        }
        catch
        {
            return Preferences.Get("wallet_server_cert_hash", string.Empty);
        }
    }

    public static async Task SetClientIdAsync(string clientId)
    {
        try
        {
            await SecureStorage.SetAsync(ClientIdKey, clientId);
        }
        catch
        {
            Preferences.Set("wallet_client_id", clientId);
        }
    }

    public static async Task<string> GetClientIdAsync()
    {
        try
        {
            return await SecureStorage.GetAsync(ClientIdKey) ?? string.Empty;
        }
        catch
        {
            return Preferences.Get("wallet_client_id", string.Empty);
        }
    }

    public static async Task SetUsernameAsync(string username)
    {
        try
        {
            await SecureStorage.SetAsync(UsernameKey, username);
        }
        catch
        {
            Preferences.Set("wallet_username", username);
        }
    }

    public static async Task<string> GetUsernameAsync()
    {
        try
        {
            return await SecureStorage.GetAsync(UsernameKey) ?? string.Empty;
        }
        catch
        {
            return Preferences.Get("wallet_username", string.Empty);
        }
    }
}
