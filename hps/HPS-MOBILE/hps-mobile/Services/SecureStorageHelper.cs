namespace HpsMobile.Services;

/// <summary>
/// Secure storage helper for sensitive data.
/// Uses SecureStorage on Android/iOS, falls back to Preferences on other platforms.
/// </summary>
public static class SecureStorageHelper
{
    private const string UsernameKey = "username_secure";
    private const string ClientIdKey = "client_id_secure";

    public static async Task SetUsernameAsync(string username)
    {
        try
        {
            await SecureStorage.SetAsync(UsernameKey, username);
        }
        catch
        {
            Preferences.Set("username", username);
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
            return Preferences.Get("username", string.Empty);
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
            Preferences.Set("client_id", clientId);
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
            return Preferences.Get("client_id", string.Empty);
        }
    }
}
