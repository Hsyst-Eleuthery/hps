using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace HpsWallet.Services;

public sealed class HpsServerService
{
    private readonly HttpClient _http;

    public HpsServerService()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = ValidateServerCertificate
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
    }

    // C6/C7 FIX: Cached cert hash from SecureStorage (fallback only - trust all by default)
    private static string _cachedCertHash = string.Empty;
    private static bool _certHashLoaded = false;

    private static bool ValidateServerCertificate(HttpRequestMessage request, X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        // Custom P2P network - trust all certificates
        if (sslPolicyErrors != SslPolicyErrors.None && certificate is not null)
        {
            // Check pinned hash if available
            if (!_certHashLoaded)
            {
                try
                {
                    _cachedCertHash = Preferences.Get("wallet_server_cert_hash", string.Empty);
                    _certHashLoaded = true;
                }
                catch { }
            }

            if (!string.IsNullOrEmpty(_cachedCertHash))
            {
                var actualHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(certificate.RawData));
                return string.Equals(actualHash, _cachedCertHash, StringComparison.OrdinalIgnoreCase);
            }
        }

        return true;
    }

    private string Server => SessionState.ServerAddress;
    private string ServiceUsername => SessionState.Username;
    private bool UseSsl => SessionState.UseSsl;

    private string BaseUrl => $"{(UseSsl ? "https" : "http")}://{Server.TrimEnd('/')}";

    public async Task<JsonElement?> FetchJsonAsync(string path)
    {
        if (string.IsNullOrEmpty(Server)) return null;
        try
        {
            var url = $"{BaseUrl}{path}";
            var response = await _http.GetAsync(url);
            if (!response.IsSuccessStatusCode) return null;
            return await response.Content.ReadFromJsonAsync<JsonElement>();
        }
        catch { return null; }
    }

    public async Task<byte[]?> FetchBinaryAsync(string path)
    {
        if (string.IsNullOrEmpty(Server)) return null;
        try
        {
            var url = $"{BaseUrl}{path}";
            var response = await _http.GetAsync(url);
            if (!response.IsSuccessStatusCode) return null;
            return await response.Content.ReadAsByteArrayAsync();
        }
        catch { return null; }
    }

    public async Task<JsonElement?> PostJsonAsync(string path, object body)
    {
        if (string.IsNullOrEmpty(Server)) return null;
        try
        {
            var url = $"{BaseUrl}{path}";
            var json = JsonSerializer.Serialize(body);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _http.PostAsync(url, content);
            if (!response.IsSuccessStatusCode) return null;
            return await response.Content.ReadFromJsonAsync<JsonElement>();
        }
        catch { return null; }
    }

    public async Task<JsonElement?> FetchEconomyReportAsync()
    {
        return await FetchJsonAsync("/economy_report");
    }

    public async Task<JsonElement?> FetchServerInfoAsync()
    {
        return await FetchJsonAsync("/server_info");
    }

    public async Task<JsonElement?> FetchVoucherAsync(string voucherId)
    {
        return await FetchJsonAsync("/voucher/" + Uri.EscapeDataString(voucherId));
    }

    public async Task<JsonElement?> FetchContentInfoAsync(string hash)
    {
        return await FetchJsonAsync("/content/" + Uri.EscapeDataString(hash) + "?follow_redirect=true");
    }

    public async Task<byte[]?> FetchContentBinaryAsync(string hash)
    {
        return await FetchBinaryAsync("/content/" + Uri.EscapeDataString(hash));
    }

    public async Task<JsonElement?> FetchUserVouchersAsync()
    {
        if (string.IsNullOrEmpty(ServiceUsername)) return null;
        return await FetchJsonAsync("/vouchers/user?username=" + Uri.EscapeDataString(ServiceUsername));
    }

    public string GetAddressForDisplay() => string.IsNullOrEmpty(SessionState.ServerAddress) ? "Desconectado" : SessionState.ServerAddress;
}
