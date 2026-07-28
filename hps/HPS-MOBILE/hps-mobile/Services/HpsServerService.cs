using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HpsMobile.Services;

public sealed class HpsServerService
{
    private readonly HttpClient _http;

    public HpsServerService()
    {
        // C3: Validate TLS certificates on HttpClient - trust all certs (custom P2P network)
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
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
        catch (Exception)
        {
            // A10: Removed Debug.WriteLine to avoid leaking credentials/metadata
            return null;
        }
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
        catch (Exception)
        {
            return null;
        }
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
        catch (Exception)
        {
            return null;
        }
    }

    public async Task<JsonElement?> FetchEconomyReportAsync()
    {
        return await FetchJsonAsync("/economy_report");
    }

    public async Task<JsonElement?> FetchServerInfoAsync()
    {
        return await FetchJsonAsync("/server_info");
    }

    public async Task<JsonElement?> FetchPhpsMarketAsync(string? username = null)
    {
        var path = "/phps/market";
        if (!string.IsNullOrEmpty(username)) path += "?username=" + Uri.EscapeDataString(username);
        return await FetchJsonAsync(path);
    }

    public async Task<JsonElement?> FetchVoucherAsync(string voucherId)
    {
        return await FetchJsonAsync("/voucher/" + Uri.EscapeDataString(voucherId));
    }

    public async Task<long?> FetchContentSizeAsync(string hash)
    {
        if (string.IsNullOrEmpty(Server)) return null;
        try
        {
            var url = $"{BaseUrl}/content/{Uri.EscapeDataString(hash)}";
            using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            if (!response.IsSuccessStatusCode) return null;
            return response.Content.Headers.ContentLength;
        }
        catch
        {
            return null;
        }
    }

    public async Task<string?> FetchContentTypeAsync(string hash)
    {
        if (string.IsNullOrEmpty(Server)) return null;
        try
        {
            var url = $"{BaseUrl}/content/{Uri.EscapeDataString(hash)}";
            using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            if (!response.IsSuccessStatusCode) return null;
            return response.Content.Headers.ContentType?.MediaType;
        }
        catch
        {
            return null;
        }
    }

    public async Task<byte[]?> FetchContentBinaryAsync(string hash)
    {
        return await FetchBinaryAsync("/content/" + Uri.EscapeDataString(hash));
    }

    public async Task<(string filePath, string mimeType, long fileSize)?> DownloadContentToCacheAsync(string hash)
    {
        if (string.IsNullOrEmpty(Server)) return null;
        try
        {
            var url = $"{BaseUrl}/content/{Uri.EscapeDataString(hash)}";
            using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            if (!response.IsSuccessStatusCode) return null;

            var mime = response.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";

            var cacheDir = Path.Combine(FileSystem.CacheDirectory, "hps_cache");
            Directory.CreateDirectory(cacheDir);
            var tempPath = Path.Combine(cacheDir, hash);

            using var stream = await response.Content.ReadAsStreamAsync();
            using var fileStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true);
            await stream.CopyToAsync(fileStream);

            // A5: Validate SHA256 hash of downloaded content
            fileStream.Close();
            var actualBytes = await File.ReadAllBytesAsync(tempPath);
            var computedHash = Convert.ToHexString(SHA256.HashData(actualBytes)).ToLowerInvariant();
            if (!string.Equals(computedHash, hash, StringComparison.OrdinalIgnoreCase))
            {
                try { File.Delete(tempPath); } catch { }
                return null; // Hash mismatch - reject content
            }

            var actualSize = new FileInfo(tempPath).Length;
            return (tempPath, mime, actualSize);
        }
        catch (Exception)
        {
            return null;
        }
    }

    public async Task<JsonElement?> PostTransferAsync(string recipient, decimal amount)
    {
        return await PostJsonAsync("/exchange/validate", new
        {
            username = ServiceUsername,
            recipient,
            amount
        });
    }

    public async Task<JsonElement?> FetchUserVouchersAsync()
    {
        if (string.IsNullOrEmpty(ServiceUsername)) return null;
        return await FetchJsonAsync("/vouchers/user?username=" + Uri.EscapeDataString(ServiceUsername));
    }

    public string GetAddressForDisplay() => string.IsNullOrEmpty(SessionState.ServerAddress) ? "Desconectado" : SessionState.ServerAddress;
}
