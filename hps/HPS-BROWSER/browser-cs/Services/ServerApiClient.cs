using System;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace HpsBrowser.Services;

public sealed class ServerApiClient
{
    private readonly HttpClient _client;

    public ServerApiClient(HttpClient? client = null)
    {
        _client = client ?? new HttpClient(TlsCertificateValidation.CreateHttpClientHandler());
        _client.Timeout = TimeSpan.FromSeconds(12);
    }

    public IEnumerable<string> BuildServerUrlOptions(string serverAddress, bool useSsl)
    {
        var primary = TryBuildBaseUri(serverAddress, "https");
        if (primary is null)
        {
            return Array.Empty<string>();
        }

        return new[] { primary.AbsoluteUri.TrimEnd('/') };
    }

    private static Uri? TryBuildBaseUri(string serverAddress, string defaultScheme)
    {
        if (string.IsNullOrWhiteSpace(serverAddress))
        {
            return null;
        }

        var trimmed = serverAddress.Trim();
        if (trimmed.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = "http://" + trimmed.Substring("ws://".Length);
        }
        else if (trimmed.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = "https://" + trimmed.Substring("wss://".Length);
        }

        if (!trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = $"{defaultScheme}://{trimmed}";
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
        {
            return null;
        }

        if (absolute.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(absolute.Host))
        {
            return null;
        }

        var builder = new UriBuilder(absolute)
        {
            Path = string.Empty,
            Query = string.Empty,
            Fragment = string.Empty
        };
        return builder.Uri;
    }

    public async Task<JsonElement?> FetchServerInfoAsync(string serverAddress, bool useSsl, CancellationToken cancellationToken = default)
    {
        var baseUrl = TryBuildBaseUri(serverAddress, "https");
        if (baseUrl is null)
        {
            return null;
        }

        var url = $"{baseUrl.AbsoluteUri.TrimEnd('/')}/server_info";
        var response = await _client.GetAsync(url, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var json = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
        if (json.ValueKind == JsonValueKind.Object && json.TryGetProperty("public_key", out var publicKey))
        {
            var normalized = NormalizePublicKey(publicKey.GetString());
            using var doc = JsonDocument.Parse(json.GetRawText());
            var dict = doc.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
            dict["public_key"] = JsonDocument.Parse(JsonSerializer.Serialize(normalized)).RootElement;
            var rebuilt = JsonSerializer.SerializeToElement(dict);
            return rebuilt;
        }

        return json;
    }

    public async Task<string?> FetchContractAsync(string serverAddress, bool useSsl, string contractId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(contractId))
        {
            return null;
        }

        foreach (var baseUrl in BuildServerUrlOptions(serverAddress, useSsl))
        {
            try
            {
                var url = $"{baseUrl}/contract/{contractId}";
                var response = await _client.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                return Encoding.UTF8.GetString(bytes);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"FetchContract failed for {baseUrl}: {ex.Message}");
                
            }
        }

        return null;
    }

    public async Task<JsonElement?> FetchVoucherAuditAsync(string serverAddress, bool useSsl, IEnumerable<string> voucherIds, CancellationToken cancellationToken = default)
    {
        var ids = voucherIds.Where(v => !string.IsNullOrWhiteSpace(v)).ToArray();
        if (ids.Length == 0)
        {
            return null;
        }

        foreach (var baseUrl in BuildServerUrlOptions(serverAddress, useSsl))
        {
            try
            {
                var url = $"{baseUrl}/voucher/audit";
                var response = await _client.PostAsJsonAsync(url, new { voucher_ids = ids }, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var json = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                return json;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"FetchVoucherAudit failed for {baseUrl}: {ex.Message}");
                
            }
        }

        return null;
    }

    private static bool IsValidPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        if (!path.StartsWith("/", StringComparison.Ordinal))
        {
            return false;
        }
        if (path.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }
        var decoded = Uri.UnescapeDataString(path);
        if (decoded.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }
        if (decoded.Contains('\\', StringComparison.Ordinal))
        {
            return false;
        }
        return true;
    }

    public async Task<JsonElement?> FetchJsonPathAsync(string serverAddress, bool useSsl, string path, CancellationToken cancellationToken = default)
    {
        if (!IsValidPath(path))
        {
            return null;
        }

        foreach (var baseUrl in BuildServerUrlOptions(serverAddress, useSsl))
        {
            try
            {
                var url = $"{baseUrl}{path}";
                var response = await _client.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
            }
            catch
            {
                
            }
        }

        return null;
    }

    public async Task<byte[]?> FetchBinaryPathAsync(string serverAddress, bool useSsl, string path, CancellationToken cancellationToken = default)
    {
        if (!IsValidPath(path))
        {
            return null;
        }

        foreach (var baseUrl in BuildServerUrlOptions(serverAddress, useSsl))
        {
            try
            {
                var url = $"{baseUrl}{path}";
                var response = await _client.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                return await response.Content.ReadAsByteArrayAsync(cancellationToken);
            }
            catch
            {
                
            }
        }

        return null;
    }

    public async Task<JsonElement?> PostJsonAsync(string serverAddress, bool useSsl, string path, object body, CancellationToken cancellationToken = default)
    {
        if (!IsValidPath(path))
        {
            return null;
        }

        foreach (var baseUrl in BuildServerUrlOptions(serverAddress, useSsl))
        {
            try
            {
                var url = $"{baseUrl}{path}";
                var response = await _client.PostAsJsonAsync(url, body, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
            }
            catch
            {
            }
        }

        return null;
    }

    private static string NormalizePublicKey(string? keyValue)
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
            
        }

        return trimmed;
    }
}
