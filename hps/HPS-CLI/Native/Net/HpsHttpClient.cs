using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Hps.Cli.Native.Net;

public sealed class HpsHttpClient
{
    private readonly HttpClient _http;

    public HpsHttpClient(HttpClient? httpClient = null)
    {
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
    }

    public async Task<(bool Ok, string ContentHash, string Domain, string Username, bool Verified, string Signature, string PublicKey, string DdnsHash, byte[] DdnsContent, string RawJson, string Error)> ResolveDomainAsync(string server, string domain, CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/dns/" + Uri.EscapeDataString(domain.Trim().ToLowerInvariant());
        using var res = await _http.GetAsync(endpoint, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, string.Empty, string.Empty, string.Empty, false, string.Empty, string.Empty, string.Empty, Array.Empty<byte>(), raw, TrimError(raw, (int)res.StatusCode));
        }
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("success", out var s) && s.ValueKind == JsonValueKind.True;
            var hash = root.TryGetProperty("content_hash", out var h) ? h.GetString() ?? string.Empty : string.Empty;
            if (!ok || string.IsNullOrWhiteSpace(hash))
            {
                var err = root.TryGetProperty("error", out var e) ? e.GetString() ?? "dns_invalid_response" : "dns_invalid_response";
                return (false, string.Empty, string.Empty, string.Empty, false, string.Empty, string.Empty, string.Empty, Array.Empty<byte>(), raw, err);
            }
            var resolvedDomain = root.TryGetProperty("domain", out var d) ? d.GetString() ?? domain : domain;
            var username = root.TryGetProperty("username", out var u) ? u.GetString() ?? string.Empty : string.Empty;
            var verified = root.TryGetProperty("verified", out var v) && v.ValueKind == JsonValueKind.True;
            var signature = root.TryGetProperty("signature", out var sig) ? sig.GetString() ?? string.Empty : string.Empty;
            var publicKey = root.TryGetProperty("public_key", out var key) ? key.GetString() ?? string.Empty : string.Empty;
            var ddnsHash = root.TryGetProperty("ddns_hash", out var dh) ? dh.GetString() ?? string.Empty : string.Empty;
            var ddnsContent = Array.Empty<byte>();
            if (root.TryGetProperty("ddns_content", out var dc) && dc.ValueKind == JsonValueKind.String)
            {
                try
                {
                    ddnsContent = Convert.FromBase64String(dc.GetString() ?? string.Empty);
                }
                catch
                {
                    ddnsContent = Array.Empty<byte>();
                }
            }
            if (ddnsContent.Length == 0 && !string.IsNullOrWhiteSpace(ddnsHash))
            {
                ddnsContent = await FetchDdnsBytesAsync(server, resolvedDomain, ct).ConfigureAwait(false);
            }
            return (true, hash, resolvedDomain, username, verified, signature, publicKey, ddnsHash, ddnsContent, raw, string.Empty);
        }
        catch (Exception ex)
        {
            return (false, string.Empty, string.Empty, string.Empty, false, string.Empty, string.Empty, string.Empty, Array.Empty<byte>(), raw, ex.Message);
        }
    }

    public async Task<byte[]> FetchDdnsBytesAsync(string server, string domain, CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/ddns/" + Uri.EscapeDataString(domain.Trim().ToLowerInvariant());
        using var res = await _http.GetAsync(endpoint, ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return Array.Empty<byte>();
        }
        return await res.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }

    public async Task<(bool Ok, string RawJson, string Error)> GetHealthAsync(string server, CancellationToken ct) =>
        await GetJsonAsync(BuildBase(server) + "/health", ct).ConfigureAwait(false);

    public async Task<(bool Ok, string RawJson, string Error)> GetServerInfoAsync(string server, CancellationToken ct) =>
        await GetJsonAsync(BuildBase(server) + "/server_info", ct).ConfigureAwait(false);

    public async Task<(bool Ok, string RawJson, string Error)> GetEconomyReportAsync(string server, CancellationToken ct) =>
        await GetJsonAsync(BuildBase(server) + "/economy_report", ct).ConfigureAwait(false);

    public async Task<(bool Ok, byte[] Data, string Mime, Dictionary<string, string[]> Headers, string Error)> FetchContentAsync(string server, string hash, CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/content/" + Uri.EscapeDataString(hash.Trim());
        using var res = await _http.GetAsync(endpoint, ct).ConfigureAwait(false);
        var bytes = await res.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, Array.Empty<byte>(), string.Empty, new Dictionary<string, string[]>(), TrimError(Encoding.UTF8.GetString(bytes), (int)res.StatusCode));
        }
        var mime = res.Content.Headers.ContentType?.MediaType ?? DetectMime(bytes);
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in res.Headers)
        {
            headers[h.Key] = h.Value.ToArray();
        }
        foreach (var h in res.Content.Headers)
        {
            headers[h.Key] = h.Value.ToArray();
        }
        return (true, bytes, mime, headers, string.Empty);
    }

    public async Task<(bool Ok, string Error)> UploadFileAsync(string server, string username, byte[] signature, string filePath, string title, string description, string mimeType, CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/upload";
        await using var fs = File.OpenRead(filePath);
        using var content = new MultipartFormDataContent();
        using var stream = new StreamContent(fs);
        stream.Headers.ContentType = new MediaTypeHeaderValue(string.IsNullOrWhiteSpace(mimeType) ? "application/octet-stream" : mimeType);
        content.Add(stream, "file", Path.GetFileName(filePath));
        using var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        req.Content = content;
        req.Headers.Add("X-Username", username ?? string.Empty);
        req.Headers.Add("X-Signature", Convert.ToBase64String(signature ?? Array.Empty<byte>()));
        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, TrimError(raw, (int)res.StatusCode));
        }
        return (true, string.Empty);
    }

    public async Task<(bool Ok, string Error)> UploadFileAsync(
        string server,
        string username,
        string clientId,
        string publicKeyBase64,
        byte[] signature,
        string filePath,
        string mimeType,
        CancellationToken ct)
    {
        var fileName = Path.GetFileName(filePath);
        var bytes = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
        return await UploadBytesAsync(server, username, clientId, publicKeyBase64, signature, fileName, bytes, mimeType, ct).ConfigureAwait(false);
    }

    public async Task<(bool Ok, string Error)> UploadBytesAsync(
        string server,
        string username,
        string clientId,
        string publicKeyBase64,
        byte[] signature,
        string fileName,
        byte[] fileBytes,
        string mimeType,
        CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/upload";
        using var content = new MultipartFormDataContent();
        using var stream = new StreamContent(new MemoryStream(fileBytes, writable: false));
        stream.Headers.ContentType = new MediaTypeHeaderValue(string.IsNullOrWhiteSpace(mimeType) ? "application/octet-stream" : mimeType);
        content.Add(stream, "file", string.IsNullOrWhiteSpace(fileName) ? "upload.bin" : fileName);

        using var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        req.Content = content;
        req.Headers.Add("X-Username", username ?? string.Empty);
        req.Headers.Add("X-Signature", Convert.ToBase64String(signature ?? Array.Empty<byte>()));
        req.Headers.Add("X-Public-Key", publicKeyBase64 ?? string.Empty);
        req.Headers.Add("X-Client-ID", clientId ?? string.Empty);

        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, TrimError(raw, (int)res.StatusCode));
        }
        return (true, string.Empty);
    }

    public async Task<(bool Ok, SyncSnapshot Snapshot, string Error)> SyncAllAsync(string server, int limit, CancellationToken ct)
    {
        if (limit <= 0)
        {
            limit = 200;
        }
        var baseUrl = BuildBase(server);
        try
        {
            var content = await FetchListAsync(baseUrl + $"/sync/content?limit={limit}", ct).ConfigureAwait(false);
            var dns = await FetchListAsync(baseUrl + "/sync/dns", ct).ConfigureAwait(false);
            var contracts = await FetchListAsync(baseUrl + $"/sync/contracts?limit={limit}", ct).ConfigureAwait(false);
            var users = await FetchListAsync(baseUrl + "/sync/users", ct).ConfigureAwait(false);
            return (true, new SyncSnapshot(content, dns, contracts, users), string.Empty);
        }
        catch (Exception ex)
        {
            return (false, new SyncSnapshot([], [], [], []), ex.Message);
        }
    }

    public async Task<(bool Ok, string Content, string Error)> FetchContractAsync(string server, string contractId, CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/contract/" + Uri.EscapeDataString(contractId.Trim());
        using var res = await _http.GetAsync(endpoint, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, string.Empty, TrimError(raw, (int)res.StatusCode));
        }
        return (true, raw, string.Empty);
    }

    public async Task<(bool Ok, string Content, string Mime, string Error)> FetchVoucherAsync(string server, string voucherId, bool asHtml, CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/voucher/" + Uri.EscapeDataString(voucherId.Trim());
        using var req = new HttpRequestMessage(HttpMethod.Get, endpoint);
        if (asHtml)
        {
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
        }
        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, string.Empty, string.Empty, TrimError(raw, (int)res.StatusCode));
        }
        var mime = res.Content.Headers.ContentType?.MediaType ?? "text/plain";
        return (true, raw, mime, string.Empty);
    }

    public async Task<(bool Ok, string RawJson, string Error)> AuditVouchersAsync(string server, IReadOnlyList<string> voucherIds, CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/voucher/audit";
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?> { ["voucher_ids"] = voucherIds });
        using var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, string.Empty, TrimError(raw, (int)res.StatusCode));
        }
        return (true, raw, string.Empty);
    }

    public async Task<(bool Ok, string RawJson, string Error)> ExchangeValidateAsync(
        string server,
        IReadOnlyList<string> voucherIds,
        string targetServer,
        string clientSignature,
        string clientPublicKey,
        string requestId,
        double timestamp,
        CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/exchange/validate";
        var payload = new Dictionary<string, object?>
        {
            ["voucher_ids"] = voucherIds,
            ["target_server"] = targetServer,
            ["client_signature"] = clientSignature,
            ["client_public_key"] = clientPublicKey,
            ["request_id"] = requestId,
            ["timestamp"] = timestamp
        };
        return await PostJsonAsync(endpoint, payload, ct).ConfigureAwait(false);
    }

    public async Task<(bool Ok, string RawJson, string Error)> ExchangeConfirmAsync(
        string server,
        Dictionary<string, object?> token,
        string signature,
        CancellationToken ct)
    {
        var endpoint = BuildBase(server) + "/exchange/confirm";
        var payload = new Dictionary<string, object?>
        {
            ["token"] = token,
            ["signature"] = signature
        };
        return await PostJsonAsync(endpoint, payload, ct).ConfigureAwait(false);
    }

    private async Task<List<Dictionary<string, object?>>> FetchListAsync(string endpoint, CancellationToken ct)
    {
        using var res = await _http.GetAsync(endpoint, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(TrimError(raw, (int)res.StatusCode));
        }
        using var doc = JsonDocument.Parse(raw);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return [];
        }
        var list = new List<Dictionary<string, object?>>();
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            list.Add(ToDictionary(item));
        }
        return list;
    }

    private async Task<(bool Ok, string RawJson, string Error)> GetJsonAsync(string endpoint, CancellationToken ct)
    {
        using var res = await _http.GetAsync(endpoint, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, string.Empty, TrimError(raw, (int)res.StatusCode));
        }
        return (true, raw, string.Empty);
    }

    private async Task<(bool Ok, string RawJson, string Error)> PostJsonAsync(string endpoint, object payload, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(payload);
        using var req = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var raw = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            return (false, string.Empty, TrimError(raw, (int)res.StatusCode));
        }
        return (true, raw, string.Empty);
    }

    private static Dictionary<string, object?> ToDictionary(JsonElement e)
    {
        var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (e.ValueKind != JsonValueKind.Object)
        {
            return d;
        }
        foreach (var p in e.EnumerateObject())
        {
            d[p.Name] = ToValue(p.Value);
        }
        return d;
    }

    private static object? ToValue(JsonElement e)
    {
        return e.ValueKind switch
        {
            JsonValueKind.String => e.GetString(),
            JsonValueKind.Number => e.TryGetInt64(out var i) ? i : e.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            JsonValueKind.Object => ToDictionary(e),
            JsonValueKind.Array => e.EnumerateArray().Select(ToValue).ToList(),
            _ => e.GetRawText()
        };
    }

    private static string BuildBase(string server)
    {
        server = (server ?? string.Empty).Trim();
        if (server.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            server.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return server.TrimEnd('/');
        }
        return ("http://" + server).TrimEnd('/');
    }

    private static string DetectMime(byte[] bytes)
    {
        if (bytes.Length >= 8 &&
            bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47 &&
            bytes[4] == 0x0D && bytes[5] == 0x0A && bytes[6] == 0x1A && bytes[7] == 0x0A)
        {
            return "image/png";
        }
        if (bytes.Length >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF)
        {
            return "image/jpeg";
        }
        if (bytes.Length >= 6)
        {
            var h = Encoding.ASCII.GetString(bytes, 0, Math.Min(6, bytes.Length));
            if (h.StartsWith("GIF87a", StringComparison.Ordinal) || h.StartsWith("GIF89a", StringComparison.Ordinal))
            {
                return "image/gif";
            }
        }
        return "application/octet-stream";
    }

    private static string TrimError(string raw, int status)
    {
        var v = (raw ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(v))
        {
            return "status " + status;
        }
        return v.Length > 500 ? v[..500] + "..." : v;
    }
}

public readonly record struct SyncSnapshot(
    List<Dictionary<string, object?>> Content,
    List<Dictionary<string, object?>> Dns,
    List<Dictionary<string, object?>> Contracts,
    List<Dictionary<string, object?>> Users);
