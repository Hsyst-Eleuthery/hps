using System.Text;
using System.Text.Json;
using HpsMobile.Services;

namespace HpsMobile.Views;

public partial class BrowserPage : ContentPage
{
    private readonly List<string> _history = new();
    private int _historyIndex = -1;
    private byte[]? _lastContentBytes;
    private string _lastContentHash = string.Empty;
    private string _lastContentMime = string.Empty;

    public BrowserPage()
    {
        InitializeComponent();
        RegisterSocketHandlers();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        if (string.IsNullOrEmpty(UrlEntry.Text))
            UrlEntry.Text = "hps://rede";
    }

    private void RegisterSocketHandlers()
    {
        var socket = SessionState.Socket;
        if (socket == null) return;

        socket.On("content_response", HandleContentResponse);
        socket.On("browser_navigation", HandleBrowserNavigation);
    }

    private async Task HandleContentResponse(SocketEventResponse response)
    {
        var payload = response.GetValue<JsonElement>();
        var success = payload.TryGetProperty("success", out var s) && s.GetBoolean();
        if (!success)
        {
            var error = payload.TryGetProperty("error", out var e) ? e.GetString() : "Erro desconhecido";
            MainThread.BeginInvokeOnMainThread(() =>
            {
                StatusLabel.Text = $"Erro: {error}";
                SecurityFrame.IsVisible = false;
            });
            return;
        }

        if (!payload.TryGetProperty("hash", out var hashProp)) return;
        var hash = hashProp.GetString() ?? string.Empty;

        string? b64 = null;
        if (payload.TryGetProperty("content_base64", out var contentProp))
            b64 = contentProp.GetString();
        else if (payload.TryGetProperty("data", out var dataProp))
            b64 = dataProp.GetString();

        if (string.IsNullOrEmpty(b64)) return;

        var rawBytes = Convert.FromBase64String(b64);

        // A8: Verify signature client-side using SHA256 hash comparison
        var computedHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(rawBytes)).ToLowerInvariant();
        var clientSigValid = string.Equals(computedHash, hash, StringComparison.OrdinalIgnoreCase);
        var sigValid = payload.TryGetProperty("signature_valid", out var sigProp) && sigProp.GetBoolean();
        // Client-side hash validation takes precedence over server's signature_valid
        var validated = sigValid && clientSigValid;
        var mime = payload.TryGetProperty("mime_type", out var mimeProp) ? mimeProp.GetString() ?? "text/plain" : "text/plain";

        _lastContentBytes = rawBytes;
        _lastContentHash = hash;
        _lastContentMime = mime;

        MainThread.BeginInvokeOnMainThread(() => DisplayContent(rawBytes, mime, validated));
    }

    private async Task HandleBrowserNavigation(SocketEventResponse response)
    {
        var payload = response.GetValue<JsonElement>();
        if (payload.TryGetProperty("url", out var urlProp))
        {
            var url = urlProp.GetString() ?? string.Empty;
            MainThread.BeginInvokeOnMainThread(() => UrlEntry.Text = url);
        }
    }

    private const int MaxRenderSize = 2 * 1024 * 1024; // 2 MB max for inline rendering

    private static string GetDownloadsDirectory()
    {
        var fallback = Path.Combine(FileSystem.AppDataDirectory, "downloads");
        try
        {
#if ANDROID
            var publicDir = Android.OS.Environment.GetExternalStoragePublicDirectory(Android.OS.Environment.DirectoryDownloads)?.AbsolutePath;
            if (!string.IsNullOrEmpty(publicDir))
            {
                var hpsDir = Path.Combine(publicDir, "HPS");
                Directory.CreateDirectory(hpsDir);
                return hpsDir;
            }
#endif
        }
        catch
        {
            // Fall through
        }
        Directory.CreateDirectory(fallback);
        return fallback;
    }

    private void DisplayContent(byte[] data, string mime, bool sigValid)
    {
        SecurityFrame.IsVisible = true;
        SecurityFrame.BackgroundColor = sigValid ? Color.FromArgb("#065F46") : Color.FromArgb("#92400E");
        SecurityLabel.Text = sigValid
            ? "Assinatura verificada"
            : "Conteudo nao verificado";

        ContentLabel.IsVisible = true;
        ContentImage.IsVisible = false;
        StatusLabel.Text = "Carregado";

        bool isRenderableText = mime.StartsWith("text/") || mime.Contains("json") || mime.Contains("xml") || mime.Contains("html");

        if (isRenderableText && data.Length <= MaxRenderSize)
        {
            ContentLabel.Text = Encoding.UTF8.GetString(data);
        }
        else
        {
            var sizeStr = data.Length >= 1024 * 1024
                ? $"{data.Length / 1024 / 1024} MB"
                : $"{data.Length / 1024} KB";
            ContentLabel.Text = $"Arquivo muito grande ({sizeStr}). Baixe para que voce possa visualiza-lo.";
        }
    }

    private async void OnUrlSubmitted(object? sender, EventArgs e)
    {
        await NavigateToUrl(UrlEntry.Text?.Trim() ?? string.Empty);
    }

    private async void OnGo(object? sender, EventArgs e)
    {
        await NavigateToUrl(UrlEntry.Text?.Trim() ?? string.Empty);
    }

    private async void OnReload(object? sender, EventArgs e)
    {
        if (!string.IsNullOrEmpty(_lastContentHash))
            await NavigateToUrl($"hps://{_lastContentHash}");
    }

    private async void OnHome(object? sender, EventArgs e)
    {
        await NavigateToUrl("hps://rede");
    }

    private async void OnSearch(object? sender, EventArgs e)
    {
        var query = await DisplayPromptAsync("Buscar Conteudo",
            "Digite o termo de busca:",
            "Buscar", "Cancelar",
            placeholder: "ex: hps, tutorial");

        if (string.IsNullOrEmpty(query)) return;
        await NavigateToUrl($"hps://search:{Uri.EscapeDataString(query)}");
    }

    private async void OnSave(object? sender, EventArgs e)
    {
        if (_lastContentBytes == null || string.IsNullOrEmpty(_lastContentHash))
        {
            await DisplayAlertAsync("Salvar", "Nenhum conteudo carregado.", "OK");
            return;
        }

        try
        {
            var ext = GetExtensionFromMime(_lastContentMime);
            var truncLen = Math.Min(_lastContentHash.Length, 16);
            var fileName = $"{_lastContentHash[..truncLen]}{ext}";
            var filePath = Path.Combine(GetDownloadsDirectory(), fileName);
            await File.WriteAllBytesAsync(filePath, _lastContentBytes);

            var addBookmark = await DisplayAlertAsync("Salvo",
                $"Conteudo salvo em:\n{filePath}\n\nAdicionar aos favoritos?", "Sim", "Nao");
            if (addBookmark)
            {
                var title = await DisplayPromptAsync("Favorito", "Nome do favorito:", initialValue: fileName);
                if (!string.IsNullOrEmpty(title))
                {
                    AddBookmark(title, UrlEntry.Text ?? _lastContentHash, _lastContentHash);
                    await DisplayAlertAsync("Favorito", $"'{title}' adicionado aos favoritos!", "OK");
                }
            }
        }
        catch (Exception ex)
        {
            await DisplayAlertAsync("Erro", $"Falha ao salvar: {ex.Message}", "OK");
        }
    }

    private async void OnBookmarks(object? sender, EventArgs e)
    {
        var bookmarks = GetBookmarks();
        if (bookmarks.Count == 0)
        {
            await DisplayAlertAsync("Favoritos", "Nenhum favorito salvo.", "OK");
            return;
        }

        var names = bookmarks.Select(b => b.Title).ToArray();
        var selected = await DisplayActionSheet("Favoritos", "Cancelar", null, names);
        if (string.IsNullOrEmpty(selected) || selected == "Cancelar") return;

        var bookmark = bookmarks.FirstOrDefault(b => b.Title == selected);
        if (bookmark != null)
            await NavigateToUrl(bookmark.Url);
    }

    private List<BookmarkItem> GetBookmarks()
    {
        try
        {
            var json = Preferences.Get("browser_bookmarks", "[]");
            return JsonSerializer.Deserialize<List<BookmarkItem>>(json) ?? new List<BookmarkItem>();
        }
        catch { return new List<BookmarkItem>(); }
    }

    private void AddBookmark(string title, string url, string hash)
    {
        var bookmarks = GetBookmarks();
        bookmarks.RemoveAll(b => b.Url == url);
        bookmarks.Insert(0, new BookmarkItem { Title = title, Url = url, Hash = hash, AddedAt = DateTime.Now.ToString("dd/MM HH:mm") });
        if (bookmarks.Count > 50) bookmarks = bookmarks.Take(50).ToList();
        Preferences.Set("browser_bookmarks", JsonSerializer.Serialize(bookmarks));
    }

    private class BookmarkItem
    {
        public string Title { get; set; } = "";
        public string Url { get; set; } = "";
        public string Hash { get; set; } = "";
        public string AddedAt { get; set; } = "";
    }

    private async void OnBack(object? sender, EventArgs e)
    {
        if (_historyIndex > 0)
        {
            _historyIndex--;
            await NavigateToUrl(_history[_historyIndex], addToHistory: false);
        }
    }

    private async Task NavigateToUrl(string url, bool addToHistory = true)
    {
        if (string.IsNullOrWhiteSpace(url)) return;

        UrlEntry.Text = url;
        StatusLabel.Text = "Carregando...";
        ContentLabel.IsVisible = false;
        ContentImage.IsVisible = false;
        SecurityFrame.IsVisible = false;

        if (url.StartsWith("hps://"))
        {
            var path = url["hps://".Length..].Trim();

            if (path.Equals("rede", StringComparison.OrdinalIgnoreCase))
            {
                // Show server info page
                await LoadServerInfo();
                return;
            }

            if (path.StartsWith("search:", StringComparison.OrdinalIgnoreCase))
            {
                var query = path["search:".Length..];
                var decoded = Uri.UnescapeDataString(query);
                await SearchContent(decoded);
                return;
            }

            if (path.StartsWith("dns:", StringComparison.OrdinalIgnoreCase))
            {
                var domain = path["dns:".Length..].Trim();
                await ResolveDnsAndNavigate(domain);
                return;
            }

            // If path contains dots, try DNS resolution first
            if (path.Contains('.'))
            {
                var resolved = await SessionState.Server.FetchJsonAsync($"/dns/{Uri.EscapeDataString(path)}");
                if (resolved.HasValue)
                {
                    if (resolved.Value.TryGetProperty("content_hash", out var hashProp))
                    {
                        var hash = hashProp.GetString() ?? string.Empty;
                        if (!string.IsNullOrEmpty(hash))
                        {
                            await NavigateToUrl($"hps://{hash}", addToHistory: false);
                            return;
                        }
                    }

                    // Domain exists but has no content -> show DNS info
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        ContentLabel.IsVisible = true;
                        var sb = new System.Text.StringBuilder();
                        sb.AppendLine("╔═══ RESOLUCAO DNS ═══");
                        sb.AppendLine($"║ Dominio: {path}");
                        if (resolved.Value.TryGetProperty("owner", out var dnsOwner))
                            sb.AppendLine($"║ Dono: {dnsOwner.GetString()}");
                        if (resolved.Value.TryGetProperty("expires", out var dnsExp))
                            sb.AppendLine($"║ Expira: {dnsExp.GetInt64()}");
                        sb.AppendLine("╚═════════════════════");
                        ContentLabel.Text = sb.ToString();
                        StatusLabel.Text = "DNS - sem conteudo";
                        SecurityFrame.IsVisible = false;
                    });
                    return;
                }

                // DNS resolution failed - show error instead of falling through to hash lookup
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ContentLabel.IsVisible = true;
                    ContentLabel.Text = $"Dominio nao encontrado: {path}";
                    StatusLabel.Text = "DNS nao resolvido";
                    SecurityFrame.IsVisible = false;
                });
                return;
            }

            // Assume it's a hash
            await LoadContentByHash(path);
        }
        else if (url.StartsWith("http://") || url.StartsWith("https://"))
        {
            // External URL - use system browser
            try
            {
                await Browser.Default.OpenAsync(url, BrowserLaunchMode.SystemPreferred);
            }
            catch (Exception ex)
            {
                StatusLabel.Text = $"Erro: {ex.Message}";
            }
        }
        else
        {
            StatusLabel.Text = $"Protocolo nao suportado: {url}";
        }

        if (addToHistory && url != "hps://rede")
        {
            // Remove entries after current index
            if (_historyIndex < _history.Count - 1)
                _history.RemoveRange(_historyIndex + 1, _history.Count - _historyIndex - 1);
            _history.Add(url);
            _historyIndex = _history.Count - 1;
        }
    }

    private async Task LoadServerInfo()
    {
        try
        {
            var serverInfo = await SessionState.Server.FetchServerInfoAsync();
            MainThread.BeginInvokeOnMainThread(() =>
            {
                ContentLabel.IsVisible = true;
                SecurityFrame.IsVisible = false;
                StatusLabel.Text = "Servidor";
                if (serverInfo.HasValue)
                {
                    var info = serverInfo.Value;
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("╔═══ INFORMACOES DO SERVIDOR ═══");
                    if (info.TryGetProperty("name", out var nameProp))
                        sb.AppendLine($"║ Nome: {nameProp.GetString()}");
                    sb.AppendLine($"║ Endereco: {SessionState.ServerAddress}");
                    if (info.TryGetProperty("version", out var verProp))
                        sb.AppendLine($"║ Versao: {verProp.GetString()}");
                    if (info.TryGetProperty("uptime", out var upProp))
                        sb.AppendLine($"║ Ativo: {upProp.GetString()}");
                    if (info.TryGetProperty("nodes_online", out var nodesProp))
                        sb.AppendLine($"║ Nos online: {nodesProp.GetInt32()}");
                    if (info.TryGetProperty("total_content", out var contentProp))
                        sb.AppendLine($"║ Conteudos: {contentProp.GetInt32()}");
                    if (info.TryGetProperty("total_dns", out var dnsProp))
                        sb.AppendLine($"║ Dominios DNS: {dnsProp.GetInt32()}");
                    if (info.TryGetProperty("total_minted", out var mintProp))
                        sb.AppendLine($"║ HPS Minerado: {mintProp.GetDouble():N2}");
                    if (info.TryGetProperty("total_burned", out var burnProp))
                        sb.AppendLine($"║ HPS Queimado: {burnProp.GetDouble():N2}");
                    if (info.TryGetProperty("owner", out var ownerProp))
                        sb.AppendLine($"║ Dono: {ownerProp.GetString()}");
                    sb.AppendLine($"║ Usuario: {SessionState.Username}");
                    sb.AppendLine("╚═══════════════════════════════");
                    ContentLabel.Text = sb.ToString();
                }
                else
                {
                    ContentLabel.Text = $"╔═══ REDE HPS ═══\n║\n║ Conectado a: {SessionState.ServerAddress}\n║ Usuario: {SessionState.Username}\n║\n║ Use hps://&lt;hash&gt; para navegar.\n║ Use hps://search:&lt;termo&gt; para buscar.\n║ Use hps://dns:&lt;dominio&gt; para resolver DNS.\n╚═══════════════";
                }
            });
        }
        catch (Exception ex)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                ContentLabel.IsVisible = true;
                ContentLabel.Text = $"Erro ao carregar informacoes do servidor: {ex.Message}";
            });
        }
    }

    private const long MaxDownloadSize = 50 * 1024 * 1024; // 50 MB max to download

    private static string GetExtensionFromMime(string mime) => mime switch
    {
        "text/html" => ".html",
        "text/plain" => ".txt",
        "application/json" => ".json",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        _ => ".bin"
    };

    private async Task LoadContentByHash(string hash)
    {
        try
        {
            var size = await SessionState.Server.FetchContentSizeAsync(hash);
            if (size > MaxDownloadSize)
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ContentLabel.IsVisible = true;
                    ContentLabel.Text = $"Arquivo muito grande ({size / 1024 / 1024} MB). Use o botao Salvar para baixar.";
                    StatusLabel.Text = "Grande demais";
                    SecurityFrame.IsVisible = false;
                });
                return;
            }

            var mime = await SessionState.Server.FetchContentTypeAsync(hash) ?? "application/octet-stream";
            bool isRenderableText = mime.StartsWith("text/") || mime.Contains("json") || mime.Contains("xml") || mime.Contains("html");

            if (isRenderableText && size <= MaxRenderSize)
            {
                var data = await SessionState.Server.FetchContentBinaryAsync(hash);
                if (data != null)
                {
                    _lastContentBytes = data;
                    _lastContentHash = hash;
                    _lastContentMime = mime;

                    MainThread.BeginInvokeOnMainThread(() =>
                        DisplayContent(data, mime, false));
                    return;
                }
            }

            // Streaming download to temp cache for non-text or large content
            var result = await SessionState.Server.DownloadContentToCacheAsync(hash);
            if (result == null)
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ContentLabel.IsVisible = true;
                    ContentLabel.Text = $"Conteudo nao encontrado: {hash}";
                    StatusLabel.Text = "Nao encontrado";
                    SecurityFrame.IsVisible = false;
                });
                return;
            }

            var (filePath, mimeType, fileSize) = result.Value;
            _lastContentBytes = null;
            _lastContentHash = hash;
            _lastContentMime = mimeType;

            var sizeStr = fileSize >= 1024 * 1024
                ? $"{fileSize / 1024 / 1024} MB"
                : $"{fileSize / 1024} KB";

            var action = await MainThread.InvokeOnMainThreadAsync(() =>
                DisplayActionSheet(
                    $"Arquivo ({sizeStr}, {mimeType})",
                    "Cancelar", null, "Salvar"));

            if (action == "Salvar")
            {
                var ext = GetExtensionFromMime(mimeType);
                var truncLen = Math.Min(hash.Length, 16);
                var fileName = $"{hash[..truncLen]}{ext}";
                var downloadDir = GetDownloadsDirectory();
                var destPath = Path.Combine(downloadDir, fileName);
                File.Copy(filePath, destPath, true);

                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ContentLabel.IsVisible = true;
                    ContentLabel.Text = $"Salvo em:\n{destPath}";
                    StatusLabel.Text = "Salvo";
                    SecurityFrame.IsVisible = false;
                });

                var addBookmark = await MainThread.InvokeOnMainThreadAsync(() =>
                    DisplayAlert("Salvo",
                        $"Conteudo salvo em:\n{destPath}\n\nAdicionar aos favoritos?", "Sim", "Nao"));
                if (addBookmark)
                {
                    var title = await MainThread.InvokeOnMainThreadAsync(() =>
                        DisplayPromptAsync("Favorito", "Nome do favorito:", initialValue: fileName));
                    if (!string.IsNullOrEmpty(title))
                    {
                        AddBookmark(title, $"hps://{hash}", hash);
                        await MainThread.InvokeOnMainThreadAsync(() =>
                            DisplayAlert("Favorito", $"'{title}' adicionado aos favoritos!", "OK"));
                    }
                }
            }
            else
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ContentLabel.IsVisible = true;
                    ContentLabel.Text = $"Arquivo ({sizeStr}) - {mimeType}";
                    StatusLabel.Text = "Nao baixado";
                    SecurityFrame.IsVisible = false;
                });
            }

            // Clean up temp file
            try { File.Delete(filePath); } catch { }
        }
        catch (Exception ex)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                ContentLabel.IsVisible = true;
                ContentLabel.Text = $"Erro ao carregar: {ex.Message}";
                StatusLabel.Text = "Erro";
                SecurityFrame.IsVisible = false;
            });
        }
    }

    private async Task SearchContent(string query)
    {
        try
        {
            var result = await SessionState.Server.PostJsonAsync("/content/search", new { query });
            MainThread.BeginInvokeOnMainThread(() =>
            {
                ContentLabel.IsVisible = true;
                SecurityFrame.IsVisible = false;
                if (result.HasValue)
                {
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("╔═══ RESULTADOS DA BUSCA ═══");
                    if (result.Value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in result.Value.EnumerateArray())
                        {
                            sb.AppendLine("║");
                            if (item.TryGetProperty("hash", out var h))
                                sb.AppendLine($"║ Hash: {h.GetString()?[..Math.Min(h.GetString()!.Length, 16)]}...");
                            if (item.TryGetProperty("title", out var t) && t.ValueKind == JsonValueKind.String)
                                sb.AppendLine($"║ Titulo: {t.GetString()}");
                            if (item.TryGetProperty("user", out var u))
                                sb.AppendLine($"║ Usuario: {u.GetString()}");
                            if (item.TryGetProperty("mime_type", out var m))
                                sb.AppendLine($"║ Tipo: {m.GetString()}");
                            if (item.TryGetProperty("timestamp", out var ts))
                                sb.AppendLine($"║ Data: {ts.GetInt64()}");
                        }
                    }
                    else if (result.Value.TryGetProperty("results", out var results) && results.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in results.EnumerateArray())
                        {
                            sb.AppendLine("║");
                            if (item.TryGetProperty("hash", out var h))
                                sb.AppendLine($"║ Hash: {h.GetString()?[..Math.Min(h.GetString()!.Length, 16)]}...");
                            if (item.TryGetProperty("title", out var t) && t.ValueKind == JsonValueKind.String)
                                sb.AppendLine($"║ Titulo: {t.GetString()}");
                            if (item.TryGetProperty("user", out var u))
                                sb.AppendLine($"║ Usuario: {u.GetString()}");
                        }
                    }
                    else
                    {
                        sb.AppendLine($"║ {result.Value.GetRawText()}");
                    }
                    sb.AppendLine("╚═══════════════════════════════");
                    ContentLabel.Text = sb.ToString();
                }
                else
                    ContentLabel.Text = "Nenhum resultado encontrado.";
                StatusLabel.Text = "Busca concluida";
            });
        }
        catch (Exception ex)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                ContentLabel.IsVisible = true;
                ContentLabel.Text = $"Erro na busca: {ex.Message}";
            });
        }
    }

    private async Task ResolveDnsAndNavigate(string domain)
    {
        try
        {
            var result = await SessionState.Server.FetchJsonAsync($"/dns/{Uri.EscapeDataString(domain)}");
            if (result != null && result.Value.TryGetProperty("content_hash", out var hashProp))
            {
                var hash = hashProp.GetString() ?? string.Empty;
                if (!string.IsNullOrEmpty(hash))
                {
                    await NavigateToUrl($"hps://{hash}", addToHistory: true);
                    return;
                }
            }

            MainThread.BeginInvokeOnMainThread(() =>
            {
                ContentLabel.IsVisible = true;
                if (result.HasValue)
                {
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("╔═══ RESOLUCAO DNS ═══");
                    sb.AppendLine($"║ Dominio: {domain}");
                    if (result.Value.TryGetProperty("content_hash", out var dnsHash))
                        sb.AppendLine($"║ Hash: {dnsHash.GetString()}");
                    if (result.Value.TryGetProperty("owner", out var dnsOwner))
                        sb.AppendLine($"║ Dono: {dnsOwner.GetString()}");
                    if (result.Value.TryGetProperty("expires", out var dnsExp))
                        sb.AppendLine($"║ Expira: {dnsExp.GetInt64()}");
                    sb.AppendLine("╚═════════════════════");
                    ContentLabel.Text = sb.ToString();
                }
                else
                    ContentLabel.Text = $"Dominio nao encontrado: {domain}";
                StatusLabel.Text = "DNS nao resolvido";
            });
        }
        catch (Exception ex)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                ContentLabel.IsVisible = true;
                ContentLabel.Text = $"Erro DNS: {ex.Message}";
            });
        }
    }
}
