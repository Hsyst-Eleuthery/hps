using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Maui.Views;
using CommunityToolkit.Maui.Extensions;
using HpsMobile.Services;

namespace HpsMobile.Views;

public partial class NetworkPage : ContentPage
{
    private string? _selectedFilePath;
    private byte[]? _selectedFileBytes;
    private string _selectedFileName = string.Empty;
    private string? _selectedFileBase64;
    private CancellationTokenSource? _powCts;

    private Func<SocketEventResponse, Task>? _powHandler;
    private bool _handlersRegistered;

    public NetworkPage()
    {
        InitializeComponent();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        RegisterAllHandlers();
        UpdateConnectionStatus();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        UnregisterAllHandlers();
    }

    private void RegisterAllHandlers()
    {
        if (_handlersRegistered) return;
        _handlersRegistered = true;
        RegisterSocketHandlers();
        RegisterPowHandler();
    }

    private void UnregisterAllHandlers()
    {
        _handlersRegistered = false;
        var socket = SessionState.Socket;
        if (socket == null) return;
        if (_powHandler != null)
            socket.Off("pow_challenge", _powHandler);
        socket.Off("dns_result");
        socket.Off("dns_resolution");
        socket.Off("dns_progress");
        socket.Off("publish_result");
        socket.Off("network_nodes");
    }

    private void RegisterPowHandler()
    {
        var socket = SessionState.Socket;
        if (socket == null) return;
        if (_powHandler != null) socket.Off("pow_challenge", _powHandler);

        _powHandler = async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var actionType = payload.TryGetProperty("action_type", out var actProp) ? actProp.GetString() : null;
            if (string.Equals(actionType, "dns", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(actionType, "upload", StringComparison.OrdinalIgnoreCase))
                await HandlePowChallenge(payload);
        };
        socket.On("pow_challenge", _powHandler);
    }

    private void RegisterSocketHandlers()
    {
        var socket = SessionState.Socket;
        if (socket == null) return;

        socket.On("dns_result", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var s) && s.GetBoolean();
            var msg = success ? "DNS registrado com sucesso!" : payload.TryGetProperty("error", out var e) ? e.GetString() : "Erro desconhecido";
            MainThread.BeginInvokeOnMainThread(() => DnsStatusLabel.Text = msg);
        });

        socket.On("dns_resolution", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            MainThread.BeginInvokeOnMainThread(() =>
            {
                var domain = payload.TryGetProperty("domain", out var dom) ? dom.GetString() : "";
                var hash = payload.TryGetProperty("content_hash", out var h) ? h.GetString() : "";
                var owner = payload.TryGetProperty("owner", out var o) ? o.GetString() : "";
                if (!string.IsNullOrEmpty(hash))
                    ResolveResultLabel.Text = $"{domain} -> {hash[..Math.Min(hash.Length, 20)]}...{(string.IsNullOrEmpty(owner) ? "" : $" (dono: {owner})")}";
                else if (payload.TryGetProperty("error", out var e))
                    ResolveResultLabel.Text = $"Erro: {e.GetString()}";
                else if (payload.TryGetProperty("success", out var s) && s.GetBoolean())
                    ResolveResultLabel.Text = "Resolvido com sucesso.";
                else
                    ResolveResultLabel.Text = "Falha na resolucao.";
            });
        });

        socket.On("dns_progress", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var step = payload.TryGetProperty("step", out var stepProp) ? stepProp.GetString() : "";
            MainThread.BeginInvokeOnMainThread(() => DnsStatusLabel.Text = $"DNS: {step}");
        });

        socket.On("publish_result", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var s) && s.GetBoolean();
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (success)
                {
                    var hash = payload.TryGetProperty("content_hash", out var h) ? h.GetString() : "";
                    UploadStatusLabel.Text = $"Publicado! Hash: {hash?[..16]}...";
                    if (!string.IsNullOrEmpty(hash))
                    {
                        try
                        {
                            Clipboard.Default.SetTextAsync(hash);
                            _ = Task.Run(async () => { await Task.Delay(10000); try { await Clipboard.Default.SetTextAsync(""); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Clipboard] Clear failed: {ex.Message}"); } });
                        }
                        catch { }
                    }
                }
                else
                {
                    var error = payload.TryGetProperty("error", out var e) ? e.GetString() : "Erro desconhecido";
                    UploadStatusLabel.Text = $"Erro: {error}";
                }
            });
        });

        socket.On("network_nodes", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            MainThread.BeginInvokeOnMainThread(() =>
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("╔═══ NOS DA REDE ═══");
                if (payload.ValueKind == JsonValueKind.Array)
                {
                    foreach (var node in payload.EnumerateArray())
                    {
                        sb.AppendLine("║");
                        if (node.TryGetProperty("id", out var id))
                            sb.AppendLine($"║ ID: {id.GetString()?[..Math.Min(id.GetString()!.Length, 16)]}...");
                        if (node.TryGetProperty("address", out var addr))
                            sb.AppendLine($"║ Endereco: {addr.GetString()}");
                        if (node.TryGetProperty("port", out var port))
                            sb.AppendLine($"║ Porta: {port.GetInt32()}");
                        if (node.TryGetProperty("status", out var st))
                            sb.AppendLine($"║ Status: {st.GetString()}");
                        if (node.TryGetProperty("latency", out var lat))
                            sb.AppendLine($"║ Latencia: {lat.GetDouble():F0}ms");
                        if (node.TryGetProperty("version", out var ver))
                            sb.AppendLine($"║ Versao: {ver.GetString()}");
                    }
                }
                else
                {
                    if (payload.TryGetProperty("nodes", out var nodes) && nodes.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var node in nodes.EnumerateArray())
                        {
                            sb.AppendLine("║");
                            if (node.TryGetProperty("id", out var id))
                                sb.AppendLine($"║ ID: {id.GetString()?[..Math.Min(id.GetString()!.Length, 16)]}...");
                            if (node.TryGetProperty("address", out var addr))
                                sb.AppendLine($"║ Endereco: {addr.GetString()}");
                            if (node.TryGetProperty("port", out var port))
                                sb.AppendLine($"║ Porta: {port.GetInt32()}");
                            if (node.TryGetProperty("status", out var st))
                                sb.AppendLine($"║ Status: {st.GetString()}");
                        }
                    }
                    else if (payload.TryGetProperty("error", out var err))
                        sb.AppendLine($"║ Erro: {err.GetString()}");
                    else
                        sb.AppendLine($"║ {payload.GetRawText()}");
                }
                sb.AppendLine("╚════════════════════");
                NetworkLabel.Text = sb.ToString();
            });
        });
    }

    private void UpdateConnectionStatus()
    {
        var connected = SessionState.IsLoggedIn && SessionState.Socket.IsConnected;
        PublishButton.IsEnabled = connected && _selectedFileBytes != null;
    }

    private async void OnRegisterDns(object? sender, EventArgs e)
    {
        var domain = DomainEntry.Text?.Trim();
        var contentHash = DnsContentEntry.Text?.Trim();

        if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(contentHash))
        {
            DnsStatusLabel.Text = "Preencha dominio e hash do conteudo.";
            return;
        }

        if (!SessionState.Socket.IsConnected)
        {
            DnsStatusLabel.Text = "Conecte-se ao servidor primeiro.";
            return;
        }

        DnsStatusLabel.Text = "Solicitando PoW para registro DNS...";

        _powCts?.Cancel();
        _powCts = new CancellationTokenSource();

        await SessionState.Socket.EmitAsync("request_pow_challenge", new
        {
            client_identifier = Preferences.Get("client_id", Guid.NewGuid().ToString("N")),
            action_type = "dns"
        });

        var timeoutToken = _powCts.Token;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(20), timeoutToken);
                if (!timeoutToken.IsCancellationRequested)
                    MainThread.BeginInvokeOnMainThread(() => DnsStatusLabel.Text = "Timeout PoW.");
            }
            catch (TaskCanceledException) { }
        });
    }

    private void OnResolveCompleted(object? sender, EventArgs e)
    {
        OnResolveClicked(sender, e);
    }

    private async void OnResolveClicked(object? sender, EventArgs e)
    {
        var domain = ResolveEntry.Text?.Trim();
        if (string.IsNullOrEmpty(domain))
        {
            ResolveResultLabel.Text = "Digite um dominio.";
            return;
        }

        ResolveResultLabel.Text = "Resolvendo...";
        try
        {
            var result = await SessionState.Server.FetchJsonAsync($"/dns/{Uri.EscapeDataString(domain)}");
            if (result != null)
            {
                if (result.Value.TryGetProperty("content_hash", out var hashProp))
                {
                    var hash = hashProp.GetString() ?? "";
                    ResolveResultLabel.Text = $"{domain} -> {hash}";
                }
                else
                {
                    ResolveResultLabel.Text = result.Value.GetRawText();
                }
            }
            else
            {
                ResolveResultLabel.Text = $"Dominio nao encontrado: {domain}";
            }
        }
        catch (Exception ex)
        {
            ResolveResultLabel.Text = $"Erro: {ex.Message}";
        }
    }

    private async void OnSelectFile(object? sender, EventArgs e)
    {
        try
        {
            var result = await FilePicker.Default.PickAsync(new PickOptions
            {
                PickerTitle = "Selecione um arquivo para publicar"
            });

            if (result == null) return;

            _selectedFileName = result.FileName;
            _selectedFilePath = result.FullPath;

            UploadStatusLabel.Text = "Lendo arquivo...";
            using var stream = await result.OpenReadAsync();
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms);
            _selectedFileBytes = ms.ToArray();

            if (_selectedFileBytes.Length > 100 * 1024 * 1024)
            {
                UploadStatusLabel.Text = "Arquivo muito grande (max 100MB).";
                _selectedFileBytes = null;
                _selectedFilePath = null;
                PublishButton.IsEnabled = false;
                return;
            }

            UploadFileLabel.Text = $"{_selectedFileName} ({(double)_selectedFileBytes.Length / 1024:0.0} KB)";
            PublishButton.IsEnabled = SessionState.IsLoggedIn && SessionState.Socket.IsConnected;

            UploadStatusLabel.Text = "Preparando arquivo...";
            _selectedFileBase64 = await Task.Run(() => Convert.ToBase64String(_selectedFileBytes));
            UploadStatusLabel.Text = "Arquivo pronto para publicar.";
        }
        catch (Exception ex)
        {
            UploadStatusLabel.Text = $"Erro: {ex.Message}";
        }
    }

    private async void OnPublishClicked(object? sender, EventArgs e)
    {
        if (_selectedFileBytes == null) return;
        if (!SessionState.Socket.IsConnected || !SessionState.IsLoggedIn)
        {
            UploadStatusLabel.Text = "Conecte-se ao servidor primeiro.";
            return;
        }

        UploadStatusLabel.Text = "Solicitando PoW para publicacao...";

        _powCts?.Cancel();
        _powCts = new CancellationTokenSource();

        await SessionState.Socket.EmitAsync("request_pow_challenge", new
        {
            client_identifier = Preferences.Get("client_id", Guid.NewGuid().ToString("N")),
            action_type = "upload"
        });

        _pendingUploadTitle = UploadTitleEntry.Text?.Trim() ?? string.Empty;
    }

    private string _pendingUploadTitle = string.Empty;

    public async Task HandlePowChallenge(JsonElement payload)
    {
        _powCts?.Cancel();
        _powCts = new CancellationTokenSource();

        if (payload.TryGetProperty("error", out var errProp))
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                var type = payload.TryGetProperty("action_type", out var t) ? t.GetString() : "";
                if (type == "dns")
                    DnsStatusLabel.Text = $"Erro PoW: {errProp.GetString()}";
                else if (type == "upload")
                    UploadStatusLabel.Text = $"Erro PoW: {errProp.GetString()}";
            });
            return;
        }

        var challenge = payload.TryGetProperty("challenge", out var chalProp) ? chalProp.GetString() : null;
        var targetBits = payload.TryGetProperty("target_bits", out var bitsProp) ? bitsProp.GetInt32() : 0;
        var actionType = payload.TryGetProperty("action_type", out var actProp) ? actProp.GetString() : "";

        if (string.IsNullOrWhiteSpace(challenge) || targetBits <= 0) return;

        var popup = new PowPopup(actionType, targetBits);
        var shownTcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        popup.Opened += (_, _) => shownTcs.TrySetResult(null);
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            await this.ShowPopupAsync(popup);
        });
        await shownTcs.Task;

        var cts = _powCts;
        var challengeBytes = Convert.FromBase64String(challenge);
        _ = Task.Run(async () =>
        {
            try
            {
                var threads = Preferences.Get("pow_threads", 2);
                var solver = new PowSolver();

                var result = await solver.SolveAsync(challengeBytes, targetBits, threads, cts.Token, progress =>
                {
                    popup.UpdateProgress((long)progress.Attempts, progress.Hashrate);
                });

                if (result is null || cts.Token.IsCancellationRequested) return;

                var hashrate = result.Attempts / Math.Max(1, result.Elapsed.TotalSeconds);
                popup.AppendLog($"Nonce={result.Nonce}, bits={result.LeadingZeroBits}, {result.Elapsed.TotalSeconds:0.00}s, {hashrate:0} H/s");

                MainThread.BeginInvokeOnMainThread(() =>
                {
                    if (actionType == "dns")
                        DnsStatusLabel.Text = "Registrando DNS...";
                    else if (actionType == "upload")
                        UploadStatusLabel.Text = "Publicando...";
                });

                if (string.Equals(actionType, "dns", StringComparison.OrdinalIgnoreCase))
                {
                    await SubmitDnsRegistrationAsync(result.Nonce, hashrate);
                    popup.AutoClose(800);
                }
                else if (string.Equals(actionType, "upload", StringComparison.OrdinalIgnoreCase))
                {
                    await SubmitPublishAsync(result.Nonce, hashrate);
                    popup.AutoClose(800);
                }
            }
            catch (Exception ex)
            {
                popup.AppendLog($"Erro: {ex.Message}");
                popup.AutoClose(500);
            }
        });
    }

    private async Task SubmitDnsRegistrationAsync(ulong powNonce, double hashrateObserved)
    {
        if (SessionState.GetPrivateKey() is null)
        {
            MainThread.BeginInvokeOnMainThread(() =>
                DnsStatusLabel.Text = "Chave privada nao disponivel.");
            return;
        }

        var domain = DomainEntry.Text?.Trim() ?? string.Empty;
        var contentHash = DnsContentEntry.Text?.Trim() ?? string.Empty;

        var headerText = $"# HSYST P2P SERVICE\n# DOMAIN: {domain}\n# CONTENT_HASH: {contentHash}\n### :END START\n";
        var headerBytes = Encoding.UTF8.GetBytes(headerText);

        // Data to sign = everything after "### :END START"
        const string endMarker = "### :END START";
        var endIdx = headerText.IndexOf(endMarker, StringComparison.Ordinal) + endMarker.Length;
        var dataToSign = Encoding.UTF8.GetBytes(headerText[endIdx..]);

        var signatureBytes = SessionState.GetPrivateKey().SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var signatureB64 = Convert.ToBase64String(signatureBytes);

        var details = new Dictionary<string, string>
        {
            { "DOMAIN", domain },
            { "CONTENT_HASH", contentHash }
        };
        var contractText = BuildContractTemplate("register_dns", details);
        var signedContract = ApplyContractSignature(contractText, SessionState.GetPrivateKey(), SessionState.Username);
        var contractBytes = Encoding.UTF8.GetBytes(signedContract);

        // DDNS content = header + contract (server extracts contract from end)
        var ddnsBytes = new byte[headerBytes.Length + contractBytes.Length];
        Buffer.BlockCopy(headerBytes, 0, ddnsBytes, 0, headerBytes.Length);
        Buffer.BlockCopy(contractBytes, 0, ddnsBytes, headerBytes.Length, contractBytes.Length);
        var ddnsContentB64 = Convert.ToBase64String(ddnsBytes);

        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(SessionState.PublicKeyPem));

        MainThread.BeginInvokeOnMainThread(() =>
            DnsStatusLabel.Text = "Enviando registro DNS...");

        await SessionState.Socket.EmitAsync("register_dns", new
        {
            domain,
            ddns_content = ddnsContentB64,
            signature = signatureB64,
            public_key = publicKeyB64,
            pow_nonce = powNonce.ToString(),
            hashrate_observed = hashrateObserved
        });
    }

    private async Task SubmitPublishAsync(ulong powNonce, double hashrateObserved)
    {
        if (SessionState.GetPrivateKey() is null)
        {
            UploadStatusLabel.Text = "Chave privada nao disponivel.";
            return;
        }
        if (_selectedFileBytes == null && _selectedFileBase64 == null) return;

        var title = _pendingUploadTitle;
        var mimeType = GetMimeType(_selectedFileName);

        // Recover raw bytes
        byte[] rawBytes;
        if (_selectedFileBytes != null)
            rawBytes = _selectedFileBytes;
        else
            rawBytes = Convert.FromBase64String(_selectedFileBase64!);

        // Compute content hash (SHA256 of raw content)
        var contentHash = Convert.ToHexString(SHA256.HashData(rawBytes)).ToLowerInvariant();

        // Sign the raw content bytes
        var signature = SessionState.GetPrivateKey().SignData(rawBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var signatureB64 = Convert.ToBase64String(signature);

        // Public key (PEM) base64-encoded
        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(SessionState.PublicKeyPem));

        var safeTitle = string.IsNullOrWhiteSpace(title) ? _selectedFileName : title;
        var details = new Dictionary<string, string>
        {
            { "FILE_NAME", _selectedFileName },
            { "FILE_SIZE", rawBytes.Length.ToString() },
            { "FILE_HASH", contentHash },
            { "TITLE", safeTitle },
            { "MIME", mimeType },
            { "DESCRIPTION", "" },
            { "PUBLIC_KEY", publicKeyB64 }
        };
        var contractText = BuildContractTemplate("upload_file", details);
        var signedContract = ApplyContractSignature(contractText, SessionState.GetPrivateKey(), SessionState.Username);

        // Embed signed contract at the end of content bytes
        var contractBytes = Encoding.UTF8.GetBytes(signedContract);
        var fullContent = new byte[rawBytes.Length + contractBytes.Length];
        Buffer.BlockCopy(rawBytes, 0, fullContent, 0, rawBytes.Length);
        Buffer.BlockCopy(contractBytes, 0, fullContent, rawBytes.Length, contractBytes.Length);
        var fullContentB64 = Convert.ToBase64String(fullContent);

        // Free raw data
        _selectedFileBytes = null;
        _selectedFileBase64 = null;
        _selectedFilePath = null;

        MainThread.BeginInvokeOnMainThread(() => UploadStatusLabel.Text = "Publicando conteudo...");

        await SessionState.Socket.EmitAsync("publish_content", new
        {
            content_hash = contentHash,
            title = safeTitle,
            description = "",
            mime_type = mimeType,
            size = rawBytes.Length,
            signature = signatureB64,
            public_key = publicKeyB64,
            content_b64 = fullContentB64,
            pow_nonce = powNonce.ToString(),
            hashrate_observed = hashrateObserved,
            hps_payment = (object?)null
        });

        _pendingUploadTitle = string.Empty;
        MainThread.BeginInvokeOnMainThread(() =>
        {
            UploadFileLabel.Text = "Nenhum arquivo selecionado";
            PublishButton.IsEnabled = false;
        });
    }

    private async void OnSyncNetwork(object? sender, EventArgs e)
    {
        if (!SessionState.Socket.IsConnected)
        {
            NetworkLabel.Text = "Conecte-se ao servidor primeiro.";
            return;
        }

        NetworkLabel.Text = "Sincronizando...";
        await SessionState.Socket.EmitAsync("sync_servers", new { });
    }

    private static string BuildContractTemplate(string actionType, Dictionary<string, string> details)
    {
        if (!details.ContainsKey("NONCE"))
            details["NONCE"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        if (!details.ContainsKey("TIMESTAMP"))
            details["TIMESTAMP"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

        var lines = new List<string>
        {
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            $"# ACTION: {actionType}"
        };
        foreach (var kv in details)
            lines.Add($"# {kv.Key}: {kv.Value}");
        lines.Add("### :END DETAILS");
        lines.Add("### START:");
        lines.Add($"# USER: {SessionState.Username}");
        lines.Add("# SIGNATURE: ");
        lines.Add("### :END START");
        lines.Add("## :END CONTRACT");
        return string.Join("\n", lines) + "\n";
    }

    private static string ApplyContractSignature(string contractText, System.Security.Cryptography.RSA privateKey, string username)
    {
        const string signaturePlaceholder = "# SIGNATURE:";
        var trimmed = contractText.TrimEnd('\r', '\n');
        var lines = trimmed.Split('\n').ToList();
        var signatureIndex = lines.FindIndex(line => line.TrimStart().StartsWith(signaturePlaceholder, StringComparison.Ordinal));
        if (signatureIndex < 0) return contractText;

        var signedLines = new List<string>();
        for (var i = 0; i < lines.Count; i++)
        {
            if (i == signatureIndex) continue;
            signedLines.Add(lines[i]);
        }
        var signedText = string.Join("\n", signedLines);
        var signature = CryptoUtils.SignPayload(privateKey, signedText);
        var signatureB64 = Convert.ToBase64String(signature);
        lines[signatureIndex] = $"{signaturePlaceholder} {signatureB64}";
        return string.Join("\n", lines).TrimEnd() + "\n";
    }

    private static string GetMimeType(string filename)
    {
        var ext = Path.GetExtension(filename)?.ToLowerInvariant();
        return ext switch
        {
            ".txt" => "text/plain",
            ".html" or ".htm" => "text/html",
            ".json" => "application/json",
            ".xml" => "application/xml",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".webp" => "image/webp",
            ".pdf" => "application/pdf",
            ".mp4" => "video/mp4",
            ".mp3" => "audio/mpeg",
            ".zip" => "application/zip",
            _ => "application/octet-stream"
        };
    }
}