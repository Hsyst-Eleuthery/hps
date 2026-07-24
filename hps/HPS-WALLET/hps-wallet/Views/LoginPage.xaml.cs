using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HpsWallet.Services;

namespace HpsWallet.Views;

public partial class LoginPage : ContentPage
{
    private readonly CryptoService _crypto = new();
    private RSA? _privateKey;
    private string _publicKeyPem = string.Empty;
    private string _clientAuthChallenge = string.Empty;
    private string _clientId = string.Empty;
    private bool _isLoggingIn;
    private bool _authCompleted;
    private CancellationTokenSource? _powCts;
    private TaskCompletionSource? _authSignalTcs;

    public LoginPage()
    {
        InitializeComponent();
        ServerEntry.Text = Preferences.Get("wallet_server", "");
        SslSwitch.IsToggled = Preferences.Get("wallet_use_ssl", false);
        // Use SecureStorage for username
        _ = LoadUsernameAsync();
        // Use SecureStorage for client ID
        _ = LoadClientIdAsync();
        UpdateRecentServers();
    }

    private async Task LoadUsernameAsync()
    {
        var username = await SecureStorageHelper.GetUsernameAsync();
        if (string.IsNullOrEmpty(username))
        {
            username = Preferences.Get("wallet_username", string.Empty);
        }
        UsernameEntry.Text = username;
    }

    private async Task LoadClientIdAsync()
    {
        _clientId = await SecureStorageHelper.GetClientIdAsync();
        if (string.IsNullOrEmpty(_clientId))
        {
            _clientId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            await SecureStorageHelper.SetClientIdAsync(_clientId);
        }
    }

    private void UpdateRecentServers()
    {
        var known = Preferences.Get("wallet_known_servers", "");
        if (!string.IsNullOrEmpty(known))
        {
            var servers = known.Split(',').Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)).ToList();
            RecentServersLabel.Text = string.Join("\n", servers.Select(s => $"  › {s}"));
            RecentServersLabel.GestureRecognizers.Clear();
            var tapGesture = new TapGestureRecognizer();
            tapGesture.Tapped += (_, _) =>
            {
                var first = servers.FirstOrDefault();
                if (first != null) ServerEntry.Text = first;
            };
            RecentServersLabel.GestureRecognizers.Add(tapGesture);
        }
    }

    private async void OnConnectClicked(object? sender, EventArgs e)
    {
        if (_isLoggingIn) return;

        var server = ServerEntry.Text?.Trim();
        var username = UsernameEntry.Text?.Trim();
        var password = PasswordEntry.Text;
        var useSsl = SslSwitch.IsToggled;

        if (string.IsNullOrEmpty(server) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            SetStatus("Preencha todos os campos.");
            return;
        }

        _isLoggingIn = true;
        _authCompleted = false;
        ConnectButton.IsEnabled = false;
        ConnectButton.Text = "Conectando...";
        ProgressFrame.IsVisible = true;
        ProgressBar.Progress = 0;

        try
        {
            SetStatus("");
            SavePreferences(server, username, useSsl);

            SessionState.ServerAddress = server;
            SessionState.Username = username;
            SessionState.UseSsl = useSsl;

            UpdateProgress("Preparando chaves criptograficas...", 0.1);
            if (!LoadKeys(username, password))
            {
                SetStatus("Falha ao carregar chaves. Verifique usuario e senha.");
                return;
            }
            SessionState.SetPrivateKey(_privateKey);
            SessionState.PublicKeyPem = _publicKeyPem;

            UpdateProgress("Conectando ao servidor...", 0.25);
            if (!await ConnectSocketAsync(server, useSsl))
            {
                SetStatus("Falha ao conectar ao servidor.");
                return;
            }

            UpdateProgress("Aguardando autenticacao...", 0.5);
            _authSignalTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var authTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));

            var socket = SessionState.Socket;
            EventHandler? onReconnected = null;
            onReconnected = (_, _) =>
            {
                if (_isLoggingIn && !_authCompleted)
                {
                    System.Diagnostics.Debug.WriteLine("[Login] Reconnected during auth, re-registering handlers");
                    ReRegisterAuthHandlers(socket);
                }
            };
            socket.Connected += onReconnected;
            try
            {
                var completedSignal = await Task.WhenAny(_authSignalTcs.Task, Task.Delay(Timeout.Infinite, authTimeout.Token));
                if (completedSignal != _authSignalTcs.Task || !_authCompleted)
                {
                    SetStatus("Falha na autenticacao (timeout).");
                    return;
                }
            }
            finally
            {
                socket.Connected -= onReconnected;
            }

            UpdateProgress("Login realizado!", 1.0);
            SessionState.IsLoggedIn = true;
            await Task.Delay(500);

            var events = new[] { "status", "request_server_auth_challenge", "server_auth_challenge",
                "server_auth_result", "usage_contract_required", "usage_contract_status",
                "usage_contract_ack", "authentication_result", "flow_progress", "action_queue_update",
                "pow_challenge" };
            foreach (var ev in events) socket.Off(ev);

            Application.Current!.Windows[0].Page = new NavigationPage(new Views.WalletMainPage())
            {
                BarBackgroundColor = Color.FromArgb("#1A0A2E"),
                BarTextColor = Colors.White
            };
        }
        catch (Exception ex)
        {
            SetStatus($"Erro: {ex.Message}");
        }
        finally
        {
            _isLoggingIn = false;
            ConnectButton.IsEnabled = true;
            ConnectButton.Text = "Entrar na Rede";
        }
    }

    private bool LoadKeys(string username, string password)
    {
        try
        {
            if (!_crypto.UserKeyMaterialExists(username))
                UpdateProgress("Primeiro acesso: gerando chaves RSA de 4096 bits...", 0.15);
            var (privateKey, publicKeyPem) = _crypto.LoadOrCreateKeys(username, password);
            _privateKey?.Dispose();
            _privateKey = privateKey;
            _publicKeyPem = publicKeyPem;
            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[Login] Key error: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> ConnectSocketAsync(string server, bool useSsl)
    {
        var scheme = useSsl ? "https" : "http";
        var url = $"{scheme}://{server.TrimEnd('/')}";

        var socket = SessionState.Socket;

        socket.On("flow_progress", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var stepLabel = payload.TryGetProperty("step_label", out var sl) ? sl.GetString() : null;
            var stepIndex = payload.TryGetProperty("step_index", out var si) ? si.GetInt32() : 0;
            var totalSteps = payload.TryGetProperty("total_steps", out var ts) ? ts.GetInt32() : 3;
            if (!string.IsNullOrEmpty(stepLabel))
            {
                var progress = 0.5 + (stepIndex / (double)Math.Max(1, totalSteps)) * 0.4;
                UpdateProgress(stepLabel, Math.Min(progress, 0.9));
            }
        });
        socket.On("action_queue_update", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var status = payload.TryGetProperty("status", out var s) ? s.GetString() : null;
            var position = payload.TryGetProperty("position", out var p) ? p.GetInt32() : 0;
            if (status == "queued" && position > 0)
                UpdateProgress($"Na fila (posicao {position})...", 0.45);
        });
        socket.On("request_server_auth_challenge", async _ =>
        {
            await socket.EmitAsync("request_server_auth_challenge", new { });
        });
        socket.On("server_auth_challenge", HandleServerAuthChallenge);
        socket.On("server_auth_result", HandleServerAuthResult);
        socket.On("usage_contract_required", HandleUsageContractRequired);
        socket.On("usage_contract_status", HandleUsageContractStatus);
        socket.On("usage_contract_ack", HandleUsageContractAck);
        socket.On("pow_challenge", HandlePowChallenge);
        socket.On("authentication_result", HandleAuthenticationResult);

        try
        {
            await socket.ConnectAsync(url);
            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[Login] Connect error: {ex.Message}");
            return false;
        }
    }

    private void ReRegisterAuthHandlers(HpsSocketService socket)
    {
        socket.Off("flow_progress");
        socket.Off("action_queue_update");
        socket.Off("request_server_auth_challenge");
        socket.Off("server_auth_challenge");
        socket.Off("server_auth_result");
        socket.Off("usage_contract_required");
        socket.Off("usage_contract_status");
        socket.Off("usage_contract_ack");
        socket.Off("pow_challenge");
        socket.Off("authentication_result");

        socket.On("flow_progress", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var stepLabel = payload.TryGetProperty("step_label", out var sl) ? sl.GetString() : null;
            var stepIndex = payload.TryGetProperty("step_index", out var si) ? si.GetInt32() : 0;
            var totalSteps = payload.TryGetProperty("total_steps", out var ts) ? ts.GetInt32() : 3;
            if (!string.IsNullOrEmpty(stepLabel))
            {
                var progress = 0.5 + (stepIndex / (double)Math.Max(1, totalSteps)) * 0.4;
                UpdateProgress(stepLabel, Math.Min(progress, 0.9));
            }
        });
        socket.On("action_queue_update", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var status = payload.TryGetProperty("status", out var s) ? s.GetString() : null;
            var position = payload.TryGetProperty("position", out var p) ? p.GetInt32() : 0;
            if (status == "queued" && position > 0)
                UpdateProgress($"Na fila (posicao {position})...", 0.45);
        });
        socket.On("request_server_auth_challenge", async _ =>
        {
            await socket.EmitAsync("request_server_auth_challenge", new { });
        });
        socket.On("server_auth_challenge", HandleServerAuthChallenge);
        socket.On("server_auth_result", HandleServerAuthResult);
        socket.On("usage_contract_required", HandleUsageContractRequired);
        socket.On("usage_contract_status", HandleUsageContractStatus);
        socket.On("usage_contract_ack", HandleUsageContractAck);
        socket.On("pow_challenge", HandlePowChallenge);
        socket.On("authentication_result", HandleAuthenticationResult);
    }

    private async Task HandleServerAuthChallenge(SocketEventResponse response)
    {
        var payload = response.GetValue<JsonElement>();
        if (!payload.TryGetProperty("challenge", out var challengeProp) ||
            !payload.TryGetProperty("server_public_key", out var serverKeyProp) ||
            !payload.TryGetProperty("signature", out var signatureProp))
        {
            SetStatus("Falha na autenticacao: dados incompletos");
            return;
        }

        var challenge = challengeProp.GetString() ?? string.Empty;
        var serverPublicKeyB64 = serverKeyProp.GetString() ?? string.Empty;
        var signatureB64 = signatureProp.GetString() ?? string.Empty;

        try
        {
            var serverPemBytes = Convert.FromBase64String(serverPublicKeyB64);
            var serverPem = Encoding.UTF8.GetString(serverPemBytes);
            var sigBytes = Convert.FromBase64String(signatureB64);
            var ok = CryptoUtils.VerifyServerSignature(serverPem, serverPublicKeyB64, challenge, sigBytes);
            if (!ok) { SetStatus("Falha na autenticacao: assinatura do servidor invalida"); return; }

            _clientAuthChallenge = CryptoUtils.GenerateToken();
            if (_privateKey is null) { SetStatus("Falha ao assinar desafio"); return; }

            var clientSignature = CryptoUtils.SignPayload(_privateKey, _clientAuthChallenge);
            var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(_publicKeyPem));

            await SessionState.Socket.EmitAsync("verify_server_auth_response", new
            {
                client_challenge = _clientAuthChallenge,
                client_signature = Convert.ToBase64String(clientSignature),
                client_public_key = publicKeyB64
            });

            MainThread.BeginInvokeOnMainThread(() => UpdateProgress("Servidor autenticado. Preparando login...", 0.6));
        }
        catch (Exception ex) { SetStatus($"Erro na autenticacao: {ex.Message}"); }
    }

    private async Task HandleServerAuthResult(SocketEventResponse response)
    {
        var payload = response.GetValue<JsonElement>();
        var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
        if (!success)
        {
            var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
            SetStatus($"Falha na autenticacao do servidor: {error}");
            return;
        }
        UpdateProgress("Servidor autenticado com sucesso", 0.65);
        await SessionState.Socket.EmitAsync("request_usage_contract", new { username = SessionState.Username.Trim() });
    }

    private async Task HandleUsageContractRequired(SocketEventResponse response)
    {
        var payload = response.GetValue<JsonElement>();
        var contractHash = payload.TryGetProperty("contract_hash", out var hashProp) ? hashProp.GetString() : null;
        var contractText = payload.TryGetProperty("contract_text", out var textProp) ? textProp.GetString() : null;

        if (string.IsNullOrWhiteSpace(contractHash))
        {
            SetStatus("Contrato de uso nao disponivel no servidor.");
            return;
        }

        var template = BuildUsageContractTemplate(contractText ?? string.Empty, contractHash.Trim(), SessionState.Username.Trim());

        var accepted = await MainThread.InvokeOnMainThreadAsync(async () =>
        {
            var msg = string.IsNullOrWhiteSpace(contractText)
                ? "O servidor requer aceitacao do contrato de uso para continuar."
                : template;
            return await DisplayAlertAsync("Contrato de Uso", msg, "Aceitar", "Recusar");
        });

        if (!accepted)
        {
            SetStatus("Contrato de uso nao aceito. Login cancelado.");
            return;
        }

        if (_privateKey is null) { SetStatus("Chave privada nao disponivel."); return; }

        var signedContract = ApplyContractSignature(template, _privateKey, SessionState.Username.Trim());
        SessionState.PendingUsageContractText = signedContract;
        UpdateProgress("Contrato de uso aceito. Solicitando PoW...", 0.7);
        await RequestPowChallengeAsync("usage_contract");
    }

    private async Task HandleUsageContractStatus(SocketEventResponse response)
    {
        var payload = response.GetValue<JsonElement>();
        var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
        if (!success)
        {
            var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
            SetStatus($"Falha no contrato de uso: {error}");
            return;
        }
        var required = payload.TryGetProperty("required", out var reqProp) && reqProp.GetBoolean();
        if (!required)
        {
            UpdateProgress("Solicitando desafio PoW para login...", 0.7);
            await RequestPowChallengeAsync("login");
        }
    }

    private async Task HandleUsageContractAck(SocketEventResponse response)
    {
        var payload = response.GetValue<JsonElement>();
        if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
        {
            SetStatus("Contrato de uso pendente de analise...");
            return;
        }

        var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
        if (!success)
        {
            var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
            SetStatus($"Falha no contrato de uso: {error}");
            return;
        }

        var deferredPayment = payload.TryGetProperty("deferred_payment", out var deferredProp) && deferredProp.GetBoolean();
        if (deferredPayment)
        {
            UpdateProgress("Contrato aceito via minerador. Continuando...", 0.85);
            return;
        }

        UpdateProgress("Contrato de uso aceito. Solicitando PoW para login...", 0.75);
        await RequestPowChallengeAsync("login");
    }

    private async Task RequestPowChallengeAsync(string actionType)
    {
        await SessionState.Socket.EmitAsync("request_pow_challenge", new
        {
            client_identifier = _clientId,
            action_type = actionType
        });
    }

    private async Task HandlePowChallenge(SocketEventResponse response)
    {
        _powCts?.Cancel();
        var payload = response.GetValue<JsonElement>();

        if (payload.TryGetProperty("error", out var errProp))
        {
            SetStatus($"Erro PoW: {errProp.GetString()}");
            return;
        }

        var challenge = payload.TryGetProperty("challenge", out var chalProp) ? chalProp.GetString() : null;
        var targetBits = payload.TryGetProperty("target_bits", out var bitsProp) ? bitsProp.GetInt32() : 0;
        var actionType = payload.TryGetProperty("action_type", out var actProp) ? actProp.GetString() : "login";

        if (string.IsNullOrWhiteSpace(challenge) || targetBits <= 0)
        {
            SetStatus("Desafio PoW invalido");
            return;
        }

        UpdateProgress($"Resolvendo PoW: {targetBits} bits para {actionType}...", 0.8);

        var challengeBytes = Convert.FromBase64String(challenge);
        _powCts = new CancellationTokenSource();

        // Run PoW on background thread to avoid blocking the socket receive loop
        var cts = _powCts;
        var powThreads = Preferences.Get("wallet_pow_threads", 2);
        _ = Task.Run(async () =>
        {
            var solver = new PowSolver();
            var result = await solver.SolveAsync(challengeBytes, targetBits, powThreads, cts.Token, progress =>
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    UpdateProgress($"PoW: {progress.Attempts} tentativas, {progress.Hashrate:0} H/s", 0.8);
                });
            });

            if (result is null)
            {
                SetStatus("PoW cancelado ou nao resolvido.");
                return;
            }

            var hashrate = result.Attempts / Math.Max(1, result.Elapsed.TotalSeconds);
            UpdateProgress($"PoW resolvido ({result.Elapsed.TotalSeconds:0.0}s). Enviando...", 0.9);

            if (string.Equals(actionType, "login", StringComparison.OrdinalIgnoreCase))
                await SendAuthenticationAsync(result.Nonce, hashrate);
            else if (string.Equals(actionType, "usage_contract", StringComparison.OrdinalIgnoreCase))
                await SubmitPendingUsageContractAsync(result.Nonce, hashrate);
        });
    }

    private async Task SendAuthenticationAsync(ulong powNonce, double hashrateObserved)
    {
        if (_privateKey is null) { SetStatus("Chave privada nao disponivel"); return; }
        if (string.IsNullOrWhiteSpace(_clientAuthChallenge)) { SetStatus("Desafio do cliente ausente"); return; }

        var clientSignature = CryptoUtils.SignPayload(_privateKey, _clientAuthChallenge);
        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(_publicKeyPem));

        UpdateProgress("Enviando login...", 0.95);
        await SessionState.Socket.EmitAsync("authenticate", new
        {
            username = SessionState.Username,
            public_key = publicKeyB64,
            node_type = "wallet",
            client_identifier = _clientId,
            pow_nonce = powNonce.ToString(),
            hashrate_observed = hashrateObserved,
            client_challenge_signature = Convert.ToBase64String(clientSignature),
            client_challenge = _clientAuthChallenge
        });
    }

    private async Task SubmitPendingUsageContractAsync(ulong powNonce, double hashrateObserved)
    {
        var contractContent = SessionState.PendingUsageContractText;
        if (string.IsNullOrWhiteSpace(contractContent))
        {
            SetStatus("Nenhum contrato de uso pendente.");
            return;
        }

        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(_publicKeyPem));

        await SessionState.Socket.EmitAsync("accept_usage_contract", new
        {
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contractContent)),
            public_key = publicKeyB64,
            client_identifier = _clientId,
            username = SessionState.Username.Trim(),
            pow_nonce = powNonce.ToString(),
            hashrate_observed = hashrateObserved
        });

        UpdateProgress("Contrato de uso enviado. Aguardando confirmacao...", 0.85);
    }

    private async Task HandleAuthenticationResult(SocketEventResponse response)
    {
        var payload = response.GetValue<JsonElement>();
        var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
        if (!success)
        {
            var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
            SetStatus($"Falha no login: {error}");
            return;
        }

        var serverUsername = payload.TryGetProperty("username", out var userProp) ? userProp.GetString() : null;
        if (string.IsNullOrEmpty(serverUsername) || !string.Equals(serverUsername, SessionState.Username, StringComparison.OrdinalIgnoreCase))
        {
            var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : null;
            SetStatus($"Falha no login: {error ?? "username do servidor nao corresponde ao informado"}");
            return;
        }

        SessionState.Username = serverUsername;
        UpdateProgress("Login bem-sucedido!", 1.0);
        _authCompleted = true;
        _authSignalTcs?.TrySetResult();
    }

    private static string BuildUsageContractTemplate(string termsText, string contractHash, string username)
    {
        var lines = new List<string>
        {
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            "# ACTION: accept_usage",
            $"# USAGE_CONTRACT_HASH: {contractHash}",
            "### :END DETAILS",
            "### TERMS:"
        };
        foreach (var line in termsText.Split('\n'))
            lines.Add($"# {line}");
        lines.Add("### :END TERMS");
        lines.Add("### START:");
        lines.Add($"# USER: {username}");
        lines.Add("# SIGNATURE: ");
        lines.Add("### :END START");
        lines.Add("## :END CONTRACT");
        return string.Join("\n", lines) + "\n";
    }

    private static string ApplyContractSignature(string contractText, RSA privateKey, string username)
    {
        const string signaturePlaceholder = "# SIGNATURE:";
        const string userPlaceholder = "# USER:";

        var trimmed = contractText.TrimEnd('\r', '\n');
        var lines = trimmed.Split('\n').ToList();
        var signatureIndex = lines.FindIndex(line => line.TrimStart().StartsWith(signaturePlaceholder, StringComparison.Ordinal));
        if (signatureIndex < 0) return contractText;

        var userIndex = lines.FindIndex(line => line.TrimStart().StartsWith(userPlaceholder, StringComparison.Ordinal));
        if (userIndex >= 0) lines[userIndex] = $"{userPlaceholder} {username}";

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

    private void SavePreferences(string server, string username, bool useSsl)
    {
        Preferences.Set("wallet_server", server);
        // Use SecureStorage for username
        _ = SecureStorageHelper.SetUsernameAsync(username);
        Preferences.Set("wallet_use_ssl", useSsl);
        var known = Preferences.Get("wallet_known_servers", "");
        var servers = string.IsNullOrEmpty(known)
            ? server
            : string.Join(", ", known.Split(',').Select(s => s.Trim()).Prepend(server).Distinct().Take(5));
        Preferences.Set("wallet_known_servers", servers);
        UpdateRecentServers();
    }

    private void UpdateProgress(string text, double progress)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            ProgressTitle.Text = text;
            ProgressBar.ProgressTo(progress, 300, Easing.SinInOut);
        });
    }

    private void SetStatus(string msg)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            if (!string.IsNullOrEmpty(msg)) StatusLabel.Text = msg;
        });
    }
}
