using System.Text;
using System.Text.Json;
using CommunityToolkit.Maui.Views;
using CommunityToolkit.Maui.Extensions;
using HpsMobile.Services;

namespace HpsMobile.Views;

public partial class MiningPage : ContentPage
{
    private CancellationTokenSource? _powCts;
    private bool _isMining;
    private bool _isContinuousMiningInFlight;
    private string _pendingHpsMintVoucherId = string.Empty;
    private int _minedCount;
    private double _totalMiningSeconds;
    private bool _isActive;

    private Func<SocketEventResponse, Task>? _powHandler;

    public MiningPage()
    {
        InitializeComponent();
        RegisterSocketHandlers();
        LoadSettings();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        _isActive = true;
        RegisterPowHandler();
        UpdateConnectionStatus();
        // Force layout refresh to recover from popup close corruption
        MainThread.BeginInvokeOnMainThread(() => ForceLayout());
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _isActive = false;
        _powCts?.Cancel();
        if (_powHandler != null)
            SessionState.Socket?.Off("pow_challenge", _powHandler);
        MainThread.BeginInvokeOnMainThread(() =>
        {
            _isMining = false;
            _isContinuousMiningInFlight = false;
            StopButton.IsVisible = false;
            MintButton.Text = "Mineração Única";
            MiningStatusLabel.Text = "Parado";
            MiningSpinner.IsRunning = false;
            MiningSpinner.IsVisible = false;
        });
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
            if (string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
                await HandlePowChallenge(payload);
        };
        socket.On("pow_challenge", _powHandler);
    }

    private void LoadSettings()
    {
        ContinuousSwitch.IsToggled = Preferences.Get("continuous_mining", false);
        ThreadsSlider.Value = Preferences.Get("pow_threads", 2);
        ThreadsLabel.Text = $"Threads PoW: {(int)ThreadsSlider.Value}";
    }

    private void RegisterSocketHandlers()
    {
        var socket = SessionState.Socket;
        if (socket == null) return;

        socket.On("hps_voucher_issued", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("voucher_id", out var vidProp))
            {
                var voucherId = vidProp.GetString() ?? string.Empty;
                var value = payload.TryGetProperty("value", out var valProp) ? valProp.GetInt32() : 0;
                AppendLog($"Voucher emitido: {voucherId} valor={value}");
                _minedCount++;
                UpdateStats();
                MintStatusLabel.Text = value > 0 ? $"Voucher de {value} $HPS emitido!" : "Voucher emitido!";
                MintStatusLabel.TextColor = Color.FromArgb("#34D399");
                ScheduleNextMining();
            }
        });
        socket.On("hps_voucher_offer", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var voucherId = payload.TryGetProperty("voucher_id", out var vidProp) ? vidProp.GetString() : null;
            if (string.IsNullOrEmpty(voucherId) || SessionState.GetPrivateKey() is null)
                return;

            var payloadCanonical = payload.TryGetProperty("payload_canonical", out var pcProp) && pcProp.ValueKind == JsonValueKind.String
                ? pcProp.GetString()
                : null;
            if (string.IsNullOrEmpty(payloadCanonical))
            {
                AppendLog($"Voucher {voucherId} sem payload canonical");
                return;
            }

            AppendLog($"Confirmando voucher: {voucherId}");
            var signature = CryptoUtils.SignPayload(SessionState.GetPrivateKey(), payloadCanonical);
            var signatureB64 = Convert.ToBase64String(signature);
            await SessionState.Socket.EmitAsync("confirm_hps_voucher", new
            {
                voucher_id = voucherId,
                owner_signature = signatureB64,
                payload_signed_text = payloadCanonical
            });
            AppendLog($"Voucher {voucherId} assinado e confirmado.");
        });

        socket.On("hps_voucher_withheld", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var value = payload.TryGetProperty("value", out var vProp) ? vProp.GetInt32() : 0;
            var debtStatus = payload.TryGetProperty("debt_status", out var dProp) ? dProp.GetString() : null;
            AppendLog($"Voucher retido{(value > 0 ? $" valor={value}" : "")}{(debtStatus != null ? $" divida={debtStatus}" : "")}");
            ScheduleNextMining();
        });

        socket.On("hps_voucher_error", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var error = payload.TryGetProperty("error", out var eProp) ? eProp.GetString() : "Erro desconhecido";
            AppendLog($"Erro no voucher: {error}");
            ScheduleNextMining();
        });

        socket.On("hps_economy_update", async response =>
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                var payload = response.GetValue<JsonElement>();
                if (payload.TryGetProperty("multiplier", out var multProp))
                    StatBitsLabel.Text = multProp.GetDouble().ToString("F1");
            });
        });
    }

    private void UpdateConnectionStatus()
    {
        if (!SessionState.IsLoggedIn || !SessionState.Socket.IsConnected)
        {
            MintButton.IsEnabled = false;
            MintButton.Text = "Conecte-se primeiro";
            MiningStatusLabel.Text = "Desconectado";
            MiningStatusLabel.TextColor = Color.FromArgb("#F87171");
            MiningSpinner.IsRunning = false;
            MiningSpinner.IsVisible = false;
        }
        else
        {
            MintButton.IsEnabled = true;
            MintButton.Text = _isMining ? "Minerando..." : "Mineração Única";
            MiningStatusLabel.Text = "Pronto";
            MiningStatusLabel.TextColor = Color.FromArgb("#34D399");
            if (!_isMining)
            {
                MiningSpinner.IsRunning = false;
                MiningSpinner.IsVisible = false;
            }
        }
    }

    private async void OnMintClicked(object? sender, EventArgs e)
    {
        if (_isMining || !SessionState.IsLoggedIn) return;
        await StartHpsMintAsync();
    }

    private async void OnStopClicked(object? sender, EventArgs e)
    {
        _powCts?.Cancel();
        _isMining = false;
        _isContinuousMiningInFlight = false;
        StopButton.IsVisible = false;
        MintButton.Text = "Mineração Única";
        MiningStatusLabel.Text = "Parado";
        MiningStatusLabel.TextColor = Color.FromArgb("#FCA5A5");
        MiningSpinner.IsRunning = false;
        MiningSpinner.IsVisible = false;
    }

    private void OnContinuousToggled(object? sender, ToggledEventArgs e)
    {
        Preferences.Set("continuous_mining", e.Value);
        if (e.Value && SessionState.IsLoggedIn && SessionState.Socket.IsConnected)
            _ = StartContinuousMiningAsync();
    }

    private void OnThreadsChanged(object? sender, ValueChangedEventArgs e)
    {
        ThreadsLabel.Text = $"Threads PoW: {(int)e.NewValue}";
        Preferences.Set("pow_threads", (int)e.NewValue);
    }

    private async Task StartHpsMintAsync()
    {
        if (!SessionState.IsLoggedIn || !SessionState.Socket.IsConnected)
        {
            MintStatusLabel.Text = "Conecte-se a rede para minerar HPS.";
            return;
        }

        _pendingHpsMintVoucherId = string.Empty;
        _isMining = true;
        StopButton.IsVisible = true;
        MintButton.Text = "Minerando...";
        MiningStatusLabel.Text = "Solicitando PoW";
        MiningStatusLabel.TextColor = Color.FromArgb("#FBBF24");
        MintStatusLabel.Text = "Solicitando PoW para mineracao...";
        MiningSpinner.IsRunning = true;
        MiningSpinner.IsVisible = true;
        AppendLog("Solicitando desafio de PoW para mineracao.");
        await RequestPowChallengeAsync("hps_mint");
    }

    private async Task StartContinuousMiningAsync()
    {
        if (!ContinuousSwitch.IsToggled || _isContinuousMiningInFlight) return;
        if (!SessionState.IsLoggedIn || !SessionState.Socket.IsConnected)
        {
            MiningStatusLabel.Text = "Aguardando conexao";
            return;
        }

        _isContinuousMiningInFlight = true;
        await StartHpsMintAsync();
    }

    private void ScheduleNextMining()
    {
        _isContinuousMiningInFlight = false;
        if (!ContinuousSwitch.IsToggled) return;
        // M9: Increase delay between mining cycles to reduce server load and prevent rate limiting
        _ = Task.Delay(5000).ContinueWith(_ =>
        {
            if (_isActive)
                MainThread.BeginInvokeOnMainThread(() => _ = StartContinuousMiningAsync());
        }, TaskContinuationOptions.ExecuteSynchronously);
    }

    private async Task RequestPowChallengeAsync(string actionType)
    {
        if (!SessionState.Socket.IsConnected)
        {
            MintStatusLabel.Text = "Conexao perdida.";
            _isMining = false;
            _isContinuousMiningInFlight = false;
            StopButton.IsVisible = false;
            MintButton.Text = "Mineração Única";
            return;
        }

        await SessionState.Socket.EmitAsync("request_pow_challenge", new
        {
            client_identifier = Preferences.Get("client_id", Guid.NewGuid().ToString("N")),
            action_type = actionType
        });

        _powCts?.Cancel();
        _powCts = new CancellationTokenSource();

        var timeoutToken = _powCts.Token;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(15), timeoutToken);
                if (!timeoutToken.IsCancellationRequested)
                {
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        MintStatusLabel.Text = "Timeout ao solicitar PoW.";
                        _isMining = false;
                        _isContinuousMiningInFlight = false;
                        StopButton.IsVisible = false;
                        MintButton.Text = "Mineração Única";
                        MiningStatusLabel.Text = "Timeout";
                    });
                }
            }
            catch (TaskCanceledException) { }
        });
    }

    private async Task SubmitHpsMintAsync(ulong powNonce, double hashrateObserved, PowPopup? popup)
    {
        if (SessionState.GetPrivateKey() is null)
        {
            MainThread.BeginInvokeOnMainThread(() =>
                MintStatusLabel.Text = "Chave privada nao disponivel.");
            ResetMiningState();
            return;
        }
        if (!SessionState.Socket.IsConnected || !SessionState.IsLoggedIn)
        {
            MainThread.BeginInvokeOnMainThread(() =>
                MintStatusLabel.Text = "Conecte-se a rede para minerar HPS.");
            ResetMiningState();
            return;
        }

        var details = new Dictionary<string, string> { { "REASON", "mining" } };
        if (!string.IsNullOrWhiteSpace(_pendingHpsMintVoucherId))
            details["VOUCHER_ID"] = _pendingHpsMintVoucherId;

        var contractTemplate = BuildContractTemplate("hps_mint", details);
        var signedContract = ApplyContractSignature(contractTemplate, SessionState.GetPrivateKey(), SessionState.Username);

        AppendLog("Enviando prova de mineracao...");
        MainThread.BeginInvokeOnMainThread(() =>
            MintStatusLabel.Text = "Enviando mineracao...");

        var voucherId = string.IsNullOrWhiteSpace(_pendingHpsMintVoucherId) ? null : _pendingHpsMintVoucherId;
        _pendingHpsMintVoucherId = string.Empty;

        await SessionState.Socket.EmitAsync("mint_hps_voucher", new
        {
            pow_nonce = powNonce.ToString(),
            hashrate_observed = hashrateObserved,
            reason = "mining",
            voucher_id = voucherId,
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract))
        });

        popup?.AutoClose(800);

        AppendLog("Mineracao enviada, aguardando confirmacao...");
        _ = Task.Delay(15000).ContinueWith(_ =>
        {
            if (_isActive)
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    if (MintStatusLabel.Text == "Enviando mineracao...")
                    {
                        MintStatusLabel.Text = "Timeout - servidor nao respondeu";
                        AppendLog("Timeout: servidor nao confirmou mineracao.");
                    }
                });
        });
    }

    private void ResetMiningState()
    {
        _isMining = false;
        _isContinuousMiningInFlight = false;
        MainThread.BeginInvokeOnMainThread(() =>
        {
            StopButton.IsVisible = false;
            MintButton.Text = "Mineração Única";
            MiningStatusLabel.Text = "Parado";
            MiningSpinner.IsRunning = false;
            MiningSpinner.IsVisible = false;
        });
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

    public async Task HandlePowChallenge(JsonElement payload)
    {
        if (!_isActive)
        {
            ResetMiningState();
            return;
        }

        if (payload.TryGetProperty("error", out var errProp))
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                MintStatusLabel.Text = $"Erro PoW: {errProp.GetString()}";
                MiningStatusLabel.Text = "Erro";
                _isMining = false;
                _isContinuousMiningInFlight = false;
                StopButton.IsVisible = false;
                MintButton.Text = "Mineração Única";
                MiningSpinner.IsRunning = false;
                MiningSpinner.IsVisible = false;
            });
            return;
        }

        var challenge = payload.TryGetProperty("challenge", out var chalProp) ? chalProp.GetString() : null;
        var targetBits = payload.TryGetProperty("target_bits", out var bitsProp) ? bitsProp.GetInt32() : 0;
        var actionType = payload.TryGetProperty("action_type", out var actProp) ? actProp.GetString() : "hps_mint";

        if (string.IsNullOrWhiteSpace(challenge) || targetBits <= 0)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                MintStatusLabel.Text = "Desafio PoW invalido.";
                _isMining = false;
                _isContinuousMiningInFlight = false;
                StopButton.IsVisible = false;
                MintButton.Text = "Mineração Única";
                MiningSpinner.IsRunning = false;
                MiningSpinner.IsVisible = false;
            });
            return;
        }

        var voucherId = payload.TryGetProperty("voucher_id", out var vidProp) ? vidProp.GetString() : null;
        if (!string.IsNullOrWhiteSpace(voucherId))
            _pendingHpsMintVoucherId = voucherId;

        var threads = (int)ThreadsSlider.Value;
        var challengeBytes = Convert.FromBase64String(challenge);

        var popup = new PowPopup(actionType, targetBits);

        // Force layout refresh when popup closes to prevent black page
        popup.Closed += (_, _) => MainThread.BeginInvokeOnMainThread(() => ForceLayout());

        // Wait for popup to be SHOWN (not dismissed) before starting PoW
        var shownTcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        popup.Opened += (_, _) => shownTcs.TrySetResult(null);
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            await this.ShowPopupAsync(popup);
        });
        // Safety timeout: if popup never opens within 5s, unblock anyway
        _ = Task.Delay(5000).ContinueWith(_ => shownTcs.TrySetResult(null));
        await shownTcs.Task;

        _powCts?.Cancel();
        _powCts = CancellationTokenSource.CreateLinkedTokenSource(popup.Token);

        var cts = _powCts;
        _ = Task.Run(async () =>
        {
            try
            {
                var solver = new PowSolver();
                var result = await solver.SolveAsync(challengeBytes, targetBits, threads, cts.Token, progress =>
                {
                    if (!_isActive) return;
                    popup.UpdateProgress((long)progress.Attempts, progress.Hashrate);
                });

                if (result is null || cts.Token.IsCancellationRequested)
                {
                    popup.AppendLog("Mineracao cancelada.");
                    popup.SetStatus("Cancelada", true);
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        MintStatusLabel.Text = "Mineracao cancelada.";
                        if (!ContinuousSwitch.IsToggled)
                        {
                            _isMining = false;
                            StopButton.IsVisible = false;
                            MintButton.Text = "Mineração Única";
                            MiningStatusLabel.Text = "Parado";
                            MiningSpinner.IsRunning = false;
                            MiningSpinner.IsVisible = false;
                        }
                    });
                    return;
                }

                var hashrate = result.Attempts / Math.Max(1, result.Elapsed.TotalSeconds);
                popup.MarkComplete((long)result.Elapsed.TotalSeconds);
                popup.AppendLog($"Nonce={result.Nonce}, bits={result.LeadingZeroBits}, {result.Elapsed.TotalSeconds:0.00}s, {hashrate:0} H/s");

                MainThread.BeginInvokeOnMainThread(() =>
                {
                    _totalMiningSeconds += result.Elapsed.TotalSeconds;
                    UpdateStats();
                    StatBitsLabel.Text = targetBits.ToString();
                });

                // Always submit if PoW solved (regardless of _isActive)
                if (string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
                {
                    await SubmitHpsMintAsync(result.Nonce, hashrate, popup);
                }
            }
            catch (Exception ex)
            {
                popup.AppendLog($"Erro: {ex.Message}");
                popup.AutoClose(500);
            }
        });
    }

    private void UpdateStats()
    {
        StatCountLabel.Text = _minedCount.ToString();
        StatTotalTimeLabel.Text = $"{(int)_totalMiningSeconds}s";
    }

    private void AppendLog(string msg)
    {
        if (!_isActive) return;
        MainThread.BeginInvokeOnMainThread(() =>
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var current = LogLabel.Text;
            if (current == "Pronto para minerar.") current = "";
            var lines = (current + $"\n[{timestamp}] {msg}").Trim('\n');
            var allLines = lines.Split('\n');
            if (allLines.Length > 50)
                lines = string.Join("\n", allLines[^50..]);
            LogLabel.Text = lines;
            _ = LogScroll.ScrollToAsync(0, LogScroll.ContentSize.Height, true);
        });
    }

    private void OnClearLog(object? sender, EventArgs e)
    {
        LogLabel.Text = "";
    }
}