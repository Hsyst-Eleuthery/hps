using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Maui.Views;
using HpsWallet.Models;
using HpsWallet.Services;
using ZXing.Net.Maui;
using ZXing.QrCode;

namespace HpsWallet.Views;

public partial class WalletMainPage : ContentPage
{
    private bool _handlersRegistered;
    private List<PendingTransferItem> _pendingItems = new();
    private TaskCompletionSource<JsonElement>? _powChallengeTcs;
    private readonly object _powLock = new();
    private DateTime _lastBalanceRefresh = DateTime.MinValue;
    private JsonElement? _cachedBalanceData;
    private bool _pendingNoticeShown;

    public WalletMainPage()
    {
        InitializeComponent();
        UpdateAddressDisplay();
    }

    private void UpdateAddressDisplay()
    {
        var u = SessionState.Username;
        var s = SessionState.ServerAddress;
        if (!string.IsNullOrEmpty(s) && !string.IsNullOrEmpty(u))
            MyAddressLabel.Text = $"@{u} em {s}";
        else
            MyAddressLabel.Text = "Conecte-se primeiro";
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        if (BarcodeReader != null)
        {
            BarcodeReader.IsDetecting = true;
            BarcodeReader.BarcodesDetected += OnBarcodesDetected;
        }
        RegisterHandlers();
        _ = RefreshBalance();
        _ = LoadHistory();
        _ = LoadPendingTransfers();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        if (BarcodeReader != null)
        {
            BarcodeReader.IsDetecting = false;
            BarcodeReader.BarcodesDetected -= OnBarcodesDetected;
        }
        UnregisterHandlers();
    }

    private void RegisterHandlers()
    {
        if (_handlersRegistered) return;
        _handlersRegistered = true;

        var socket = SessionState.Socket;
        if (socket == null) return;

        socket.On("hps_economy_update", async _ =>
        {
            _lastBalanceRefresh = DateTime.MinValue;
            await MainThread.InvokeOnMainThreadAsync(() => RefreshBalance());
        });

        socket.On("hps_voucher_offer", async response =>
        {
            var data = response.GetValue<JsonElement>();
            var voucherId = data.TryGetProperty("voucher_id", out var vidProp) ? vidProp.GetString() : null;
            data.TryGetProperty("payload", out var payloadProp);
            var offerValue = payloadProp.ValueKind == JsonValueKind.Object && payloadProp.TryGetProperty("value", out var valProp) ? valProp.GetInt32() : 0;
            if (!string.IsNullOrEmpty(voucherId) && SessionState.GetPrivateKey() != null)
            {
                var payloadCanonical = data.TryGetProperty("payload_canonical", out var pcProp) && pcProp.ValueKind == JsonValueKind.String
                    ? pcProp.GetString() : null;
                if (!string.IsNullOrEmpty(payloadCanonical))
                {
                    var confirmed = await MainThread.InvokeOnMainThreadAsync(async () =>
                        await DisplayAlertAsync("Confirmar Recebimento",
                            $"Oferta de voucher: {offerValue} $HPS\nID: {voucherId}\n\nDeseja assinar e aceitar este voucher?",
                            "Aceitar", "Rejeitar"));
                    if (confirmed)
                    {
                        var signature = CryptoUtils.SignPayload(SessionState.GetPrivateKey(), payloadCanonical);
                        var signatureB64 = Convert.ToBase64String(signature);
                        await SessionState.Socket.EmitAsync("confirm_hps_voucher", new
                        {
                            voucher_id = voucherId,
                            owner_signature = signatureB64,
                            payload_signed_text = payloadCanonical
                        });
                    }
                    else
                    {
                        // A13 FIX: Don't log voucher_id in debug output
                        System.Diagnostics.Debug.WriteLine("[Wallet] Voucher offer rejeitada pelo usuario");
                    }
                }
                else if (data.TryGetProperty("value", out var val))
                {
                    // A13 FIX: Don't log voucher_id in debug output
                    System.Diagnostics.Debug.WriteLine($"[Wallet] Voucher offer sem payload_canonical, value={val.GetInt32()}");
                }
            }
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await RefreshBalance(force: true);
                if (offerValue > 0)
                    await DisplayAlertAsync("Novo Voucher", $"Voce recebeu {offerValue} $HPS!", "OK");
            });
        });

        socket.On("hps_transfer_ack", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var s) && s.GetBoolean();
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                if (success)
                {
                    await DisplayAlertAsync("Sucesso", "Transferencia enviada com sucesso!", "OK");
                    SendRecipient.Text = "";
                    SendAmount.Text = "";
                    await RefreshBalance();
                }
                else
                {
                    var error = payload.TryGetProperty("error", out var e) ? e.GetString() : "Erro desconhecido";
                    await DisplayAlertAsync("Erro", $"Falha na transferencia: {error}", "OK");
                }
            });
        });

        socket.On("pending_transfers", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await RefreshPendingTransfers(payload);
            });
        });

        socket.On("pending_transfer_notice", async _ =>
        {
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await LoadPendingTransfers();
                await RefreshBalance();
            });
        });

        socket.On("accept_hps_transfer_ack", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var s) && s.GetBoolean();
            await MainThread.InvokeOnMainThreadAsync(async () =>
            {
                if (success)
                {
                    await LoadPendingTransfers();
                    await RefreshBalance();
                    await DisplayAlertAsync("Sucesso", "Transferencia aceita! Verifique seus vouchers.", "OK");
                }
                else
                {
                    var error = payload.TryGetProperty("error", out var e) ? e.GetString() : "Erro desconhecido";
                    await DisplayAlertAsync("Erro", $"Falha ao aceitar: {error}", "OK");
                }
            });
        });

        socket.On("reject_transfer_ack", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var s) && s.GetBoolean();
            await MainThread.InvokeOnMainThreadAsync(async () =>
            {
                if (success)
                {
                    await DisplayAlertAsync("Sucesso", "Transferencia rejeitada!", "OK");
                    await LoadPendingTransfers();
                    await RefreshBalance();
                }
                else
                {
                    var error = payload.TryGetProperty("error", out var e) ? e.GetString() : "Erro desconhecido";
                    await DisplayAlertAsync("Erro", $"Falha ao rejeitar: {error}", "OK");
                }
            });
        });

        socket.On("pow_challenge", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var actionType = payload.TryGetProperty("action_type", out var actP) ? actP.GetString() : "";
            if (actionType == "contract_transfer" || actionType == "hps_transfer")
            {
                var tcs = Interlocked.Exchange(ref _powChallengeTcs, null);
                if (tcs != null)
                    tcs.TrySetResult(payload);
            }
        });
    }

    private void UnregisterHandlers()
    {
        _handlersRegistered = false;
        var socket = SessionState.Socket;
        if (socket == null) return;
        socket.Off("hps_economy_update");
        socket.Off("hps_voucher_offer");
        socket.Off("hps_transfer_ack");
        socket.Off("pending_transfers");
        socket.Off("pending_transfer_notice");
        socket.Off("accept_hps_transfer_ack");
        socket.Off("reject_transfer_ack");
        socket.Off("pow_challenge");
    }

    private void OnTabClicked(object? sender, EventArgs e)
    {
        if (sender is not Button btn) return;

        SendPanel.IsVisible = btn == TabSendBtn;
        ReceivePanel.IsVisible = btn == TabReceiveBtn;
        ScanPanel.IsVisible = btn == TabScanBtn;
        PendingPanel.IsVisible = btn == TabPendingBtn;
        HistoryPanel.IsVisible = btn == TabHistoryBtn;

        if (btn == TabPendingBtn) _ = LoadPendingTransfers();
        if (btn == TabHistoryBtn) _ = LoadHistory();
    }

    private async Task<JsonElement?> FetchBalanceData()
    {
        var now = DateTime.UtcNow;
        if (_cachedBalanceData.HasValue && (now - _lastBalanceRefresh).TotalSeconds < 2)
            return _cachedBalanceData.Value;
        var result = await SessionState.Server.FetchUserVouchersAsync();
        if (result.HasValue)
        {
            _cachedBalanceData = result.Value;
            _lastBalanceRefresh = now;
        }
        return result;
    }

    private async Task RefreshBalance(bool force = false)
    {
        if (force) { _cachedBalanceData = null; _lastBalanceRefresh = DateTime.MinValue; }
        var result = await FetchBalanceData();
        if (result == null)
        {
            BalanceLabel.Text = "0 $HPS";
            UserLabel.Text = "Desconectado";
            return;
        }

        try
        {
            if (result.Value.TryGetProperty("balance", out var bal))
                BalanceLabel.Text = $"{bal.GetInt32()} $HPS";
            if (result.Value.TryGetProperty("username", out var un))
                UserLabel.Text = $"@{un.GetString()}";
            else
                UserLabel.Text = $"@{SessionState.Username}";
        }
        catch
        {
            UserLabel.Text = $"@{SessionState.Username}";
        }
    }

    private async Task LoadHistory()
    {
        try
        {
            var result = await FetchBalanceData();
            if (result == null || !result.Value.TryGetProperty("vouchers", out var vouchers) || vouchers.ValueKind != JsonValueKind.Array)
            {
                HistoryCollection.ItemsSource = new ObservableCollection<WalletTransactionItem>
                {
                    new() { Icon = "⟳", Description = "Nenhuma transacao encontrada", Date = "", Amount = "", AmountColor = Colors.Gray }
                };
                return;
            }

            var items = new ObservableCollection<WalletTransactionItem>();
            foreach (var v in vouchers.EnumerateArray())
            {
                var reason = v.TryGetProperty("reason", out var r) ? r.GetString() ?? "voucher" : "voucher";
                var date = v.TryGetProperty("issued_at", out var d)
                    ? DateTimeOffset.FromUnixTimeSeconds((long)d.GetDouble()).LocalDateTime.ToString("dd/MM HH:mm")
                    : "";
                var value = v.TryGetProperty("value", out var amt) ? amt.GetInt32() : 0;
                var isNegative = reason.Contains("exchange_out") || reason.Contains("spend");
                items.Add(new WalletTransactionItem
                {
                    Icon = isNegative ? "↑" : "↓",
                    Description = reason,
                    Date = date,
                    Amount = $"{(isNegative ? "-" : "+")}{value} $HPS",
                    AmountColor = isNegative ? Colors.OrangeRed : Colors.LimeGreen
                });
            }
            HistoryCollection.ItemsSource = items;
        }
        catch
        {
            System.Diagnostics.Debug.WriteLine("[Wallet] Erro ao carregar historico");
        }
    }

    private async void OnOpenPendingPage(object? sender, EventArgs e)
    {
        await Navigation.PushAsync(new PendingPage());
    }

    private async void OnRefreshPendingClicked(object? sender, EventArgs e)
    {
        await LoadPendingTransfers();
    }

    private async Task LoadPendingTransfers()
    {
        if (SessionState.Socket == null || !SessionState.Socket.IsConnected) return;
        await SessionState.Socket.EmitAsync("get_pending_transfers", new { username = SessionState.Username });
    }

    private async Task RefreshPendingTransfers(JsonElement payload)
    {
        try
        {
            if (payload.TryGetProperty("transfers", out var transfers) && transfers.ValueKind == JsonValueKind.Array)
            {
                var list = new List<PendingTransferItem>();
                foreach (var t in transfers.EnumerateArray())
                {
                    var id = t.TryGetProperty("transfer_id", out var idP) ? idP.GetString() ?? "" : "";
                    var fromUser = t.TryGetProperty("original_owner", out var fP) ? fP.GetString() ?? "" : "";
                    var targetUser = t.TryGetProperty("target_user", out var tP) ? tP.GetString() ?? "" : "";
                    var amount = 0;
                    if (t.TryGetProperty("hps_amount", out var aP) && aP.ValueKind == JsonValueKind.Number)
                        amount = aP.GetInt32();
                    var status = t.TryGetProperty("status", out var sP) ? sP.GetString() ?? "pending" : "pending";
                    var createdAt = "";
                    if (t.TryGetProperty("timestamp", out var tsP) && tsP.ValueKind == JsonValueKind.Number)
                    {
                        var unix = tsP.GetDouble();
                        createdAt = DateTimeOffset.FromUnixTimeSeconds((long)unix).LocalDateTime.ToString("dd/MM HH:mm");
                    }
                    var incoming = string.Equals(targetUser, SessionState.Username, StringComparison.OrdinalIgnoreCase);

                    list.Add(new PendingTransferItem
                    {
                        TransferId = id,
                        FromUser = fromUser,
                        RawAmount = amount,
                        Status = status,
                        CreatedAt = createdAt,
                        IsIncoming = incoming,
                    });
                }
                _pendingItems = list;
                PendingCountLabel.Text = list.Count > 0
                    ? $"{list.Count} transferencia(s) pendente(s)"
                    : "Nenhuma transferencia pendente";
                if (!_pendingNoticeShown && list.Count > 0)
                {
                    _pendingNoticeShown = true;
                    await DisplayAlertAsync("Transferencias Pendentes",
                        $"Voce tem {list.Count} transferencia(s) pendente(s).\nAcesse a aba Pendentes para revisa-las.",
                        "OK");
                }
            }
            else
            {
                _pendingItems = new List<PendingTransferItem>();
                PendingCountLabel.Text = "Nenhuma transferencia pendente";
            }
        }
        catch
        {
            _pendingItems = new List<PendingTransferItem>();
            PendingCountLabel.Text = "Nenhuma transferencia pendente";
        }
    }

    private async void OnDebugTestClicked(object? sender, EventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("[Wallet] Debug test button clicked!");
        var first = _pendingItems.FirstOrDefault();
        if (first != null)
            await OnAcceptTransferAsync(first);
        else
            await DisplayAlertAsync("Debug", "Nenhum item pendente para testar", "OK");
    }

    private async Task OnAcceptTransferAsync(PendingTransferItem item)
    {
        System.Diagnostics.Debug.WriteLine($"[Wallet] OnAcceptTransfer chamado, item={item?.TransferId}");
        if (item == null || string.IsNullOrEmpty(item.TransferId))
        {
            System.Diagnostics.Debug.WriteLine("[Wallet] OnAcceptTransfer: item invalido");
            return;
        }
        try { await HandleTransferWithPoW(item.TransferId, "accept_hps_transfer", "Aceitar Transferencia", "aceitar"); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Wallet] OnAcceptTransfer erro: {ex}"); await DisplayAlertAsync("Erro", ex.Message, "OK"); }
    }

    private async Task OnRejectTransferAsync(PendingTransferItem item)
    {
        System.Diagnostics.Debug.WriteLine($"[Wallet] OnRejectTransfer chamado, item={item?.TransferId}");
        if (item == null || string.IsNullOrEmpty(item.TransferId))
        {
            System.Diagnostics.Debug.WriteLine("[Wallet] OnRejectTransfer: item invalido");
            return;
        }
        try { await HandleTransferWithPoW(item.TransferId, "reject_transfer", "Rejeitar Transferencia", "rejeitar"); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Wallet] OnRejectTransfer erro: {ex}"); await DisplayAlertAsync("Erro", ex.Message, "OK"); }
    }

    private async Task HandleTransferWithPoW(string transferId, string serverEvent, string alertTitle, string actionLabel)
    {
        if (SessionState.GetPrivateKey() is null)
        {
            await DisplayAlertAsync("Erro", "Chave privada nao disponivel.", "OK");
            return;
        }

        var item = _pendingItems.FirstOrDefault(i => i.TransferId == transferId);
        var msg = item != null
            ? $"De: {item.FromUser}\nValor: {item.RawAmount} $HPS\n\nDeseja {actionLabel}?"
            : $"Deseja {actionLabel} a transferencia?";

        var confirmed = await DisplayAlertAsync(alertTitle, msg, "Sim", "Nao");
        if (!confirmed) return;

        var clientId = await SecureStorageHelper.GetClientIdAsync();
        if (string.IsNullOrEmpty(clientId))
        {
            await DisplayAlertAsync("Erro", "Identificador do cliente nao disponivel.", "OK");
            return;
        }

        var powTcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_powLock)
        {
            _powChallengeTcs = powTcs;
        }
        await SessionState.Socket.EmitAsync("request_pow_challenge", new
        {
            client_identifier = clientId,
            action_type = "contract_transfer"
        });

        var timeoutTask = Task.Delay(30000);
        var completedTask = await Task.WhenAny(powTcs.Task, timeoutTask);
        if (completedTask != powTcs.Task)
        {
            Interlocked.Exchange(ref _powChallengeTcs, null)?.TrySetCanceled();
            await DisplayAlertAsync("Erro", "Tempo limite excedido ao solicitar PoW.", "OK");
            return;
        }

        var challengePayload = await powTcs.Task;

        var challenge = challengePayload.TryGetProperty("challenge", out var chalP) ? chalP.GetString() : null;
        var targetBits = challengePayload.TryGetProperty("target_bits", out var bitsP) ? bitsP.GetInt32() : 0;
        if (string.IsNullOrEmpty(challenge) || targetBits <= 0)
        {
            await DisplayAlertAsync("Erro", "Desafio PoW invalido.", "OK");
            return;
        }

        var challengeBytes = Convert.FromBase64String(challenge);
        var powThreads = Preferences.Get("wallet_pow_threads", 2);

        var popup = new PowPopup(actionLabel, targetBits);
        var shownTcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        popup.Opened += (_, _) => shownTcs.TrySetResult(null);
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            await this.ShowPopupAsync(popup);
        });
        await shownTcs.Task;

        var cts = CancellationTokenSource.CreateLinkedTokenSource(popup.Token);

        try
        {
            var solver = new PowSolver();
            var result = await Task.Run(() => solver.SolveAsync(challengeBytes, targetBits, powThreads, cts.Token, progress =>
            {
                popup.UpdateProgress((long)progress.Attempts, progress.Hashrate);
            }));

            if (result is null || cts.Token.IsCancellationRequested)
            {
                popup.AutoClose(500);
                return;
            }

            var hashrate = result.Attempts / Math.Max(1, result.Elapsed.TotalSeconds);
            popup.AppendLog($"Nonce={result.Nonce}, bits={result.LeadingZeroBits}, {result.Elapsed.TotalSeconds:0.00}s, {hashrate:0} H/s");
            popup.SetStatus("Enviando comprovante...");

            var details = new Dictionary<string, string>
            {
                { "TRANSFER_ID", transferId },
                { "ACTION", actionLabel }
            };
            var contractText = BuildContractTemplate(serverEvent, details);
            var signedContract = ApplyContractSignature(contractText, SessionState.GetPrivateKey(), SessionState.Username);

            await SessionState.Socket.EmitAsync(serverEvent, new
            {
                transfer_id = transferId,
                pow_nonce = result.Nonce.ToString(),
                hashrate_observed = hashrate,
                contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract))
            });

            popup.AutoClose(800);
        }
        catch (Exception ex)
        {
            popup.AppendLog($"Erro: {ex.Message}");
            popup.AutoClose(500);
        }
    }

    private async void OnSendClicked(object? sender, EventArgs e)
    {
        var recipient = SendRecipient.Text?.Trim();
        var amountText = SendAmount.Text?.Trim();

        if (string.IsNullOrEmpty(recipient) || string.IsNullOrEmpty(amountText))
        {
            await DisplayAlertAsync("Erro", "Preencha destinatario e valor", "OK");
            return;
        }

        if (!int.TryParse(amountText, out var amount) || amount <= 0)
        {
            await DisplayAlertAsync("Erro", "Valor invalido", "OK");
            return;
        }

        if (!SessionState.Socket.IsConnected || !SessionState.IsLoggedIn)
        {
            await DisplayAlertAsync("Erro", "Conecte-se a rede primeiro", "OK");
            return;
        }

        if (SessionState.GetPrivateKey() is null)
        {
            await DisplayAlertAsync("Erro", "Chave privada nao disponivel", "OK");
            return;
        }

        var confirmed = await DisplayAlertAsync("Confirmar Transferencia",
            $"Enviar {amount} $HPS para {recipient}?", "Confirmar", "Cancelar");

        if (!confirmed) return;

        try
        {
            var balanceResult = await FetchBalanceData();
            if (balanceResult == null || !balanceResult.Value.TryGetProperty("vouchers", out var vouchers) || vouchers.ValueKind != JsonValueKind.Array)
            {
                await DisplayAlertAsync("Erro", "Nao foi possivel obter seus vouchers.", "OK");
                return;
            }

            var validVouchers = new List<(string id, int value)>();
            foreach (var v in vouchers.EnumerateArray())
            {
                var status = v.TryGetProperty("status", out var st) ? st.GetString() : "";
                var invalidated = v.TryGetProperty("invalidated", out var inv) && inv.GetBoolean();
                if (status == "valid" && !invalidated)
                {
                    var vid = v.TryGetProperty("voucher_id", out var idP) ? idP.GetString() ?? "" : "";
                    var val = v.TryGetProperty("value", out var vlP) ? vlP.GetInt32() : 0;
                    if (!string.IsNullOrEmpty(vid) && val > 0)
                        validVouchers.Add((vid, val));
                }
            }

            var totalBalance = validVouchers.Sum(x => x.value);
            if (totalBalance < amount)
            {
                await DisplayAlertAsync("Erro", $"Saldo insuficiente. Disponivel: {totalBalance} $HPS, necessario: {amount} $HPS.", "OK");
                return;
            }

            var selectedVouchers = new List<string>();
            var accumulated = 0;
            foreach (var (id, val) in validVouchers.OrderBy(v => v.value))
            {
                if (accumulated >= amount) break;
                selectedVouchers.Add(id);
                accumulated += val;
            }

            var clientId = await SecureStorageHelper.GetClientIdAsync();
            if (string.IsNullOrEmpty(clientId))
            {
                await DisplayAlertAsync("Erro", "Identificador do cliente nao disponivel.", "OK");
                return;
            }

            var powTcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_powLock)
            {
                _powChallengeTcs = powTcs;
            }
            await SessionState.Socket.EmitAsync("request_pow_challenge", new
            {
                client_identifier = clientId,
                action_type = "hps_transfer"
            });

            var timeoutTask = Task.Delay(30000);
            var completedTask = await Task.WhenAny(powTcs.Task, timeoutTask);
            if (completedTask != powTcs.Task)
            {
                Interlocked.Exchange(ref _powChallengeTcs, null)?.TrySetCanceled();
                await DisplayAlertAsync("Erro", "Tempo limite excedido ao solicitar PoW.", "OK");
                return;
            }

            var challengePayload = await powTcs.Task;
            var challenge = challengePayload.TryGetProperty("challenge", out var chalP) ? chalP.GetString() : null;
            var targetBits = challengePayload.TryGetProperty("target_bits", out var bitsP) ? bitsP.GetInt32() : 0;
            if (string.IsNullOrEmpty(challenge) || targetBits <= 0)
            {
                await DisplayAlertAsync("Erro", "Desafio PoW invalido.", "OK");
                return;
            }

            var challengeBytes = Convert.FromBase64String(challenge);
            var powThreads = Preferences.Get("wallet_pow_threads", 2);

            var popup = new PowPopup("Enviar $HPS", targetBits);
            var shownTcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            popup.Opened += (_, _) => shownTcs.TrySetResult(null);
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await this.ShowPopupAsync(popup);
            });
            await shownTcs.Task;

            var cts = CancellationTokenSource.CreateLinkedTokenSource(popup.Token);

            try
            {
                var solver = new PowSolver();
                var result = await Task.Run(() => solver.SolveAsync(challengeBytes, targetBits, powThreads, cts.Token, progress =>
                {
                    popup.UpdateProgress((long)progress.Attempts, progress.Hashrate);
                }));

                if (result is null || cts.Token.IsCancellationRequested)
                {
                    popup.AutoClose(500);
                    return;
                }

                var hashrate = result.Attempts / Math.Max(1, result.Elapsed.TotalSeconds);
                popup.AppendLog($"Nonce={result.Nonce}, bits={result.LeadingZeroBits}, {result.Elapsed.TotalSeconds:0.00}s, {hashrate:0} H/s");
                popup.SetStatus("Enviando transferencia...");

                var voucherIdsJson = System.Text.Json.JsonSerializer.Serialize(selectedVouchers);
                var details = new Dictionary<string, string>
                {
                    { "TARGET_USER", recipient },
                    { "AMOUNT", amount.ToString() },
                    { "VOUCHERS", voucherIdsJson }
                };
                if (!string.IsNullOrEmpty(SessionState.PublicKeyPem))
                    details["PUBLIC_KEY"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(SessionState.PublicKeyPem));

                var contractText = BuildContractTemplate("transfer_hps", details);
                var signedContract = ApplyContractSignature(contractText, SessionState.GetPrivateKey(), SessionState.Username);

                await SessionState.Socket.EmitAsync("transfer_hps", new
                {
                    target_user = recipient,
                    amount,
                    voucher_ids = selectedVouchers,
                    contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract)),
                    pow_nonce = result.Nonce.ToString(),
                    hashrate_observed = hashrate
                });

                popup.AutoClose(800);
                SendRecipient.Text = "";
                SendAmount.Text = "";
                await DisplayAlertAsync("Transferencia Enviada",
                    $"Transferencia de {amount} $HPS para {recipient} enviada!\n\nAguardando validacao do minerador.", "OK");
            }
            catch (Exception ex)
            {
                popup.AppendLog($"Erro: {ex.Message}");
                popup.AutoClose(500);
            }
        }
        catch (Exception ex)
        {
            await DisplayAlertAsync("Erro", $"Falha na conexao: {ex.Message}", "OK");
        }
    }

    private async void OnCopyAddressClicked(object? sender, EventArgs e)
    {
        var addressText = $"@{SessionState.Username} em {SessionState.ServerAddress}";
        await Clipboard.SetTextAsync(addressText);
        _ = Task.Run(async () => { await Task.Delay(10000); try { await Clipboard.SetTextAsync(""); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Clipboard] Clear failed: {ex.Message}"); } });
        await DisplayAlertAsync("Copiado", "Endereco copiado para a area de transferencia", "OK");
    }

    private async void OnRefreshClicked(object? sender, EventArgs e)
    {
        _lastBalanceRefresh = DateTime.MinValue;
        await RefreshBalance();
        await DisplayAlertAsync("Atualizado", "Saldo atualizado", "OK");
    }

    private void OnBarcodesDetected(object? sender, BarcodeDetectionEventArgs e)
    {
        var result = e.Results?.FirstOrDefault();
        if (result?.Value == null) return;

        MainThread.BeginInvokeOnMainThread(async () =>
        {
            if (BarcodeReader != null) BarcodeReader.IsDetecting = false;
            var scanned = result.Value;
            ScanResultLabel.Text = $"Escaneado: {scanned}";

            if (scanned.StartsWith("hps:pay?", StringComparison.OrdinalIgnoreCase))
            {
                await HandlePaymentRequestQrAsync(scanned);
                if (BarcodeReader != null) BarcodeReader.IsDetecting = true;
                return;
            }

            try
            {
                var voucher = await SessionState.Server.FetchVoucherAsync(scanned);
                if (voucher == null)
                {
                    await DisplayAlertAsync("Voucher", "Voucher nao encontrado ou invalido.", "OK");
                    if (BarcodeReader != null) BarcodeReader.IsDetecting = true;
                    return;
                }

                var msg = $"ID: {scanned}\n\nVoucher valido!";
                if (voucher.Value.TryGetProperty("payload", out var payload) &&
                    payload.TryGetProperty("value", out var val))
                    msg += $"\nValor: {val.GetInt32()} $HPS";
                await DisplayAlertAsync("Voucher Verificado", msg, "OK");
            }
            catch (Exception ex)
            {
                await DisplayAlertAsync("Erro", $"Falha: {ex.Message}", "OK");
            }

            if (BarcodeReader != null) BarcodeReader.IsDetecting = true;
        });
    }

    private async Task HandlePaymentRequestQrAsync(string qrData)
    {
        try
        {
            var queryPart = qrData.Split('?').Length > 1 ? qrData.Split('?')[1] : "";
            var parts = queryPart.Split('&');
            var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in parts)
            {
                var kv = p.Split('=', 2);
                if (kv.Length == 2)
                    query[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1]);
            }
            var toUser = query.GetValueOrDefault("to", "desconhecido");
            var amountStr = query.GetValueOrDefault("amount", "0");
            var server = query.GetValueOrDefault("server", "");

            if (string.IsNullOrEmpty(toUser) || toUser == "desconhecido" || toUser.Length > 64 || !System.Text.RegularExpressions.Regex.IsMatch(toUser, @"^[a-zA-Z0-9_\-\.]+$"))
            {
                await DisplayAlertAsync("QR Invalido", "QR de pagamento com destinatario invalido.", "OK");
                return;
            }

            if (!int.TryParse(amountStr, out var amount) || amount <= 0 || amount > 100000000)
            {
                await DisplayAlertAsync("QR Invalido", "QR de pagamento com valor invalido.", "OK");
                return;
            }

            if (string.IsNullOrEmpty(server) || !Uri.TryCreate(server.StartsWith("http") ? server : $"http://{server}", UriKind.Absolute, out _))
            {
                await DisplayAlertAsync("QR Invalido", "QR de pagamento com servidor invalido.", "OK");
                return;
            }

            if (!server.Equals(SessionState.ServerAddress, StringComparison.OrdinalIgnoreCase))
            {
                await DisplayAlertAsync("QR Invalido", "QR de pagamento com servidor incompativel.", "OK");
                return;
            }

            var confirmed = await DisplayAlertAsync("Pagamento via QR",
                $"Deseja enviar {amount} $HPS para {toUser} em {server}?",
                "Enviar", "Cancelar");

            if (!confirmed) return;

            if (SessionState.GetPrivateKey() is null)
            {
                await DisplayAlertAsync("Erro", "Chave privada nao disponivel.", "OK");
                return;
            }

            var balanceResult = await FetchBalanceData();
            if (balanceResult == null || !balanceResult.Value.TryGetProperty("vouchers", out var vouchers) || vouchers.ValueKind != JsonValueKind.Array)
            {
                await DisplayAlertAsync("Erro", "Nao foi possivel obter seus vouchers.", "OK");
                return;
            }

            var validVouchers = new List<(string id, int value)>();
            foreach (var v in vouchers.EnumerateArray())
            {
                var status = v.TryGetProperty("status", out var st) ? st.GetString() : "";
                var invalidated = v.TryGetProperty("invalidated", out var inv) && inv.GetBoolean();
                if (status == "valid" && !invalidated)
                {
                    var vid = v.TryGetProperty("voucher_id", out var idP) ? idP.GetString() ?? "" : "";
                    var val = v.TryGetProperty("value", out var vlP) ? vlP.GetInt32() : 0;
                    if (!string.IsNullOrEmpty(vid) && val > 0)
                        validVouchers.Add((vid, val));
                }
            }

            var totalBalance = validVouchers.Sum(x => x.value);
            if (totalBalance < amount)
            {
                await DisplayAlertAsync("Erro", $"Saldo insuficiente. Disponivel: {totalBalance} $HPS, necessario: {amount} $HPS.", "OK");
                return;
            }

            var selectedVouchers = new List<string>();
            var accumulated = 0;
            foreach (var (id, val) in validVouchers.OrderBy(v => v.value))
            {
                if (accumulated >= amount) break;
                selectedVouchers.Add(id);
                accumulated += val;
            }

            var clientId = await SecureStorageHelper.GetClientIdAsync();
            if (string.IsNullOrEmpty(clientId))
            {
                await DisplayAlertAsync("Erro", "Identificador do cliente nao disponivel.", "OK");
                return;
            }

            var powTcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_powLock)
            {
                _powChallengeTcs = powTcs;
            }
            await SessionState.Socket.EmitAsync("request_pow_challenge", new
            {
                client_identifier = clientId,
                action_type = "hps_transfer"
            });

            var timeoutTask = Task.Delay(30000);
            var completedTask = await Task.WhenAny(powTcs.Task, timeoutTask);
            if (completedTask != powTcs.Task)
            {
                Interlocked.Exchange(ref _powChallengeTcs, null)?.TrySetCanceled();
                await DisplayAlertAsync("Erro", "Tempo limite excedido ao solicitar PoW.", "OK");
                return;
            }

            var challengePayload = await powTcs.Task;
            var challenge = challengePayload.TryGetProperty("challenge", out var chalP) ? chalP.GetString() : null;
            var targetBits = challengePayload.TryGetProperty("target_bits", out var bitsP) ? bitsP.GetInt32() : 0;
            if (string.IsNullOrEmpty(challenge) || targetBits <= 0)
            {
                await DisplayAlertAsync("Erro", "Desafio PoW invalido.", "OK");
                return;
            }

            var challengeBytes = Convert.FromBase64String(challenge);
            var powThreads = Preferences.Get("wallet_pow_threads", 2);

            var popup = new PowPopup("Enviar $HPS (QR)", targetBits);
            var shownTcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            popup.Opened += (_, _) => shownTcs.TrySetResult(null);
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await this.ShowPopupAsync(popup);
            });
            await shownTcs.Task;

            var cts = CancellationTokenSource.CreateLinkedTokenSource(popup.Token);

            try
            {
                var solver = new PowSolver();
                var result = await Task.Run(() => solver.SolveAsync(challengeBytes, targetBits, powThreads, cts.Token, progress =>
                {
                    popup.UpdateProgress((long)progress.Attempts, progress.Hashrate);
                }));

                if (result is null || cts.Token.IsCancellationRequested)
                {
                    popup.AutoClose(500);
                    return;
                }

                var hashrate = result.Attempts / Math.Max(1, result.Elapsed.TotalSeconds);
                popup.AppendLog($"Nonce={result.Nonce}, bits={result.LeadingZeroBits}, {result.Elapsed.TotalSeconds:0.00}s, {hashrate:0} H/s");
                popup.SetStatus("Enviando transferencia...");

                var voucherIdsJson = JsonSerializer.Serialize(selectedVouchers);
                var details = new Dictionary<string, string>
                {
                    { "TARGET_USER", toUser },
                    { "AMOUNT", amount.ToString() },
                    { "VOUCHERS", voucherIdsJson },
                    { "SOURCE", "qr_scan" }
                };
                if (!string.IsNullOrEmpty(SessionState.PublicKeyPem))
                    details["PUBLIC_KEY"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(SessionState.PublicKeyPem));

                var contractText = BuildContractTemplate("transfer_hps", details);
                var signedContract = ApplyContractSignature(contractText, SessionState.GetPrivateKey(), SessionState.Username);

                await SessionState.Socket.EmitAsync("transfer_hps", new
                {
                    target_user = toUser,
                    amount,
                    voucher_ids = selectedVouchers,
                    contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract)),
                    pow_nonce = result.Nonce.ToString(),
                    hashrate_observed = hashrate
                });

                popup.AutoClose(800);
                await DisplayAlertAsync("Transferencia Iniciada",
                    $"Enviando {amount} $HPS para {toUser} via QR!\nAguardando validacao do minerador.", "OK");
            }
            catch (Exception ex)
            {
                popup.AppendLog($"Erro: {ex.Message}");
                popup.AutoClose(500);
            }
        }
        catch (Exception ex)
        {
            await DisplayAlertAsync("Erro", $"Falha ao processar QR de pagamento: {ex.Message}", "OK");
        }
    }

    private async void OnGenerateQrClicked(object? sender, EventArgs e)
    {
        var amountText = QrAmountEntry.Text?.Trim();
        if (string.IsNullOrEmpty(amountText) || !int.TryParse(amountText, out var amount) || amount <= 0)
        {
            await DisplayAlertAsync("Erro", "Digite um valor valido em $HPS.", "OK");
            return;
        }

        var qrContent = $"hps:pay?to={Uri.EscapeDataString(SessionState.Username)}&amount={amount}&server={Uri.EscapeDataString(SessionState.ServerAddress)}";

        try
        {
            var writer = new QRCodeWriter();
            var bitMatrix = writer.encode(qrContent, ZXing.BarcodeFormat.QR_CODE, 220, 220);
            QrGraphicsView.Drawable = new QrCodeDrawable(bitMatrix);
            QrGraphicsView.IsVisible = true;
            QrDataLabel.Text = qrContent;
            QrDataLabel.IsVisible = true;
            CopyQrButton.IsVisible = true;
            await DisplayAlertAsync("QR Gerado",
                $"QR de pagamento gerado!\n\nValor: {amount} $HPS\n\nCompartilhe este QR com quem deseja receber o pagamento.",
                "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlertAsync("Erro", $"Falha ao gerar QR: {ex.Message}", "OK");
        }
    }

    private async void OnCopyQrDataClicked(object? sender, EventArgs e)
    {
        if (!string.IsNullOrEmpty(QrDataLabel.Text))
        {
            await Clipboard.SetTextAsync(QrDataLabel.Text);
            _ = Task.Run(async () => { await Task.Delay(10000); try { await Clipboard.SetTextAsync(""); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Clipboard] Clear failed: {ex.Message}"); } });
            await DisplayAlertAsync("Copiado", "Dados do QR copiados para area de transferencia.", "OK");
        }
    }

    private sealed class QrCodeDrawable : IDrawable
    {
        private readonly ZXing.Common.BitMatrix _matrix;
        private readonly int _size;

        public QrCodeDrawable(ZXing.Common.BitMatrix matrix)
        {
            _matrix = matrix;
            _size = matrix.Width;
        }

        public void Draw(ICanvas canvas, RectF dirtyRect)
        {
            if (_matrix == null) return;
            var cellW = dirtyRect.Width / _size;
            var cellH = dirtyRect.Height / _size;
            canvas.FillColor = Colors.White;
            canvas.FillRectangle(dirtyRect);
            canvas.FillColor = Color.FromArgb("#1A0A2E");
            for (var y = 0; y < _size; y++)
            {
                for (var x = 0; x < _size; x++)
                {
                    if (_matrix[x, y])
                        canvas.FillRectangle(x * cellW, y * cellH, cellW + 0.5f, cellH + 0.5f);
                }
            }
        }
    }

    private static string BuildContractTemplate(string actionType, Dictionary<string, string> details)
    {
        const int MaxContractSize = 8192;
        const int MaxFieldValueLength = 2048;
        const int MaxFieldCount = 50;

        if (details.Count > MaxFieldCount)
            throw new InvalidOperationException("Contrato excede numero maximo de campos.");

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
        {
            var key = kv.Key.Length > 128 ? kv.Key[..128] : kv.Key;
            var value = kv.Value.Length > MaxFieldValueLength ? kv.Value[..MaxFieldValueLength] : kv.Value;
            lines.Add($"# {key}: {value}");
        }
        lines.Add("### :END DETAILS");
        lines.Add("### START:");
        lines.Add($"# USER: {SessionState.Username}");
        lines.Add("# SIGNATURE: ");
        lines.Add("### :END START");
        lines.Add("## :END CONTRACT");
        var contract = string.Join("\n", lines) + "\n";
        if (contract.Length > MaxContractSize)
            throw new InvalidOperationException("Contrato excede tamanho maximo permitido.");
        return contract;
    }

    private static string ApplyContractSignature(string contractText, System.Security.Cryptography.RSA privateKey, string username)
    {
        const string signaturePlaceholder = "# SIGNATURE:";
        var trimmed = contractText.TrimEnd('\r', '\n');
        var lines = trimmed.Split('\n').ToList();
        var signatureIndex = lines.FindLastIndex(line => line.TrimStart().StartsWith(signaturePlaceholder, StringComparison.Ordinal));
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
}
// 19:25:04