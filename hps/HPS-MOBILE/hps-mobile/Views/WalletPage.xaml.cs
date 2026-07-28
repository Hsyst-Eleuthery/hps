using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Maui.Views;
using CommunityToolkit.Maui.Extensions;
using HpsMobile.Models;
using HpsMobile.Services;

namespace HpsMobile.Views;

public partial class WalletPage : ContentPage
{
    private bool _handlersRegistered;
    private DateTime _lastBalanceRefresh = DateTime.MinValue;
    private JsonElement? _cachedBalanceData;
    private bool _pendingNoticeShown;
    private List<PendingTransferItem> _mobilePendingItems = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonElement>> _powChallengeTcsMap = new(StringComparer.OrdinalIgnoreCase);

    public WalletPage()
    {
        InitializeComponent();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        RegisterHandlers();
        _ = RefreshBalance();
        _ = LoadHistory();
        _ = LoadPendingTransfers();
        OnTabClicked(TabSendBtn, EventArgs.Empty);
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
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
            await MainThread.InvokeOnMainThreadAsync(RefreshBalance);
        });
        socket.On("hps_voucher_withheld", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var value = payload.TryGetProperty("value", out var v) ? v.GetInt32() : 0;
            MainThread.BeginInvokeOnMainThread(() =>
                GhostStatusLabel.Text = value > 0 ? $"Voucher retido. Valor: {value} HPS." : "Voucher retido pelo servidor.");
        });
        socket.On("hps_voucher_offer", async response =>
        {
            var data = response.GetValue<JsonElement>();
            var voucherId = data.TryGetProperty("voucher_id", out var vidProp) ? vidProp.GetString() : null;
            if (!string.IsNullOrEmpty(voucherId) && SessionState.GetPrivateKey() != null)
            {
                var payloadCanonical = data.TryGetProperty("payload_canonical", out var pcProp) && pcProp.ValueKind == JsonValueKind.String
                    ? pcProp.GetString() : null;
                if (!string.IsNullOrEmpty(payloadCanonical))
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
            }
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await RefreshBalance();
                if (data.TryGetProperty("value", out var val))
                    await DisplayAlertAsync("Novo Voucher", $"Voce recebeu {val.GetInt32()} $HPS!", "OK");
            });
        });
        socket.On("hps_voucher_error", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var error = payload.TryGetProperty("error", out var e) ? e.GetString() : "Erro desconhecido";
            MainThread.BeginInvokeOnMainThread(() => GhostStatusLabel.Text = $"Erro: {error}");
        });
        socket.On("exchange_quote", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            MainThread.BeginInvokeOnMainThread(() =>
            {
                var rate = payload.TryGetProperty("rate", out var r) ? r.GetDouble() : 0;
                var fee = payload.TryGetProperty("fee", out var f) ? f.GetDouble() : 0;
                var total = payload.TryGetProperty("total", out var t) ? t.GetDouble() : 0;
                var issuer = payload.TryGetProperty("target_issuer", out var iss) ? iss.GetString() : null;
                var error = payload.TryGetProperty("error", out var e) ? e.GetString() : null;

                if (!string.IsNullOrEmpty(error))
                {
                    ExchangeStatusLabel.Text = $"Erro: {error}";
                    ExchangeConfirmFrame.IsVisible = false;
                }
                else
                {
                    var detail = $"Taxa: {rate:F4}";
                    if (fee > 0) detail += $" | Taxa servico: {fee:F2}";
                    if (total > 0) detail += $" | Total: {total:F2} HPS";
                    if (!string.IsNullOrEmpty(issuer)) detail += $" | Emissor: {issuer}";
                    ExchangeStatusLabel.Text = "Cotacao recebida!";
                    ExchangeQuoteDetailLabel.Text = detail;
                    ExchangeConfirmFrame.IsVisible = true;
                }
            });
        });
        socket.On("exchange_complete", async response =>
        {
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                ExchangeStatusLabel.Text = "Cambio concluido!";
                ExchangeConfirmFrame.IsVisible = false;
                await RefreshBalance();
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
                    RecipientEntry.Text = "";
                    AmountEntry.Text = "";
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
            MainThread.BeginInvokeOnMainThread(() =>
            {
                PendingTransferFrame.IsVisible = true;
                UpdatePendingTransfers(payload);
            });
        });
        socket.On("transfer_offer", async _ =>
        {
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                PendingTransferFrame.IsVisible = true;
                await LoadPendingTransfers();
                await RefreshBalance();
            });
        });
        socket.On("transfer_response", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var s) && s.GetBoolean();
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                if (success)
                {
                    await DisplayAlertAsync("Sucesso", "Resposta enviada!", "OK");
                    await LoadPendingTransfers();
                    await RefreshBalance();
                }
                else
                {
                    var error = payload.TryGetProperty("error", out var e) ? e.GetString() : "Erro desconhecido";
                    await DisplayAlertAsync("Erro", $"Falha: {error}", "OK");
                }
            });
        });
        socket.On("pow_challenge", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var actionType = payload.TryGetProperty("action_type", out var actP) ? actP.GetString() : "";
            if (!string.IsNullOrEmpty(actionType) && _powChallengeTcsMap.TryRemove(actionType, out var tcs))
            {
                tcs.TrySetResult(payload);
            }
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
    }

    private void UnregisterHandlers()
    {
        _handlersRegistered = false;
        var socket = SessionState.Socket;
        if (socket == null) return;
        socket.Off("hps_economy_update");
        socket.Off("hps_voucher_withheld");
        socket.Off("hps_voucher_offer");
        socket.Off("hps_voucher_error");
        socket.Off("exchange_quote");
        socket.Off("exchange_complete");
        socket.Off("hps_transfer_ack");
        socket.Off("pending_transfers");
        socket.Off("transfer_offer");
        socket.Off("transfer_response");
        socket.Off("pow_challenge");
        socket.Off("accept_hps_transfer_ack");
        socket.Off("reject_transfer_ack");
    }

    private async Task LoadPendingTransfers()
    {
        if (!SessionState.Socket.IsConnected || !SessionState.IsLoggedIn) return;
        PendingTransferFrame.IsVisible = true;
        await SessionState.Socket.EmitAsync("get_pending_transfers", new { username = SessionState.Username });
    }

    private void BuildPendingItemUI(PendingTransferItem item)
    {
        var container = new VerticalStackLayout { Spacing = 4, Padding = new Thickness(0, 0, 0, 6) };

        container.Children.Add(new Label
        {
            Text = item.Description,
            TextColor = Colors.White,
            FontSize = 13,
            FontAttributes = FontAttributes.Bold
        });
        container.Children.Add(new Label
        {
            Text = item.Date,
            TextColor = Color.FromArgb("#9CA3AF"),
            FontSize = 10
        });
        container.Children.Add(new Label
        {
            Text = item.AmountDisplay,
            TextColor = item.AmountColor,
            FontSize = 15,
            FontAttributes = FontAttributes.Bold
        });

        var acceptBtn = new Button
        {
            Text = "✓ Aceitar",
            BackgroundColor = Color.FromArgb("#10B981"),
            TextColor = Colors.White,
            FontSize = 12,
            HeightRequest = 38,
            CornerRadius = 8,
            Margin = new Thickness(0, 4, 0, 0)
        };
        var clickedItem = item;
        acceptBtn.Clicked += (_, _) => OnAcceptTransfer(clickedItem);
        container.Children.Add(acceptBtn);

        var rejectBtn = new Button
        {
            Text = "✗ Rejeitar",
            BackgroundColor = Color.FromArgb("#DC2626"),
            TextColor = Colors.White,
            FontSize = 12,
            HeightRequest = 38,
            CornerRadius = 8
        };
        rejectBtn.Clicked += (_, _) => OnRejectTransfer(clickedItem);
        container.Children.Add(rejectBtn);

        PendingStack.Children.Add(container);
    }

    private void UpdatePendingTransfers(JsonElement payload)
    {
        try
        {
            if (payload.TryGetProperty("transfers", out var transfers) && transfers.ValueKind == JsonValueKind.Array)
            {
                var items = new List<PendingTransferItem>();
                foreach (var t in transfers.EnumerateArray())
                {
                    var id = t.TryGetProperty("id", out var idP) ? idP.GetString() ?? "" : "";
                    var fromUser = t.TryGetProperty("from_user", out var fP) ? fP.GetString() ?? "" : "";
                    var amount = t.TryGetProperty("amount", out var aP) ? aP.GetInt32() : 0;
                    var status = t.TryGetProperty("status", out var sP) ? sP.GetString() ?? "pending" : "pending";
                    var createdAt = t.TryGetProperty("created_at", out var cP) ? cP.GetString() ?? "" : "";
                    var incoming = t.TryGetProperty("direction", out var dP) ? dP.GetString() == "incoming" : true;

                    items.Add(new PendingTransferItem
                    {
                        TransferId = id,
                        FromUser = fromUser,
                        Amount = amount,
                        Status = status,
                        CreatedAt = createdAt,
                        IsIncoming = incoming,
                    });
                }
                _mobilePendingItems = items;
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    PendingStack.Children.Clear();
                    foreach (var eachItem in items)
                        BuildPendingItemUI(eachItem);
                });

                if (!_pendingNoticeShown && _mobilePendingItems.Count > 0)
                {
                    _pendingNoticeShown = true;
                    MainThread.BeginInvokeOnMainThread(async () =>
                    {
                        await DisplayAlertAsync("Transferencias Pendentes",
                            $"Voce tem {_mobilePendingItems.Count} transferencia(s) pendente(s).\nAcesse a aba Pendentes para revisa-las.",
                            "OK");
                    });
                }
            }
            else
            {
                _mobilePendingItems = new List<PendingTransferItem>();
                MainThread.BeginInvokeOnMainThread(() => PendingStack.Children.Clear());
            }
        }
        catch { }
    }

    private async void OnRefreshPending(object? sender, EventArgs e)
    {
        await LoadPendingTransfers();
    }

    private async void OnAcceptTransfer(PendingTransferItem item)
    {
        if (item == null || string.IsNullOrEmpty(item.TransferId)) return;
        try { await HandleTransferWithPoW(item.TransferId, "accept_hps_transfer", "Aceitar Transferencia", "aceitar"); }
        catch (Exception ex) { await DisplayAlertAsync("Erro", ex.Message, "OK"); }
    }

    private async void OnRejectTransfer(PendingTransferItem item)
    {
        if (item == null || string.IsNullOrEmpty(item.TransferId)) return;
        try { await HandleTransferWithPoW(item.TransferId, "reject_transfer", "Rejeitar Transferencia", "rejeitar"); }
        catch (Exception ex) { await DisplayAlertAsync("Erro", ex.Message, "OK"); }
    }

    private async Task HandleTransferWithPoW(string transferId, string serverEvent, string alertTitle, string actionLabel)
    {
        if (SessionState.GetPrivateKey() is null)
        {
            await DisplayAlertAsync("Erro", "Chave privada nao disponivel.", "OK");
            return;
        }

        var item = _mobilePendingItems.FirstOrDefault(i => i.TransferId == transferId);
        var msg = item != null
            ? $"De: {item.FromUser}\nValor: {item.Amount} $HPS\n\nDeseja {actionLabel}?"
            : $"Deseja {actionLabel} a transferencia?";

        var confirmed = await DisplayAlertAsync(alertTitle, msg, "Sim", "Nao");
        if (!confirmed) return;

        var clientId = await SecureStorageHelper.GetClientIdAsync();
        if (string.IsNullOrEmpty(clientId))
        {
            await DisplayAlertAsync("Erro", "Identificador do cliente nao disponivel.", "OK");
            return;
        }

        var powActionType = "contract_transfer";
        var powTcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _powChallengeTcsMap[powActionType] = powTcs;
        await SessionState.Socket.EmitAsync("request_pow_challenge", new
        {
            client_identifier = clientId,
            action_type = powActionType
        });

        var timeoutTask = Task.Delay(30000);
        var completedTask = await Task.WhenAny(powTcs.Task, timeoutTask);
        if (completedTask != powTcs.Task)
        {
            _powChallengeTcsMap.TryRemove(powActionType, out var _);
            powTcs.TrySetCanceled();
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
        var powThreads = Preferences.Get("mobile_pow_threads", 2);

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

    private async Task RefreshBalance()
    {
        var vouchers = await FetchBalanceData();
        if (vouchers == null)
        {
            BalanceLabel.Text = "0 $HPS";
            UserLabel.Text = "Desconectado";
            MultiplierLabel.Text = "";
            return;
        }

        try
        {
            if (vouchers.Value.TryGetProperty("balance", out var bal))
                BalanceLabel.Text = $"{bal.GetInt32()} $HPS";
            if (vouchers.Value.TryGetProperty("username", out var un))
                UserLabel.Text = $"@{un.GetString()}";
            if (vouchers.Value.TryGetProperty("multiplier", out var mult))
                MultiplierLabel.Text = $"Multiplicador: {mult.GetDouble():F2}x";
        }
        catch
        {
            UserLabel.Text = "Conectado";
        }
    }

    private async Task LoadHistory()
    {
        try
        {
            var result = await FetchBalanceData();
            if (result == null || !result.Value.TryGetProperty("vouchers", out var vouchers) || vouchers.ValueKind != JsonValueKind.Array)
            {
                HistoryCollection.ItemsSource = null;
                return;
            }

            var items = new ObservableCollection<TransactionItem>();
            foreach (var v in vouchers.EnumerateArray())
            {
                var reason = v.TryGetProperty("reason", out var r) ? r.GetString() ?? "voucher" : "voucher";
                var date = v.TryGetProperty("issued_at", out var d)
                    ? DateTimeOffset.FromUnixTimeSeconds((long)d.GetDouble()).LocalDateTime.ToString("dd/MM HH:mm")
                    : "";
                var value = v.TryGetProperty("value", out var amt) ? amt.GetInt32() : 0;
                var isNegative = reason.Contains("exchange_out") || reason.Contains("spend") || reason.Contains("transfer_out") || reason.Contains("ghost");
                items.Add(new TransactionItem
                {
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
#if DEBUG
            System.Diagnostics.Debug.WriteLine("[Wallet] Erro ao carregar historico");
#endif
        }
    }

    private void OnTabClicked(object? sender, EventArgs e)
    {
        if (sender is not Button btn) return;
        var tab = btn.Text;
        SendPanel.IsVisible = tab == "Enviar";
        ReceivePanel.IsVisible = tab == "Receber";
        VoucherPanel.IsVisible = tab == "Voucher";
        ExchangePanel.IsVisible = tab == "Cambio";
        HistoryPanel.IsVisible = tab == "Historico";

        if (tab == "Receber")
            MyUsernameDisplay.Text = $"@{SessionState.Username}";

        var activeColor = "#7C3AED";
        var inactiveColor = "#2D1B4E";
        TabSendBtn.BackgroundColor = tab == "Enviar" ? Color.FromArgb(activeColor) : Color.FromArgb(inactiveColor);
        TabSendBtn.TextColor = tab == "Enviar" ? Colors.White : Color.FromArgb("#C084FC");
        TabReceiveBtn.BackgroundColor = tab == "Receber" ? Color.FromArgb(activeColor) : Color.FromArgb(inactiveColor);
        TabReceiveBtn.TextColor = tab == "Receber" ? Colors.White : Color.FromArgb("#C084FC");
        TabVoucherBtn.BackgroundColor = tab == "Voucher" ? Color.FromArgb(activeColor) : Color.FromArgb(inactiveColor);
        TabVoucherBtn.TextColor = tab == "Voucher" ? Colors.White : Color.FromArgb("#C084FC");
        TabExchangeBtn.BackgroundColor = tab == "Cambio" ? Color.FromArgb(activeColor) : Color.FromArgb(inactiveColor);
        TabExchangeBtn.TextColor = tab == "Cambio" ? Colors.White : Color.FromArgb("#C084FC");
        TabHistoryBtn.BackgroundColor = tab == "Historico" ? Color.FromArgb(activeColor) : Color.FromArgb(inactiveColor);
        TabHistoryBtn.TextColor = tab == "Historico" ? Colors.White : Color.FromArgb("#C084FC");
    }

    private void OnSendClicked(object? sender, EventArgs e)
    {
        OnTabClicked(TabSendBtn, EventArgs.Empty);
    }

    private void OnReceiveClicked(object? sender, EventArgs e)
    {
        MyUsernameDisplay.Text = $"@{SessionState.Username}";
        OnTabClicked(TabReceiveBtn, EventArgs.Empty);
    }

    private async void OnTransferConfirmed(object? sender, EventArgs e)
    {
        var recipient = RecipientEntry.Text?.Trim();
        var amountText = AmountEntry.Text?.Trim();

        if (string.IsNullOrEmpty(recipient) || string.IsNullOrEmpty(amountText))
        {
            await DisplayAlertAsync("Erro", "Preencha todos os campos", "OK");
            return;
        }

        if (!int.TryParse(amountText, out var amount) || amount <= 0)
        {
            await DisplayAlertAsync("Erro", "Valor invalido", "OK");
            return;
        }

        if (SessionState.GetPrivateKey() is null)
        {
            await DisplayAlertAsync("Erro", "Chave privada nao disponivel.", "OK");
            return;
        }

        var confirmed = await DisplayAlertAsync("Confirmar",
            $"Enviar {amount} $HPS para {recipient}?", "Sim", "Nao");

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
                if (invalidated) continue;
                if (status != "" && status != "valid" && status != "active") continue;
                var vid = v.TryGetProperty("voucher_id", out var idP) ? idP.GetString() ?? "" : "";
                var val = v.TryGetProperty("value", out var vlP) ? vlP.GetInt32() : 0;
                if (!string.IsNullOrEmpty(vid) && val > 0)
                    validVouchers.Add((vid, val));
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

            var powActionType = "hps_transfer";
            var powTcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
            _powChallengeTcsMap[powActionType] = powTcs;
            await SessionState.Socket.EmitAsync("request_pow_challenge", new
            {
                client_identifier = clientId,
                action_type = powActionType
            });

            var timeoutTask = Task.Delay(30000);
            var completedTask = await Task.WhenAny(powTcs.Task, timeoutTask);
            if (completedTask != powTcs.Task)
            {
                _powChallengeTcsMap.TryRemove(powActionType, out var _);
                powTcs.TrySetCanceled();
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
            var powThreads = Preferences.Get("mobile_pow_threads", 2);

            var popup = new PowPopup("Enviar $HPS", targetBits);
            var shownTcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            popup.Opened += (_, _) => shownTcs.TrySetResult(null);
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await this.ShowPopupAsync(popup);
            });
            await shownTcs.Task;

            var cts = CancellationTokenSource.CreateLinkedTokenSource(popup.Token);

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
            RecipientEntry.Text = "";
            AmountEntry.Text = "";
            await DisplayAlertAsync("Transferencia Enviada",
                $"Transferencia de {amount} $HPS para {recipient} enviada!\n\nAguardando validacao do minerador.", "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlertAsync("Erro", $"Falha na transferencia: {ex.Message}", "OK");
        }
    }

    private async void OnGhostVoucher(object? sender, EventArgs e)
    {
        var voucherId = GhostVoucherEntry.Text?.Trim();
        if (string.IsNullOrEmpty(voucherId))
        {
            GhostStatusLabel.Text = "Digite o ID do voucher.";
            return;
        }

        var confirmed = await DisplayAlertAsync("Ghost Voucher",
            $"Tem certeza que deseja destruir permanentemente o voucher {voucherId[..Math.Min(voucherId.Length, 20)]}...?",
            "Sim, Destruir", "Cancelar");

        if (!confirmed) return;

        GhostStatusLabel.Text = "Resolvendo desafio PoW...";

        var clientId = await SecureStorageHelper.GetClientIdAsync();
        if (string.IsNullOrEmpty(clientId))
        {
            GhostStatusLabel.Text = "Identificador do cliente nao disponivel.";
            return;
        }

        var powActionType = "ghost_voucher";
        var powTcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _powChallengeTcsMap[powActionType] = powTcs;
        await SessionState.Socket.EmitAsync("request_pow_challenge", new
        {
            client_identifier = clientId,
            action_type = powActionType
        });

        var timeoutTask = Task.Delay(30000);
        var completedTask = await Task.WhenAny(powTcs.Task, timeoutTask);
        if (completedTask != powTcs.Task)
        {
            _powChallengeTcsMap.TryRemove(powActionType, out var _);
            powTcs.TrySetCanceled();
            GhostStatusLabel.Text = "Tempo limite excedido.";
            return;
        }

        var challengePayload = await powTcs.Task;
        var challenge = challengePayload.TryGetProperty("challenge", out var chalP) ? chalP.GetString() : null;
        var targetBits = challengePayload.TryGetProperty("target_bits", out var bitsP) ? bitsP.GetInt32() : 0;
        if (string.IsNullOrEmpty(challenge) || targetBits < 20)
        {
            GhostStatusLabel.Text = "Desafio PoW invalido (min 20 bits).";
            return;
        }

        var challengeBytes = Convert.FromBase64String(challenge);
        var powThreads = Preferences.Get("mobile_pow_threads", 2);
        var cts = new CancellationTokenSource();
        var solver = new PowSolver();
        var result = await Task.Run(() => solver.SolveAsync(challengeBytes, targetBits, powThreads, cts.Token));

        if (result is null)
        {
            GhostStatusLabel.Text = "PoW cancelado.";
            return;
        }

        GhostStatusLabel.Text = "Enviando ghost...";

        // C4: Add authorization via signed contract for ghost_voucher
        var details = new Dictionary<string, string>
        {
            { "VOUCHER_ID", voucherId },
            { "ACTION", "ghost_voucher" }
        };
        var contractText = BuildContractTemplate("ghost_voucher", details);
        var signedContract = ApplyContractSignature(contractText, SessionState.GetPrivateKey(), SessionState.Username);

        await SessionState.Socket.EmitAsync("ghost_voucher", new
        {
            voucher_id = voucherId,
            pow_nonce = result.Nonce.ToString(),
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract))
        });
    }

    private async void OnExchangeQuote(object? sender, EventArgs e)
    {
        var targetServer = ExchangeTargetEntry.Text?.Trim();
        var amountText = ExchangeAmountEntry.Text?.Trim();

        if (string.IsNullOrEmpty(targetServer) || string.IsNullOrEmpty(amountText))
        {
            ExchangeStatusLabel.Text = "Preencha servidor e valor.";
            return;
        }

        if (!decimal.TryParse(amountText, out var amount) || amount <= 0)
        {
            ExchangeStatusLabel.Text = "Valor invalido.";
            return;
        }

        ExchangeStatusLabel.Text = "Solicitando cotacao...";
        ExchangeConfirmFrame.IsVisible = false;
        await SessionState.Socket.EmitAsync("request_exchange_quote", new
        {
            target_server = targetServer,
            amount = (int)amount
        });
    }

    private async void OnExecuteExchange(object? sender, EventArgs e)
    {
        var targetServer = ExchangeTargetEntry.Text?.Trim();
        var amountText = ExchangeAmountEntry.Text?.Trim();

        if (string.IsNullOrEmpty(targetServer) || string.IsNullOrEmpty(amountText))
        {
            ExchangeStatusLabel.Text = "Preencha servidor e valor.";
            return;
        }

        if (!decimal.TryParse(amountText, out var amount) || amount <= 0)
        {
            ExchangeStatusLabel.Text = "Valor invalido.";
            return;
        }

        var confirm = await DisplayAlertAsync("Confirmar Cambio",
            $"Enviar {amount} $HPS para {targetServer}?", "Sim", "Cancelar");
        if (!confirm) return;

        ExchangeStatusLabel.Text = "Executando cambio...";
        ExchangeConfirmFrame.IsVisible = false;

        if (SessionState.GetPrivateKey() is null)
        {
            ExchangeStatusLabel.Text = "Chave privada nao disponivel.";
            return;
        }

        var details = new Dictionary<string, string>
        {
            { "REASON", "exchange" },
            { "TARGET_SERVER", targetServer },
            { "AMOUNT", ((int)amount).ToString() }
        };
        var contractTemplate = BuildContractTemplate("exchange_hps", details);
        var signedContract = ApplyContractSignature(contractTemplate, SessionState.GetPrivateKey(), SessionState.Username);

        await SessionState.Socket.EmitAsync("execute_exchange", new
        {
            target_server = targetServer,
            amount = (int)amount,
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract))
        });
    }

    private async void OnCheckVoucher(object? sender, EventArgs e)
    {
        var voucherId = VoucherEntry.Text?.Trim();
        if (string.IsNullOrEmpty(voucherId))
        {
            voucherId = await DisplayPromptAsync("Verificar Voucher",
                "Digite o ID do voucher:", "Verificar", "Cancelar");
            if (string.IsNullOrEmpty(voucherId)) return;
            VoucherEntry.Text = voucherId;
        }

        try
        {
            var voucher = await SessionState.Server.FetchVoucherAsync(voucherId);
            if (voucher == null)
            {
                await DisplayAlertAsync("Nao Encontrado", $"Voucher {voucherId} nao encontrado.", "OK");
                return;
            }

            VoucherInfoFrame.IsVisible = true;
            VoucherIdLabel.Text = $"ID: {voucherId[..Math.Min(voucherId.Length, 20)]}...";
            if (voucher.Value.TryGetProperty("payload", out var payload))
            {
                if (payload.TryGetProperty("value", out var val))
                    VoucherValueLabel.Text = $"{val.GetInt32()} $HPS";
                if (payload.TryGetProperty("owner", out var owner))
                    VoucherOwnerLabel.Text = $"Proprietario: {owner.GetString()}";
            }
            VoucherStatusLabel.Text = "Voucher Valido";
            VoucherStatusLabel.TextColor = Colors.LimeGreen;
        }
        catch (Exception ex)
        {
            await DisplayAlertAsync("Erro", $"Falha ao verificar: {ex.Message}", "OK");
        }
    }

    private void OnScanClicked(object? sender, EventArgs e)
    {
        OnCheckVoucher(sender, e);
    }

    private async void OnRefreshHistory(object? sender, EventArgs e)
    {
        await LoadHistory();
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
}