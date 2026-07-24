using HpsWallet.Models;
using HpsWallet.Services;
using CommunityToolkit.Maui.Views;
using System.Collections.ObjectModel;
using System.Text.Json;
using System.Text;

namespace HpsWallet.Views;

public partial class PendingPage : ContentPage
{
    private List<PendingTransferItem> _pendingItems = new();
    private bool _isProcessing;

    public PendingPage()
    {
        InitializeComponent();
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        RegisterVoucherHandler();
        await LoadItems();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        UnregisterVoucherHandler();
    }

    private void RegisterVoucherHandler()
    {
        if (SessionState.Socket == null) return;
        SessionState.Socket.On("hps_voucher_offer", OnVoucherOffer);
    }

    private void UnregisterVoucherHandler()
    {
        if (SessionState.Socket == null) return;
        SessionState.Socket.Off("hps_voucher_offer", OnVoucherOffer);
    }

    private async Task OnVoucherOffer(SocketEventResponse response)
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
        data.TryGetProperty("payload", out var payloadProp);
        var value = 0;
        if (payloadProp.ValueKind == JsonValueKind.Object && payloadProp.TryGetProperty("value", out var valProp))
            value = valProp.GetInt32();
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            await DisplayAlertAsync("Voucher Recebido", $"Voce recebeu {value} $HPS!", "OK");
            await LoadItems();
        });
    }

    private async Task LoadItems()
    {
        LoadingLabel.Text = "Carregando...";
        LoadingLabel.IsVisible = true;
        ItemsContainer.Children.Clear();

        if (!SessionState.Socket.IsConnected)
        {
            LoadingLabel.Text = "Desconectado";
            return;
        }

        try
        {
            var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
            Func<SocketEventResponse, Task>? OnEvent = null;
            OnEvent = async response =>
            {
                try
                {
                    var payload = response.GetValue<JsonElement>();
                    if (payload.TryGetProperty("pending", out _) || payload.TryGetProperty("transfers", out _))
                        tcs.TrySetResult(payload);
                }
                catch { }
                SessionState.Socket.Off("pending_transfers", OnEvent);
            };
            SessionState.Socket.On("pending_transfers", OnEvent);
            await SessionState.Socket.EmitAsync("get_pending_transfers", new { username = SessionState.Username });

            var timeoutTask = Task.Delay(10000);
            var completed = await Task.WhenAny(tcs.Task, timeoutTask);
            SessionState.Socket.Off("pending_transfers", OnEvent);

            if (completed != tcs.Task)
            {
                LoadingLabel.Text = "Tempo limite ao carregar pendentes";
                return;
            }

            var payload2 = await tcs.Task;
            var list = new List<PendingTransferItem>();
            JsonElement arr;

            if (payload2.TryGetProperty("pending", out var pendingProp) && pendingProp.ValueKind == JsonValueKind.Array)
                arr = pendingProp;
            else if (payload2.TryGetProperty("transfers", out var transfersProp) && transfersProp.ValueKind == JsonValueKind.Array)
                arr = transfersProp;
            else
            {
                LoadingLabel.Text = "Nenhuma transferencia pendente";
                return;
            }

            foreach (var t in arr.EnumerateArray())
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

            MainThread.BeginInvokeOnMainThread(() => BuildItemViews(list));
        }
        catch (Exception ex)
        {
            LoadingLabel.Text = $"Erro: {ex.Message}";
            System.Diagnostics.Debug.WriteLine($"[PendingPage] Erro: {ex}");
        }
    }

    private void BuildItemViews(List<PendingTransferItem> items)
    {
        ItemsContainer.Children.Clear();
        LoadingLabel.IsVisible = false;

        if (items.Count == 0)
        {
            LoadingLabel.Text = "Nenhuma transferencia pendente";
            LoadingLabel.IsVisible = true;
            return;
        }

        foreach (var item in items)
        {
            var row = new Grid
            {
                ColumnDefinitions =
                {
                    new ColumnDefinition(GridLength.Star),
                    new ColumnDefinition(GridLength.Auto),
                    new ColumnDefinition(GridLength.Auto)
                },
                RowDefinitions =
                {
                    new RowDefinition(GridLength.Auto),
                    new RowDefinition(GridLength.Auto),
                    new RowDefinition(GridLength.Auto)
                },
                ColumnSpacing = 8,
                RowSpacing = 3,
                Padding = new Thickness(12),
                BackgroundColor = Color.FromArgb("#1E0F33"),
                InputTransparent = false
            };

            var desc = new Label
            {
                Text = item.Description,
                TextColor = Colors.White,
                FontSize = 13,
                FontAttributes = FontAttributes.Bold,
                InputTransparent = false
            };
            Grid.SetColumnSpan(desc, 3);
            row.Add(desc);

            var date = new Label
            {
                Text = item.Date,
                TextColor = Color.FromArgb("#9CA3AF"),
                FontSize = 10,
                InputTransparent = false
            };
            Grid.SetRow(date, 1);
            Grid.SetColumnSpan(date, 3);
            row.Add(date);

            var amount = new Label
            {
                Text = item.Amount,
                TextColor = item.AmountColor,
                FontSize = 16,
                FontAttributes = FontAttributes.Bold,
                VerticalOptions = LayoutOptions.Center,
                InputTransparent = false
            };
            Grid.SetRow(amount, 2);
            row.Add(amount);

            if (item.IsIncoming && item.Status == "pending")
            {
                var acceptBtn = new Button
                {
                    Text = "Aceitar",
                    BackgroundColor = Color.FromArgb("#10B981"),
                    TextColor = Colors.White,
                    FontSize = 11,
                    CornerRadius = 8,
                    Padding = new Thickness(12, 4),
                    HeightRequest = 34,
                    InputTransparent = false
                };
                Grid.SetRow(acceptBtn, 2);
                Grid.SetColumn(acceptBtn, 1);

                var itemCopy = item;
                acceptBtn.Clicked += async (_, _) => { if (!_isProcessing) await AcceptTransfer(itemCopy); };
                row.Add(acceptBtn);

                var rejectBtn = new Button
                {
                    Text = "Rejeitar",
                    BackgroundColor = Color.FromArgb("#EF4444"),
                    TextColor = Colors.White,
                    FontSize = 11,
                    CornerRadius = 8,
                    Padding = new Thickness(12, 4),
                    HeightRequest = 34,
                    InputTransparent = false
                };
                Grid.SetRow(rejectBtn, 2);
                Grid.SetColumn(rejectBtn, 2);

                var itemCopy2 = item;
                rejectBtn.Clicked += async (_, _) => { if (!_isProcessing) await RejectTransfer(itemCopy2); };
                row.Add(rejectBtn);
            }

            ItemsContainer.Children.Add(row);
        }
    }

    private async Task AcceptTransfer(PendingTransferItem item)
    {
        if (_isProcessing) return;
        _isProcessing = true;
        try
        {
            await HandleTransferWithPoW(item, "accept_hps_transfer", "Aceitar Transferencia", "aceitar");
        }
        finally
        {
            _isProcessing = false;
        }
    }

    private async Task RejectTransfer(PendingTransferItem item)
    {
        if (_isProcessing) return;
        _isProcessing = true;
        try
        {
            await HandleTransferWithPoW(item, "reject_transfer", "Rejeitar Transferencia", "rejeitar");
        }
        finally
        {
            _isProcessing = false;
        }
    }

    private async Task HandleTransferWithPoW(PendingTransferItem item, string serverEvent, string alertTitle, string actionLabel)
    {
        if (SessionState.GetPrivateKey() is null)
        {
            await DisplayAlertAsync("Erro", "Chave privada nao disponivel.", "OK");
            return;
        }

        var msg = $"De: {item.FromUser}\nValor: {item.RawAmount} $HPS\n\nDeseja {actionLabel}?";
        var confirmed = await DisplayAlertAsync(alertTitle, msg, "Sim", "Nao");
        if (!confirmed) return;

        var clientId = await SecureStorageHelper.GetClientIdAsync();
        if (string.IsNullOrEmpty(clientId))
        {
            await DisplayAlertAsync("Erro", "Identificador do cliente nao disponivel.", "OK");
            return;
        }

        var powTcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        Func<SocketEventResponse, Task>? powHandler = null;
        powHandler = async response =>
        {
            try
            {
                var payload = response.GetValue<JsonElement>();
                var actionType = payload.TryGetProperty("action_type", out var actP) ? actP.GetString() : "";
                if (actionType == "contract_transfer" || actionType == "hps_transfer")
                    powTcs.TrySetResult(payload);
            }
            catch { }
        };

        SessionState.Socket.On("pow_challenge", powHandler);

        try
        {
            await SessionState.Socket.EmitAsync("request_pow_challenge", new
            {
                client_identifier = clientId,
                action_type = "contract_transfer"
            });

            var timeoutTask = Task.Delay(30000);
            var completedTask = await Task.WhenAny(powTcs.Task, timeoutTask);
            if (completedTask != powTcs.Task)
            {
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
                    { "TRANSFER_ID", item.TransferId },
                    { "ACTION", actionLabel }
                };
                var contractText = BuildContractTemplate(serverEvent, details);
                var signedContract = ApplyContractSignature(contractText, SessionState.GetPrivateKey(), SessionState.Username);

                await SessionState.Socket.EmitAsync(serverEvent, new
                {
                    transfer_id = item.TransferId,
                    contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract)),
                    pow_nonce = result.Nonce.ToString(),
                    hashrate_observed = hashrate
                });

                popup.SetStatus("Aguardando confirmacao...");

            var ackTcs = new TaskCompletionSource<(bool success, string error)>(TaskCreationOptions.RunContinuationsAsynchronously);
            Func<SocketEventResponse, Task>? ackHandler = null;
            ackHandler = async response =>
            {
                try
                {
                    var payload = response.GetValue<JsonElement>();
                    var s = payload.TryGetProperty("success", out var sp) && sp.GetBoolean();
                    var err = payload.TryGetProperty("error", out var ep) ? ep.GetString() : "";
                    ackTcs.TrySetResult((s, err ?? ""));
                }
                catch { ackTcs.TrySetResult((false, "excecao")); }
                SessionState.Socket.Off(serverEvent + "_ack", ackHandler);
            };
                SessionState.Socket.On(serverEvent + "_ack", ackHandler);

                var ackTimeout = Task.Delay(15000);
                var ackCompleted = await Task.WhenAny(ackTcs.Task, ackTimeout);
                SessionState.Socket.Off(serverEvent + "_ack", ackHandler);

                popup.AutoClose(500);

                if (ackCompleted != ackTcs.Task)
                {
                    await DisplayAlertAsync("Erro", $"Timeout: {actionLabel} sem confirmacao do servidor.", "OK");
                }
                else
                {
                    var (ok, serverErr) = await ackTcs.Task;
                    if (ok)
                    {
                        await DisplayAlertAsync("Sucesso", $"Transferencia {actionLabel} com sucesso!", "OK");
                    }
                    else
                    {
                        await DisplayAlertAsync("Erro", $"Falha ao {actionLabel} transferencia: {serverErr}", "OK");
                    }
                }

                await LoadItems();
            }
            catch (Exception ex)
            {
                popup.AutoClose(500);
                await DisplayAlertAsync("Erro", $"Erro: {ex.Message}", "OK");
            }
        }
        finally
        {
            SessionState.Socket.Off("pow_challenge", powHandler);
        }
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