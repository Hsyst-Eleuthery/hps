using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hps.Cli.Native.Core;
using Hps.Cli.Native.Display;
using Hps.Cli.Native.Pow;
using Hps.Cli.Native.Storage;

namespace Hps.Cli.Native.Socket;

public sealed class HpsRealtimeSession : IAsyncDisposable
{
    private static readonly SemaphoreSlim SharedGate = new(1, 1);
    private static HpsRealtimeSession? SharedSession;
    private static string SharedServer = string.Empty;
    private static string SharedUser = string.Empty;

    private readonly HpsSocketClient _socket;
    private readonly NativeClientService _service;
    private readonly NativeContext _ctx;
    private readonly ICliDisplay _display;
    private IDisposable? _queueRegistration;
    private IDisposable? _requestContentRegistration;
    private IDisposable? _requestDdnsRegistration;
    private IDisposable? _requestContractRegistration;
    private readonly List<IDisposable> _handlerRegistrations = new();
    private bool _isShared;

    private HpsRealtimeSession(HpsSocketClient socket, NativeClientService service, NativeContext ctx, ICliDisplay display)
    {
        _socket = socket;
        _service = service;
        _ctx = ctx;
        _display = display;
    }

    public static async Task<HpsRealtimeSession> ConnectAuthenticatedAsync(
        string server,
        string username,
        NativeClientService service,
        NativeContext ctx,
        ICliDisplay display,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new InvalidOperationException("usuario nao definido");
        }
        if (!service.IsCryptoUnlocked)
        {
            throw new InvalidOperationException("cofre nao desbloqueado. use: keys unlock <username>");
        }

        var serverKey = NormalizeServerKey(server);
        var userKey = (username ?? string.Empty).Trim();

        await SharedGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (SharedSession is not null &&
                SharedSession._socket.IsConnected &&
                SharedServer.Equals(serverKey, StringComparison.OrdinalIgnoreCase) &&
                SharedUser.Equals(userKey, StringComparison.OrdinalIgnoreCase))
            {
                return SharedSession;
            }

            if (SharedSession is not null)
            {
                await SharedSession.DisposeInternalAsync().ConfigureAwait(false);
                SharedSession = null;
                SharedServer = string.Empty;
                SharedUser = string.Empty;
            }

            var socket = new HpsSocketClient();
            await socket.ConnectAsync(server, ct).ConfigureAwait(false);
            var session = new HpsRealtimeSession(socket, service, ctx, display)
            {
                _isShared = true
            };
            try
            {
                await session.AuthenticateAsync(server, userKey, ct).ConfigureAwait(false);
                SharedSession = session;
                SharedServer = serverKey;
                SharedUser = userKey;
                return session;
            }
            catch
            {
                await socket.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            SharedGate.Release();
        }
    }

    public static async Task ClearSharedSessionAsync()
    {
        await SharedGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (SharedSession is not null)
            {
                await SharedSession.DisposeInternalAsync().ConfigureAwait(false);
            }
            SharedSession = null;
            SharedServer = string.Empty;
            SharedUser = string.Empty;
        }
        finally
        {
            SharedGate.Release();
        }
    }

    public async Task<JsonElement> EmitAndWaitAsync(
        string emitEvent,
        object payload,
        string responseEvent,
        TimeSpan timeout,
        CancellationToken ct,
        Func<JsonElement, bool>? predicate = null)
    {
        var waiting = _socket.WaitForEventAsync(responseEvent, timeout, ct, predicate);
        await _socket.EmitAsync(emitEvent, payload, ct).ConfigureAwait(false);
        return await waiting.ConfigureAwait(false);
    }

    public Task EmitAsync(string emitEvent, object payload, CancellationToken ct) =>
        _socket.EmitAsync(emitEvent, payload, ct);

    public Task<JsonElement> WaitForEventAsync(
        string eventName,
        TimeSpan timeout,
        CancellationToken ct,
        Func<JsonElement, bool>? predicate = null) =>
        _socket.WaitForEventAsync(eventName, timeout, ct, predicate);

    public async Task<(string EventName, JsonElement Payload)> EmitAndWaitAnyAsync(
        string emitEvent,
        object payload,
        IReadOnlyCollection<string> responseEvents,
        TimeSpan timeout,
        CancellationToken ct)
    {
        if (responseEvents is null || responseEvents.Count == 0)
        {
            throw new ArgumentException("responseEvents vazio", nameof(responseEvents));
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        var token = timeoutCts.Token;

        var waits = responseEvents
            .Select(async eventName =>
            {
                var data = await _socket.WaitForEventAsync(eventName, timeout, token).ConfigureAwait(false);
                return (EventName: eventName, Payload: data);
            })
            .ToArray();

        await _socket.EmitAsync(emitEvent, payload, ct).ConfigureAwait(false);
        var completed = await Task.WhenAny(waits).ConfigureAwait(false);
        return await completed.ConfigureAwait(false);
    }

    public async Task<(string Nonce, double Hashrate)> SolvePowAsync(string actionType, CancellationToken ct)
    {
        var challenge = await EmitAndWaitAsync(
            "request_pow_challenge",
            new
            {
                client_identifier = _service.ClientIdentifier,
                action_type = actionType
            },
            "pow_challenge",
            TimeSpan.FromSeconds(35),
            ct).ConfigureAwait(false);

        if (challenge.TryGetProperty("error", out var e) && !string.IsNullOrWhiteSpace(e.GetString()))
        {
            throw new InvalidOperationException("pow_challenge: " + e.GetString());
        }

        var challengeB64 = challenge.TryGetProperty("challenge", out var ch) ? ch.GetString() ?? string.Empty : string.Empty;
        var targetBits = challenge.TryGetProperty("target_bits", out var bits) ? bits.GetInt32() : 20;
        const int MaxTargetBits = 32;
        if (targetBits > MaxTargetBits)
        {
            targetBits = MaxTargetBits;
        }
        var targetSeconds = challenge.TryGetProperty("target_seconds", out var sec) ? sec.GetDouble() : 12.0;
        if (string.IsNullOrWhiteSpace(challengeB64))
        {
            throw new InvalidOperationException("pow_challenge invalido");
        }

        var solver = new CliPowSolver();
        solver.ProgressChanged += p =>
        {
            var pct = p.TargetSeconds <= 0 ? 0 : (int)Math.Min(99, (p.ElapsedSeconds / p.TargetSeconds) * 100);
            _display.PrintProgress(pct, 100, $"pow:{actionType} rate={p.Hashrate:0}H/s bits={p.TargetBits}");
        };

        var result = await solver.SolveAsync(challengeB64, targetBits, targetSeconds, actionType, threads: ResolvePowThreads(), cancellationToken: ct).ConfigureAwait(false);
        _display.PrintProgress(100, 100, $"pow:{actionType} concluido");
        if (!result.Solved)
        {
            throw new InvalidOperationException(result.Error ?? "falha no pow");
        }
        _service.IncrementStat("pow_solved");
        _service.IncrementStat("hashes_calculated", (long)Math.Min(long.MaxValue, result.TotalHashes));
        return (result.Nonce.ToString(CultureInfo.InvariantCulture), result.Hashrate);
    }

    public async ValueTask DisposeAsync()
    {
        if (_isShared &&
            SharedSession is not null &&
            ReferenceEquals(this, SharedSession) &&
            _socket.IsConnected)
        {
            return;
        }
        await DisposeInternalAsync().ConfigureAwait(false);
    }

    private async ValueTask DisposeInternalAsync()
    {
        _queueRegistration?.Dispose();
        _queueRegistration = null;
        _requestContentRegistration?.Dispose();
        _requestContentRegistration = null;
        _requestDdnsRegistration?.Dispose();
        _requestDdnsRegistration = null;
        _requestContractRegistration?.Dispose();
        _requestContractRegistration = null;
        foreach (var reg in _handlerRegistrations)
        {
            reg.Dispose();
        }
        _handlerRegistrations.Clear();
        await _socket.DisposeAsync().ConfigureAwait(false);
    }

    private async Task AuthenticateAsync(string server, string username, CancellationToken ct)
    {
        JsonElement challengePayload = default;
        Exception? challengeError = null;
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                challengePayload = await EmitAndWaitAsync(
                    "request_server_auth_challenge",
                    new { },
                    "server_auth_challenge",
                    TimeSpan.FromSeconds(20),
                    ct).ConfigureAwait(false);
                challengeError = null;
                break;
            }
            catch (TimeoutException ex) when (attempt < 3)
            {
                challengeError = ex;
                await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), ct).ConfigureAwait(false);
            }
        }

        if (challengeError is not null)
        {
            throw challengeError;
        }

        var challenge = challengePayload.TryGetProperty("challenge", out var ch) ? ch.GetString() ?? string.Empty : string.Empty;
        var serverPublicKeyB64 = challengePayload.TryGetProperty("server_public_key", out var pk) ? pk.GetString() ?? string.Empty : string.Empty;
        var serverSignatureB64 = challengePayload.TryGetProperty("signature", out var sig) ? sig.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(challenge) || string.IsNullOrWhiteSpace(serverPublicKeyB64) || string.IsNullOrWhiteSpace(serverSignatureB64))
        {
            throw new InvalidOperationException("server_auth_challenge incompleto");
        }

        VerifyServerChallenge(challenge, serverPublicKeyB64, serverSignatureB64);
        PinOrVerifyServerPublicKey(server, serverPublicKeyB64);

        var clientChallenge = Guid.NewGuid().ToString("N");
        var clientSig = Convert.ToBase64String(_ctx.KeyManager.SignPayload(clientChallenge));
        var clientPublicKey = _ctx.KeyManager.ExportPublicKeyBase64();

        var authResult = await EmitAndWaitAsync(
            "verify_server_auth_response",
            new
            {
                client_challenge = clientChallenge,
                client_signature = clientSig,
                client_public_key = clientPublicKey
            },
            "server_auth_result",
            TimeSpan.FromSeconds(20),
            ct).ConfigureAwait(false);

        if (!ReadSuccess(authResult))
        {
            throw new InvalidOperationException("server_auth falhou: " + ReadError(authResult));
        }

        var (nonce, rate) = await SolvePowAsync("login", ct).ConfigureAwait(false);
        var loginResult = await EmitAndWaitAsync(
            "authenticate",
            new
            {
                username = username,
                public_key = clientPublicKey,
                node_type = "client",
                client_identifier = _service.ClientIdentifier,
                pow_nonce = nonce,
                hashrate_observed = rate,
                client_challenge_signature = clientSig,
                client_challenge = clientChallenge
            },
            "authentication_result",
            TimeSpan.FromSeconds(45),
            ct).ConfigureAwait(false);

        if (!ReadSuccess(loginResult))
        {
            throw new InvalidOperationException("authenticate falhou: " + ReadError(loginResult));
        }

        _service.IncrementStat("login_count");

        _queueRegistration = _socket.On("action_queue_update", q =>
        {
            var action = q.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "";
            var status = q.TryGetProperty("status", out var s) ? s.GetString() ?? "" : "";
            var position = q.TryGetProperty("position", out var p) ? p.ToString() : "";
            if (!string.IsNullOrWhiteSpace(action) && !string.IsNullOrWhiteSpace(status))
            {
                _display.PrintInfo($"fila: action={action} status={status} pos={position}");
            }
        });

        _requestContentRegistration = _socket.On("request_content_from_client", payload =>
        {
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(contentHash))
            {
                _ = Task.Run(async () =>
                {
                    try { await SendContentToServerAsync(contentHash, CancellationToken.None).ConfigureAwait(false); }
                    catch (Exception ex) { Console.Error.WriteLine($"[WARN] fire-and-forget SendContentToServer failed: {ex.Message}"); }
                });
            }
        });

        _requestDdnsRegistration = _socket.On("request_ddns_from_client", payload =>
        {
            var domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(domain))
            {
                _ = Task.Run(async () =>
                {
                    try { await SendDdnsToServerAsync(domain, CancellationToken.None).ConfigureAwait(false); }
                    catch (Exception ex) { Console.Error.WriteLine($"[WARN] fire-and-forget SendDdnsToServer failed: {ex.Message}"); }
                });
            }
        });

        _requestContractRegistration = _socket.On("request_contract_from_client", payload =>
        {
            var contractId = payload.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(contractId))
            {
                _ = Task.Run(async () =>
                {
                    try { await SendContractToServerAsync(contractId, CancellationToken.None).ConfigureAwait(false); }
                    catch (Exception ex) { Console.Error.WriteLine($"[WARN] fire-and-forget SendContractToServer failed: {ex.Message}"); }
                });
            }
        });

        _handlerRegistrations.Add(_socket.On("notification", payload =>
        {
            var message = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? string.Empty : string.Empty;
            var level = payload.TryGetProperty("level", out var levelProp) ? levelProp.GetString() ?? "info" : "info";
            if (!string.IsNullOrWhiteSpace(message))
            {
                _display.PrintInfo($"[{level}] {message}");
            }
        }));

        _handlerRegistrations.Add(_socket.On("content_integrity_ack", payload =>
        {
            var hash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() : null;
            var ok = payload.TryGetProperty("success", out var succProp) && succProp.GetBoolean();
            var msg = hash is not null ? $"Integridade: {hash} {(ok ? "OK" : "FALHA")}" : "Integridade: resposta vazia";
            if (ok) _display.PrintSuccess(msg); else _display.PrintError(msg);
        }));

        _handlerRegistrations.Add(_socket.On("hps_voucher_issued", payload =>
        {
            var voucherId = payload.TryGetProperty("voucher_id", out var vidProp) ? vidProp.GetString() : null;
            if (!string.IsNullOrWhiteSpace(voucherId))
            {
                _display.PrintInfo($"Voucher emitido: {voucherId}");
                try
                {
                    _service.SaveWalletSync(payload);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[WARN] hps_voucher_issued SaveWalletSync failed: {ex.Message}");
                }
            }
        }));

        _handlerRegistrations.Add(_socket.On("fraud_report_ack", payload =>
        {
            var ok = payload.TryGetProperty("success", out var succProp) && succProp.GetBoolean();
            if (ok) _display.PrintSuccess("Denúncia registrada."); else _display.PrintError("Falha ao registrar denúncia.");
        }));

        _handlerRegistrations.Add(_socket.On("voucher_invalidate_ack", payload =>
        {
            var ok = payload.TryGetProperty("success", out var succProp) && succProp.GetBoolean();
            if (ok) _display.PrintSuccess("Voucher invalidado."); else _display.PrintError("Falha ao invalidar voucher.");
        }));

        _handlerRegistrations.Add(_socket.On("contract_violation_ack", payload =>
        {
            var ok = payload.TryGetProperty("success", out var succProp) && succProp.GetBoolean();
            var violationId = payload.TryGetProperty("violation_id", out var vidProp) ? vidProp.GetString() : null;
            if (ok) _display.PrintSuccess(violationId is not null ? $"Violação registrada: {violationId}" : "Violação registrada.");
            else _display.PrintError("Falha ao registrar violação.");
        }));

        _handlerRegistrations.Add(_socket.On("contract_canonical", payload =>
        {
            var contractId = payload.TryGetProperty("contract_id", out var cidProp) ? cidProp.GetString() : null;
            if (!string.IsNullOrWhiteSpace(contractId))
            {
                try
                {
                    var contentB64 = payload.TryGetProperty("contract_content", out var ccProp) ? ccProp.GetString() : null;
                    var contractContent = contentB64 is not null ? Encoding.UTF8.GetString(Convert.FromBase64String(contentB64)) : string.Empty;
                    var tsUnix = payload.TryGetProperty("timestamp", out var tsProp) ? tsProp.GetDouble() : 0;
                    var record = new ContractRecord
                    {
                        ContractId = contractId,
                        ActionType = payload.TryGetProperty("action_type", out var actProp) ? actProp.GetString() ?? string.Empty : string.Empty,
                        ContentHash = payload.TryGetProperty("content_hash", out var chProp) ? chProp.GetString() ?? string.Empty : string.Empty,
                        Domain = payload.TryGetProperty("domain", out var domProp) ? domProp.GetString() ?? string.Empty : string.Empty,
                        Username = payload.TryGetProperty("username", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty,
                        Signature = payload.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() ?? string.Empty : string.Empty,
                        Verified = payload.TryGetProperty("verified", out var verProp) && verProp.GetBoolean(),
                        Timestamp = tsUnix > 0 ? DateTimeOffset.FromUnixTimeSeconds((long)tsUnix) : DateTimeOffset.UtcNow,
                        ContractContent = contractContent
                    };
                    _service.SaveContractToStorage(record);
                    _display.PrintInfo($"Contrato canônico recebido: {contractId}");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[WARN] contract_canonical SaveContractToStorage failed: {ex.Message}");
                }
            }
        }));

        _handlerRegistrations.Add(_socket.On("invalidate_contract_ack", payload =>
        {
            var ok = payload.TryGetProperty("success", out var succProp) && succProp.GetBoolean();
            if (ok) _display.PrintSuccess("Contrato invalidado."); else _display.PrintError("Falha ao invalidar contrato.");
        }));

        _handlerRegistrations.Add(_socket.On("certify_contract_ack", payload =>
        {
            var ok = payload.TryGetProperty("success", out var succProp) && succProp.GetBoolean();
            if (ok) _display.PrintSuccess("Contrato certificado."); else _display.PrintError("Falha ao certificar contrato.");
        }));

        _handlerRegistrations.Add(_socket.On("reputation_update", payload =>
        {
            var reputation = payload.TryGetProperty("reputation", out var repProp) ? repProp.GetInt32() : 0;
            try
            {
                _service.SaveSession(null, null, reputation, null, null);
                _display.PrintInfo($"Reputação atualizada: {reputation}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[WARN] reputation_update SaveSession failed: {ex.Message}");
            }
        }));

        _handlerRegistrations.Add(_socket.On("inventory_response", payload =>
        {
            if (payload.TryGetProperty("items", out var itemsProp) && itemsProp.ValueKind == JsonValueKind.Array)
            {
                var count = itemsProp.GetArrayLength();
                _display.PrintInfo($"Inventário recebido com {count} ite(ns).");
            }
        }));

        _handlerRegistrations.Add(_socket.On("inventory_request", payload =>
        {
            var requester = payload.TryGetProperty("requester", out var reqProp) ? reqProp.GetString() : null;
            _display.PrintInfo($"Requisição de inventário de: {requester ?? "desconhecido"}");
        }));

        _handlerRegistrations.Add(_socket.On("inventory_transfer_ack", payload =>
        {
            var ok = payload.TryGetProperty("success", out var succProp) && succProp.GetBoolean();
            if (ok) _display.PrintSuccess("Transferência de inventário concluída."); else _display.PrintError("Falha na transferência de inventário.");
        }));

        _handlerRegistrations.Add(_socket.On("inventory_transfer_request", payload =>
        {
            var fromUser = payload.TryGetProperty("from_user", out var fromProp) ? fromProp.GetString() : null;
            var contentHash = payload.TryGetProperty("content_hash", out var chProp) ? chProp.GetString() : null;
            _display.PrintInfo($"Solicitação de transferência de inventário de {fromUser ?? "?"} para {contentHash ?? "?"}");
        }));

        _handlerRegistrations.Add(_socket.On("inventory_transfer_rejected", payload =>
        {
            var reason = payload.TryGetProperty("reason", out var rProp) ? rProp.GetString() ?? "Sem motivo" : "Sem motivo";
            _display.PrintInfo($"Transferência de inventário rejeitada: {reason}");
        }));

        _handlerRegistrations.Add(_socket.On("inventory_transfer_payload", payload =>
        {
            var contentB64 = payload.TryGetProperty("content", out var cProp) ? cProp.GetString() : null;
            var contentHash = payload.TryGetProperty("content_hash", out var hProp) ? hProp.GetString() : null;
            if (!string.IsNullOrWhiteSpace(contentB64) && !string.IsNullOrWhiteSpace(contentHash))
            {
                try
                {
                    var data = Convert.FromBase64String(contentB64);
                    _service.SaveContentToStorage(contentHash, data, null);
                    _display.PrintInfo($"Conteúdo recebido via inventário: {contentHash}");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[WARN] inventory_transfer_payload SaveContent failed: {ex.Message}");
                }
            }
        }));

        _handlerRegistrations.Add(_socket.On("miner_transfer", payload =>
        {
            var contentHash = payload.TryGetProperty("content_hash", out var hProp) ? hProp.GetString() : null;
            var contentB64 = payload.TryGetProperty("content", out var cProp) ? cProp.GetString() : null;
            if (!string.IsNullOrWhiteSpace(contentHash) && !string.IsNullOrWhiteSpace(contentB64))
            {
                try
                {
                    var data = Convert.FromBase64String(contentB64);
                    _service.SaveContentToStorage(contentHash, data, null);
                    _display.PrintInfo($"Transferência de minerador recebida: {contentHash}");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[WARN] miner_transfer SaveContent failed: {ex.Message}");
                }
            }
        }));

        _handlerRegistrations.Add(_socket.On("sync_client_files", payload =>
        {
            if (payload.TryGetProperty("content_hashes", out var hashesProp) && hashesProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var hashElem in hashesProp.EnumerateArray())
                {
                    var hash = hashElem.GetString();
                    if (!string.IsNullOrWhiteSpace(hash))
                    {
                        _ = Task.Run(async () =>
                        {
                            try { await SendContentToServerAsync(hash, CancellationToken.None).ConfigureAwait(false); }
                            catch (Exception ex) { Console.Error.WriteLine($"[WARN] sync_client_files SendContent failed: {ex.Message}"); }
                        });
                    }
                }
            }
        }));

        _handlerRegistrations.Add(_socket.On("sync_client_dns_files", payload =>
        {
            if (payload.TryGetProperty("domains", out var domainsProp) && domainsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var domainElem in domainsProp.EnumerateArray())
                {
                    var domain = domainElem.GetString();
                    if (!string.IsNullOrWhiteSpace(domain))
                    {
                        _ = Task.Run(async () =>
                        {
                            try { await SendDdnsToServerAsync(domain, CancellationToken.None).ConfigureAwait(false); }
                            catch (Exception ex) { Console.Error.WriteLine($"[WARN] sync_client_dns_files SendDdns failed: {ex.Message}"); }
                        });
                    }
                }
            }
        }));

        _handlerRegistrations.Add(_socket.On("sync_client_contracts", payload =>
        {
            if (payload.TryGetProperty("contract_ids", out var idsProp) && idsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var idElem in idsProp.EnumerateArray())
                {
                    var contractId = idElem.GetString();
                    if (!string.IsNullOrWhiteSpace(contractId))
                    {
                        _ = Task.Run(async () =>
                        {
                            try { await SendContractToServerAsync(contractId, CancellationToken.None).ConfigureAwait(false); }
                            catch (Exception ex) { Console.Error.WriteLine($"[WARN] sync_client_contracts SendContract failed: {ex.Message}"); }
                        });
                    }
                }
            }
        }));

        _handlerRegistrations.Add(_socket.On("client_files_response", payload =>
        {
            if (payload.TryGetProperty("files", out var filesProp) && filesProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var file in filesProp.EnumerateArray())
                {
                    var hash = file.TryGetProperty("content_hash", out var hProp) ? hProp.GetString() : null;
                    var contentB64 = file.TryGetProperty("content", out var cProp) ? cProp.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(hash) && !string.IsNullOrWhiteSpace(contentB64))
                    {
                        try
                        {
                            var data = Convert.FromBase64String(contentB64);
                            _service.SaveContentToStorage(hash, data, null);
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"[WARN] client_files_response SaveContent failed for {hash}: {ex.Message}");
                        }
                    }
                }
                _display.PrintInfo("Arquivos sincronizados do servidor.");
            }
        }));

        _handlerRegistrations.Add(_socket.On("client_dns_files_response", payload =>
        {
            if (payload.TryGetProperty("dns_files", out var dnsProp) && dnsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var dnsFile in dnsProp.EnumerateArray())
                {
                    var domain = dnsFile.TryGetProperty("domain", out var domProp) ? domProp.GetString() : null;
                    var contentB64 = dnsFile.TryGetProperty("ddns_content", out var cProp) ? cProp.GetString() : null;
                    var contentHash = dnsFile.TryGetProperty("content_hash", out var hProp) ? hProp.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(contentB64))
                    {
                        try
                        {
                            var ddnsBytes = Convert.FromBase64String(contentB64);
                            _service.SaveDdnsToStorage(domain, ddnsBytes, null);
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"[WARN] client_dns_files_response SaveDdns failed for {domain}: {ex.Message}");
                        }
                    }
                }
                _display.PrintInfo("DNS sincronizados do servidor.");
            }
        }));
    }

    private async Task SendContentToServerAsync(string contentHash, CancellationToken ct)
    {
        try
        {
            var cached = _service.LoadCachedContent(contentHash);
            if (cached is null)
            {
                await _socket.EmitAsync("content_from_client_failure", new { content_hash = contentHash, reason = "missing_local_content" }, ct).ConfigureAwait(false);
                return;
            }
            var (content, metadata) = cached.Value;
            if (string.IsNullOrWhiteSpace(metadata.Signature) || string.IsNullOrWhiteSpace(metadata.PublicKey))
            {
                await _socket.EmitAsync("content_from_client_failure", new { content_hash = contentHash, reason = "missing_local_signature" }, ct).ConfigureAwait(false);
                return;
            }
            await _socket.EmitAsync("content_from_client", new
            {
                content_hash = contentHash,
                content = Convert.ToBase64String(content),
                title = metadata.Title,
                description = metadata.Description,
                mime_type = metadata.MimeType,
                username = metadata.Username,
                signature = metadata.Signature,
                public_key = metadata.PublicKey,
                verified = metadata.Verified,
                contracts = _service.ListContracts(1000)
                    .Where(c => c.ContentHash.Equals(contentHash, StringComparison.OrdinalIgnoreCase))
                    .Select(BuildContractPayload)
                    .Where(c => c is not null)
                    .ToArray()
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] SendContentToServer failed for {contentHash}: {ex.Message}");
        }
    }

    private async Task SendDdnsToServerAsync(string domain, CancellationToken ct)
    {
        try
        {
            var record = _service.GetDdnsRecord(domain);
            var ddnsContent = _service.LoadDdnsContent(domain);
            if (record is null || ddnsContent is null || ddnsContent.Length == 0)
            {
                return;
            }
            await _socket.EmitAsync("ddns_from_client", new
            {
                domain = record.Domain,
                ddns_content = Convert.ToBase64String(ddnsContent),
                content_hash = record.ContentHash,
                username = record.Username,
                signature = record.Signature,
                public_key = record.PublicKey,
                verified = record.Verified
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] SendDdnsToServer failed for {domain}: {ex.Message}");
        }
    }

    private async Task SendContractToServerAsync(string contractId, CancellationToken ct)
    {
        try
        {
            var contract = _service.GetContractRecord(contractId);
            if (contract is null || string.IsNullOrWhiteSpace(contract.ContractContent))
            {
                return;
            }
            await _socket.EmitAsync("contract_from_client", BuildContractPayload(contract)!, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] SendContractToServer failed for {contractId}: {ex.Message}");
        }
    }

    private static object? BuildContractPayload(ContractRecord contract)
    {
        if (string.IsNullOrWhiteSpace(contract.ContractId) || string.IsNullOrWhiteSpace(contract.ContractContent))
        {
            return null;
        }
        return new
        {
            contract_id = contract.ContractId,
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contract.ContractContent)),
            action_type = contract.ActionType,
            content_hash = contract.ContentHash,
            domain = contract.Domain,
            username = contract.Username,
            signature = contract.Signature,
            verified = contract.Verified
        };
    }

    private static bool ReadSuccess(JsonElement payload) =>
        payload.TryGetProperty("success", out var s) && s.ValueKind == JsonValueKind.True;

    private static string ReadError(JsonElement payload)
    {
        var value = payload.TryGetProperty("error", out var e) ? e.GetString() ?? "erro desconhecido" : "erro desconhecido";
        return NormalizePossibleMojibake(value);
    }

    private static readonly object _pinnedKeysLock = new();
    private static readonly Dictionary<string, string> _pinnedServerPublicKeys = new(StringComparer.OrdinalIgnoreCase);
    private static readonly string _pinnedKeysPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "HPS-CLI", "pinned_keys.json");

    // C9 FIX: Load pinned keys from disk on startup
    static HpsRealtimeSession()
    {
        try
        {
            if (File.Exists(_pinnedKeysPath))
            {
                var json = File.ReadAllText(_pinnedKeysPath);
                var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (loaded != null)
                {
                    foreach (var kv in loaded)
                    {
                        _pinnedServerPublicKeys[kv.Key] = kv.Value;
                    }
                }
            }
        }
        catch { /* Ignore load errors */ }
    }

    // C9 FIX: Save pinned keys to disk
    private static void SavePinnedKeys()
    {
        try
        {
            var dir = Path.GetDirectoryName(_pinnedKeysPath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            var json = JsonSerializer.Serialize(_pinnedServerPublicKeys, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_pinnedKeysPath, json);
        }
        catch { /* Ignore save errors */ }
    }

    private static void VerifyServerChallenge(string challenge, string serverPublicKeyB64, string serverSignatureB64)
    {
        var signature = Convert.FromBase64String(serverSignatureB64);
        var data = Encoding.UTF8.GetBytes(challenge);
        var hash = SHA256.HashData(data);

        // Decode public key from base64 if needed
        var publicKeyB64 = serverPublicKeyB64;

        // Try ECDsa verification first (server uses ECDSA P-256)
        using var ecdsa = LoadServerECDsaPublicKey(publicKeyB64);
        if (ecdsa != null)
        {
            if (ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256))
                return;
            if (ecdsa.VerifyHash(hash, signature))
                return;

            // Try DER-to-IEEE P1363 conversion (server signs with ASN.1/DER, .NET expects r||s)
            var p1363Sig = DerToIeeeP1363(signature, 32);
            if (p1363Sig != null)
            {
                if (ecdsa.VerifyData(data, p1363Sig, HashAlgorithmName.SHA256))
                    return;
                if (ecdsa.VerifyHash(hash, p1363Sig))
                    return;
            }
        }

        // Try RSA verification (fallback)
        using var rsa = LoadServerPublicKey(publicKeyB64);
        if (rsa != null && rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        {
            return;
        }

        throw new InvalidOperationException("assinatura do desafio do servidor invalida");
    }

    private static byte[]? DerToIeeeP1363(byte[] derSig, int keySizeBytes)
    {
        var idx = 0;
        if (idx >= derSig.Length || derSig[idx++] != 0x30) return null;
        var seqLen = derSig[idx++];

        if (idx >= derSig.Length || derSig[idx++] != 0x02) return null;
        var rLen = derSig[idx++];
        var rBytes = new byte[keySizeBytes];
        var rOffset = Math.Max(0, keySizeBytes - rLen);
        var rCopyLen = Math.Min(rLen, keySizeBytes);
        var rSrcOffset = Math.Max(0, rLen - keySizeBytes);
        Array.Copy(derSig, idx + rSrcOffset, rBytes, rOffset, rCopyLen);
        idx += rLen;

        if (idx >= derSig.Length || derSig[idx++] != 0x02) return null;
        var sLen = derSig[idx++];
        var sBytes = new byte[keySizeBytes];
        var sOffset = Math.Max(0, keySizeBytes - sLen);
        var sCopyLen = Math.Min(sLen, keySizeBytes);
        var sSrcOffset = Math.Max(0, sLen - keySizeBytes);
        Array.Copy(derSig, idx + sSrcOffset, sBytes, sOffset, sCopyLen);
        idx += sLen;

        var result = new byte[keySizeBytes * 2];
        Array.Copy(rBytes, 0, result, 0, keySizeBytes);
        Array.Copy(sBytes, 0, result, keySizeBytes, keySizeBytes);
        return result;
    }

    private static string NormalizePublicKeyForAuth(string keyValue)
    {
        if (string.IsNullOrWhiteSpace(keyValue)) return string.Empty;
        var trimmed = keyValue.Trim();
        if (trimmed.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase)) return trimmed;
        try
        {
            var decoded = Convert.FromBase64String(trimmed);
            var decodedText = Encoding.UTF8.GetString(decoded).Trim();
            if (decodedText.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase)) return decodedText;
        }
        catch { }
        return trimmed;
    }

    private static ECDsa? LoadServerECDsaPublicKey(string serverPublicKey)
    {
        var normalized = NormalizePublicKeyForAuth(serverPublicKey);
        if (string.IsNullOrWhiteSpace(normalized)) return null;
        try
        {
            var ecdsa = ECDsa.Create();
            if (normalized.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
            {
                ecdsa.ImportFromPem(normalized.ToCharArray());
                return ecdsa;
            }
            var decoded = Convert.FromBase64String(normalized);
            ecdsa.ImportSubjectPublicKeyInfo(decoded, out _);
            return ecdsa;
        }
        catch
        {
            return null;
        }
    }

    private static RSA? LoadServerPublicKey(string serverPublicKey)
    {
        if (string.IsNullOrWhiteSpace(serverPublicKey))
        {
            return null;
        }

        var normalized = serverPublicKey.Trim();
        if (!normalized.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded = Convert.FromBase64String(normalized);
                var decodedText = Encoding.UTF8.GetString(decoded).Trim();
                if (decodedText.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
                {
                    normalized = decodedText;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[WARN] LoadServerPublicKey Base64 decode failed: {ex.Message}");
            }
        }

        var rsa = RSA.Create();
        try
        {
            if (normalized.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase))
            {
                rsa.ImportFromPem(normalized);
                return rsa;
            }
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(normalized), out _);
            return rsa;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] LoadServerPublicKey failed: {ex.Message}");
            rsa.Dispose();
            return null;
        }
    }



    private static string NormalizePossibleMojibake(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text;
        }
        if (!text.Contains('Ã') && !text.Contains('Â'))
        {
            return text;
        }
        try
        {
            var latinBytes = Encoding.Latin1.GetBytes(text);
            var utf8 = Encoding.UTF8.GetString(latinBytes);
            return utf8.Contains('�') ? text : utf8;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] NormalizePossibleMojibake failed: {ex.Message}");
            return text;
        }
    }

    private static int ResolvePowThreads()
    {
        var raw = Environment.GetEnvironmentVariable("HPS_POW_THREADS");
        if (int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var configured) && configured > 0)
        {
            return configured;
        }
        return Math.Max(1, Environment.ProcessorCount);
    }

    private static void PinOrVerifyServerPublicKey(string server, string serverPublicKeyB64)
    {
        var key = NormalizeServerKey(server);
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(serverPublicKeyB64))
        {
            return;
        }
        lock (_pinnedKeysLock)
        {
            if (_pinnedServerPublicKeys.TryGetValue(key, out var pinnedKey))
            {
                if (!string.Equals(pinnedKey, serverPublicKeyB64, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"chave publica do servidor mudou para {key}; possivel ataque MITM. delete o registro de pins para aceitar.");
                }
            }
            else
            {
                _pinnedServerPublicKeys[key] = serverPublicKeyB64;
                // C9 FIX: Persist pinned keys to disk
                SavePinnedKeys();
            }
        }
    }

    private static string NormalizeServerKey(string server)
    {
        var raw = (server ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }
        if (!raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            raw = "https://" + raw;
        }
        return raw.TrimEnd('/').ToLowerInvariant();
    }
}
