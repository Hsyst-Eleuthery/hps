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
    private IDisposable? _messageRequestRegistration;
    private IDisposable? _messageStatusRegistration;
    private IDisposable? _incomingMessageRegistration;
    private IDisposable? _requestContentRegistration;
    private IDisposable? _requestDdnsRegistration;
    private IDisposable? _requestContractRegistration;
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
        _messageRequestRegistration?.Dispose();
        _messageRequestRegistration = null;
        _messageStatusRegistration?.Dispose();
        _messageStatusRegistration = null;
        _incomingMessageRegistration?.Dispose();
        _incomingMessageRegistration = null;
        _requestContentRegistration?.Dispose();
        _requestContentRegistration = null;
        _requestDdnsRegistration?.Dispose();
        _requestDdnsRegistration = null;
        _requestContractRegistration?.Dispose();
        _requestContractRegistration = null;
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

        _messageRequestRegistration = _socket.On("message_contact_request", payload =>
        {
            var sender = payload.TryGetProperty("sender", out var senderProp) ? senderProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(sender))
            {
                _display.PrintWarning("nova solicitacao de conversa recebida");
            }
            else
            {
                _display.PrintWarning($"nova solicitacao de conversa de {sender}");
            }
        });

        _messageStatusRegistration = _socket.On("message_contact_status", payload =>
        {
            var status = payload.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            var peerUser = payload.TryGetProperty("peer_user", out var peerProp) ? peerProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(peerUser))
            {
                _display.PrintInfo($"conversa com {peerUser}: {status}");
            }
        });

        _incomingMessageRegistration = _socket.On("incoming_message", payload =>
        {
            var fromUser = payload.TryGetProperty("from_user", out var fromProp) ? fromProp.GetString() ?? string.Empty : string.Empty;
            var fileName = payload.TryGetProperty("file_name", out var fileProp) ? fileProp.GetString() ?? string.Empty : string.Empty;
            var fileB64 = payload.TryGetProperty("message_file_b64", out var messageProp) ? messageProp.GetString() ?? string.Empty : string.Empty;
            if (!TryDecodeIncomingMessage(fileB64, out var preview, out var timestamp))
            {
                preview = string.Empty;
                timestamp = DateTimeOffset.UtcNow;
            }

            if (!string.IsNullOrWhiteSpace(fromUser) && !string.IsNullOrWhiteSpace(fileName))
            {
                _service.SaveMessageRecord(new Storage.MessageRecord
                {
                    MessageId = $"{fromUser}:{fileName}",
                    PeerUser = fromUser,
                    SenderUser = fromUser,
                    Direction = "in",
                    FileName = fileName,
                    Preview = preview,
                    Timestamp = timestamp
                });
            }

            _display.PrintInfo(string.IsNullOrWhiteSpace(fromUser)
                ? "nova mensagem recebida"
                : $"nova mensagem de {fromUser}: {preview}");
        });

        _requestContentRegistration = _socket.On("request_content_from_client", payload =>
        {
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(contentHash))
            {
                _ = SendContentToServerAsync(contentHash, CancellationToken.None);
            }
        });

        _requestDdnsRegistration = _socket.On("request_ddns_from_client", payload =>
        {
            var domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(domain))
            {
                _ = SendDdnsToServerAsync(domain, CancellationToken.None);
            }
        });

        _requestContractRegistration = _socket.On("request_contract_from_client", payload =>
        {
            var contractId = payload.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(contractId))
            {
                _ = SendContractToServerAsync(contractId, CancellationToken.None);
            }
        });
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
        catch
        {
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
        catch
        {
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
        catch
        {
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

    private static bool TryDecodeIncomingMessage(string fileB64, out string preview, out DateTimeOffset timestamp)
    {
        preview = string.Empty;
        timestamp = DateTimeOffset.UtcNow;
        if (string.IsNullOrWhiteSpace(fileB64))
        {
            return false;
        }

        try
        {
            var text = Encoding.UTF8.GetString(Convert.FromBase64String(fileB64));
            foreach (var raw in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
            {
                var line = raw.Trim();
                if (line.StartsWith("# CONTENT_BASE64:", StringComparison.OrdinalIgnoreCase))
                {
                    var contentB64 = line.Split(':', 2)[1].Trim();
                    preview = BuildPreview(Encoding.UTF8.GetString(Convert.FromBase64String(contentB64)));
                }
                else if (line.StartsWith("# TIMESTAMP:", StringComparison.OrdinalIgnoreCase))
                {
                    var tsRaw = line.Split(':', 2)[1].Trim();
                    if (long.TryParse(tsRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var millis) && millis > 0)
                    {
                        timestamp = DateTimeOffset.FromUnixTimeMilliseconds(millis);
                    }
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string BuildPreview(string text)
    {
        var normalized = (text ?? string.Empty).Replace("\r\n", "\n").Replace('\r', '\n').Trim();
        if (normalized.Length <= 140)
        {
            return normalized;
        }
        return normalized[..140] + "...";
    }

    private static bool ReadSuccess(JsonElement payload) =>
        payload.TryGetProperty("success", out var s) && s.ValueKind == JsonValueKind.True;

    private static string ReadError(JsonElement payload)
    {
        var value = payload.TryGetProperty("error", out var e) ? e.GetString() ?? "erro desconhecido" : "erro desconhecido";
        return NormalizePossibleMojibake(value);
    }

    private static void VerifyServerChallenge(string challenge, string serverPublicKeyB64, string serverSignatureB64)
    {
        var signature = Convert.FromBase64String(serverSignatureB64);
        using var rsa = LoadServerPublicKey(serverPublicKeyB64);
        if (rsa is null)
        {
            throw new InvalidOperationException("chave publica do servidor invalida");
        }
        var data = Encoding.UTF8.GetBytes(challenge);
        if (!VerifyServerSignature(rsa, data, signature))
        {
            throw new InvalidOperationException("assinatura do desafio do servidor invalida");
        }
    }

    private static bool VerifyServerSignature(RSA rsa, byte[] data, byte[] signature)
    {
        // Keep compatibility with different PSS salt-length implementations used by clients/servers.
        if (TryVerify(() => rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)))
        {
            return true;
        }

        var hash = SHA256.HashData(data);
        var maxSaltPadding = GetPssPaddingMax(rsa, HashAlgorithmName.SHA256);
        if (TryVerify(() => rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, maxSaltPadding)))
        {
            return true;
        }

        var hashLenPadding = CreatePssPadding(32);
        if (TryVerify(() => rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, hashLenPadding)))
        {
            return true;
        }

        if (VerifySignaturePssAuto(rsa, data, signature))
        {
            return true;
        }

        return false;
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
            catch
            {
                // Keep original value and try alternate import paths below.
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
        catch
        {
            rsa.Dispose();
            return null;
        }
    }

    private static bool TryVerify(Func<bool> verify)
    {
        try
        {
            return verify();
        }
        catch
        {
            return false;
        }
    }

    private static RSASignaturePadding GetPssPaddingMax(RSA key, HashAlgorithmName hashAlgorithm)
    {
        var hashSize = hashAlgorithm == HashAlgorithmName.SHA256 ? 32 : 32;
        var maxSalt = Math.Max(0, (key.KeySize / 8) - hashSize - 2);
        return CreatePssPadding(maxSalt);
    }

    private static RSASignaturePadding CreatePssPadding(int saltLength)
    {
        if (saltLength <= 0)
        {
            return RSASignaturePadding.Pss;
        }

        var createPss = typeof(RSASignaturePadding).GetMethod("CreatePss", new[] { typeof(int) });
        if (createPss is not null)
        {
            try
            {
                return (RSASignaturePadding)createPss.Invoke(null, new object[] { saltLength })!;
            }
            catch
            {
                return RSASignaturePadding.Pss;
            }
        }

        return RSASignaturePadding.Pss;
    }

    private static bool VerifySignaturePssAuto(RSA publicKey, byte[] payload, byte[] signature)
    {
        try
        {
            var mHash = SHA256.HashData(payload);
            var hashLen = mHash.Length;

            var parameters = publicKey.ExportParameters(false);
            if (parameters.Modulus is null || parameters.Exponent is null)
            {
                return false;
            }

            var modBits = parameters.Modulus.Length * 8;
            var emBits = modBits - 1;
            var emLen = (emBits + 7) / 8;
            if (signature.Length != parameters.Modulus.Length)
            {
                return false;
            }

            var sigInt = new BigInteger(signature, isUnsigned: true, isBigEndian: true);
            var modInt = new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true);
            var expInt = new BigInteger(parameters.Exponent, isUnsigned: true, isBigEndian: true);
            var emInt = BigInteger.ModPow(sigInt, expInt, modInt);
            var em = emInt.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (em.Length < emLen)
            {
                var padded = new byte[emLen];
                Buffer.BlockCopy(em, 0, padded, emLen - em.Length, em.Length);
                em = padded;
            }
            if (em.Length != emLen)
            {
                return false;
            }

            if (em[^1] != 0xBC)
            {
                return false;
            }

            if (emLen < hashLen + 2)
            {
                return false;
            }

            var maskedDbLen = emLen - hashLen - 1;
            var maskedDb = new byte[maskedDbLen];
            Buffer.BlockCopy(em, 0, maskedDb, 0, maskedDbLen);
            var h = new byte[hashLen];
            Buffer.BlockCopy(em, maskedDbLen, h, 0, hashLen);

            var leftBits = 8 * emLen - emBits;
            if (leftBits > 0)
            {
                var mask = (byte)(0xFF >> leftBits);
                if ((maskedDb[0] & ~mask) != 0)
                {
                    return false;
                }
            }

            var dbMask = Mgf1(h, maskedDbLen);
            var db = new byte[maskedDbLen];
            for (var i = 0; i < maskedDbLen; i++)
            {
                db[i] = (byte)(maskedDb[i] ^ dbMask[i]);
            }

            if (leftBits > 0)
            {
                var mask = (byte)(0xFF >> leftBits);
                db[0] &= mask;
            }

            var index = 0;
            while (index < db.Length && db[index] == 0x00)
            {
                index++;
            }
            if (index >= db.Length || db[index] != 0x01)
            {
                return false;
            }

            var salt = db[(index + 1)..];
            var mPrime = new byte[8 + hashLen + salt.Length];
            Buffer.BlockCopy(mHash, 0, mPrime, 8, hashLen);
            Buffer.BlockCopy(salt, 0, mPrime, 8 + hashLen, salt.Length);
            var hPrime = SHA256.HashData(mPrime);
            return CryptographicOperations.FixedTimeEquals(h, hPrime);
        }
        catch
        {
            return false;
        }
    }

    private static byte[] Mgf1(byte[] seed, int maskLen)
    {
        const int hashLen = 32;
        var count = (int)Math.Ceiling(maskLen / (double)hashLen);
        var output = new byte[maskLen];
        var counter = new byte[4];
        var offset = 0;
        for (var i = 0; i < count; i++)
        {
            counter[0] = (byte)((i >> 24) & 0xFF);
            counter[1] = (byte)((i >> 16) & 0xFF);
            counter[2] = (byte)((i >> 8) & 0xFF);
            counter[3] = (byte)(i & 0xFF);
            var data = new byte[seed.Length + 4];
            Buffer.BlockCopy(seed, 0, data, 0, seed.Length);
            Buffer.BlockCopy(counter, 0, data, seed.Length, 4);
            var hash = SHA256.HashData(data);
            var copy = Math.Min(hashLen, maskLen - offset);
            Buffer.BlockCopy(hash, 0, output, offset, copy);
            offset += copy;
        }
        return output;
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
        catch
        {
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
            raw = "http://" + raw;
        }
        return raw.TrimEnd('/').ToLowerInvariant();
    }
}
