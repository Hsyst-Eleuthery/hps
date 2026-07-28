using System.Collections.Concurrent;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace HpsWallet.Services;

public sealed class HpsSocketService
{
    private ClientWebSocket? _socket;
    private CancellationTokenSource? _receiveCts;
    private Task? _receiveLoop;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly ConcurrentDictionary<string, List<Func<SocketEventResponse, Task>>> _asyncHandlers = new(StringComparer.OrdinalIgnoreCase);
    private TaskCompletionSource<bool>? _openTcs;
    private TaskCompletionSource<bool>? _connectTcs;
    private volatile bool _connected;
    private static readonly TimeSpan SendTimeout = TimeSpan.FromSeconds(10);
    private readonly HttpClient _http = new();
    private DateTime _lastServerMessage = DateTime.MinValue;
    private Timer? _keepaliveTimer;

    public bool IsConnected => _connected && _socket?.State == WebSocketState.Open;
    public string? ServerUrl { get; set; }
    public bool AutoReconnectEnabled { get; set; } = true;
    private int _reconnectAttempts;
    private const int MaxReconnectAttempts = 10;

    public event EventHandler? Connected;
    public event EventHandler? Disconnected;
    public event EventHandler<string>? Error;

    public async Task ConnectAsync(string serverUrl, CancellationToken cancellationToken = default, bool isReconnect = false)
    {
        await DisconnectAsync(keepKeys: true);
        ServerUrl = serverUrl?.TrimEnd('/');

        if (!Uri.TryCreate(ServerUrl, UriKind.Absolute, out var uri))
            throw new InvalidOperationException($"Servidor invalido: {ServerUrl}");

        var wsScheme = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? "wss" : "ws";
        var wsUrl = new UriBuilder(uri) { Scheme = wsScheme, Path = "/socket.io/", Query = "EIO=4&transport=websocket" }.Uri;

        _socket = new ClientWebSocket();
        _socket.Options.Proxy = null;
        _socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(15);
        _socket.Options.RemoteCertificateValidationCallback = ValidateServerCertificate;

        _connectTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _openTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _receiveCts = new CancellationTokenSource();

        var connectTask = _socket.ConnectAsync(wsUrl, cancellationToken);
        var completed = await Task.WhenAny(connectTask, Task.Delay(TimeSpan.FromSeconds(8), cancellationToken));
        if (completed != connectTask)
            throw new TimeoutException("Timeout ao abrir WebSocket.");
        await connectTask;

        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_receiveCts.Token));
        _reconnectAttempts = 0;

        using var openTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        openTimeout.CancelAfter(TimeSpan.FromSeconds(10));
        var opened = await Task.WhenAny(_openTcs.Task, Task.Delay(Timeout.Infinite, openTimeout.Token));
        if (opened != _openTcs.Task)
            throw new TimeoutException("Timeout no handshake Engine.IO.");
        await _openTcs.Task;

        await SendTextAsync("40");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var done = await Task.WhenAny(_connectTcs.Task, Task.Delay(Timeout.Infinite, timeout.Token));
        if (done != _connectTcs.Task)
            throw new TimeoutException("Timeout no handshake Socket.IO.");
        await _connectTcs.Task;

        StartKeepaliveTimer();
    }

    public async Task ReconnectAsync()
    {
        if (!AutoReconnectEnabled || string.IsNullOrEmpty(ServerUrl)) return;
        if (_reconnectAttempts >= MaxReconnectAttempts) return;

        _reconnectAttempts++;
        var delay = Math.Min(1000 * (int)Math.Pow(2, _reconnectAttempts - 1), 30000);
        Error?.Invoke(this, $"Tentando reconectar em {delay / 1000}s (tentativa {_reconnectAttempts}/{MaxReconnectAttempts})...");

        await Task.Delay(delay);
        try
        {
            await ConnectAsync(ServerUrl, default, true);
            SessionState.IsLoggedIn = false;
            Error?.Invoke(this, "Reconectado. Reautenticacao necessaria.");
            Disconnected?.Invoke(this, EventArgs.Empty);
        }
        catch { Error?.Invoke(this, "Falha na reconexao."); }
    }

    public async Task DisconnectAsync(bool keepKeys = false)
    {
        AutoReconnectEnabled = false;
        StopKeepaliveTimer();
        if (!keepKeys) SessionState.ClearPrivateKey();
        SessionState.IsLoggedIn = false;
        if (_socket == null) return;
        try { _receiveCts?.Cancel(); } catch { }
        try { if (_socket.State == WebSocketState.Open) await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "disconnect", CancellationToken.None); } catch { }
        _connected = false;
        _socket.Dispose();
        _socket = null;
    }

    public void On(string eventName, Func<SocketEventResponse, Task> handler)
    {
        if (!_asyncHandlers.TryGetValue(eventName, out var list))
            _asyncHandlers[eventName] = list = new List<Func<SocketEventResponse, Task>>();
        list.Add(handler);
    }

    public void Off(string eventName, Func<SocketEventResponse, Task>? handler = null)
    {
        if (handler == null)
        {
            _asyncHandlers.TryRemove(eventName, out _);
        }
        else if (_asyncHandlers.TryGetValue(eventName, out var list))
        {
            list.Remove(handler);
            if (list.Count == 0)
                _asyncHandlers.TryRemove(eventName, out _);
        }
    }

    public async Task EmitAsync(string eventName, object payload)
    {
        if (!IsConnected || _socket == null) return;
        var data = JsonSerializer.Serialize(new object[] { eventName, payload });
        await SendTextAsync($"42{data}");
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[128 * 1024];
        // W1 FIX: Limit total message size to 10MB to prevent memory exhaustion
        const int maxMessageSize = 10 * 1024 * 1024;
        try
        {
            while (!ct.IsCancellationRequested && _socket != null)
            {
                var result = await _socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                if (result.MessageType == WebSocketMessageType.Close) break;

                using var ms = new MemoryStream();
                ms.Write(buffer, 0, result.Count);
                while (!result.EndOfMessage)
                {
                    // W1 FIX: Check message size limit
                    if (ms.Length > maxMessageSize)
                    {
                        System.Diagnostics.Debug.WriteLine("[Wallet] Message too large, disconnecting");
                        break;
                    }
                    result = await _socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                    ms.Write(buffer, 0, result.Count);
                }

                if (ms.Length > maxMessageSize)
                {
                    break; // Disconnect on oversized message
                }

                var text = Encoding.UTF8.GetString(ms.ToArray());
                _lastServerMessage = DateTime.UtcNow;
                foreach (var segment in text.Split('\u001e', StringSplitOptions.RemoveEmptyEntries))
                    await HandleIncomingAsync(segment);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Error?.Invoke(this, ex.Message); }
        finally
        {
            _connected = false;
            StopKeepaliveTimer();
            Disconnected?.Invoke(this, EventArgs.Empty);
            if (AutoReconnectEnabled)
                _ = ReconnectAsync();
        }
    }

    private async Task HandleIncomingAsync(string msg)
    {
        if (string.IsNullOrEmpty(msg)) return;

        if (msg[0] == '0') { _openTcs?.TrySetResult(true); return; }
        if (msg[0] == '2') { await SendTextAsync("3"); return; }
        if (msg.StartsWith("40"))
        {
            _connected = true;
            _connectTcs?.TrySetResult(true);
            Connected?.Invoke(this, EventArgs.Empty);
            return;
        }
        if (msg.StartsWith("41")) { _connected = false; Disconnected?.Invoke(this, EventArgs.Empty); return; }

        if (msg.StartsWith("42"))
        {
            var payloadJson = msg.Substring(2);
            using var doc = JsonDocument.Parse(payloadJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array || doc.RootElement.GetArrayLength() < 1) return;

            var eventName = doc.RootElement[0].GetString();
            if (string.IsNullOrWhiteSpace(eventName)) return;

            var data = doc.RootElement.GetArrayLength() > 1 ? doc.RootElement[1].Clone() : default;

            if (_asyncHandlers.TryGetValue(eventName, out var list))
            {
                foreach (var handler in list.ToArray())
                {
                    try { await handler(new SocketEventResponse(data)); }
                    catch (Exception ex) { Error?.Invoke(this, $"Handler {eventName}: {ex.Message}"); }
                }
            }
        }
    }

    private async Task SendTextAsync(string payload)
    {
        if (_socket == null || _socket.State != WebSocketState.Open) return;
        var bytes = Encoding.UTF8.GetBytes(payload);
        await _sendLock.WaitAsync();
        try
        {
            // W2 FIX: Use timeout instead of CancellationToken.None
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, cts.Token);
        }
        catch (OperationCanceledException)
        {
            System.Diagnostics.Debug.WriteLine("[Wallet] Send timed out");
        }
        finally { _sendLock.Release(); }
    }

    private void StartKeepaliveTimer()
    {
        StopKeepaliveTimer();
        _lastServerMessage = DateTime.UtcNow;
        _keepaliveTimer = new Timer(_ =>
        {
            if (!_connected) return;
            var elapsed = (DateTime.UtcNow - _lastServerMessage).TotalSeconds;
            if (elapsed > 120)
            {
                Error?.Invoke(this, "Servidor sem resposta. Reconectando...");
                _ = ReconnectAsync();
            }
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    private void StopKeepaliveTimer()
    {
        try { _keepaliveTimer?.Dispose(); } catch { }
        _keepaliveTimer = null;
    }

    // C6/C7 FIX: Cached cert hash from SecureStorage (fallback only - trust all by default)
    private static string _cachedCertHash = string.Empty;
    private static bool _certHashLoaded = false;

    private static bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
    {
        // Custom P2P network - trust all certificates
        if (sslPolicyErrors != System.Net.Security.SslPolicyErrors.None && certificate is X509Certificate2 cert)
        {
            // Check pinned hash if available
            if (!_certHashLoaded)
            {
                try
                {
                    _cachedCertHash = Preferences.Get("wallet_server_cert_hash", string.Empty);
                    _certHashLoaded = true;
                }
                catch { }
            }

            if (!string.IsNullOrEmpty(_cachedCertHash))
            {
                var actualHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.RawData));
                return string.Equals(actualHash, _cachedCertHash, StringComparison.OrdinalIgnoreCase);
            }
        }

        return true;
    }
}
