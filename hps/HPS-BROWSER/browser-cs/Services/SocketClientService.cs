using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using Avalonia.Threading;

namespace HpsBrowser.Services;

public sealed class SocketClientService
{
    private const int MaxSocketMessageSize = 256 * 1024 * 1024; // 256 MB
    private static readonly TimeSpan SendTimeout = TimeSpan.FromSeconds(15);
    private ClientWebSocket? _socket;
    private HttpClient? _pollingClient;
    private Uri? _pollingUri;
    private CancellationTokenSource? _receiveCts;
    private Task? _receiveLoop;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly Dictionary<string, List<Action<SocketEventResponse>>> _handlers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<Func<SocketEventResponse, Task>>> _asyncHandlers = new(StringComparer.OrdinalIgnoreCase);
    private TaskCompletionSource<bool>? _openTcs;
    private TaskCompletionSource<bool>? _probeTcs;
    private TaskCompletionSource<bool>? _connectTcs;
    private volatile bool _connected;
    private volatile bool _pollingMode;
    private long _bytesSent;
    private long _bytesReceived;

    public bool IsConnected => _connected && (_pollingMode || _socket?.State == WebSocketState.Open);
    public long TotalBytesSent => Interlocked.Read(ref _bytesSent);
    public long TotalBytesReceived => Interlocked.Read(ref _bytesReceived);
    public Action<Action> Dispatch { get; set; } = action => Dispatcher.UIThread.Post(action);

    public event EventHandler? Connected;
    public event EventHandler? Disconnected;
    public event EventHandler<string>? Error;
    public event EventHandler<SocketTrafficEventArgs>? TrafficUpdated;

    public async Task ConnectAsync(string serverUrl, string? engineIoSid = null, CancellationToken cancellationToken = default)
    {
        await DisconnectAsync();

        var targetUrl = TryBuildIpv4Loopback(serverUrl);
        Console.WriteLine($"[SocketIO] Connect {targetUrl} transport=WebSocket path=/socket.io");
        await TryConnectAsync(targetUrl, engineIoSid, cancellationToken);
    }

    private static string TryBuildIpv4Loopback(string serverUrl)
    {
        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out var uri))
        {
            return serverUrl;
        }

        if (!string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return serverUrl;
        }

        var builder = new UriBuilder(uri)
        {
            Host = "127.0.0.1"
        };
        return builder.Uri.ToString().TrimEnd('/');
    }

    private async Task TryConnectAsync(string serverUrl, string? engineIoSid, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(engineIoSid))
        {
            await TryConnectPollingAsync(serverUrl, engineIoSid, cancellationToken);
            return;
        }

        var wsUrl = BuildWebSocketUrl(serverUrl, engineIoSid);
        Console.WriteLine($"[SocketIO] WS url {wsUrl}");
        _socket = new ClientWebSocket();
        _socket.Options.Proxy = null;
        _socket.Options.UseDefaultCredentials = false;
        _socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
        TlsCertificateValidation.ApplyTo(_socket.Options);

        _openTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _probeTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _connectTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        _receiveCts = new CancellationTokenSource();
        Console.WriteLine("[SocketIO] ConnectAsync start");
        var connectTask = _socket.ConnectAsync(wsUrl, cancellationToken);
        var connectCompleted = await Task.WhenAny(connectTask, Task.Delay(TimeSpan.FromSeconds(6), cancellationToken));
        if (connectCompleted != connectTask)
        {
            throw new TimeoutException("Timeout ao abrir WebSocket.");
        }
        await connectTask;
        Console.WriteLine("[SocketIO] ConnectAsync connected, start receive loop");
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_receiveCts.Token));

        if (string.IsNullOrWhiteSpace(engineIoSid))
        {
            using var openTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            openTimeout.CancelAfter(TimeSpan.FromSeconds(10));
            await WaitOrTimeoutAsync(_openTcs.Task, openTimeout.Token, "Timeout no handshake Engine.IO.");
            Console.WriteLine("[SocketIO] Engine.IO open ok");
        }
        else
        {
            await SendTextAsync("2probe", cancellationToken);
            using var probeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            probeTimeout.CancelAfter(TimeSpan.FromSeconds(10));
            await WaitOrTimeoutAsync(_probeTcs.Task, probeTimeout.Token, "Timeout no upgrade Engine.IO.");
            await SendTextAsync("5", cancellationToken);
            Console.WriteLine("[SocketIO] Engine.IO upgrade ok");
        }

        await SendTextAsync("40", cancellationToken);
        using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectTimeout.CancelAfter(TimeSpan.FromSeconds(10));
        await WaitOrTimeoutAsync(_connectTcs.Task, connectTimeout.Token, "Timeout ao conectar no servidor Socket.IO.");
        Console.WriteLine("[SocketIO] Socket.IO connected");
    }

    private async Task TryConnectPollingAsync(string serverUrl, string engineIoSid, CancellationToken cancellationToken)
    {
        _pollingUri = BuildPollingUrl(serverUrl, engineIoSid);
        _pollingClient = new HttpClient(TlsCertificateValidation.CreateHttpClientHandler())
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        _pollingMode = true;
        _openTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _connectTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _receiveCts = new CancellationTokenSource();

        Console.WriteLine($"[SocketIO] Polling url {_pollingUri}");
        _receiveLoop = Task.Run(() => PollingReceiveLoopAsync(_receiveCts.Token));

        await SendTextAsync("40", cancellationToken);
        using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectTimeout.CancelAfter(TimeSpan.FromSeconds(10));
        await WaitOrTimeoutAsync(_connectTcs.Task, connectTimeout.Token, "Timeout ao conectar no servidor Socket.IO.");
        Console.WriteLine("[SocketIO] Socket.IO connected via polling");
    }

    public async Task DisconnectAsync()
    {
        if (_socket is null && _pollingClient is null)
        {
            return;
        }

        try
        {
            _receiveCts?.Cancel();
            if (_socket is not null && _socket.State == WebSocketState.Open)
            {
                await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "client disconnect", CancellationToken.None);
            }
        }
        catch
        {
            // Ignore disconnect errors.
        }
        finally
        {
            _connected = false;
            _pollingMode = false;
            _pollingClient?.Dispose();
            _pollingClient = null;
            _pollingUri = null;
            _socket?.Dispose();
            _socket = null;
            _receiveCts?.Dispose();
            _receiveCts = null;
        }
    }

    public void On(string eventName, Action<SocketEventResponse> handler)
    {
        if (!_handlers.TryGetValue(eventName, out var list))
        {
            list = new List<Action<SocketEventResponse>>();
            _handlers[eventName] = list;
        }
        list.Add(handler);
    }

    public void OnAsync(string eventName, Func<SocketEventResponse, Task> handler)
    {
        if (!_asyncHandlers.TryGetValue(eventName, out var list))
        {
            list = new List<Func<SocketEventResponse, Task>>();
            _asyncHandlers[eventName] = list;
        }
        list.Add(handler);
    }

    public async Task EmitAsync(string eventName, object payload)
    {
        if (!IsConnected)
        {
            return;
        }

        var data = JsonSerializer.Serialize(new object[] { eventName, payload });
        try
        {
            await SendTextAsync($"42{data}", CancellationToken.None);
        }
        catch (OperationCanceledException)
        {
            // AbortSocket already marked the connection as unhealthy.
        }
        catch (ObjectDisposedException)
        {
            AbortSocket("Socket disposed during emit.");
        }
        catch (WebSocketException ex)
        {
            AbortSocket(ex.Message);
        }
    }

    public async Task<bool> EmitCriticalAsync(string eventName, object payload, CancellationToken cancellationToken = default)
    {
        if (!IsConnected)
        {
            return false;
        }

        var data = JsonSerializer.Serialize(new object[] { eventName, payload });
        try
        {
            await SendTextAsync($"42{data}", cancellationToken);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (ObjectDisposedException)
        {
            AbortSocket("Socket disposed during critical emit.");
            return false;
        }
        catch (WebSocketException ex)
        {
            AbortSocket(ex.Message);
            return false;
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        const int bufferSize = 128 * 1024;
        var buffer = new byte[bufferSize];
        try
        {
            Console.WriteLine("[SocketIO] Receive loop started");
            while (!cancellationToken.IsCancellationRequested && _socket is not null)
            {
                var result = await _socket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }

                if (result.Count > 0)
                {
                    TrackReceivedBytes(result.Count);
                }

                using var messageStream = new MemoryStream(result.Count + 1024);
                messageStream.Write(buffer, 0, result.Count);
                while (!result.EndOfMessage)
                {
                    result = await _socket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
                    if (result.Count > 0)
                    {
                        TrackReceivedBytes(result.Count);
                    }
                    messageStream.Write(buffer, 0, result.Count);
                    if (messageStream.Length > MaxSocketMessageSize)
                    {
                        throw new InvalidOperationException($"Mensagem Socket.IO muito grande (> {MaxSocketMessageSize / (1024 * 1024)}MB).");
                    }
                }

                var text = Encoding.UTF8.GetString(messageStream.ToArray());
                var segments = text.Split('\u001e', StringSplitOptions.RemoveEmptyEntries);
                foreach (var segment in segments)
                {
                    await HandleIncomingAsync(segment, cancellationToken);
                }
            }
        }
        catch (Exception ex)
        {
            Error?.Invoke(this, ex.Message);
        }
        finally
        {
            _connected = false;
            Disconnected?.Invoke(this, EventArgs.Empty);
        }
    }

    private async Task PollingReceiveLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            Console.WriteLine("[SocketIO] Polling receive loop started");
            while (!cancellationToken.IsCancellationRequested && _pollingClient is not null && _pollingUri is not null)
            {
                using var response = await _pollingClient.GetAsync(_pollingUri, cancellationToken);
                var text = await response.Content.ReadAsStringAsync(cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    throw new InvalidOperationException($"Polling HTTP {(int)response.StatusCode}: {text}");
                }
                if (text.Length > 0)
                {
                    TrackReceivedBytes(Encoding.UTF8.GetByteCount(text));
                }

                var segments = text.Split('\u001e', StringSplitOptions.RemoveEmptyEntries);
                foreach (var segment in segments)
                {
                    await HandleIncomingAsync(segment, cancellationToken);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Error?.Invoke(this, ex.Message);
        }
        finally
        {
            _connected = false;
            Disconnected?.Invoke(this, EventArgs.Empty);
        }
    }

    private async Task HandleIncomingAsync(string message, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(message))
        {
            return;
        }

        if (message[0] == '0')
        {
            _openTcs?.TrySetResult(true);
            return;
        }

        if (message[0] == '2')
        {
            await SendTextAsync("3", cancellationToken);
            return;
        }

        if (string.Equals(message, "3probe", StringComparison.Ordinal))
        {
            _probeTcs?.TrySetResult(true);
            return;
        }

        if (message.StartsWith("40", StringComparison.Ordinal))
        {
            _connected = true;
            _connectTcs?.TrySetResult(true);
            Connected?.Invoke(this, EventArgs.Empty);
            return;
        }

        if (message.StartsWith("41", StringComparison.Ordinal))
        {
            _connected = false;
            Disconnected?.Invoke(this, EventArgs.Empty);
            return;
        }

        if (message.StartsWith("42", StringComparison.Ordinal))
        {
            var payloadJson = message.Substring(2);
            using var doc = JsonDocument.Parse(payloadJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array || doc.RootElement.GetArrayLength() < 1)
            {
                return;
            }

            var eventName = doc.RootElement[0].GetString();
            if (string.IsNullOrWhiteSpace(eventName))
            {
                return;
            }

            JsonElement data = default;
            if (doc.RootElement.GetArrayLength() > 1)
            {
                data = doc.RootElement[1].Clone();
            }

            if (_handlers.TryGetValue(eventName, out var list))
            {
                var response = new SocketEventResponse(data);
                foreach (var handler in list.ToArray())
                {
                    Dispatch(() =>
                    {
                        try
                        {
                            handler(response);
                        }
                        catch (Exception ex)
                        {
                            Error?.Invoke(this, ex.Message);
                        }
                    });
                }
            }
            if (_asyncHandlers.TryGetValue(eventName, out var asyncList))
            {
                var response = new SocketEventResponse(data);
                foreach (var handler in asyncList.ToArray())
                {
                    Dispatch(() =>
                    {
                        _ = InvokeAsyncHandlerAsync(handler, response);
                    });
                }
            }
        }
    }

    private async Task InvokeAsyncHandlerAsync(Func<SocketEventResponse, Task> handler, SocketEventResponse response)
    {
        try
        {
            await handler(response);
        }
        catch (Exception ex)
        {
            Error?.Invoke(this, ex.Message);
        }
    }

    private async Task SendTextAsync(string payload, CancellationToken cancellationToken)
    {
        if (_pollingMode)
        {
            await SendPollingTextAsync(payload, cancellationToken);
            return;
        }

        if (_socket is null || _socket.State != WebSocketState.Open)
        {
            throw new WebSocketException(WebSocketError.NotAWebSocket, "Socket não está aberto para envio.");
        }

        var bytes = Encoding.UTF8.GetBytes(payload);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(SendTimeout);

        try
        {
            await _sendLock.WaitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            AbortSocket("Timeout ao obter slot de envio Socket.IO.");
            throw;
        }

        try
        {
            await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, timeoutCts.Token);
            TrackSentBytes(bytes.Length);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            AbortSocket("Timeout ao enviar mensagem Socket.IO.");
            throw;
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async Task SendPollingTextAsync(string payload, CancellationToken cancellationToken)
    {
        if (_pollingClient is null || _pollingUri is null)
        {
            return;
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(SendTimeout);

        var lockTaken = false;
        try
        {
            await _sendLock.WaitAsync(timeoutCts.Token);
            lockTaken = true;
            using var content = new StringContent(payload, Encoding.UTF8, "text/plain");
            using var response = await _pollingClient.PostAsync(_pollingUri, content, timeoutCts.Token);
            var body = await response.Content.ReadAsStringAsync(timeoutCts.Token);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"Polling send HTTP {(int)response.StatusCode}: {body}");
            }
            TrackSentBytes(Encoding.UTF8.GetByteCount(payload));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            AbortSocket("Timeout ao enviar mensagem Socket.IO.");
            throw;
        }
        finally
        {
            if (lockTaken)
            {
                _sendLock.Release();
            }
        }
    }

    private void AbortSocket(string reason)
    {
        try
        {
            _receiveCts?.Cancel();
            _socket?.Abort();
        }
        catch
        {
        }

        _connected = false;
        _pollingMode = false;
        if (!string.IsNullOrWhiteSpace(reason))
        {
            Error?.Invoke(this, reason);
        }
        Disconnected?.Invoke(this, EventArgs.Empty);
    }

    private void TrackSentBytes(int count)
    {
        if (count <= 0)
        {
            return;
        }
        var totalSent = Interlocked.Add(ref _bytesSent, count);
        var totalReceived = Interlocked.Read(ref _bytesReceived);
        TrafficUpdated?.Invoke(this, new SocketTrafficEventArgs(count, 0, totalSent, totalReceived));
    }

    private void TrackReceivedBytes(int count)
    {
        if (count <= 0)
        {
            return;
        }
        var totalReceived = Interlocked.Add(ref _bytesReceived, count);
        var totalSent = Interlocked.Read(ref _bytesSent);
        TrafficUpdated?.Invoke(this, new SocketTrafficEventArgs(0, count, totalSent, totalReceived));
    }

    private static Uri BuildWebSocketUrl(string serverUrl, string? engineIoSid)
    {
        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"Servidor inválido: {serverUrl}");
        }

        var scheme = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? "wss" : "ws";
        var builder = new UriBuilder(uri)
        {
            Scheme = scheme,
            Path = "/socket.io/",
            Query = string.IsNullOrWhiteSpace(engineIoSid)
                ? "EIO=4&transport=websocket"
                : $"EIO=4&transport=websocket&sid={Uri.EscapeDataString(engineIoSid)}"
        };
        return builder.Uri;
    }

    private static Uri BuildPollingUrl(string serverUrl, string engineIoSid)
    {
        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"Servidor invÃ¡lido: {serverUrl}");
        }

        var builder = new UriBuilder(uri)
        {
            Path = "/socket.io/",
            Query = $"EIO=4&transport=polling&sid={Uri.EscapeDataString(engineIoSid)}"
        };
        return builder.Uri;
    }

    private static async Task WaitOrTimeoutAsync(Task task, CancellationToken cancellationToken, string timeoutMessage)
    {
        var completed = await Task.WhenAny(task, Task.Delay(Timeout.Infinite, cancellationToken));
        if (completed != task)
        {
            throw new TimeoutException(timeoutMessage);
        }
        await task;
    }
}

public sealed class SocketTrafficEventArgs : EventArgs
{
    public SocketTrafficEventArgs(long sentDelta, long receivedDelta, long totalSent, long totalReceived)
    {
        SentDelta = sentDelta;
        ReceivedDelta = receivedDelta;
        TotalSent = totalSent;
        TotalReceived = totalReceived;
    }

    public long SentDelta { get; }
    public long ReceivedDelta { get; }
    public long TotalSent { get; }
    public long TotalReceived { get; }
}
