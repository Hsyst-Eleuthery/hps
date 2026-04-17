using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace Hps.Cli.Native.Socket;

public sealed class HpsSocketClient : IAsyncDisposable
{
    private readonly Dictionary<string, List<Action<JsonElement>>> _handlers = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly object _handlersLock = new();

    private ClientWebSocket? _socket;
    private CancellationTokenSource? _receiveCts;
    private Task? _receiveLoop;
    private TaskCompletionSource<bool>? _openTcs;
    private TaskCompletionSource<bool>? _connectTcs;
    private volatile bool _connected;

    public bool IsConnected => _connected && _socket?.State == WebSocketState.Open;

    public async Task ConnectAsync(string serverUrl, CancellationToken ct)
    {
        await DisconnectAsync().ConfigureAwait(false);

        var wsUrl = BuildWebSocketUrl(serverUrl);
        _socket = new ClientWebSocket();
        _socket.Options.Proxy = null;
        _socket.Options.UseDefaultCredentials = false;
        _socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);

        _openTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _connectTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _receiveCts = new CancellationTokenSource();

        var connectTask = _socket.ConnectAsync(wsUrl, ct);
        var connectCompleted = await Task.WhenAny(connectTask, Task.Delay(TimeSpan.FromSeconds(8), ct)).ConfigureAwait(false);
        if (connectCompleted != connectTask)
        {
            throw new TimeoutException("timeout ao abrir websocket");
        }
        await connectTask.ConfigureAwait(false);

        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_receiveCts.Token));

        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            await WaitOrTimeoutAsync(_openTcs.Task, timeout.Token, "timeout no handshake engine.io").ConfigureAwait(false);
        }

        await SendTextAsync("40", ct).ConfigureAwait(false);
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            await WaitOrTimeoutAsync(_connectTcs.Task, timeout.Token, "timeout no connect socket.io").ConfigureAwait(false);
        }
    }

    public async Task DisconnectAsync()
    {
        if (_socket is null)
        {
            return;
        }

        try
        {
            _receiveCts?.Cancel();
            if (_socket.State == WebSocketState.Open)
            {
                await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "disconnect", CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch
        {
        }
        finally
        {
            _connected = false;
            _socket.Dispose();
            _socket = null;
            _receiveCts?.Dispose();
            _receiveCts = null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync().ConfigureAwait(false);
        _sendLock.Dispose();
    }

    public IDisposable On(string eventName, Action<JsonElement> handler)
    {
        lock (_handlersLock)
        {
            if (!_handlers.TryGetValue(eventName, out var list))
            {
                list = [];
                _handlers[eventName] = list;
            }
            list.Add(handler);
        }

        return new HandlerRegistration(() =>
        {
            lock (_handlersLock)
            {
                if (_handlers.TryGetValue(eventName, out var list))
                {
                    list.Remove(handler);
                    if (list.Count == 0)
                    {
                        _handlers.Remove(eventName);
                    }
                }
            }
        });
    }

    public async Task<JsonElement> WaitForEventAsync(
        string eventName,
        TimeSpan timeout,
        CancellationToken ct,
        Func<JsonElement, bool>? predicate = null)
    {
        var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var reg = On(eventName, data =>
        {
            if (predicate is not null && !predicate(data))
            {
                return;
            }
            tcs.TrySetResult(data.Clone());
        });

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        using var cancelReg = timeoutCts.Token.Register(() => tcs.TrySetCanceled(timeoutCts.Token));

        try
        {
            return await tcs.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException($"timeout aguardando evento '{eventName}'");
        }
    }

    public Task EmitAsync(string eventName, object payload, CancellationToken ct)
    {
        if (_socket is null || _socket.State != WebSocketState.Open)
        {
            throw new InvalidOperationException("socket desconectado");
        }
        var json = JsonSerializer.Serialize(new object[] { eventName, payload });
        return SendTextAsync("42" + json, ct);
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[128 * 1024];
        try
        {
            while (!ct.IsCancellationRequested && _socket is not null)
            {
                var result = await _socket.ReceiveAsync(buffer, ct).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }

                using var ms = new MemoryStream(result.Count + 1024);
                ms.Write(buffer, 0, result.Count);
                while (!result.EndOfMessage)
                {
                    result = await _socket.ReceiveAsync(buffer, ct).ConfigureAwait(false);
                    ms.Write(buffer, 0, result.Count);
                    if (ms.Length > 256L * 1024L * 1024L)
                    {
                        throw new InvalidOperationException("mensagem socket muito grande");
                    }
                }

                var text = Encoding.UTF8.GetString(ms.ToArray());
                var segments = text.Split('\u001e', StringSplitOptions.RemoveEmptyEntries);
                foreach (var segment in segments)
                {
                    await HandleIncomingAsync(segment, ct).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            _connected = false;
        }
    }

    private async Task HandleIncomingAsync(string message, CancellationToken ct)
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
            await SendTextAsync("3", ct).ConfigureAwait(false);
            return;
        }
        if (message.StartsWith("40", StringComparison.Ordinal))
        {
            _connected = true;
            _connectTcs?.TrySetResult(true);
            return;
        }
        if (!message.StartsWith("42", StringComparison.Ordinal))
        {
            return;
        }

        var payloadJson = message[2..];
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
        var data = doc.RootElement.GetArrayLength() > 1 ? doc.RootElement[1].Clone() : default;
        Action<JsonElement>[] callbacks;
        lock (_handlersLock)
        {
            if (!_handlers.TryGetValue(eventName, out var list) || list.Count == 0)
            {
                return;
            }
            callbacks = list.ToArray();
        }
        foreach (var callback in callbacks)
        {
            try
            {
                callback(data);
            }
            catch
            {
            }
        }
    }

    private async Task SendTextAsync(string payload, CancellationToken ct)
    {
        if (_socket is null || _socket.State != WebSocketState.Open)
        {
            return;
        }
        var bytes = Encoding.UTF8.GetBytes(payload);
        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _socket.SendAsync(bytes, WebSocketMessageType.Text, true, ct).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private static Uri BuildWebSocketUrl(string serverUrl)
    {
        var raw = (serverUrl ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            throw new InvalidOperationException("servidor invalido");
        }

        // host:port (e.g. localhost:8081) must be treated as HTTP URL, not URI scheme "localhost".
        if (!raw.Contains("://", StringComparison.Ordinal))
        {
            raw = "http://" + raw;
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException("servidor invalido");
        }

        var scheme = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? "wss" : "ws";
        var builder = new UriBuilder(uri)
        {
            Scheme = scheme,
            Path = "/socket.io/",
            Query = "EIO=4&transport=websocket"
        };
        return builder.Uri;
    }

    private static async Task WaitOrTimeoutAsync(Task task, CancellationToken ct, string timeoutMessage)
    {
        var completed = await Task.WhenAny(task, Task.Delay(Timeout.Infinite, ct)).ConfigureAwait(false);
        if (completed != task)
        {
            throw new TimeoutException(timeoutMessage);
        }
        await task.ConfigureAwait(false);
    }

    private sealed class HandlerRegistration : IDisposable
    {
        private readonly Action _dispose;
        private int _disposed;

        public HandlerRegistration(Action dispose) => _dispose = dispose;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _dispose();
            }
        }
    }
}
