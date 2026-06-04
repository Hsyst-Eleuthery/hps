using System.Text.Json;

namespace HpsBrowser.Services;

public sealed class SocketEventResponse
{
    private readonly JsonElement _data;

    public SocketEventResponse(JsonElement data)
    {
        _data = data;
    }

    public T GetValue<T>()
    {
        if (typeof(T) == typeof(JsonElement))
        {
            return (T)(object)_data;
        }

        return JsonSerializer.Deserialize<T>(_data.GetRawText())!;
    }
}
