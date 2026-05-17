using System.Net.Http;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;

namespace HpsBrowser.Services;

public static class TlsCertificateValidation
{
    public static HttpClientHandler CreateHttpClientHandler()
    {
        return new HttpClientHandler
        {
            UseProxy = false,
            Proxy = null,
            ServerCertificateCustomValidationCallback = AcceptServerCertificate
        };
    }

    public static void ApplyTo(ClientWebSocketOptions options)
    {
        options.RemoteCertificateValidationCallback = AcceptServerCertificate;
    }

    private static bool AcceptServerCertificate(
        object? sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        return true;
    }
}
