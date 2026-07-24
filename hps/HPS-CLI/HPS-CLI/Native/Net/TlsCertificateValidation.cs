using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;

namespace Hps.Cli.Native.Net;

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
        // A3 FIX: If no SSL errors, accept the certificate
        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            return true;
        }

        // A3 FIX: Reject name mismatch - prevents passive observation
        if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            return false;
        }

        // A3 FIX: Reject if certificate is not available
        if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
        {
            return false;
        }

        // A3 FIX: For chain errors (self-signed, untrusted root), accept with TOFU model
        if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
        {
            if (chain != null && chain.ChainStatus.Length > 0)
            {
                foreach (var status in chain.ChainStatus)
                {
                    if (status.Status != X509ChainStatusFlags.PartialChain &&
                        status.Status != X509ChainStatusFlags.UntrustedRoot &&
                        status.Status != X509ChainStatusFlags.RevocationStatusUnknown)
                    {
                        return false;
                    }
                }
                return true;
            }
        }

        // A3 FIX: Reject all other errors
        return false;
    }
}
