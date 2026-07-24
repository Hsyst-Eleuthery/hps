using System.Collections.Generic;

namespace HpsBrowser.Models;

public sealed record ContentSecurityInfo(
    string Title,
    string Description,
    string Username,
    string OriginalOwner,
    string ContentHash,
    string MimeType,
    string Signature,
    string PublicKey,
    bool SignatureValid,
    int Reputation,
    IReadOnlyList<string> Contracts,
    string Certifier
);
