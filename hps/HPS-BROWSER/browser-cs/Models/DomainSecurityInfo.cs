using System.Collections.Generic;

namespace HpsBrowser.Models;

public sealed record DomainSecurityInfo(
    string Domain,
    string ContentHash,
    string Username,
    string OriginalOwner,
    bool Verified,
    string Signature,
    IReadOnlyList<string> Contracts,
    string Certifier
);
