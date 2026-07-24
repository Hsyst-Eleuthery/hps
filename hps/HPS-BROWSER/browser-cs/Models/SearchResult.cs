namespace HpsBrowser.Models;

public sealed record SearchResult(
    string ContentHash,
    string Title,
    string Description,
    string MimeType,
    string Username,
    int Reputation,
    bool Verified
);
