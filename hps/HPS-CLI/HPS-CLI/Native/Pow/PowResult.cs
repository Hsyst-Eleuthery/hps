namespace Hps.Cli.Native.Pow;

public sealed record PowResult(
    bool Solved,
    ulong Nonce,
    int LeadingZeroBits,
    double ElapsedSeconds,
    double Hashrate,
    ulong TotalHashes,
    string Error);
