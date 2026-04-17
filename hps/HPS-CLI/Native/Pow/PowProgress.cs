namespace Hps.Cli.Native.Pow;

public sealed record PowProgress(
    string Status,
    int TargetBits,
    double TargetSeconds,
    double Hashrate,
    ulong Attempts,
    double ElapsedSeconds);
