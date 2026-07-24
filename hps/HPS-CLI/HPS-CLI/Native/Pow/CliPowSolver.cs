using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Hps.Cli.Native.Pow;

public sealed class CliPowSolver
{
    public event Action<PowProgress>? ProgressChanged;

    public async Task<PowResult> SolveAsync(
        string challengeBase64,
        int targetBits,
        double targetSeconds,
        string actionType = "login",
        int threads = 1,
        TimeSpan? maxDuration = null,
        CancellationToken cancellationToken = default)
    {
        if (targetBits < 1)
        {
            targetBits = 1;
        }
        if (targetBits > 255)
        {
            targetBits = 255;
        }

        byte[] challenge;
        try
        {
            challenge = Convert.FromBase64String(challengeBase64);
        }
        catch (Exception ex)
        {
            return new PowResult(false, 0, 0, 0, 0, 0, $"invalid_challenge: {ex.Message}");
        }

        var workerCount = Math.Max(1, threads);
        var started = DateTimeOffset.UtcNow;
        var limit = maxDuration ?? TimeSpan.FromMinutes(10);
        var hashrate = await CalibrateHashrateAsync(0.4, cancellationToken).ConfigureAwait(false);
        Report("Iniciando", targetBits, targetSeconds, hashrate, 0, 0);

        long attempts = 0;
        long found = 0;
        ulong solvedNonce = 0;
        int solvedLzb = 0;
        double currentRate = hashrate;
        var lastAttempts = 0L;
        var lastTick = DateTimeOffset.UtcNow;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = linkedCts.Token;

        var progressTask = Task.Run(async () =>
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(300, token).ConfigureAwait(false);
                    var now = DateTimeOffset.UtcNow;
                    var total = Interlocked.Read(ref attempts);
                    var delta = total - lastAttempts;
                    var sec = Math.Max(0.001, (now - lastTick).TotalSeconds);
                    currentRate = delta / sec;
                    lastAttempts = total;
                    lastTick = now;
                    var elapsed = (now - started).TotalSeconds;
                    Report("Minerando", targetBits, targetSeconds, currentRate, (ulong)Math.Max(0, total), elapsed);
                    if ((now - started) > limit)
                    {
                        linkedCts.Cancel();
                        break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
        }, token);

        var workers = Enumerable.Range(0, workerCount).Select(workerId => Task.Run(() =>
        {
            var nonce = (ulong)workerId;
            var stride = (ulong)workerCount;
            var payload = new byte[challenge.Length + sizeof(ulong)];
            Buffer.BlockCopy(challenge, 0, payload, 0, challenge.Length);

            while (!token.IsCancellationRequested)
            {
                BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(challenge.Length), nonce);
                var sum = SHA256.HashData(payload);
                var lzb = LeadingZeroBits(sum);
                Interlocked.Increment(ref attempts);

                if (lzb >= targetBits && Interlocked.CompareExchange(ref found, 1, 0) == 0)
                {
                    solvedNonce = nonce;
                    solvedLzb = lzb;
                    linkedCts.Cancel();
                    break;
                }

                nonce += stride;
            }
        }, token)).ToArray();

        try
        {
            await Task.WhenAll(workers).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        linkedCts.Cancel();
        try
        {
            await progressTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        var elapsedSeconds = (DateTimeOffset.UtcNow - started).TotalSeconds;
        var totalAttempts = (ulong)Math.Max(0, Interlocked.Read(ref attempts));
        if (Interlocked.Read(ref found) == 1)
        {
            Report("Solucao encontrada", targetBits, targetSeconds, currentRate, totalAttempts, elapsedSeconds);
            return new PowResult(true, solvedNonce, solvedLzb, elapsedSeconds, currentRate, totalAttempts, string.Empty);
        }

        var timeoutReached = elapsedSeconds >= limit.TotalSeconds;
        return new PowResult(false, solvedNonce, 0, elapsedSeconds, currentRate, totalAttempts, timeoutReached ? "timeout" : "canceled");
    }

    public static int LeadingZeroBits(ReadOnlySpan<byte> hash)
    {
        var count = 0;
        foreach (var b in hash)
        {
            if (b == 0)
            {
                count += 8;
                continue;
            }
            for (var i = 7; i >= 0; i--)
            {
                if (((b >> i) & 1) == 0)
                {
                    count++;
                }
                else
                {
                    return count;
                }
            }
        }
        return count;
    }

    private static async Task<double> CalibrateHashrateAsync(double seconds, CancellationToken ct)
    {
        if (seconds <= 0)
        {
            seconds = 0.5;
        }

        var challenge = RandomNumberGenerator.GetBytes(16);
        var payload = new byte[challenge.Length + sizeof(ulong)];
        Buffer.BlockCopy(challenge, 0, payload, 0, challenge.Length);

        var started = DateTimeOffset.UtcNow;
        var end = started.AddSeconds(seconds);
        ulong nonce = 0;
        ulong count = 0;

        while (DateTimeOffset.UtcNow < end && !ct.IsCancellationRequested)
        {
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(challenge.Length), nonce++);
            _ = SHA256.HashData(payload);
            count++;

            if ((count & 0x3FFF) == 0)
            {
                await Task.Yield();
            }
        }

        var elapsed = Math.Max(0.001, (DateTimeOffset.UtcNow - started).TotalSeconds);
        return count / elapsed;
    }

    private void Report(string status, int targetBits, double targetSeconds, double hashrate, ulong attempts, double elapsed)
    {
        ProgressChanged?.Invoke(new PowProgress(status, targetBits, targetSeconds, hashrate, attempts, elapsed));
    }
}
