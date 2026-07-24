using System.Buffers.Binary;
using System.Security.Cryptography;

namespace HpsWallet.Services;

public sealed class PowSolver
{
    public sealed record PowProgress(ulong Attempts, TimeSpan Elapsed, double Hashrate);
    public sealed record PowResult(ulong Nonce, byte[] Hash, int LeadingZeroBits, TimeSpan Elapsed, ulong Attempts);

    public async Task<PowResult?> SolveAsync(
        byte[] challenge, int targetBits, int threads,
        CancellationToken cancellationToken,
        Action<PowProgress>? progressCallback = null)
    {
        if (targetBits <= 0) return null;

        var tcs = new TaskCompletionSource<PowResult?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var start = DateTime.UtcNow;
        long attempts = 0;
        var found = 0;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = linkedCts.Token;

        var progressTask = Task.Run(async () =>
        {
            if (progressCallback is null) return;
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(250, token);
                var elapsed = DateTime.UtcNow - start;
                var totalAttempts = (ulong)Interlocked.Read(ref attempts);
                var hashrate = totalAttempts / Math.Max(0.001, elapsed.TotalSeconds);
                progressCallback(new PowProgress(totalAttempts, elapsed, hashrate));
            }
        }, token);

        Task RunWorker(int workerId) => Task.Run(() =>
        {
            var randomBytes = new byte[sizeof(ulong)];
            RandomNumberGenerator.Fill(randomBytes);
            var nonce = BitConverter.ToUInt64(randomBytes, 0);
            var stride = (ulong)threads;
            var localAttempts = 0UL;
            var payload = new byte[challenge.Length + sizeof(ulong)];
            var hashBuffer = new byte[32];
            Buffer.BlockCopy(challenge, 0, payload, 0, challenge.Length);
            while (!token.IsCancellationRequested)
            {
                BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(challenge.Length, sizeof(ulong)), nonce);
                SHA256.TryHashData(payload, hashBuffer, out _);
                var leading = CountLeadingZeroBits(hashBuffer);
                localAttempts++;
                if ((localAttempts & 1023) == 0)
                {
                    Interlocked.Add(ref attempts, (long)localAttempts);
                    localAttempts = 0;
                }
                if (leading >= targetBits && Interlocked.CompareExchange(ref found, 1, 0) == 0)
                {
                    if (localAttempts > 0)
                        Interlocked.Add(ref attempts, (long)localAttempts);
                    linkedCts.Cancel();
                    var elapsed = DateTime.UtcNow - start;
                    tcs.TrySetResult(new PowResult(nonce, hashBuffer.ToArray(), leading, elapsed, (ulong)Interlocked.Read(ref attempts)));
                    return;
                }
                nonce += stride;
            }
            if (localAttempts > 0)
                Interlocked.Add(ref attempts, (long)localAttempts);
        }, token);

        var workers = Enumerable.Range(0, Math.Max(1, threads)).Select(RunWorker).ToArray();
        await Task.WhenAll(workers).ContinueWith(_ => { });
        linkedCts.Cancel();
        await progressTask.ContinueWith(_ => { });
        if (tcs.Task.IsCompleted) return await tcs.Task;
        return null;
    }

    private static int CountLeadingZeroBits(ReadOnlySpan<byte> hash)
    {
        var count = 0;
        foreach (var b in hash)
        {
            if (b == 0) { count += 8; continue; }
            for (var i = 7; i >= 0; i--)
            {
                if (((b >> i) & 1) == 0) count++;
                else return count;
            }
        }
        return count;
    }
}
