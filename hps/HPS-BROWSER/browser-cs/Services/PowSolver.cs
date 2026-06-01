using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace HpsBrowser.Services;

public sealed class PowSolver
{
    private const int AttemptFlushInterval = 1024;

    public sealed record PowProgress(ulong Attempts, TimeSpan Elapsed, double Hashrate);
    public sealed record PowResult(ulong Nonce, byte[] Hash, int LeadingZeroBits, TimeSpan Elapsed, ulong Attempts);

    public async Task<PowResult?> SolveAsync(
        byte[] challenge,
        int targetBits,
        int threads,
        CancellationToken cancellationToken,
        Action<PowProgress>? progressCallback = null)
    {
        if (targetBits <= 0)
        {
            return null;
        }

        var tcs = new TaskCompletionSource<PowResult?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var start = DateTime.UtcNow;
        long attempts = 0;
        var found = 0;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = linkedCts.Token;

        var progressTask = Task.Run(async () =>
        {
            if (progressCallback is null)
            {
                return;
            }

            try
            {
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(250, token);
                    var elapsed = DateTime.UtcNow - start;
                    var totalAttempts = (ulong)Interlocked.Read(ref attempts);
                    var hashrate = totalAttempts / Math.Max(0.001, elapsed.TotalSeconds);
                    progressCallback(new PowProgress(totalAttempts, elapsed, hashrate));
                }
            }
            catch (OperationCanceledException)
            {
                // Expected on cancellation.
            }
        }, token);

        Task RunWorker(int workerId)
        {
            return Task.Run(() =>
            {
                var nonce = (ulong)workerId;
                var stride = (ulong)threads;
                var localAttempts = 0UL;
                var payload = new byte[challenge.Length + sizeof(ulong)];
                var hashBuffer = new byte[32];
                Buffer.BlockCopy(challenge, 0, payload, 0, challenge.Length);
                try
                {
                    while (!token.IsCancellationRequested)
                    {
                        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(challenge.Length, sizeof(ulong)), nonce);

                        SHA256.TryHashData(payload, hashBuffer, out _);
                        var leading = CountLeadingZeroBits(hashBuffer);
                        localAttempts++;
                        if ((localAttempts & (AttemptFlushInterval - 1)) == 0)
                        {
                            Interlocked.Add(ref attempts, (long)localAttempts);
                            localAttempts = 0;
                        }

                        if (leading >= targetBits && Interlocked.CompareExchange(ref found, 1, 0) == 0)
                        {
                            if (localAttempts > 0)
                            {
                                Interlocked.Add(ref attempts, (long)localAttempts);
                                localAttempts = 0;
                            }
                            linkedCts.Cancel();
                            var elapsed = DateTime.UtcNow - start;
                            var totalAttempts = (ulong)Interlocked.Read(ref attempts);
                            tcs.TrySetResult(new PowResult(nonce, hashBuffer.ToArray(), leading, elapsed, totalAttempts));
                            return;
                        }

                        nonce += stride;
                    }
                }
                finally
                {
                    if (localAttempts > 0)
                    {
                        Interlocked.Add(ref attempts, (long)localAttempts);
                    }
                }
            }, token);
        }

        var workers = Enumerable.Range(0, Math.Max(1, threads)).Select(RunWorker).ToArray();
        await Task.WhenAll(workers).ContinueWith(_ => { });
        linkedCts.Cancel();
        await progressTask.ContinueWith(_ => { });
        if (tcs.Task.IsCompleted)
        {
            return await tcs.Task;
        }

        return null;
    }

    private static int CountLeadingZeroBits(ReadOnlySpan<byte> hash)
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
}
