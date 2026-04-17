using Hps.Cli.Native.Display;
using Hps.Cli.Native.Pow;
using Hps.Cli.Native.Core;
using Hps.Cli.Native.Storage;
using Hps.Cli.Native.Crypto;
using Hps.Cli.Native.Net;
using System.Text;

namespace Hps.Cli.Native;

public sealed class NativeCliRunner
{
    private readonly ICliDisplay _display;

    public NativeCliRunner(ICliDisplay? display = null)
    {
        _display = display ?? new CliDisplay();
    }

    public async Task<int> RunAsync(string[] args, bool runPowSelfTest, string pipeFilePath, bool pipeControllerMode, CancellationToken ct)
    {
        var paths = NativePaths.Resolve();
        var hasPipeFileArg = !string.IsNullOrWhiteSpace(pipeFilePath);
        var resolvedPipeFile = (pipeControllerMode || hasPipeFileArg)
            ? ResolvePipeFilePath(paths, pipeFilePath)
            : string.Empty;
        var isPipeMode = pipeControllerMode || hasPipeFileArg;
        if (!isPipeMode)
        {
            _display.PrintHeader("HPS CLI Native Mode (C#)");
            _display.PrintInfo("Modo nativo ativo.");
        }
        var ctx = new NativeContext(paths, new NativeStateStore(paths), new KeyPairManager(paths));
        var service = new NativeClientService(ctx);
        var http = new HpsHttpClient();
        var shell = new NativeCommandShell(_display, service, ctx, http);

        if (runPowSelfTest)
        {
            return await RunPowSelfTestAsync(ct).ConfigureAwait(false);
        }

        if (pipeControllerMode)
        {
            return await RunPipeControllerAsync(shell, resolvedPipeFile, ct).ConfigureAwait(false);
        }
        if (!string.IsNullOrWhiteSpace(resolvedPipeFile))
        {
            return await RunPipeFileOnceAsync(shell, resolvedPipeFile, ct).ConfigureAwait(false);
        }

        if (args.Length == 0 && Console.IsInputRedirected)
        {
            _display.PrintInfo("modo pipe: lendo comandos do stdin");
            var script = await Console.In.ReadToEndAsync().ConfigureAwait(false);
            var exitCode = 0;
            foreach (var raw in script.Replace("\r\n", "\n").Split('\n'))
            {
                var line = raw.Trim();
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                {
                    continue;
                }
                exitCode = await shell.RunCommandLineAsync(line, ct).ConfigureAwait(false);
                if (exitCode == int.MinValue)
                {
                    return 0;
                }
                if (exitCode != 0)
                {
                    return exitCode;
                }
            }
            return 0;
        }

        if (args.Length == 0)
        {
            return await shell.RunInteractiveAsync(ct).ConfigureAwait(false);
        }
        return await shell.RunCommandAsync(args, ct).ConfigureAwait(false);
    }

    private async Task<int> RunPipeControllerAsync(NativeCommandShell shell, string pipeFilePath, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(pipeFilePath))
        {
            _display.PrintError("pipe-controller sem arquivo configurado");
            return 2;
        }
        var dir = Path.GetDirectoryName(pipeFilePath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _display.PrintInfo($"pipe-controller ativo em: {pipeFilePath}");
        while (!ct.IsCancellationRequested)
        {
            if (!File.Exists(pipeFilePath))
            {
                await Task.Delay(250, ct).ConfigureAwait(false);
                continue;
            }
            var raw = await File.ReadAllTextAsync(pipeFilePath, Encoding.UTF8, ct).ConfigureAwait(false);
            var command = ExtractPipeCommand(raw);
            if (string.IsNullOrWhiteSpace(command))
            {
                await Task.Delay(200, ct).ConfigureAwait(false);
                continue;
            }
            await ExecutePipeCommandToFileAsync(shell, pipeFilePath, command, ct).ConfigureAwait(false);
        }
        return 0;
    }

    private async Task<int> RunPipeFileOnceAsync(NativeCommandShell shell, string pipeFilePath, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(pipeFilePath))
        {
            _display.PrintError("pipe-file sem arquivo configurado");
            return 2;
        }
        if (!File.Exists(pipeFilePath))
        {
            _display.PrintError($"arquivo pipe não encontrado: {pipeFilePath}");
            return 3;
        }

        var raw = await File.ReadAllTextAsync(pipeFilePath, Encoding.UTF8, ct).ConfigureAwait(false);
        var command = ExtractPipeCommand(raw);
        if (string.IsNullOrWhiteSpace(command))
        {
            await File.WriteAllTextAsync(pipeFilePath, "0\ncomando vazio\n0", Encoding.UTF8, ct).ConfigureAwait(false);
            return 2;
        }

        return await ExecutePipeCommandToFileAsync(shell, pipeFilePath, command, ct).ConfigureAwait(false);
    }

    private async Task<int> ExecutePipeCommandToFileAsync(NativeCommandShell shell, string pipeFilePath, string command, CancellationToken ct)
    {
        await File.WriteAllTextAsync(pipeFilePath, "Loading...", Encoding.UTF8, ct).ConfigureAwait(false);

        var startOk = true;
        var endOk = false;
        var code = 1;
        var logs = string.Empty;

        var oldOut = Console.Out;
        var oldErr = Console.Error;
        using var writer = new StringWriter();
        Console.SetOut(writer);
        Console.SetError(writer);
        try
        {
            code = await shell.RunCommandLineAsync(command, ct).ConfigureAwait(false);
            endOk = code == 0 || code == int.MinValue;
        }
        catch (Exception ex)
        {
            startOk = false;
            endOk = false;
            code = 1;
            writer.WriteLine("[PIPE-ERR] " + ex.Message);
        }
        finally
        {
            Console.SetOut(oldOut);
            Console.SetError(oldErr);
            logs = writer.ToString().TrimEnd();
        }

        var begin = startOk ? "1" : "0";
        var finish = endOk ? "1" : "0";
        var payload = string.IsNullOrWhiteSpace(logs)
            ? $"{begin}\n{finish}"
            : $"{begin}\n{logs}\n{finish}";
        await File.WriteAllTextAsync(pipeFilePath, payload, Encoding.UTF8, ct).ConfigureAwait(false);
        return code == int.MinValue ? 0 : code;
    }

    private static string ExtractPipeCommand(string raw)
    {
        var text = (raw ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }
        if (text.StartsWith("Loading...", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        var normalized = text.Replace("\r\n", "\n");
        var lines = normalized.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0)
        {
            return string.Empty;
        }
        if ((lines[0] == "0" || lines[0] == "1") && lines.Length >= 2)
        {
            return string.Empty;
        }
        var first = lines[0];
        if (first.StartsWith("cmd:", StringComparison.OrdinalIgnoreCase))
        {
            return first[4..].Trim();
        }
        return first.Trim();
    }

    private static string ResolvePipeFilePath(NativePaths paths, string pipeFilePath)
    {
        if (!string.IsNullOrWhiteSpace(pipeFilePath))
        {
            return pipeFilePath;
        }
        return Path.Combine(paths.RootDir, "controller_hpscli");
    }

    private async Task<int> RunPowSelfTestAsync(CancellationToken ct)
    {
        _display.PrintSection("PoW Self Test");
        var solver = new CliPowSolver();
        solver.ProgressChanged += p =>
        {
            var pct = p.TargetSeconds <= 0 ? 0 : (int)Math.Min(99, (p.ElapsedSeconds / p.TargetSeconds) * 100);
            _display.PrintProgress(pct, 100, $"status={p.Status} bits={p.TargetBits} rate={p.Hashrate:0}H/s attempts={p.Attempts}");
        };

        var challenge = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        var result = await solver.SolveAsync(challenge, targetBits: 18, targetSeconds: 8.0, actionType: "selftest", cancellationToken: ct).ConfigureAwait(false);
        _display.PrintProgress(100, 100, "finalizando");

        if (!result.Solved)
        {
            _display.PrintError($"PoW nao resolvido: {result.Error}");
            return 10;
        }

        _display.PrintSuccess($"PoW resolvido nonce={result.Nonce} lzb={result.LeadingZeroBits} tempo={result.ElapsedSeconds:0.00}s");
        return 0;
    }

}
