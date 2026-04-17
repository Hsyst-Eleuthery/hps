using Hps.Cli.Native;

namespace Hps.Cli.Core;

public sealed class CliApplication
{
    public async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        var cliArgs = CliArguments.Parse(args);
        if (cliArgs.Mode == CliMode.LegacyPython)
        {
            Console.Error.WriteLine("[hps-cli] legacy-python removido; executando modo nativo C#.");
        }

        var native = new NativeCliRunner();
        var nativeCode = await native.RunAsync(
            cliArgs.ForwardedArgs,
            cliArgs.NativePowSelfTest,
            cliArgs.PipeFilePath,
            cliArgs.PipeControllerMode,
            cancellationToken);
        return nativeCode;
    }
}
