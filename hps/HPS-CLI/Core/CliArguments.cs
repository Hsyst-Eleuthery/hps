namespace Hps.Cli.Core;

public sealed class CliArguments
{
    public CliMode Mode { get; private set; } = CliMode.NativeCSharp;
    public bool NativePowSelfTest { get; private set; }
    public string PipeFilePath { get; private set; } = string.Empty;
    public bool PipeControllerMode { get; private set; }
    public string[] ForwardedArgs { get; private set; } = Array.Empty<string>();

    public static CliArguments Parse(string[] args)
    {
        var parsed = new CliArguments();
        var forward = new List<string>(args.Length);

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (string.Equals(arg, "--native", StringComparison.OrdinalIgnoreCase))
            {
                parsed.Mode = CliMode.NativeCSharp;
                continue;
            }
            if (string.Equals(arg, "--legacy-python", StringComparison.OrdinalIgnoreCase))
            {
                parsed.Mode = CliMode.LegacyPython;
                continue;
            }
            if (string.Equals(arg, "--native-pow-selftest", StringComparison.OrdinalIgnoreCase))
            {
                parsed.Mode = CliMode.NativeCSharp;
                parsed.NativePowSelfTest = true;
                continue;
            }
            if (string.Equals(arg, "--pipe-file", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length)
                {
                    parsed.PipeFilePath = args[++i] ?? string.Empty;
                }
                continue;
            }
            if (string.Equals(arg, "--pipe-controller", StringComparison.OrdinalIgnoreCase))
            {
                parsed.PipeControllerMode = true;
                if (i + 1 < args.Length && !args[i + 1].StartsWith("-", StringComparison.Ordinal))
                {
                    parsed.PipeFilePath = args[++i] ?? string.Empty;
                }
                continue;
            }
            forward.Add(arg);
        }

        parsed.ForwardedArgs = forward.ToArray();
        return parsed;
    }
}
