using Hps.Cli.Native.Crypto;
using Hps.Cli.Native.Storage;

namespace Hps.Cli.Native.Core;

public sealed class NativeContext
{
    public NativeContext(NativePaths paths, NativeStateStore stateStore, KeyPairManager keyManager)
    {
        Paths = paths;
        StateStore = stateStore;
        KeyManager = keyManager;
    }

    public NativePaths Paths { get; }
    public NativeStateStore StateStore { get; }
    public KeyPairManager KeyManager { get; }
}
