namespace Hps.Cli.Native.Storage;

public sealed class NativePaths
{
    public string RootDir { get; init; } = string.Empty;
    public string ContentDir { get; init; } = string.Empty;
    public string ContractsDir { get; init; } = string.Empty;
    public string DdnsDir { get; init; } = string.Empty;
    public string VouchersDir { get; init; } = string.Empty;
    public string StateFile { get; init; } = string.Empty;
    public string PrivateKeyPath { get; init; } = string.Empty;
    public string PublicKeyPath { get; init; } = string.Empty;
    public string BrowserPrivateKeyPath { get; init; } = string.Empty;
    public string BrowserPublicKeyPath { get; init; } = string.Empty;

    public static NativePaths Resolve()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var root = Path.Combine(home, ".hps_cli");
        var browser = Path.Combine(home, ".hps_browser");
        return new NativePaths
        {
            RootDir = root,
            ContentDir = Path.Combine(root, "content"),
            ContractsDir = Path.Combine(root, "contracts"),
            DdnsDir = Path.Combine(root, "ddns"),
            VouchersDir = Path.Combine(root, "vouchers"),
            StateFile = Path.Combine(root, "native_state.json"),
            PrivateKeyPath = Path.Combine(root, "private_key.pem"),
            PublicKeyPath = Path.Combine(root, "public_key.pem"),
            BrowserPrivateKeyPath = Path.Combine(browser, "private_key.pem"),
            BrowserPublicKeyPath = Path.Combine(browser, "public_key.pem"),
        };
    }

    public void EnsureDirectories()
    {
        Directory.CreateDirectory(RootDir);
        Directory.CreateDirectory(ContentDir);
        Directory.CreateDirectory(ContractsDir);
        Directory.CreateDirectory(DdnsDir);
        Directory.CreateDirectory(VouchersDir);
    }
}
