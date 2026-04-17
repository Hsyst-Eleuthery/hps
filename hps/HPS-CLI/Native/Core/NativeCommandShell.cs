using System.Text;
using System.Text.Json;
using System.Globalization;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.WebSockets;
using Hps.Cli.Native.Display;
using Hps.Cli.Native.Net;
using Hps.Cli.Native.Pow;
using Hps.Cli.Native.Socket;
using Hps.Cli.Native.Storage;

namespace Hps.Cli.Native.Core;

public sealed partial class NativeCommandShell
{
    private readonly ICliDisplay _display;
    private readonly NativeClientService _service;
    private readonly NativeContext _ctx;
    private readonly HpsHttpClient _http;
    private readonly Dictionary<string, string> _lastVoucherIssueContractById = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _lastVoucherAuditOrder = [];
    private bool _walletSignatureMonitorEnabled;
    private bool _walletSignatureAutoEnabled;
    private CancellationTokenSource? _walletSignatureMonitorCts;
    private Task? _walletSignatureMonitorTask;
    private bool _walletAutoMintEnabled;
    private CancellationTokenSource? _walletAutoMintCts;
    private Task? _walletAutoMintTask;
    private bool _walletFineAutoEnabled;
    private bool _walletFinePromiseEnabled;
    private int _signatureMonitorWorkerRunning;
    private readonly Dictionary<string, (string SessionId, double Duration, DateTimeOffset Start)> _activeLiveSessions = new(StringComparer.OrdinalIgnoreCase);

    public NativeCommandShell(ICliDisplay display, NativeClientService service, NativeContext ctx, HpsHttpClient http)
    {
        _display = display;
        _service = service;
        _ctx = ctx;
        _http = http;
    }

    public async Task<int> RunInteractiveAsync(CancellationToken ct)
    {
        PrintHelp();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var promptServer = _service.GetCurrentServer();
                var input = _display.GetInput($"\n[hps:{promptServer}]> ").Trim();
                if (string.IsNullOrWhiteSpace(input))
                {
                    continue;
                }
                var args = SplitArgs(input);
                var code = await RunCommandAsync(args, ct).ConfigureAwait(false);
                if (code == int.MinValue)
                {
                    return 0;
                }
            }
            return 130;
        }
        finally
        {
            StopSignatureMonitorLoop();
            StopAutoMintLoop();
            HpsRealtimeSession.ClearSharedSessionAsync().GetAwaiter().GetResult();
        }
    }

    public async Task<int> RunCommandAsync(string[] args, CancellationToken ct)
    {
        if (args.Length == 0)
        {
            return 0;
        }
        var full = string.Join(' ', args);
        int code;
        try
        {
            code = await RunCommandCoreAsync(args, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _display.PrintWarning("operacao cancelada");
            code = 130;
        }
        catch (Exception ex)
        {
            _display.PrintError(FormatCommandError(ex));
            code = 1;
        }
        if (code != int.MinValue)
        {
            _service.AddHistory(full, code == 0, code == 0 ? "ok" : $"code={code}");
        }
        return code;
    }

    public Task<int> RunCommandLineAsync(string commandLine, CancellationToken ct)
    {
        var args = SplitArgs(commandLine ?? string.Empty);
        return RunCommandAsync(args, ct);
    }

    private async Task<int> RunCommandCoreAsync(string[] args, CancellationToken ct)
    {
        var cmd = args[0].ToLowerInvariant();
        switch (cmd)
        {
            case "help":
                PrintHelp();
                return 0;
            case "clear":
                Console.Clear();
                return 0;
            case "exit":
            case "quit":
                return int.MinValue;
            case "keys":
                return RunKeys(args.Skip(1).ToArray());
            case "servers":
                return RunServers(args.Skip(1).ToArray());
            case "login":
                return await RunLogin(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "logout":
                return RunLogout();
            case "use":
                return RunUse(args.Skip(1).ToArray());
            case "history":
                return RunHistory(args.Skip(1).ToArray());
            case "stats":
                return RunStats();
            case "state":
                return RunState();
            case "health":
                return await RunHealth(ct).ConfigureAwait(false);
            case "server-info":
                return await RunServerInfo(ct).ConfigureAwait(false);
            case "economy":
                return await RunEconomy(ct).ConfigureAwait(false);
            case "pow":
                return await RunPow(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "resolve":
            case "dns-res":
                return await RunResolve(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "get":
                return await RunGet(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "download":
                return await RunDownload(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "search":
                return await RunSearch(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "whoami":
                return RunWhoAmI(args.Skip(1).ToArray());
            case "upload":
                return await RunUpload(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "dns-reg":
                return await RunDnsRegister(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "contract":
            case "contracts":
                return await RunContract(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "voucher":
            case "vouchers":
                return await RunVoucher(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "exchange":
                return await RunExchange(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "dkvhps":
                return RunDkvhps(args.Skip(1).ToArray());
            case "network":
                return await RunNetwork(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "security":
                return await RunSecurity(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "report":
                return await RunReport(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "actions":
            case "hps-actions":
                return await RunActions(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "messages":
            case "message":
                return await RunMessages(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "wallet":
                return await RunWallet(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            case "sync":
                return await RunSync(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
            default:
                _display.PrintError($"comando desconhecido: {cmd}");
                return 2;
        }
    }

    private int RunKeys(string[] args)
    {
        var action = args.FirstOrDefault()?.ToLowerInvariant() ?? "status";
        switch (action)
        {
            case "generate":
                return RunKeys(args is { Length: > 1 } ? ["init", args[1]] : ["init"]);
            case "status":
            {
                var user = args.Length >= 2 ? args[1] : _service.CurrentUser;
                var hasUserMaterial = !string.IsNullOrWhiteSpace(user) && _ctx.KeyManager.UserKeyMaterialExists(user);
                _display.PrintInfo($"crypto_dir={_ctx.Paths.RootDir}");
                _display.PrintInfo($"any_key_material={_ctx.KeyManager.AnyUserKeyMaterialExists()}");
                _display.PrintInfo($"user={user}");
                _display.PrintInfo($"user_key_material={hasUserMaterial}");
                _display.PrintInfo($"unlocked={_service.IsCryptoUnlocked}");
                return 0;
            }
            case "init":
            {
                var user = args.Length >= 2 ? args[1] : _service.CurrentUser;
                if (string.IsNullOrWhiteSpace(user))
                {
                    _display.PrintError("uso: keys init <username>");
                    return 2;
                }
                var pass1 = _display.GetInput("Senha da chave: ", password: true);
                var pass2 = _display.GetInput("Confirmar senha da chave: ", password: true);
                if (pass1 != pass2)
                {
                    _display.PrintError("senhas nao conferem");
                    return 3;
                }
                try
                {
                    _service.UnlockCrypto(user, pass1, createIfMissing: true);
                    _display.PrintSuccess("cofre criptografico inicializado/desbloqueado");
                    return 0;
                }
                catch (Exception ex)
                {
                    _display.PrintError(ex.Message);
                    return 4;
                }
            }
            case "unlock":
            {
                var user = args.Length >= 2 ? args[1] : _service.CurrentUser;
                if (string.IsNullOrWhiteSpace(user))
                {
                    _display.PrintError("uso: keys unlock <username>");
                    return 2;
                }
                var pass = _display.GetInput("Senha da chave: ", password: true);
                try
                {
                    _service.UnlockCrypto(user, pass, createIfMissing: false);
                    _display.PrintSuccess("cofre criptografico desbloqueado");
                    return 0;
                }
                catch (Exception ex)
                {
                    _display.PrintError(ex.Message);
                    return 4;
                }
            }
            case "lock":
                _ctx.KeyManager.Lock();
                _display.PrintSuccess("cofre criptografico bloqueado");
                return 0;
            case "export-public":
                Console.WriteLine(_ctx.KeyManager.ExportPublicKeyBase64());
                return 0;
            case "show":
            {
                var b64 = _ctx.KeyManager.ExportPublicKeyBase64();
                try
                {
                    Console.WriteLine(Encoding.UTF8.GetString(Convert.FromBase64String(b64)));
                }
                catch
                {
                    Console.WriteLine(b64);
                }
                return 0;
            }
            case "export":
            {
                var user = _service.CurrentUser;
                var path = args.Length >= 2 ? args[1] : string.Empty;
                if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(path))
                {
                    _display.PrintError("uso: keys export <file_path>");
                    return 2;
                }
                if (!_service.IsCryptoUnlocked || !string.Equals(_ctx.KeyManager.ActiveUsername, user, StringComparison.OrdinalIgnoreCase))
                {
                    var pass = _display.GetInput("Senha da chave: ", password: true);
                    try
                    {
                        _service.UnlockCrypto(user, pass, createIfMissing: false);
                    }
                    catch (Exception ex)
                    {
                        _display.PrintError(ex.Message);
                        return 4;
                    }
                }
                try
                {
                    var pem = _ctx.KeyManager.ExportLoginPrivateKeyPem();
                    File.WriteAllText(path, pem, Encoding.UTF8);
                    _display.PrintSuccess("chave privada exportada (PEM)");
                    return 0;
                }
                catch (Exception ex)
                {
                    _display.PrintError(ex.Message);
                    return 4;
                }
            }
            case "import":
            {
                var user = _service.CurrentUser;
                var path = args.Length >= 2 ? args[1] : string.Empty;
                if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(path))
                {
                    _display.PrintError("uso: keys import <file_path>");
                    return 2;
                }
                if (!File.Exists(path))
                {
                    _display.PrintError("arquivo nao encontrado");
                    return 3;
                }
                var pass = _display.GetInput("Senha da chave para validar importacao: ", password: true);
                try
                {
                    var pem = File.ReadAllText(path, Encoding.UTF8);
                    _ctx.KeyManager.ImportLegacyPrivateKeyPem(user, pass, pem);
                    _service.UnlockCrypto(user, pass, createIfMissing: false);
                    _display.PrintSuccess("chave privada importada (PEM)");
                    return 0;
                }
                catch (Exception ex)
                {
                    _display.PrintError(ex.Message);
                    return 4;
                }
            }
            case "export-bundle":
            {
                var user = args.Length >= 2 ? args[1] : _service.CurrentUser;
                var path = args.Length >= 3 ? args[2] : string.Empty;
                if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(path))
                {
                    _display.PrintError("uso: keys export-bundle <username> <output_path>");
                    return 2;
                }
                try
                {
                    _ctx.KeyManager.ExportEncryptedKeyBundle(user, path);
                    _display.PrintSuccess("bundle de chaves exportado");
                    return 0;
                }
                catch (Exception ex)
                {
                    _display.PrintError(ex.Message);
                    return 4;
                }
            }
            case "import-bundle":
            {
                var user = args.Length >= 2 ? args[1] : _service.CurrentUser;
                var path = args.Length >= 3 ? args[2] : string.Empty;
                if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(path))
                {
                    _display.PrintError("uso: keys import-bundle <username> <input_path>");
                    return 2;
                }
                var pass = _display.GetInput("Senha da chave para validar bundle: ", password: true);
                try
                {
                    _ctx.KeyManager.ImportEncryptedKeyBundle(user, path, pass);
                    _service.UnlockCrypto(user, pass, createIfMissing: false);
                    _display.PrintSuccess("bundle importado e cofre desbloqueado");
                    return 0;
                }
                catch (Exception ex)
                {
                    _display.PrintError(ex.Message);
                    return 4;
                }
            }
            default:
                _display.PrintError("uso: keys [status [username]|init <username>|generate [username]|unlock <username>|lock|show|export-public|export <file_path>|import <file_path>|export-bundle <username> <output_path>|import-bundle <username> <input_path>]");
                return 2;
        }
    }

    private int RunServers(string[] args)
    {
        if (args.Length == 0)
        {
            var list = _service.ListKnownServers();
            if (list.Count == 0)
            {
                _display.PrintWarning("nenhum servidor salvo");
                return 0;
            }
            var current = _service.GetCurrentServer();
            for (var i = 0; i < list.Count; i++)
            {
                var status = string.Equals(list[i], current, StringComparison.OrdinalIgnoreCase) ? "[conectado]" : "[disponivel]";
                Console.WriteLine($"{i + 1}. {list[i]} {status}");
            }

            var choice = _display.GetInput("[A]dd, [R]emove, [C]onnect, [Enter] para voltar: ").Trim().ToLowerInvariant();
            if (choice == "a")
            {
                var server = _display.GetInput("Novo servidor: ").Trim();
                if (!string.IsNullOrWhiteSpace(server))
                {
                    _service.AddKnownServer(server);
                    _display.PrintSuccess("servidor salvo");
                }
                return 0;
            }
            if (choice == "r")
            {
                var target = _display.GetInput("Indice/host para remover: ").Trim();
                if (!string.IsNullOrWhiteSpace(target))
                {
                    if (_service.RemoveKnownServer(target))
                    {
                        _display.PrintSuccess("servidor removido");
                    }
                    else
                    {
                        _display.PrintError("servidor nao encontrado");
                    }
                }
                return 0;
            }
            if (choice == "c")
            {
                var target = _display.GetInput("Indice/host para conectar: ").Trim();
                if (!string.IsNullOrWhiteSpace(target))
                {
                    if (_service.SetCurrentServer(target))
                    {
                        _display.PrintSuccess("servidor atual atualizado");
                    }
                    else
                    {
                        _display.PrintError("servidor nao encontrado");
                    }
                }
                return 0;
            }
            return 0;
        }

        var action = args.FirstOrDefault()?.ToLowerInvariant() ?? "list";
        if (action == "list")
        {
            var list = _service.ListKnownServers();
            if (list.Count == 0)
            {
                _display.PrintWarning("nenhum servidor salvo");
                return 0;
            }
            for (var i = 0; i < list.Count; i++)
            {
                Console.WriteLine($"{i + 1}. {list[i]}");
            }
            return 0;
        }
        if (action == "add")
        {
            var server = args.Skip(1).FirstOrDefault() ?? "";
            if (string.IsNullOrWhiteSpace(server))
            {
                _display.PrintError("uso: servers add <host:porta|url>");
                return 2;
            }
            _service.AddKnownServer(server);
            _display.PrintSuccess("servidor salvo");
            return 0;
        }
        if (action == "remove")
        {
            var target = args.Skip(1).FirstOrDefault() ?? "";
            if (string.IsNullOrWhiteSpace(target))
            {
                _display.PrintError("uso: servers remove <indice|host:porta|url>");
                return 2;
            }
            if (!_service.RemoveKnownServer(target))
            {
                _display.PrintError("servidor nao encontrado");
                return 3;
            }
            _display.PrintSuccess("servidor removido");
            return 0;
        }
        if (action == "connect")
        {
            var target = args.Skip(1).FirstOrDefault() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(target))
            {
                _display.PrintError("uso: servers connect <indice|host:porta|url>");
                return 2;
            }
            if (!_service.SetCurrentServer(target))
            {
                _display.PrintError("servidor nao encontrado");
                return 3;
            }
            _display.PrintSuccess("servidor atual atualizado");
            return 0;
        }
        _display.PrintError("uso: servers [list|add|remove|connect]");
        return 2;
    }

    private int RunUse(string[] args)
    {
        var target = args.FirstOrDefault() ?? "";
        if (string.IsNullOrWhiteSpace(target))
        {
            _display.PrintError("uso: use <indice|host:porta|url>");
            return 2;
        }
        var ok = _service.SetCurrentServer(target);
        if (!ok)
        {
            _display.PrintError("servidor nao encontrado");
            return 3;
        }
        _display.PrintSuccess("servidor atual atualizado");
        return 0;
    }

    private int RunState()
    {
        var s = _ctx.StateStore.Load();
        _display.PrintInfo($"state={_ctx.Paths.StateFile}");
        _display.PrintInfo($"current_server={s.CurrentServer}");
        _display.PrintInfo($"current_user={s.CurrentUser}");
        _display.PrintInfo($"known_servers={s.KnownServers.Count(x => x.IsActive)}");
        _display.PrintInfo($"content_cache={s.ContentCache.Count}");
        _display.PrintInfo($"contracts_cache={s.ContractsCache.Count}");
        _display.PrintInfo($"voucher_cache={s.VoucherCache.Count}");
        return 0;
    }

    private async Task<int> RunHealth(CancellationToken ct)
    {
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var res = await _http.GetHealthAsync(server, ct).ConfigureAwait(false);
        if (!res.Ok)
        {
            _display.PrintError(res.Error);
            return 4;
        }
        Console.WriteLine(res.RawJson);
        return 0;
    }

    private async Task<int> RunServerInfo(CancellationToken ct)
    {
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var res = await _http.GetServerInfoAsync(server, ct).ConfigureAwait(false);
        if (!res.Ok)
        {
            _display.PrintError(res.Error);
            return 4;
        }
        Console.WriteLine(res.RawJson);
        return 0;
    }

    private async Task<int> RunEconomy(CancellationToken ct)
    {
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var res = await _http.GetEconomyReportAsync(server, ct).ConfigureAwait(false);
        if (!res.Ok)
        {
            _display.PrintError(res.Error);
            return 4;
        }
        Console.WriteLine(res.RawJson);
        return 0;
    }

    private async Task<int> RunResolve(string[] args, CancellationToken ct)
    {
        var domain = args.FirstOrDefault() ?? "";
        if (string.IsNullOrWhiteSpace(domain))
        {
            _display.PrintError("uso: resolve <dominio>");
            return 2;
        }
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var res = await _http.ResolveDomainAsync(server, domain, ct).ConfigureAwait(false);
        if (!res.Ok)
        {
            _display.PrintError(res.Error);
            return 4;
        }
        _display.PrintSuccess($"{domain} -> {res.ContentHash}");
        PersistResolvedDns(res);
        _service.IncrementStat("dns_resolved");
        return 0;
    }

    private async Task<int> RunGet(string[] args, CancellationToken ct)
    {
        var target = args.FirstOrDefault() ?? "";
        if (string.IsNullOrWhiteSpace(target))
        {
            _display.PrintError("uso: get <dominio|hash>");
            return 2;
        }
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }

        var hash = target;
        if (!LooksLikeHash(target))
        {
            var dns = await _http.ResolveDomainAsync(server, target, ct).ConfigureAwait(false);
            if (!dns.Ok)
            {
                _display.PrintError(dns.Error);
                return 4;
            }
            hash = dns.ContentHash;
            PersistResolvedDns(dns);
        }

        var content = await _http.FetchContentAsync(server, hash, ct).ConfigureAwait(false);
        if (!content.Ok)
        {
            _display.PrintError(content.Error);
            return 5;
        }
        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nÃ£o desbloqueado. use: keys unlock <username>");
            return 6;
        }

        _service.SaveContentToStorage(hash, content.Data, new ContentCacheRecord
        {
            ContentHash = hash,
            MimeType = content.Mime,
            LastAccessed = DateTimeOffset.UtcNow,
            Title = target,
            Description = target
        });
        _service.IncrementStat("content_downloaded");
        _service.IncrementStat("data_received_bytes", content.Data.LongLength);
        _display.PrintSuccess($"conteudo salvo hash={hash} bytes={content.Data.Length} mime={content.Mime}");
        return 0;
    }

    private async Task<int> RunDownload(string[] args, CancellationToken ct)
    {
        if (args.Length < 1)
        {
            _display.PrintError("uso: download <hash_or_url> [--output PATH]");
            return 2;
        }

        var target = args[0].Trim();
        string? outputPath = null;
        var i = 1;
        while (i < args.Length)
        {
            if (args[i].Equals("--output", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                outputPath = args[i + 1];
                i += 2;
                continue;
            }
            _display.PrintError($"argumento desconhecido: {args[i]}");
            return 2;
        }

        if (target.StartsWith("hps://", StringComparison.OrdinalIgnoreCase))
        {
            if (target.Equals("hps://rede", StringComparison.OrdinalIgnoreCase))
            {
                return await RunNetwork([], ct).ConfigureAwait(false);
            }
            if (target.StartsWith("hps://dns:", StringComparison.OrdinalIgnoreCase))
            {
                var domain = target["hps://dns:".Length..];
                return await RunResolve([domain], ct).ConfigureAwait(false);
            }
            target = target["hps://".Length..];
        }

        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }

        var hash = target;
        if (!LooksLikeHash(target))
        {
            var dns = await _http.ResolveDomainAsync(server, target, ct).ConfigureAwait(false);
            if (!dns.Ok)
            {
                _display.PrintError(dns.Error);
                return 4;
            }
            hash = dns.ContentHash;
            PersistResolvedDns(dns);
        }

        var content = await _http.FetchContentAsync(server, hash, ct).ConfigureAwait(false);
        if (!content.Ok)
        {
            _display.PrintError(content.Error);
            return 5;
        }

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            outputPath = GuessDownloadPath(hash, content.Mime, content.Headers);
        }
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            outputPath = hash + ".dat";
        }

        var fullPath = Path.GetFullPath(outputPath);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }
        await File.WriteAllBytesAsync(fullPath, content.Data, ct).ConfigureAwait(false);
        _service.IncrementStat("content_downloaded");
        _service.IncrementStat("data_received_bytes", content.Data.LongLength);
        _display.PrintSuccess($"conteudo salvo em: {fullPath}");
        return 0;
    }

    private async Task<int> RunSearch(string[] args, CancellationToken ct)
    {
        if (args.Length < 1)
        {
            _display.PrintError("uso: search <termo> [--type TYPE] [--sort ORDER]");
            return 2;
        }

        var query = args[0].Trim();
        var contentType = "all";
        var sortBy = "reputation";
        var i = 1;
        while (i < args.Length)
        {
            if (args[i].Equals("--type", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                contentType = args[i + 1].Trim();
                i += 2;
                continue;
            }
            if (args[i].Equals("--sort", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                sortBy = args[i + 1].Trim();
                i += 2;
                continue;
            }

            _display.PrintError($"argumento desconhecido: {args[i]}");
            return 2;
        }

        var user = _service.CurrentUser;
        if (string.IsNullOrWhiteSpace(user))
        {
            _display.PrintError("usuario nao definido. use 'whoami <username>'");
            return 3;
        }
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 4;
        }
        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
            return 6;
        }

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var payload = await session.EmitAndWaitAsync(
            "search_content",
            new
            {
                query,
                limit = 50,
                content_type = contentType.Equals("all", StringComparison.OrdinalIgnoreCase) ? string.Empty : contentType,
                sort_by = sortBy
            },
            "search_results",
            TimeSpan.FromSeconds(45),
            ct).ConfigureAwait(false);

        if (payload.TryGetProperty("error", out var err) && !string.IsNullOrWhiteSpace(err.GetString()))
        {
            _display.PrintError(err.GetString()!);
            return 5;
        }

        if (!payload.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
        {
            _display.PrintInfo("nenhum resultado");
            return 0;
        }

        var found = false;
        foreach (var item in results.EnumerateArray())
        {
            found = true;
            var hash = item.TryGetProperty("content_hash", out var h) ? h.GetString() ?? "" : "";
            var title = item.TryGetProperty("title", out var t) ? t.GetString() ?? "" : "";
            var author = item.TryGetProperty("username", out var u) ? u.GetString() ?? "" : "";
            var mime = item.TryGetProperty("mime_type", out var m) ? m.GetString() ?? "" : "";
            var reputation = item.TryGetProperty("reputation", out var r) ? r.ToString() : "";
            var verified = item.TryGetProperty("verified", out var v) && v.ValueKind == JsonValueKind.True ? "yes" : "no";
            Console.WriteLine($"{hash}|{title}|{author}|{mime}|{reputation}|verified={verified}");
        }

        if (!found)
        {
            _display.PrintInfo("nenhum resultado");
            return 0;
        }

        _service.IncrementStat("search_runs");
        return 0;
    }

    private async Task<int> RunSync(string[] args, CancellationToken ct)
    {
        if (args.Length > 0 && args[0].Equals("push-content", StringComparison.OrdinalIgnoreCase))
        {
            return await RunSyncPushContent(args.Skip(1).ToArray(), ct).ConfigureAwait(false);
        }
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var user = _service.CurrentUser;
        if (string.IsNullOrWhiteSpace(user))
        {
            _display.PrintError("usuario nao definido. use 'whoami <username>'");
            return 4;
        }
        var limit = 200;
        if (args.Length > 0 && int.TryParse(args[0], out var p) && p > 0)
        {
            limit = p;
        }
        var res = await _http.SyncAllAsync(server, limit, ct).ConfigureAwait(false);
        if (!res.Ok)
        {
            _display.PrintError(res.Error);
            return 4;
        }
        _service.ApplySyncSnapshot(res.Snapshot);
        _service.IncrementStat("sync_runs");
        try
        {
            var state = _ctx.StateStore.Load();
            var contentList = state.ContentCache.Values
                .Take(limit)
                .Select(c => new Dictionary<string, object?>
                {
                    ["content_hash"] = c.ContentHash,
                    ["file_name"] = string.IsNullOrWhiteSpace(c.FileName) ? (c.ContentHash + ".dat") : c.FileName,
                    ["file_size"] = c.Size
                })
                .Cast<object>()
                .ToList();
            var dnsList = state.DdnsCache.Values
                .Take(limit)
                .Select(d => new Dictionary<string, object?>
                {
                    ["domain"] = d.Domain,
                    ["ddns_hash"] = d.DdnsHash
                })
                .Cast<object>()
                .ToList();
            var contractList = state.ContractsCache.Values
                .Take(limit)
                .Select(c => new Dictionary<string, object?>
                {
                    ["contract_id"] = c.ContractId,
                    ["content_hash"] = c.ContentHash,
                    ["domain"] = c.Domain
                })
                .Cast<object>()
                .ToList();

            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            await session.EmitAsync("sync_client_files", new { files = contentList }, ct).ConfigureAwait(false);
            await session.EmitAsync("sync_client_dns_files", new { dns_files = dnsList }, ct).ConfigureAwait(false);
            await session.EmitAsync("sync_client_contracts", new { contracts = contractList }, ct).ConfigureAwait(false);

            var walletTask = session.EmitAndWaitAsync("request_hps_wallet", new { }, "hps_wallet_sync", TimeSpan.FromSeconds(30), ct);
            var economyTask = session.EmitAndWaitAsync("request_economy_report", new { }, "economy_report", TimeSpan.FromSeconds(30), ct);
            var networkTask = session.EmitAndWaitAsync("get_network_state", new { }, "network_state", TimeSpan.FromSeconds(30), ct);
            var walletPayload = await walletTask.ConfigureAwait(false);
            _ = await economyTask.ConfigureAwait(false);
            _ = await networkTask.ConfigureAwait(false);
            if (walletPayload.TryGetProperty("vouchers", out var vouchers))
            {
                _service.SaveWalletSync(vouchers);
            }
        }
        catch (Exception ex)
        {
            _display.PrintWarning("sync realtime parcial: " + ex.Message);
        }
        _display.PrintSuccess($"sync ok: content={res.Snapshot.Content.Count} dns={res.Snapshot.Dns.Count} contracts={res.Snapshot.Contracts.Count} users={res.Snapshot.Users.Count}");
        return 0;
    }

    private async Task<int> RunSyncPushContent(string[] args, CancellationToken ct)
    {
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var user = _service.CurrentUser;
        if (string.IsNullOrWhiteSpace(user))
        {
            _display.PrintError("usuario nao definido. use 'whoami <username>'");
            return 4;
        }

        var limit = 100;
        if (args.Length > 0 && int.TryParse(args[0], out var n) && n > 0)
        {
            limit = n;
        }
        var contents = _service.ListContentCache(limit);
        if (contents.Count == 0)
        {
            _display.PrintInfo("nenhum conteudo local para enviar");
            return 0;
        }
        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nÃ£o desbloqueado. use: keys unlock <username>");
            return 6;
        }

        var sent = 0;
        var failed = 0;
        foreach (var rec in contents)
        {
            if (!File.Exists(rec.FilePath))
            {
                continue;
            }
            var local = _service.LoadCachedContent(rec.ContentHash);
            if (local is null)
            {
                continue;
            }
            var bytes = local.Value.Content;
            var sig = _service.SignContent(bytes);
            var mime = string.IsNullOrWhiteSpace(rec.MimeType) ? "application/octet-stream" : rec.MimeType;
            var up = await _http.UploadBytesAsync(
                server,
                user,
                _service.ClientIdentifier,
                _service.PublicKeyBase64(),
                sig,
                rec.FileName,
                bytes,
                mime,
                ct).ConfigureAwait(false);
            if (up.Ok)
            {
                sent++;
            }
            else
            {
                failed++;
            }
        }
        _display.PrintSuccess($"sync push-content concluido: enviados={sent} falhas={failed}");
        return failed == 0 ? 0 : 5;
    }

    private int RunWhoAmI(string[] args)
    {
        if (args.Length > 0)
        {
            var user = args[0].Trim();
            if (string.IsNullOrWhiteSpace(user))
            {
                _display.PrintError("uso: whoami [username]");
                return 2;
            }
            _service.SetCurrentUser(user);
            _display.PrintSuccess($"usuario atual: {user}");
            return 0;
        }
        var current = _service.CurrentUser;
        if (string.IsNullOrWhiteSpace(current))
        {
            _display.PrintWarning("usuario nao definido");
            return 0;
        }
        _display.PrintInfo($"usuario atual: {current}");
        return 0;
    }
    private async Task<int> RunUpload(string[] args, CancellationToken ct)
    {
        if (args.Length < 1)
        {
            _display.PrintError("uso: upload <file_path> [mime]");
            return 2;
        }
        var filePath = args[0];
        if (!File.Exists(filePath))
        {
            _display.PrintError("arquivo nao encontrado");
            return 3;
        }
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 4;
        }
        var user = _service.CurrentUser;
        if (string.IsNullOrWhiteSpace(user))
        {
            _display.PrintError("usuario nao definido. use 'whoami <username>'");
            return 5;
        }
        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
            return 6;
        }

        var bytes = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
        var mime = args.Length > 1 ? args[1] : GuessMime(filePath);
        var title = Path.GetFileName(filePath);
        if (string.IsNullOrWhiteSpace(title))
        {
            title = "upload.bin";
        }
        var description = "uploaded";
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["FILE_NAME"] = title,
            ["FILE_SIZE"] = bytes.LongLength.ToString(),
            ["FILE_HASH"] = hash,
            ["TITLE"] = title,
            ["MIME"] = mime,
            ["DESCRIPTION"] = description,
            ["PUBLIC_KEY"] = _service.PublicKeyBase64()
        };
        var contract = _service.SignContractTemplate(_service.BuildContractTemplate("upload_file", details));
        var fullContent = bytes.Concat(Encoding.UTF8.GetBytes(contract)).ToArray();
        var signatureB64 = Convert.ToBase64String(_service.SignContent(bytes));

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var (nonce, rate) = await session.SolvePowAsync("upload", ct).ConfigureAwait(false);
        var result = await session.EmitAndWaitAsync(
            "publish_content",
            new
            {
                content_hash = hash,
                title,
                description,
                mime_type = mime,
                size = bytes.LongLength,
                signature = signatureB64,
                public_key = _service.PublicKeyBase64(),
                content_b64 = Convert.ToBase64String(fullContent),
                pow_nonce = nonce,
                hashrate_observed = rate
            },
            "publish_result",
            TimeSpan.FromSeconds(120),
            ct).ConfigureAwait(false);

        if (result.TryGetProperty("pending", out var pending) && pending.ValueKind == JsonValueKind.True)
        {
            _display.PrintWarning("upload pendente de confirmacao monetaria no servidor");
            return 0;
        }
        if (!ReadSuccess(result))
        {
            _display.PrintError(ReadError(result));
            return 6;
        }

        _service.SaveContentToStorage(hash, bytes, new ContentCacheRecord
        {
            ContentHash = hash,
            MimeType = mime,
            FileName = title,
            Title = title,
            Description = description
        });
        _service.IncrementStat("content_uploaded");
        _service.IncrementStat("data_sent_bytes", bytes.LongLength);
        _display.PrintSuccess($"upload ok hash={hash}");
        return 0;
    }
    private async Task<int> RunLogin(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            _display.PrintError("uso: login <server> <username> [passphrase]");
            return 2;
        }
        var server = args[0].Trim();
        var username = args[1].Trim();
        if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(username))
        {
            _display.PrintError("uso: login <server> <username> [passphrase]");
            return 2;
        }
        (bool Ok, string RawJson, string Error) health;
        try
        {
            health = await _http.GetHealthAsync(server, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsConnectionException(ex))
        {
            _display.PrintError($"servidor indisponivel em {NormalizeServerForDisplay(server)} ({ex.Message})");
            return 4;
        }
        if (!health.Ok)
        {
            _display.PrintError($"servidor indisponivel em {NormalizeServerForDisplay(server)} ({health.Error})");
            return 4;
        }
        _service.AddKnownServer(server);
        _service.SetCurrentServer(server);
        _service.SetCurrentUser(username);

        if (!_ctx.KeyManager.UserKeyMaterialExists(username))
        {
            _display.PrintError("chaves locais do usuario nao encontradas. use: keys import-bundle <username> <input_path> ou keys init <username>");
            return 3;
        }

        var passphrase = args.Length >= 3 ? args[2] : string.Empty;
        if (!_service.IsCryptoUnlocked || !string.Equals(_ctx.KeyManager.ActiveUsername, username, StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(passphrase))
            {
                passphrase = _display.GetInput("Senha da chave: ", password: true);
            }
            if (string.IsNullOrWhiteSpace(passphrase))
            {
                _display.PrintError("senha da chave obrigatoria para autenticar");
                return 3;
            }
            try
            {
                _service.UnlockCrypto(username, passphrase, createIfMissing: false);
            }
            catch (Exception ex)
            {
                _display.PrintError("falha ao desbloquear cofre: " + ex.Message);
                return 3;
            }
        }

        try
        {
            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, username, _service, _ctx, _display, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _display.PrintError("falha na autenticacao remota: " + FormatCommandError(ex));
            return 5;
        }

        _service.IncrementStat("login_count");
        _display.PrintSuccess($"autenticado como {username} em {_service.GetCurrentServer()} (PoW de login concluido)");
        return 0;
    }

    private string FormatCommandError(Exception ex)
    {
        var server = NormalizeServerForDisplay(_service.GetCurrentServer());
        if (IsConnectionException(ex))
        {
            return $"falha de conexao com servidor {server}: {ex.Message}";
        }
        return ex.Message;
    }

    private static string NormalizeServerForDisplay(string? server)
    {
        if (string.IsNullOrWhiteSpace(server))
        {
            return "<nao definido>";
        }
        if (server.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            server.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return server;
        }
        return "http://" + server;
    }

    private static bool IsConnectionException(Exception ex)
    {
        return ex is HttpRequestException
            or SocketException
            or WebSocketException
            or TimeoutException
            || ex.InnerException is HttpRequestException
            or SocketException
            or WebSocketException
            or TimeoutException;
    }

    private int RunLogout()
    {
        StopAutoMintLoop();
        HpsRealtimeSession.ClearSharedSessionAsync().GetAwaiter().GetResult();
        _service.Logout();
        _display.PrintSuccess("logout local concluido");
        return 0;
    }

    private int RunStats()
    {
        var stats = _service.GetStats();
        if (stats.Count == 0)
        {
            _display.PrintInfo("sem estatisticas");
            return 0;
        }
        foreach (var kv in stats.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            Console.WriteLine($"{kv.Key}: {kv.Value}");
        }
        return 0;
    }

    private async Task<int> RunContract(string[] args, CancellationToken ct)
    {
        if (args.Length < 1)
        {
            _display.PrintError("uso: contract search [--type all|hash|domain|user|type] [--value v] [--limit n] | contract get <contract_id> | contract analyze <contract_id> | contract sign <action> <k=v,...> [out_file] | contract verify <file_or_id> [pubkey] | contract pending | contract accept <transfer_id> | contract reject <transfer_id> | contract renounce <transfer_id> | contract fix | contract certify <contract_id> | contract certify-missing <target> [--type domain|content] | contract invalidate <contract_id> | contract sync");
            return 2;
        }
        var action = args[0].ToLowerInvariant();
        if (action is "search" or "list")
        {
            var searchType = "all";
            var searchValue = string.Empty;
            var limit = 50;
            for (var i = 1; i < args.Length; i++)
            {
                if (args[i] == "--type" && i + 1 < args.Length)
                {
                    searchType = args[++i];
                    continue;
                }
                if (args[i] == "--value" && i + 1 < args.Length)
                {
                    searchValue = args[++i];
                    continue;
                }
                if (args[i] == "--limit" && i + 1 < args.Length)
                {
                    if (!int.TryParse(args[++i], out limit) || limit <= 0)
                    {
                        _display.PrintError("limite invalido");
                        return 2;
                    }
                    continue;
                }
            }
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }
            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            var result = await session.EmitAndWaitAsync(
                "search_contracts",
                new { search_type = searchType, search_value = searchValue, limit, offset = 0 },
                "contracts_results",
                TimeSpan.FromSeconds(35),
                ct).ConfigureAwait(false);
            if (!ReadSuccess(result))
            {
                _display.PrintError(ReadError(result));
                return 5;
            }
            if (!result.TryGetProperty("contracts", out var contracts) || contracts.ValueKind != JsonValueKind.Array)
            {
                _display.PrintInfo("nenhum contrato encontrado");
                return 0;
            }
            var count = 0;
            foreach (var contract in contracts.EnumerateArray())
            {
                count++;
                var listedContractId = contract.TryGetProperty("contract_id", out var contractIdElement) ? contractIdElement.GetString() ?? string.Empty : string.Empty;
                var actionType = contract.TryGetProperty("action_type", out var actionTypeElement) ? actionTypeElement.GetString() ?? string.Empty : string.Empty;
                var target = contract.TryGetProperty("domain", out var domainElement) ? domainElement.GetString() ?? string.Empty : string.Empty;
                if (string.IsNullOrWhiteSpace(target))
                {
                    target = contract.TryGetProperty("content_hash", out var contentHashElement) ? contentHashElement.GetString() ?? string.Empty : string.Empty;
                }
                var owner = contract.TryGetProperty("username", out var ownerElement) ? ownerElement.GetString() ?? string.Empty : string.Empty;
                var integrity = contract.TryGetProperty("integrity_ok", out var integrityElement) && integrityElement.ValueKind == JsonValueKind.True;
                Console.WriteLine($"{listedContractId} | action={actionType} | target={target} | user={owner} | integrity={(integrity ? "ok" : "fail")}");
            }
            if (count == 0)
            {
                _display.PrintInfo("nenhum contrato encontrado");
            }
            return 0;
        }
        if (action == "analyze")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: contract analyze <contract_id>");
                return 2;
            }
            var analyzeContractId = args[1].Trim();
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }
            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            var result = await session.EmitAndWaitAsync(
                "get_contract",
                new { contract_id = analyzeContractId },
                "contract_details",
                TimeSpan.FromSeconds(25),
                ct).ConfigureAwait(false);
            if (!ReadSuccess(result))
            {
                _display.PrintError(ReadError(result));
                return 5;
            }
            var contract = result.TryGetProperty("contract", out var contractElement) && contractElement.ValueKind == JsonValueKind.Object
                ? contractElement
                : default;
            if (contract.ValueKind != JsonValueKind.Object)
            {
                _display.PrintError("detalhes de contrato ausentes");
                return 5;
            }
            var content = contract.TryGetProperty("contract_content", out var contentElement) ? contentElement.GetString() ?? string.Empty : string.Empty;
            var details = _service.ExtractContractDetailsMap(content);
            _display.PrintSection("Contract Analyzer");
            _display.PrintInfo($"id={analyzeContractId}");
            _display.PrintInfo($"action={details.GetValueOrDefault("ACTION", "")}");
            _display.PrintInfo($"user={details.GetValueOrDefault("USER", "")}");
            _display.PrintInfo($"integrity={(contract.TryGetProperty("integrity_ok", out var integrityElement) && integrityElement.ValueKind == JsonValueKind.True ? "ok" : "fail")}");
            _display.PrintInfo($"verified={(contract.TryGetProperty("verified", out var verifiedElement) && verifiedElement.ValueKind == JsonValueKind.True ? "yes" : "no")}");
            if (contract.TryGetProperty("violation_reason", out var violationElement))
            {
                var violation = violationElement.GetString() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(violation))
                {
                    _display.PrintWarning("violacao: " + violation);
                }
            }
            foreach (var kv in details.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine($"{kv.Key}={kv.Value}");
            }
            return 0;
        }
        if (action == "fix")
        {
            _display.PrintInfo("executando verificacao de pendencias contratuais...");
            await RunContract(["pending"], ct).ConfigureAwait(false);
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(currentServer))
            {
                await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
                var result = await session.EmitAndWaitAsync(
                    "search_contracts",
                    new { search_type = "all", search_value = "", limit = 200, offset = 0 },
                    "contracts_results",
                    TimeSpan.FromSeconds(35),
                    ct).ConfigureAwait(false);
                if (ReadSuccess(result) &&
                    result.TryGetProperty("contracts", out var contracts) &&
                    contracts.ValueKind == JsonValueKind.Array)
                {
                    var issues = new List<string>();
                    foreach (var contract in contracts.EnumerateArray())
                    {
                        var reason = contract.TryGetProperty("violation_reason", out var reasonElement) ? reasonElement.GetString() ?? string.Empty : string.Empty;
                        if (string.IsNullOrWhiteSpace(reason))
                        {
                            continue;
                        }
                        var target = contract.TryGetProperty("domain", out var domainElement) ? domainElement.GetString() ?? string.Empty : string.Empty;
                        var targetType = "domain";
                        if (string.IsNullOrWhiteSpace(target))
                        {
                            target = contract.TryGetProperty("content_hash", out var contentHashElement) ? contentHashElement.GetString() ?? string.Empty : string.Empty;
                            targetType = "content";
                        }
                        if (string.IsNullOrWhiteSpace(target))
                        {
                            continue;
                        }
                        issues.Add($"{targetType}:{target}:{reason}");
                    }
                    if (issues.Count == 0)
                    {
                        _display.PrintInfo("nenhuma violacao contratual ativa encontrada");
                    }
                    else
                    {
                        foreach (var issue in issues.Distinct(StringComparer.OrdinalIgnoreCase))
                        {
                            var parts = issue.Split(':', 3);
                            if (parts.Length < 3)
                            {
                                continue;
                            }
                            var targetType = parts[0];
                            var target = parts[1];
                            var reason = parts[2];
                            if (string.Equals(reason, "missing_contract", StringComparison.OrdinalIgnoreCase))
                            {
                                _display.PrintInfo($"sugestao: contract certify-missing {target} --type {targetType}");
                            }
                            else
                            {
                                _display.PrintWarning($"violacao {reason} em {targetType}:{target}");
                            }
                        }
                    }
                }
            }
            _display.PrintInfo("se houver contrato ausente, use: contract certify-missing <target> [--type domain|content]");
            return 0;
        }
        if (action == "certify")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: contract certify <contract_id>");
                return 2;
            }
            var certifyContractId = args[1].Trim();
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }
            if (!_service.IsCryptoUnlocked)
            {
                _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
                return 6;
            }
            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            var (nonce, rate) = await session.SolvePowAsync("contract_certify", ct).ConfigureAwait(false);
            var contractText = _service.SignContractTemplate(_service.BuildContractTemplate("certify_contract", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["CONTRACT_ID"] = certifyContractId
            }));
            var result = await session.EmitAndWaitAsync(
                "certify_contract",
                new
                {
                    contract_id = certifyContractId,
                    contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contractText)),
                    pow_nonce = nonce,
                    hashrate_observed = rate
                },
                "certify_contract_ack",
                TimeSpan.FromSeconds(90),
                ct).ConfigureAwait(false);
            if (!ReadSuccess(result))
            {
                _display.PrintError(ReadError(result));
                return 5;
            }
            _display.PrintSuccess("contrato certificado");
            return 0;
        }
        if (action == "certify-missing")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: contract certify-missing <target> [--type domain|content]");
                return 2;
            }
            var targetId = args[1].Trim();
            var targetType = string.Empty;
            for (var i = 2; i < args.Length; i++)
            {
                if (args[i] == "--type" && i + 1 < args.Length)
                {
                    targetType = args[++i].Trim().ToLowerInvariant();
                }
            }
            if (string.IsNullOrWhiteSpace(targetType))
            {
                targetType = IsValidDomain(targetId) ? "domain" : "content";
            }
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }
            if (!_service.IsCryptoUnlocked)
            {
                _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
                return 6;
            }
            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            var (nonce, rate) = await session.SolvePowAsync("contract_certify", ct).ConfigureAwait(false);
            var contractText = _service.SignContractTemplate(_service.BuildContractTemplate("certify_missing_contract", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["TARGET_TYPE"] = targetType,
                ["TARGET_ID"] = targetId
            }));
            var result = await session.EmitAndWaitAsync(
                "certify_missing_contract",
                new
                {
                    target_type = targetType,
                    target_id = targetId,
                    contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contractText)),
                    pow_nonce = nonce,
                    hashrate_observed = rate
                },
                "certify_missing_contract_ack",
                TimeSpan.FromSeconds(90),
                ct).ConfigureAwait(false);
            if (!ReadSuccess(result))
            {
                _display.PrintError(ReadError(result));
                return 5;
            }
            _display.PrintSuccess("contrato ausente certificado");
            return 0;
        }
        if (action == "invalidate")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: contract invalidate <contract_id>");
                return 2;
            }
            var invalidateContractId = args[1].Trim();
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }
            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            var (nonce, rate) = await session.SolvePowAsync("contract_reset", ct).ConfigureAwait(false);
            var result = await session.EmitAndWaitAsync(
                "invalidate_contract",
                new { contract_id = invalidateContractId, pow_nonce = nonce, hashrate_observed = rate },
                "invalidate_contract_ack",
                TimeSpan.FromSeconds(90),
                ct).ConfigureAwait(false);
            if (!ReadSuccess(result))
            {
                _display.PrintError(ReadError(result));
                return 5;
            }
            _display.PrintSuccess("contrato invalidado");
            return 0;
        }
        if (action == "sync")
        {
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }
            var contracts = _service.ListContracts(5000)
                .Where(x => !string.IsNullOrWhiteSpace(x.ContractId))
                .Select(x => new Dictionary<string, object?> { ["contract_id"] = x.ContractId })
                .Cast<object>()
                .ToList();
            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            await session.EmitAsync(
                "sync_client_contracts",
                new { contracts },
                ct).ConfigureAwait(false);
            _display.PrintSuccess($"contract sync enviado ({contracts.Count} ids)");
            return 0;
        }
        if (action == "sign")
        {
            if (args.Length < 3)
            {
                _display.PrintError("uso: contract sign <action> <k=v,...> [out_file]");
                return 2;
            }
            var actionType = args[1];
            var details = ParseKeyValueCsv(args[2]);
            var tpl = _service.BuildContractTemplate(actionType, details);
            if (!_service.IsCryptoUnlocked)
            {
                _display.PrintError("cofre nÃ£o desbloqueado. use: keys unlock <username>");
                return 5;
            }
            var signed = _service.SignContractTemplate(tpl);
            if (args.Length >= 4)
            {
                File.WriteAllText(args[3], signed);
                _display.PrintSuccess($"contrato assinado salvo em {args[3]}");
            }
            else
            {
                Console.WriteLine(signed);
            }
            return 0;
        }
        if (action == "verify")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: contract verify <file_or_id> [pubkey]");
                return 2;
            }
            var contractText = ResolveContractText(args[1]);
            if (string.IsNullOrWhiteSpace(contractText))
            {
                _display.PrintError("contrato nao encontrado");
                return 3;
            }
            var key = args.Length >= 3 ? args[2] : _service.CurrentPublicKeyBase64;
            var ok = _service.VerifyContractSignatureWithKey(contractText, key);
            if (ok)
            {
                _display.PrintSuccess("assinatura valida");
                return 0;
            }
            _display.PrintError("assinatura invalida");
            return 4;
        }
        if (action == "pending")
        {
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }

            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            var result = await session.EmitAndWaitAsync("get_pending_transfers", new { }, "pending_transfers", TimeSpan.FromSeconds(25), ct).ConfigureAwait(false);
            if (result.TryGetProperty("error", out var err) && !string.IsNullOrWhiteSpace(err.GetString()))
            {
                _display.PrintError(err.GetString()!);
                return 5;
            }
            if (!result.TryGetProperty("transfers", out var transfers) || transfers.ValueKind != JsonValueKind.Array)
            {
                _display.PrintInfo("nenhuma pendencia contratual");
                return 0;
            }

            var rows = transfers.EnumerateArray().ToList();
            if (rows.Count == 0)
            {
                _display.PrintInfo("nenhuma pendencia contratual");
                return 0;
            }

            foreach (var t in rows)
            {
                var transferId = t.TryGetProperty("transfer_id", out var transferIdElement) ? transferIdElement.GetString() ?? "" : "";
                var transferType = t.TryGetProperty("transfer_type", out var ty) ? ty.GetString() ?? "" : "";
                var targetUser = t.TryGetProperty("target_user", out var tu) ? tu.GetString() ?? "" : "";
                var originalOwner = t.TryGetProperty("original_owner", out var oo) ? oo.GetString() ?? "" : "";
                var pendingContractId = t.TryGetProperty("contract_id", out var cid) ? cid.GetString() ?? "" : "";
                Console.WriteLine($"{transferId} | type={transferType} | target={targetUser} | origin={originalOwner} | contract={pendingContractId}");
            }
            return 0;
        }
        if (action == "accept")
        {
            if (args.Length < 2)
            {
                _display.PrintError($"uso: contract {action} <transfer_id>");
                return 2;
            }
            var transferId = args[1].Trim();
            if (string.IsNullOrWhiteSpace(transferId))
            {
                _display.PrintError("transfer_id obrigatorio");
                return 2;
            }
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }

            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            var pending = await session.EmitAndWaitAsync("get_pending_transfers", new { }, "pending_transfers", TimeSpan.FromSeconds(25), ct).ConfigureAwait(false);
            if (pending.TryGetProperty("error", out var pendingErr) && !string.IsNullOrWhiteSpace(pendingErr.GetString()))
            {
                _display.PrintError(pendingErr.GetString()!);
                return 5;
            }

            var transferType = string.Empty;
            if (pending.TryGetProperty("transfers", out var transfers) && transfers.ValueKind == JsonValueKind.Array)
            {
                foreach (var transferItem in transfers.EnumerateArray())
                {
                    var pendingTransferId = transferItem.TryGetProperty("transfer_id", out var pendingTransferIdElement)
                        ? pendingTransferIdElement.GetString() ?? string.Empty
                        : string.Empty;
                    if (!pendingTransferId.Equals(transferId, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    transferType = transferItem.TryGetProperty("transfer_type", out var transferTypeElement)
                        ? transferTypeElement.GetString() ?? string.Empty
                        : string.Empty;
                    break;
                }
            }

            if (transferType.Equals("hps_transfer", StringComparison.OrdinalIgnoreCase))
            {
                var (nonce, rate) = await session.SolvePowAsync("contract_transfer", ct).ConfigureAwait(false);
                var result = await session.EmitAndWaitAsync(
                    "accept_hps_transfer",
                    new
                    {
                        transfer_id = transferId,
                        pow_nonce = nonce,
                        hashrate_observed = rate
                    },
                    "accept_hps_transfer_ack",
                    TimeSpan.FromSeconds(90),
                    ct).ConfigureAwait(false);

                if (!ReadSuccess(result))
                {
                    _display.PrintError(ReadError(result));
                    return 5;
                }
                Console.WriteLine(result.GetRawText());
                return 0;
            }

            var payload = await session.EmitAndWaitAsync(
                "get_transfer_payload",
                new { transfer_id = transferId },
                "transfer_payload",
                TimeSpan.FromSeconds(45),
                ct).ConfigureAwait(false);
            if (payload.TryGetProperty("error", out var payloadErr) && !string.IsNullOrWhiteSpace(payloadErr.GetString()))
            {
                _display.PrintError(payloadErr.GetString()!);
                return 5;
            }

            if (!_service.IsCryptoUnlocked)
            {
                _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
                return 6;
            }

            var contentB64 = payload.TryGetProperty("content_b64", out var b64) ? b64.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(contentB64))
            {
                _display.PrintError("payload de transferencia sem conteudo");
                return 5;
            }
            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(contentB64);
            }
            catch (Exception ex)
            {
                _display.PrintError("conteudo da transferencia invalido: " + ex.Message);
                return 5;
            }

            var mime = payload.TryGetProperty("mime_type", out var m) ? m.GetString() ?? "application/octet-stream" : "application/octet-stream";
            var fileName = payload.TryGetProperty("title", out var titleElement) ? titleElement.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(fileName))
            {
                fileName = "transfer_" + transferId + ".bin";
            }
            fileName = Path.GetFileName(fileName);
            var signature = _service.SignContent(bytes);
            var uploaded = await _http.UploadBytesAsync(
                currentServer,
                user,
                _service.ClientIdentifier,
                _service.PublicKeyBase64(),
                signature,
                fileName,
                bytes,
                mime,
                ct).ConfigureAwait(false);
            if (!uploaded.Ok)
            {
                _display.PrintError(uploaded.Error);
                return 5;
            }
            _display.PrintSuccess("transferencia aceita (conteudo reenviado)");
            _service.IncrementStat("content_uploaded");
            _service.IncrementStat("data_sent_bytes", bytes.LongLength);
            return 0;
        }
        if (action is "reject" or "renounce")
        {
            if (args.Length < 2)
            {
                _display.PrintError($"uso: contract {action} <transfer_id>");
                return 2;
            }
            var transferId = args[1].Trim();
            if (string.IsNullOrWhiteSpace(transferId))
            {
                _display.PrintError("transfer_id obrigatorio");
                return 2;
            }
            var user = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 3;
            }

            await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, user, _service, _ctx, _display, ct).ConfigureAwait(false);
            var (nonce, rate) = await session.SolvePowAsync("contract_transfer", ct).ConfigureAwait(false);

            var emitEvent = action switch
            {
                "reject" => "reject_transfer",
                _ => "renounce_transfer"
            };
            var ackEvent = action switch
            {
                "reject" => "reject_transfer_ack",
                _ => "renounce_transfer_ack"
            };
            var result = await session.EmitAndWaitAsync(
                emitEvent,
                new
                {
                    transfer_id = transferId,
                    pow_nonce = nonce,
                    hashrate_observed = rate
                },
                ackEvent,
                TimeSpan.FromSeconds(90),
                ct).ConfigureAwait(false);

            if (!ReadSuccess(result))
            {
                _display.PrintError(ReadError(result));
                return 5;
            }
            Console.WriteLine(result.GetRawText());
            return 0;
        }
        if (action is not ("get" or "show"))
        {
            _display.PrintError("uso: contract search [--type all|hash|domain|user|type] [--value v] [--limit n] | contract get <contract_id> | contract analyze <contract_id> | contract sign <action> <k=v,...> [out_file] | contract verify <file_or_id> [pubkey] | contract pending | contract accept <transfer_id> | contract reject <transfer_id> | contract renounce <transfer_id> | contract fix | contract certify <contract_id> | contract certify-missing <target> [--type domain|content] | contract invalidate <contract_id> | contract sync");
            return 2;
        }
        if (args.Length < 2)
        {
            _display.PrintError("uso: contract get <contract_id>");
            return 2;
        }
        var contractServer = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(contractServer))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var contractId = args[1].Trim();
        var fetched = await _http.FetchContractAsync(contractServer, contractId, ct).ConfigureAwait(false);
        if (!fetched.Ok)
        {
            _display.PrintError(fetched.Error);
            return 4;
        }
        _service.SaveContractToStorage(new ContractRecord
        {
            ContractId = contractId,
            ContractContent = fetched.Content,
            Timestamp = DateTimeOffset.UtcNow
        });
        _display.PrintSuccess($"contrato salvo: {contractId}");
        return 0;
    }

    private async Task<int> RunVoucher(string[] args, CancellationToken ct)
    {
        if (args.Length < 1)
        {
            _display.PrintSection("Vouchers");
            _display.PrintInfo("voucher get <voucher_id>");
            _display.PrintInfo("voucher audit <id1,id2,...>");
            _display.PrintInfo("voucher contract [voucher_id]");
            _display.PrintInfo("voucher spend <contract_id>");
            _display.PrintInfo("voucher verify <file_json>");
            _display.PrintInfo("voucher list [limit]");
            return 0;
        }
        if (args[0].Equals("list", StringComparison.OrdinalIgnoreCase))
        {
            var limit = 50;
            if (args.Length >= 2 && int.TryParse(args[1], out var n) && n > 0)
            {
                limit = n;
            }
            var list = _service.ListVouchers(limit);
            if (list.Count == 0)
            {
                _display.PrintInfo("sem vouchers locais");
                return 0;
            }
            foreach (var v in list)
            {
                Console.WriteLine($"{v.VoucherId} | owner={v.Owner} | value={v.Value} | status={v.Status} | invalidated={v.Invalidated}");
            }
            return 0;
        }
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var action = args[0].ToLowerInvariant();
        if (action == "get")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: voucher get <voucher_id>");
                return 2;
            }
            var id = args[1].Trim();
            var res = await _http.FetchVoucherAsync(server, id, asHtml: false, ct).ConfigureAwait(false);
            if (!res.Ok)
            {
                _display.PrintError(res.Error);
                return 4;
            }
            var saved = _service.SaveVoucherFromText(res.Content);
            if (!saved.Ok)
            {
                _display.PrintWarning($"voucher recebido, mas parse falhou: {saved.Error}");
                return 0;
            }
            _display.PrintSuccess($"voucher salvo: {saved.VoucherId}");
            var savePath = Path.Combine(_ctx.Paths.VouchersDir, saved.VoucherId + ".hps");
            if (res.Content.StartsWith("# HSYST P2P SERVICE", StringComparison.Ordinal))
            {
                await File.WriteAllTextAsync(savePath, res.Content, ct).ConfigureAwait(false);
            }
            else
            {
                using var doc = JsonDocument.Parse(res.Content);
                var hps = _service.FormatHpsVoucherHsyst(doc.RootElement);
                await File.WriteAllTextAsync(savePath, hps, ct).ConfigureAwait(false);
            }
            return 0;
        }
        if (action == "audit")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: voucher audit <id1,id2,...>");
                return 2;
            }
            var ids = ParseVoucherIds(args.Skip(1));
            if (ids.Length == 0)
            {
                _display.PrintError("nenhum voucher id informado");
                return 2;
            }
            var audit = await _http.AuditVouchersAsync(server, ids, ct).ConfigureAwait(false);
            if (!audit.Ok)
            {
                _display.PrintError(audit.Error);
                return 5;
            }
            Console.WriteLine(audit.RawJson);
            try
            {
                using var doc = JsonDocument.Parse(audit.RawJson);
                if (doc.RootElement.TryGetProperty("vouchers", out var arr) && arr.ValueKind == JsonValueKind.Array)
                {
                    _lastVoucherIssueContractById.Clear();
                    _lastVoucherAuditOrder.Clear();
                    foreach (var item in arr.EnumerateArray())
                    {
                        var voucherId = item.TryGetProperty("voucher_id", out var voucherIdElement)
                            ? voucherIdElement.GetString() ?? string.Empty
                            : string.Empty;
                        var issueContract = item.TryGetProperty("issue_contract", out var issueContractElement)
                            ? issueContractElement.GetString() ?? string.Empty
                            : string.Empty;
                        if (!string.IsNullOrWhiteSpace(voucherId))
                        {
                            _lastVoucherAuditOrder.Add(voucherId);
                            if (!string.IsNullOrWhiteSpace(issueContract))
                            {
                                _lastVoucherIssueContractById[voucherId] = issueContract;
                            }
                        }

                        var raw = item.GetRawText();
                        var wrapped = "{\"payload\":" + raw + ",\"signatures\":{}}";
                        _service.SaveVoucherFromText(wrapped);
                    }
                }
            }
            catch
            {
            }
            return 0;
        }
        if (action == "contract")
        {
            string voucherId;
            if (args.Length >= 2 && !string.IsNullOrWhiteSpace(args[1]))
            {
                voucherId = args[1].Trim();
            }
            else
            {
                voucherId = _lastVoucherAuditOrder.FirstOrDefault() ?? string.Empty;
            }

            if (string.IsNullOrWhiteSpace(voucherId))
            {
                _display.PrintWarning("nenhum voucher auditado recentemente. use: voucher audit <id1,id2,...>");
                return 0;
            }
            if (!_lastVoucherIssueContractById.TryGetValue(voucherId, out var issueContractB64) || string.IsNullOrWhiteSpace(issueContractB64))
            {
                _display.PrintWarning($"contrato de emissao nao encontrado para voucher {voucherId}");
                return 0;
            }

            try
            {
                var bytes = Convert.FromBase64String(issueContractB64);
                var contractText = Encoding.UTF8.GetString(bytes);
                _display.PrintSection("Contrato de emissao");
                Console.WriteLine(contractText);
                return 0;
            }
            catch (Exception ex)
            {
                _display.PrintError("falha ao decodificar contrato: " + ex.Message);
                return 4;
            }
        }
        if (action == "spend")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: voucher spend <contract_id>");
                return 2;
            }
            var contractId = args[1].Trim();
            if (string.IsNullOrWhiteSpace(contractId))
            {
                _display.PrintError("contract_id obrigatorio");
                return 2;
            }

            var contractText = ResolveContractText(contractId);
            if (string.IsNullOrWhiteSpace(contractText))
            {
                var fetched = await _http.FetchContractAsync(server, contractId, ct).ConfigureAwait(false);
                if (!fetched.Ok)
                {
                    _display.PrintError(fetched.Error);
                    return 4;
                }
                contractText = fetched.Content;
                _service.SaveContractToStorage(new ContractRecord
                {
                    ContractId = contractId,
                    ContractContent = contractText,
                    Timestamp = DateTimeOffset.UtcNow
                });
            }

            var details = _service.ExtractContractDetailsMap(contractText);
            _display.PrintSection("Voucher Spend");
            _display.PrintInfo($"contract_id={contractId}");
            _display.PrintInfo($"action={details.GetValueOrDefault("ACTION", "")}");
            _display.PrintInfo($"target_user={details.GetValueOrDefault("TARGET_USER", "")}");
            var voucherIdsText = details.GetValueOrDefault("VOUCHER_IDS", details.GetValueOrDefault("VOUCHER_ID", ""));
            if (!string.IsNullOrWhiteSpace(voucherIdsText))
            {
                _display.PrintInfo($"voucher_ids={voucherIdsText}");
            }
            Console.WriteLine(contractText);
            return 0;
        }
        if (action == "verify")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: voucher verify <file_json>");
                return 2;
            }
            var file = args[1];
            if (!File.Exists(file))
            {
                _display.PrintError("arquivo nao encontrado");
                return 3;
            }
            var text = await File.ReadAllTextAsync(file, ct).ConfigureAwait(false);
            if (text.StartsWith("# HSYST P2P SERVICE", StringComparison.Ordinal))
            {
                var parsed = _service.ParseHpsVoucherHsyst(text);
                if (parsed is null)
                {
                    _display.PrintError("formato .hps invalido");
                    return 4;
                }
                text = JsonSerializer.Serialize(parsed);
            }
            using var doc = JsonDocument.Parse(text);
            var result = _service.VerifyVoucherSignatures(doc.RootElement);
            if (!result.Ok)
            {
                _display.PrintError(result.Error);
                return 4;
            }
            _display.PrintSuccess("voucher valido");
            return 0;
        }
        _display.PrintError("uso: voucher get <voucher_id> | voucher audit <id1,id2,...> | voucher contract [voucher_id] | voucher spend <contract_id> | voucher verify <file_json> | voucher list [limit]");
        return 2;
    }

    private static string[] ParseVoucherIds(IEnumerable<string> rawParts)
    {
        var input = string.Join(" ", rawParts ?? []);
        return input
            .Split([',', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private async Task<int> RunExchange(string[] args, CancellationToken ct)
    {
        if (args.Length < 1)
        {
            _display.PrintSection("Cambio HPS");
            var byIssuer = _service.ListVouchers(2000)
                .GroupBy(v => string.IsNullOrWhiteSpace(v.Issuer) ? "(desconhecido)" : v.Issuer, StringComparer.OrdinalIgnoreCase)
                .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (byIssuer.Count == 0)
            {
                _display.PrintInfo("nenhum voucher local para cambio");
            }
            else
            {
                foreach (var g in byIssuer)
                {
                    var total = g.Sum(v => v.Value);
                    Console.WriteLine($"{g.Key} | qtd={g.Count()} | total={total}");
                }
            }
            _display.PrintInfo("exchange refresh");
            _display.PrintInfo("exchange validate <target_server> <id1,id2,...>");
            _display.PrintInfo("exchange confirm [token_json_file]");
            _display.PrintInfo("exchange convert <issuer> [amount]");
            return 0;
        }
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 3;
        }
        var action = args[0].ToLowerInvariant();
        if (action == "refresh")
        {
            return await RunWallet(["refresh"], ct).ConfigureAwait(false);
        }
        if (action == "convert")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: exchange convert <issuer> [amount]");
                return 2;
            }
            var issuer = args[1].Trim();
            long? amount = null;
            if (args.Length >= 3 && long.TryParse(args[2], out var parsedAmount) && parsedAmount > 0)
            {
                amount = parsedAmount;
            }
            var candidates = _service.ListVouchers(2000)
                .Where(v => !v.Invalidated &&
                            !string.Equals(v.Status, "spent", StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(v.Issuer, issuer, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(v => v.Value)
                .ToList();
            if (candidates.Count == 0)
            {
                _display.PrintError($"nenhum voucher local encontrado para issuer={issuer}");
                return 3;
            }

            var selected = new List<string>();
            long total = 0;
            foreach (var voucher in candidates)
            {
                selected.Add(voucher.VoucherId);
                total += voucher.Value;
                if (amount.HasValue && total >= amount.Value)
                {
                    break;
                }
            }

            _display.PrintSection("Exchange Convert");
            _display.PrintInfo($"issuer={issuer}");
            _display.PrintInfo($"vouchers={selected.Count} total={total}");
            if (!_service.IsCryptoUnlocked)
            {
                _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
                return 6;
            }
            var targetServer = server;
            var ids = selected
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray();
            var issuerForProof = _service.InferIssuerFromVouchers(ids, server);
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
            var proofPayload = new Dictionary<string, object?>
            {
                ["issuer"] = issuerForProof,
                ["target_server"] = targetServer,
                ["voucher_ids"] = ids,
                ["timestamp"] = timestamp
            };
            var clientSig = _service.SignCanonicalPayloadBase64(proofPayload);
            var requestId = Guid.NewGuid().ToString("N");
            var res = await _http.ExchangeValidateAsync(
                server,
                ids,
                targetServer,
                clientSig,
                _service.PublicKeyBase64(),
                requestId,
                timestamp,
                ct).ConfigureAwait(false);
            if (!res.Ok)
            {
                _display.PrintError(res.Error);
                return 4;
            }
            Console.WriteLine(res.RawJson);
            try
            {
                using var doc = JsonDocument.Parse(res.RawJson);
                var token = doc.RootElement.TryGetProperty("token", out var t) ? t.GetRawText() : "";
                var signature = doc.RootElement.TryGetProperty("signature", out var s) ? s.GetString() ?? "" : "";
                if (!string.IsNullOrWhiteSpace(token) && !string.IsNullOrWhiteSpace(signature))
                {
                    _service.SaveLastExchangeToken(server, token, signature);
                    _display.PrintSuccess("token de exchange salvo localmente");
                }
            }
            catch
            {
            }
            return 0;
        }
        if (action == "validate")
        {
            if (args.Length < 3)
            {
                _display.PrintError("uso: exchange validate <target_server> <id1,id2,...>");
                return 2;
            }
            var targetServer = args[1].Trim();
            var ids = args[2].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray();
            if (ids.Length == 0)
            {
                _display.PrintError("nenhum voucher id informado");
                return 2;
            }
            var issuer = _service.InferIssuerFromVouchers(ids, server);
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
            var proofPayload = new Dictionary<string, object?>
            {
                ["issuer"] = issuer,
                ["target_server"] = targetServer,
                ["voucher_ids"] = ids,
                ["timestamp"] = timestamp
            };
            if (!_service.IsCryptoUnlocked)
            {
                _display.PrintError("cofre nÃ£o desbloqueado. use: keys unlock <username>");
                return 6;
            }
            var clientSig = _service.SignCanonicalPayloadBase64(proofPayload);
            var requestId = Guid.NewGuid().ToString("N");
            var res = await _http.ExchangeValidateAsync(
                server,
                ids,
                targetServer,
                clientSig,
                _service.PublicKeyBase64(),
                requestId,
                timestamp,
                ct).ConfigureAwait(false);
            if (!res.Ok)
            {
                _display.PrintError(res.Error);
                return 4;
            }
            Console.WriteLine(res.RawJson);
            try
            {
                using var doc = JsonDocument.Parse(res.RawJson);
                var token = doc.RootElement.TryGetProperty("token", out var t) ? t.GetRawText() : "";
                var signature = doc.RootElement.TryGetProperty("signature", out var s) ? s.GetString() ?? "" : "";
                if (!string.IsNullOrWhiteSpace(token) && !string.IsNullOrWhiteSpace(signature))
                {
                    _service.SaveLastExchangeToken(server, token, signature);
                    _display.PrintSuccess("token de exchange salvo localmente");
                }
            }
            catch
            {
            }
            return 0;
        }
        if (action == "confirm")
        {
            string tokenJson;
            string signature;
            if (args.Length >= 2)
            {
                var tokenPath = args[1];
                if (!File.Exists(tokenPath))
                {
                    _display.PrintError("arquivo de token nao encontrado");
                    return 2;
                }
                var raw = await File.ReadAllTextAsync(tokenPath, ct).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(raw);
                tokenJson = doc.RootElement.TryGetProperty("token", out var t) ? t.GetRawText() : "";
                signature = doc.RootElement.TryGetProperty("signature", out var s) ? s.GetString() ?? "" : "";
            }
            else
            {
                tokenJson = _service.LastExchangeTokenJson;
                signature = _service.LastExchangeSignature;
            }
            if (string.IsNullOrWhiteSpace(tokenJson) || string.IsNullOrWhiteSpace(signature))
            {
                _display.PrintError("token/signature indisponivel");
                return 2;
            }
            Dictionary<string, object?> tokenMap;
            try
            {
                tokenMap = JsonSerializer.Deserialize<Dictionary<string, object?>>(tokenJson) ?? [];
            }
            catch (Exception ex)
            {
                _display.PrintError("token invalido: " + ex.Message);
                return 2;
            }
            var res = await _http.ExchangeConfirmAsync(server, tokenMap, signature, ct).ConfigureAwait(false);
            if (!res.Ok)
            {
                _display.PrintError(res.Error);
                return 5;
            }
            Console.WriteLine(res.RawJson);
            return 0;
        }
        _display.PrintError("uso: exchange refresh | exchange validate <target_server> <id1,id2,...> | exchange confirm [token_json_file] | exchange convert <issuer> [amount]");
        return 2;
    }

    private int RunDkvhps(string[] args)
    {
        if (args.Length == 0 || args[0].Equals("help", StringComparison.OrdinalIgnoreCase))
        {
            _display.PrintSection("DKVHPS");
            _display.PrintInfo("DKVHPS e a chave de descriptografia dos vouchers HPS.");
            _display.PrintInfo("Cada voucher possui uma chave propria e uma chave da linhagem.");
            _display.PrintInfo("No armazenamento local, o CLI protege o arquivo do voucher com a chave do voucher, depois com a da linhagem e por fim com a chave local.");
            _display.PrintInfo("Comandos:");
            _display.PrintInfo("dkvhps list");
            _display.PrintInfo("dkvhps show <lineage_root_ou_voucher_id>");
            return 0;
        }

        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
            return 6;
        }

        if (args[0].Equals("list", StringComparison.OrdinalIgnoreCase))
        {
            var lineages = _service.ListDkvhpsLineages();
            _display.PrintSection("Linhagens DKVHPS");
            if (lineages.Count == 0)
            {
                _display.PrintInfo("nenhuma linhagem local encontrada");
                return 0;
            }
            foreach (var lineage in lineages)
            {
                Console.WriteLine($"{lineage.LineageRootVoucherId} | vouchers={lineage.VoucherCount} | total={lineage.TotalValue} | ativo={lineage.ActiveVoucherId} | origem={lineage.LineageOrigin} | integ={(lineage.LineageHashVerified ? "ok" : "falha")}");
            }
            return 0;
        }

        if (args[0].Equals("show", StringComparison.OrdinalIgnoreCase))
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: dkvhps show <lineage_root_ou_voucher_id>");
                return 2;
            }
            var lineage = _service.GetDkvhpsLineage(args[1]);
            if (lineage is null)
            {
                _display.PrintError("linhagem dkvhps nao encontrada");
                return 3;
            }
            _display.PrintSection("DKVHPS Linhagem");
            _display.PrintInfo($"root={lineage.LineageRootVoucherId}");
            _display.PrintInfo($"origem={lineage.LineageOrigin}");
            _display.PrintInfo($"voucher ativo={lineage.ActiveVoucherId}");
            _display.PrintInfo($"status ativo={lineage.ActiveStatus}");
            _display.PrintInfo($"chave da linhagem={lineage.LineageKey}");
            _display.PrintInfo($"integridade da linhagem={(lineage.LineageHashVerified ? "ok" : "falha")}");
            foreach (var voucher in lineage.Vouchers)
            {
                Console.WriteLine();
                Console.WriteLine($"voucher={voucher.VoucherId}");
                Console.WriteLine($"  depth={voucher.LineageDepth} status={voucher.Status} invalidated={voucher.Invalidated} value={voucher.Value}");
                Console.WriteLine($"  parent={voucher.LineageParentVoucherId}");
                Console.WriteLine($"  parent_hash={voucher.LineageParentHash}");
                Console.WriteLine($"  voucher_hash={voucher.VoucherHash}");
                Console.WriteLine($"  lineage_hash={voucher.LineageHash}");
                Console.WriteLine($"  voucher_key={voucher.VoucherKey}");
                Console.WriteLine($"  lineage_key={voucher.LineageKey}");
                Console.WriteLine($"  voucher_owner_encrypted={voucher.VoucherOwnerEncrypted}");
                Console.WriteLine($"  lineage_owner_encrypted={voucher.LineageOwnerEncrypted}");
                Console.WriteLine($"  voucher_hash_verified={voucher.VoucherHashVerified}");
                Console.WriteLine($"  lineage_hash_verified={voucher.LineageHashVerified}");
                Console.WriteLine($"  storage={voucher.StoragePath}");
            }
            return 0;
        }

        _display.PrintError("uso: dkvhps list | dkvhps show <lineage_root_ou_voucher_id>");
        return 2;
    }

    private int RunHistory(string[] args)
    {
        var limit = 20;
        if (args.Length > 0 && int.TryParse(args[0], out var n) && n > 0)
        {
            limit = n;
        }
        var rows = _service.GetHistory(limit);
        if (rows.Count == 0)
        {
            _display.PrintInfo("historico vazio");
            return 0;
        }
        foreach (var row in rows)
        {
            Console.WriteLine($"{row.Timestamp:yyyy-MM-dd HH:mm:ss} | {(row.Success ? "OK " : "ERR")} | {row.Command} | {row.Result}");
        }
        return 0;
    }


    private static bool LooksLikeHash(string value)
    {
        var v = (value ?? string.Empty).Trim();
        if (v.Length == 64 && v.All(c => Uri.IsHexDigit(c)))
        {
            return true;
        }
        if (v.StartsWith("Qm", StringComparison.Ordinal) && v.Length >= 44)
        {
            return true;
        }
        return false;
    }

    private void PrintHelp()
    {
        _display.PrintSection("Comandos");
        Console.WriteLine("help");
        Console.WriteLine("clear");
        Console.WriteLine("exit");
        Console.WriteLine("whoami [username]");
        Console.WriteLine("login <server> <username> [passphrase]");
        Console.WriteLine("logout");
        Console.WriteLine("keys status [username]");
        Console.WriteLine("keys init <username>");
        Console.WriteLine("keys generate [username]");
        Console.WriteLine("keys unlock <username>");
        Console.WriteLine("keys lock");
        Console.WriteLine("keys show");
        Console.WriteLine("keys export-public");
        Console.WriteLine("keys export <file_path>");
        Console.WriteLine("keys import <file_path>");
        Console.WriteLine("keys export-bundle <username> <output_path>");
        Console.WriteLine("keys import-bundle <username> <input_path>");
        Console.WriteLine("servers [list|add|remove|connect]");
        Console.WriteLine("use <indice|host:porta|url>");
        Console.WriteLine("history [limit]");
        Console.WriteLine("stats");
        Console.WriteLine("health");
        Console.WriteLine("server-info");
        Console.WriteLine("economy");
        Console.WriteLine("pow [bits] [target_seconds] [challenge_b64]");
        Console.WriteLine("pow threads [n]");
        Console.WriteLine("resolve <dominio>");
        Console.WriteLine("dns-res <dominio>");
        Console.WriteLine("get <dominio|hash>");
        Console.WriteLine("download <hash_or_url> [--output PATH]");
        Console.WriteLine("search <termo> [--type TYPE] [--sort ORDER]");
        Console.WriteLine("upload <file_path> [mime]");
        Console.WriteLine("dns-reg <domain> <hash>");
        Console.WriteLine("contract get <contract_id>");
        Console.WriteLine("contract search --type <all|hash|domain|user|type> --value <value> [--limit 50]");
        Console.WriteLine("contract analyze <contract_id>");
        Console.WriteLine("contract sign <action> <k=v,...> [out_file]");
        Console.WriteLine("contract verify <file_or_id> [pubkey]");
        Console.WriteLine("contract pending");
        Console.WriteLine("contract accept <transfer_id>");
        Console.WriteLine("contract reject <transfer_id>");
        Console.WriteLine("contract renounce <transfer_id>");
        Console.WriteLine("contract fix");
        Console.WriteLine("contract certify <contract_id>");
        Console.WriteLine("contract certify-missing <target> [--type domain|content]");
        Console.WriteLine("contract invalidate <contract_id>");
        Console.WriteLine("contract sync");
        Console.WriteLine("voucher get <voucher_id>");
        Console.WriteLine("voucher audit <id1,id2,...>");
        Console.WriteLine("voucher contract [voucher_id]");
        Console.WriteLine("voucher spend <contract_id>");
        Console.WriteLine("voucher verify <file_json>");
        Console.WriteLine("voucher list [limit]");
        Console.WriteLine("exchange refresh");
        Console.WriteLine("exchange validate <target_server> <id1,id2,...>");
        Console.WriteLine("exchange confirm [token_json_file]");
        Console.WriteLine("exchange convert <issuer> [amount]");
        Console.WriteLine("dkvhps help");
        Console.WriteLine("dkvhps list");
        Console.WriteLine("dkvhps show <lineage_root_ou_voucher_id>");
        Console.WriteLine("network");
        Console.WriteLine("security <content_hash>");
        Console.WriteLine("report <content_hash> <reported_user>");
        Console.WriteLine("actions transfer-file <content_hash> <target_user>");
        Console.WriteLine("actions transfer-hps <target_user> <amount>");
        Console.WriteLine("actions transfer-domain <domain> <new_owner>");
        Console.WriteLine("actions transfer-api <app_name> <target_user> <file_path>");
        Console.WriteLine("actions api-app <app_name> <file_path>");
        Console.WriteLine("actions live --app <live:app> [--duration 60] [--max-seg 1048576] [--interval 5]");
        Console.WriteLine("messages refresh|contacts|requests [incoming|outgoing]");
        Console.WriteLine("messages request <target_user>");
        Console.WriteLine("messages accept <request_id>");
        Console.WriteLine("messages reject <request_id>");
        Console.WriteLine("messages send <target_user> <text>");
        Console.WriteLine("messages convo <peer_user>");
        Console.WriteLine("wallet refresh|list|show <voucher_id>");
        Console.WriteLine("wallet mint [--reason TEXT]");
        Console.WriteLine("wallet auto-mint on|off");
        Console.WriteLine("wallet transfer <target_user> <amount>");
        Console.WriteLine("wallet signature-monitor on|off");
        Console.WriteLine("wallet signature-auto on|off");
        Console.WriteLine("wallet auto-select on|off");
        Console.WriteLine("wallet fine-auto on|off");
        Console.WriteLine("wallet fine-promise on|off");
        Console.WriteLine("wallet sign-transfer <transfer_id>");
        Console.WriteLine("sync [limit]");
        Console.WriteLine("sync push-content [limit]");
        Console.WriteLine("state");
    }

    private static string GuessMime(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        return ext switch
        {
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".html" => "text/html",
            ".txt" => "text/plain",
            ".json" => "application/json",
            ".pdf" => "application/pdf",
            _ => "application/octet-stream"
        };
    }

    private static string GuessDownloadPath(string hash, string mime, IReadOnlyDictionary<string, string[]> headers)
    {
        var fromHeader = TryGetFileNameFromContentDisposition(headers);
        if (!string.IsNullOrWhiteSpace(fromHeader))
        {
            return Path.GetFileName(fromHeader);
        }

        var ext = mime.ToLowerInvariant() switch
        {
            "image/png" => ".png",
            "image/jpeg" => ".jpg",
            "image/gif" => ".gif",
            "text/html" => ".html",
            "text/plain" => ".txt",
            "application/json" => ".json",
            "application/pdf" => ".pdf",
            _ => ".dat"
        };
        return hash + ext;
    }

    private static string TryGetFileNameFromContentDisposition(IReadOnlyDictionary<string, string[]> headers)
    {
        foreach (var key in headers.Keys)
        {
            if (!key.Equals("Content-Disposition", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var joined = string.Join(";", headers[key] ?? []);
            var marker = "filename=";
            var idx = joined.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                return string.Empty;
            }
            var raw = joined[(idx + marker.Length)..].Trim();
            if (raw.StartsWith("\"", StringComparison.Ordinal) && raw.EndsWith("\"", StringComparison.Ordinal) && raw.Length >= 2)
            {
                raw = raw[1..^1];
            }
            return Path.GetFileName(raw);
        }
        return string.Empty;
    }

    private async Task<int> RunPow(string[] args, CancellationToken ct)
    {
        if (args.Length > 0 && string.Equals(args[0], "threads", StringComparison.OrdinalIgnoreCase))
        {
            if (args.Length == 1)
            {
                _display.PrintInfo($"pow threads={ResolvePowThreads()}");
                return 0;
            }
            if (!int.TryParse(args[1], out var configured) || configured <= 0)
            {
                _display.PrintError("uso: pow threads <n>");
                return 2;
            }
            Environment.SetEnvironmentVariable("HPS_POW_THREADS", configured.ToString(CultureInfo.InvariantCulture));
            _display.PrintSuccess($"threads de PoW definidas para {configured}");
            return 0;
        }

        var bits = 20;
        var seconds = 10.0;
        string challengeB64;

        if (args.Length >= 1 && int.TryParse(args[0], out var b) && b > 0)
        {
            bits = b;
        }
        if (args.Length >= 2 && double.TryParse(args[1], out var s) && s > 0)
        {
            seconds = s;
        }
        if (args.Length >= 3 && !string.IsNullOrWhiteSpace(args[2]))
        {
            challengeB64 = args[2];
        }
        else
        {
            challengeB64 = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        }

        _display.PrintSection("PoW");
        _display.PrintInfo($"bits={bits} target_seconds={seconds:0.0}");
        var solver = new CliPowSolver();
        solver.ProgressChanged += p =>
        {
            var pct = p.TargetSeconds <= 0 ? 0 : (int)Math.Min(99, (p.ElapsedSeconds / p.TargetSeconds) * 100);
            _display.PrintProgress(pct, 100, $"status={p.Status} rate={p.Hashrate:0}H/s attempts={p.Attempts}");
        };
        var result = await solver.SolveAsync(challengeB64, bits, seconds, "pow_cmd", threads: ResolvePowThreads(), cancellationToken: ct).ConfigureAwait(false);
        _display.PrintProgress(100, 100, "finalizando");
        if (!result.Solved)
        {
            _display.PrintError($"pow falhou: {result.Error}");
            return 5;
        }
        _display.PrintSuccess($"nonce={result.Nonce} lzb={result.LeadingZeroBits} elapsed={result.ElapsedSeconds:0.00}s");
        _service.IncrementStat("pow_solved");
        _service.IncrementStat("hashes_calculated", (long)Math.Min(long.MaxValue, result.TotalHashes));
        return 0;
    }

    private static int ResolvePowThreads()
    {
        var raw = Environment.GetEnvironmentVariable("HPS_POW_THREADS");
        if (int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var configured) && configured > 0)
        {
            return configured;
        }
        return Math.Max(1, Environment.ProcessorCount);
    }

    private static Dictionary<string, string> ParseKeyValueCsv(string csv)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in (csv ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var idx = item.IndexOf('=');
            if (idx <= 0)
            {
                continue;
            }
            var k = item[..idx].Trim();
            var v = item[(idx + 1)..].Trim();
            if (!string.IsNullOrWhiteSpace(k))
            {
                map[k] = v;
            }
        }
        return map;
    }

    private string ResolveContractText(string fileOrId)
    {
        if (File.Exists(fileOrId))
        {
            return _service.ReadTextFileFromStorage(fileOrId);
        }
        var rec = _service.GetContractRecord(fileOrId);
        if (rec is not null && !string.IsNullOrWhiteSpace(rec.ContractContent))
        {
            return rec.ContractContent;
        }
        var p = Path.Combine(_ctx.Paths.ContractsDir, fileOrId + ".contract");
        if (File.Exists(p))
        {
            return _service.ReadTextFileFromStorage(p);
        }
        return string.Empty;
    }

    private void PersistResolvedDns((bool Ok, string ContentHash, string Domain, string Username, bool Verified, string Signature, string PublicKey, string DdnsHash, byte[] DdnsContent, string RawJson, string Error) dns)
    {
        if (!dns.Ok || string.IsNullOrWhiteSpace(dns.ContentHash))
        {
            return;
        }
        var domain = string.IsNullOrWhiteSpace(dns.Domain) ? string.Empty : dns.Domain.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }
        if (dns.DdnsContent.Length > 0)
        {
            _service.SaveDdnsToStorage(domain, dns.DdnsContent, new DdnsRecord
            {
                Domain = domain,
                ContentHash = dns.ContentHash,
                DdnsHash = dns.DdnsHash,
                Username = dns.Username,
                Verified = dns.Verified,
                Timestamp = DateTimeOffset.UtcNow,
                Signature = dns.Signature,
                PublicKey = dns.PublicKey
            });
        }
        else
        {
            _service.SaveDns(domain, dns.ContentHash);
        }
        PersistContractsFromJson(dns.RawJson);
    }

    private void PersistContractsFromJson(string rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
        {
            return;
        }
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            if (!doc.RootElement.TryGetProperty("contracts", out var contracts) || contracts.ValueKind != JsonValueKind.Array)
            {
                return;
            }
            foreach (var contract in contracts.EnumerateArray())
            {
                var id = contract.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
                if (string.IsNullOrWhiteSpace(id))
                {
                    continue;
                }
                var content = contract.TryGetProperty("contract_content", out var contentProp) ? contentProp.GetString() ?? string.Empty : string.Empty;
                _service.SaveContractToStorage(new ContractRecord
                {
                    ContractId = id,
                    ActionType = contract.TryGetProperty("action_type", out var actionProp) ? actionProp.GetString() ?? string.Empty : string.Empty,
                    ContentHash = contract.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty,
                    Domain = contract.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() ?? string.Empty : string.Empty,
                    Username = contract.TryGetProperty("username", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty,
                    Signature = contract.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() ?? string.Empty : string.Empty,
                    Verified = contract.TryGetProperty("verified", out var verifiedProp) && verifiedProp.ValueKind == JsonValueKind.True,
                    ContractContent = DecodeContractContent(content),
                    Timestamp = DateTimeOffset.UtcNow
                });
            }
        }
        catch
        {
        }
    }

    private static string DecodeContractContent(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }
        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(value));
        }
        catch
        {
            return value;
        }
    }

    private static string[] SplitArgs(string commandLine)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return [];
        }

        var sb = new StringBuilder();
        var inQuote = false;
        foreach (var ch in commandLine)
        {
            if (ch == '"')
            {
                inQuote = !inQuote;
                continue;
            }
            if (!inQuote && char.IsWhiteSpace(ch))
            {
                if (sb.Length > 0)
                {
                    result.Add(sb.ToString());
                    sb.Clear();
                }
                continue;
            }
            sb.Append(ch);
        }
        if (sb.Length > 0)
        {
            result.Add(sb.ToString());
        }
        return result.ToArray();
    }
}

