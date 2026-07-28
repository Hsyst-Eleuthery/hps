using System.ComponentModel;
using System.Text.Json;
using HpsBrowser.Commands;
using HpsBrowser.Services;
using HpsBrowser.ViewModels;

namespace HpsMiner.Cli;

public static class CliRunner
{
    private static readonly string MinerCryptoDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".hps_miner");

    public static async Task RunAsync(string[] args)
    {
        if (TryHandleKeyMode(args))
        {
            return;
        }

        
        var flags = ParseFlags(args);

        if (flags.Economy || flags.Balance || flags.PhpsMarket || flags.PhpsBuy != null || flags.PhpsRedeem != null)
        {
            await HandleEconomyCommandsAsync(flags);
            return;
        }

        Console.WriteLine("HPS Miner CLI v2.0 - $HPS Mining Utility");
        Console.WriteLine("==========================================");
        Console.WriteLine();

        var vm = new MainViewModel(new CliFileDialogService(), new CliPromptService(), new CliContractDialogService(), MinerCryptoDir, useUiDispatcher: false, minerMode: true);
        vm.ShowTourOnStartup = false;

        
        vm.ServerAddress = flags.Server ?? CliPrompts.AskText("Servidor (host:porta)");
        vm.UseSsl = flags.Ssl ?? CliPrompts.AskYes("Usar SSL/TLS");
        vm.Username = flags.User ?? CliPrompts.AskText("Usuario");
        var envPassword = Environment.GetEnvironmentVariable("HPS_MINER_PASSWORD");
        if (!string.IsNullOrEmpty(envPassword))
        {
            Console.Error.WriteLine("AVISO DE SEGURANCA: HPS_MINER_PASSWORD esta definida. Variaveis de ambiente sao legiveis por qualquer processo no mesmo usuario. Prefira entrada interativa.");
            vm.KeyPassphrase = envPassword;
        }
        else
        {
            vm.KeyPassphrase = CliPrompts.AskPassword("Senha");
        }

        
        vm.AutoSignTransfers = flags.AutoSign ?? CliPrompts.AskYes("Auto-assinar pendencias");
        vm.AutoAcceptMinerSelection = flags.AutoAccept ?? CliPrompts.AskYes("Auto-aceitar selecao de minerador");

        var autoFine = flags.AutoFine ?? CliPrompts.AskYes("Ativar pagamento automatico de multas");
        vm.MinerAutoPayFine = autoFine;
        if (!autoFine)
        {
            vm.MinerFinePromise = flags.FinePromise ?? CliPrompts.AskYes("Ativar promessa automatica de multa");
        }

        vm.IsContinuousMiningEnabled = flags.Continuous ?? CliPrompts.AskYes("Ativar mineracao continua");
        vm.PowThreads = flags.Threads > 0 ? flags.Threads : CliPrompts.AskInt("Threads de mineracao PoW", 1, vm.MaxPowThreads, vm.PowThreads);
        (vm.SavePowSettingsCommand as RelayCommand)?.Execute(null);

        vm.PropertyChanged += (_, e) => PrintImportantChanges(vm, e);

        Console.WriteLine("Conectando...");
        await EnsureConnectedAsync(vm);

        if (vm.IsLoggedIn)
        {
            Console.WriteLine("Logado com sucesso.");
            var maskedServer = vm.ServerAddress?.Length > 8 ? vm.ServerAddress[..Math.Min(vm.ServerAddress.Length, 8)] + "..." : vm.ServerAddress;
            Console.WriteLine($"Servidor: {maskedServer}");
            Console.WriteLine($"Moeda: $HPS");
            Console.WriteLine($"Threads PoW: {vm.PowThreads}");
            Console.WriteLine($"Mineracao continua: {(vm.IsContinuousMiningEnabled ? "Sim" : "Nao")}");
            Console.WriteLine($"Auto-assinar: {(vm.AutoSignTransfers ? "Sim" : "Nao")}");
            Console.WriteLine();

            
            if (flags.CheckFines)
            {
                Console.WriteLine("[Prioridade C] Verificando multas...");
                vm.MinerAutoPayFine = true;
                
                
                var fineTimeout = DateTimeOffset.UtcNow.AddSeconds(10);
                while (DateTimeOffset.UtcNow < fineTimeout)
                {
                    if (!string.IsNullOrWhiteSpace(vm.MinerFineStatus))
                    {
                        Console.WriteLine($"[Multas] {vm.MinerFineStatus}");
                        break;
                    }
                    await Task.Delay(500);
                }
                Console.WriteLine($"[Multas] Pendentes: {vm.MinerPendingFines}, Valor: {vm.MinerFineAmount} HPS");
            }

            if (flags.SignPending)
            {
                Console.WriteLine("[Prioridade A] Verificando pendencias de assinatura...");
                vm.AutoSignTransfers = true;
                
                var signTimeout = DateTimeOffset.UtcNow.AddSeconds(15);
                while (DateTimeOffset.UtcNow < signTimeout)
                {
                    if (string.IsNullOrWhiteSpace(vm.Status) || vm.Status.Contains("assinando", StringComparison.OrdinalIgnoreCase))
                    {
                        await Task.Delay(500);
                        continue;
                    }
                    break;
                }
                Console.WriteLine("[Assinaturas] Verificacao concluida.");
            }

            if (flags.FinalizePow)
            {
                Console.WriteLine("[Prioridade B] Finalizando PoW...");
                
                vm.IsContinuousMiningEnabled = true;
                (vm.StartHpsMintCommand as AsyncRelayCommand)?.Execute(null);
                var powTimeout = DateTimeOffset.UtcNow.AddSeconds(20);
                while (DateTimeOffset.UtcNow < powTimeout)
                {
                    var status = vm.HpsMiningStatus ?? "";
                    if (status.Contains("conclu", StringComparison.OrdinalIgnoreCase) ||
                        status.Contains("finalizou", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"[PoW] {status}");
                        break;
                    }
                    if (!string.IsNullOrWhiteSpace(status))
                    {
                        Console.WriteLine($"[PoW] {status}");
                    }
                    await Task.Delay(1000);
                }
                vm.IsContinuousMiningEnabled = flags.Continuous ?? false;
                if (!vm.IsContinuousMiningEnabled)
                {
                    (vm.CancelPowCommand as RelayCommand)?.Execute(null);
                }
            }

            if (flags.FeeQuotes)
            {
                Console.WriteLine("[Taxas] Solicitando cotações...");
                (vm.GetFeeQuotesCommand as AsyncRelayCommand)?.Execute(null);
                var feeTimeout = DateTimeOffset.UtcNow.AddSeconds(10);
                while (DateTimeOffset.UtcNow < feeTimeout)
                {
                    if (!vm.FeeQuotesText.StartsWith("Carregando", StringComparison.OrdinalIgnoreCase) &&
                        !vm.FeeQuotesText.Contains("Clique em", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }
                    await Task.Delay(500);
                }
                Console.WriteLine($"[Taxas] {vm.FeeQuotesText}");
            }

            if (flags.FeeMarket)
            {
                Console.WriteLine("[Taxas] Solicitando dados do mercado...");
                (vm.RefreshFeeMarketCommand as AsyncRelayCommand)?.Execute(null);
                var feeTimeout = DateTimeOffset.UtcNow.AddSeconds(10);
                while (DateTimeOffset.UtcNow < feeTimeout)
                {
                    if (!vm.FeeMarketData.StartsWith("Carregando", StringComparison.OrdinalIgnoreCase) &&
                        !vm.FeeMarketData.Contains("Aguardando", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }
                    await Task.Delay(500);
                }
                Console.WriteLine($"[Taxas] {vm.FeeMarketData}");
            }

            if (flags.FeeConfigMin != null)
            {
                Console.WriteLine("[Taxas] Configurando taxas variáveis...");
                vm.MinerFeeMin = flags.FeeConfigMin ?? 0;
                vm.MinerFeeMax = flags.FeeConfigMax ?? 5;
                vm.MinerFeeVolatility = flags.FeeConfigVolatility ?? 0.5;
                vm.MinerFeeEnabled = flags.FeeConfigEnabled ?? true;
                (vm.SetMinerFeeConfigCommand as AsyncRelayCommand)?.Execute(null);
                var feeTimeout = DateTimeOffset.UtcNow.AddSeconds(10);
                while (DateTimeOffset.UtcNow < feeTimeout)
                {
                    if (!string.IsNullOrWhiteSpace(vm.MinerFeeConfigStatus) &&
                        !vm.MinerFeeConfigStatus.Contains("Salvando", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }
                    await Task.Delay(500);
                }
                Console.WriteLine($"[Taxas] {vm.MinerFeeConfigStatus}");
            }

            if (!vm.IsContinuousMiningEnabled && (flags.StartMining ?? CliPrompts.AskYes("Iniciar mineracao agora")))
            {
                Console.WriteLine("Iniciando mineracao...");
                (vm.StartHpsMintCommand as AsyncRelayCommand)?.Execute(null);
            }
        }

        var shutdownRequested = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        ConsoleCancelEventHandler? cancelHandler = null;
        cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("\nEncerrando...");
            shutdownRequested.TrySetResult(true);
        };
        Console.CancelKeyPress += cancelHandler;

        try
        {
            await shutdownRequested.Task;
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
            await vm.ShutdownAsync();
        }
    }

    private static MinerFlags ParseFlags(string[] args)
    {
        var flags = new MinerFlags();
        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i].ToLowerInvariant();
            switch (arg)
            {
                case "--server":
                case "-s":
                    flags.Server = GetNextArg(args, ref i);
                    break;
                case "--user":
                case "-u":
                    flags.User = GetNextArg(args, ref i);
                    break;
                case "--ssl":
                    flags.Ssl = true;
                    break;
                case "--no-ssl":
                    flags.Ssl = false;
                    break;
                case "--auto-sign":
                    flags.AutoSign = true;
                    break;
                case "--no-auto-sign":
                    flags.AutoSign = false;
                    break;
                case "--auto-accept":
                    flags.AutoAccept = true;
                    break;
                case "--auto-fine":
                    flags.AutoFine = true;
                    break;
                case "--fine-promise":
                    flags.FinePromise = true;
                    break;
                case "--continuous":
                case "-c":
                    flags.Continuous = true;
                    break;
                case "--threads":
                case "-t":
                    var threadsStr = GetNextArg(args, ref i);
                    if (int.TryParse(threadsStr, out int threads))
                        flags.Threads = threads;
                    break;
                case "--start-mining":
                    flags.StartMining = true;
                    break;
                case "--sign-pending":
                    flags.SignPending = true;
                    break;
                case "--finalize-pow":
                    flags.FinalizePow = true;
                    break;
                case "--check-fines":
                    flags.CheckFines = true;
                    break;
                case "--economy":
                    flags.Economy = true;
                    break;
                case "--balance":
                    flags.Balance = true;
                    break;
                case "--phps-market":
                    flags.PhpsMarket = true;
                    break;
                case "--phps-buy":
                    flags.PhpsBuy = GetNextArg(args, ref i);
                    break;
                case "--phps-redeem":
                    flags.PhpsRedeem = GetNextArg(args, ref i);
                    break;
                case "--fee-quotes":
                    flags.FeeQuotes = true;
                    break;
                case "--fee-market":
                    flags.FeeMarket = true;
                    break;
                case "--fee-config":
                    flags.FeeConfigMin = TryParseDouble(GetNextArg(args, ref i));
                    flags.FeeConfigMax = TryParseDouble(GetNextArg(args, ref i));
                    flags.FeeConfigVolatility = TryParseDouble(GetNextArg(args, ref i));
                    break;
                case "--fee-enable":
                    flags.FeeConfigEnabled = true;
                    break;
                case "--fee-disable":
                    flags.FeeConfigEnabled = false;
                    break;
                case "--help":
                case "-h":
                    PrintHelp();
                    Environment.Exit(0);
                    break;
            }
        }
        return flags;
    }

    private static string? GetNextArg(string[] args, ref int i)
    {
        if (i + 1 < args.Length)
        {
            i++;
            return args[i];
        }
        return null;
    }

    private static double? TryParseDouble(string? s)
    {
        if (s is not null && double.TryParse(s, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var v))
            return v;
        return null;
    }

    private static void PrintHelp()
    {
        Console.WriteLine(@"
HPS Miner CLI v2.0 - $HPS Mining Utility
==========================================

Uso: hps-miner [opcoes]

Opcoes de conexao:
  --server, -s <host:port>    Endereco do servidor
  --user, -u <usuario>        Nome de usuario
  --ssl                       Usar SSL/TLS
  --no-ssl                    Nao usar SSL/TLS
  Senha: variavel de ambiente HPS_MINER_PASSWORD ou entrada interativa

Opcoes de mineracao:
  --continuous, -c            Mineracao continua
  --threads, -t <N>           Threads de mineracao PoW
  --start-mining              Iniciar mineracao imediatamente

Opcoes de operacao:
  --auto-sign                 Auto-assinar pendencias
  --no-auto-sign              Nao auto-assinar
  --auto-accept               Auto-aceitar selecao de minerador
  --auto-fine                 Pagamento automatico de multas
  --fine-promise              Promessa automatica de multa

Tarefas prioritarias:
  --sign-pending              [A] Verificar pendencias de assinatura
  --finalize-pow              [B] Finalizar PoW pendente
  --check-fines               [C] Verificar multas

Comandos de economia:
  --economy                   Exibir relatorio economico do servidor
  --balance                   Exibir saldo de vouchers do usuario
  --phps-market               Exibir dados do mercado pHPS
  --phps-buy <preco>          Comprar titulo pHPS pelo preco informado
  --phps-redeem <id>          Resgatar titulo pHPS pelo ID informado

Comandos de taxas variaveis:
  --fee-quotes                Exibir cotacoes de taxas dos mineradores
  --fee-market                Exibir dados do mercado de taxas
  --fee-config <min> <max> <vol>  Configurar taxas variaveis (min, max, volatilidade)
  --fee-enable                Habilitar taxas variaveis
  --fee-disable               Desabilitar taxas variaveis

Chaves:
  --export-keys <arquivo>     Exportar chaves
  --import-keys <arquivo>     Importar chaves
  Senha das chaves: variavel de ambiente HPS_KEY_PASS ou entrada interativa

Exemplos:
  hps-miner --server 192.168.1.100:8000 --user alice --continuous
  hps-miner -s localhost:8000 -u bob -t 4 --auto-sign --auto-accept
  hps-miner --sign-pending --check-fines
  hps-miner --server 192.168.1.100:8000 --economy
  hps-miner --server 192.168.1.100:8000 --user alice --balance
");
    }

    private static bool TryHandleKeyMode(string[] args)
    {
        var exportPath = ReadOption(args, "--export-keys");
        var importPath = ReadOption(args, "--import-keys");
        if (string.IsNullOrWhiteSpace(exportPath) && string.IsNullOrWhiteSpace(importPath))
        {
            return false;
        }

        // Sanitize file paths to prevent path traversal
        if (!string.IsNullOrWhiteSpace(exportPath))
        {
            exportPath = Path.GetFullPath(exportPath);
        }
        if (!string.IsNullOrWhiteSpace(importPath))
        {
            importPath = Path.GetFullPath(importPath);
        }

        var username = ReadOption(args, "--username") ?? ReadOption(args, "--user");
        var passphrase = ReadOption(args, "--key-pass");
        if (!string.IsNullOrWhiteSpace(passphrase))
        {
            Console.Error.WriteLine("AVISO: --key-pass via linha de comando e visivel em /proc/PID/cmdline. Prefira a variavel de ambiente HPS_KEY_PASS ou entrada interativa.");
        }
        else
        {
            var envKeyPass = Environment.GetEnvironmentVariable("HPS_KEY_PASS");
            if (!string.IsNullOrEmpty(envKeyPass))
            {
                passphrase = envKeyPass;
            }
            else
            {
                Console.Write("Senha das chaves: ");
                passphrase = ReadPasswordFromConsole();
            }
        }
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(passphrase))
        {
            Console.WriteLine("Uso: --export-keys <arquivo> --user <usuario>");
            Console.WriteLine(" ou: --import-keys <arquivo> --user <usuario>");
            Console.WriteLine("Senha: HPS_KEY_PASS (env) ou entrada interativa");
            return true;
        }

        try
        {
            var crypto = new CryptoService(MinerCryptoDir);

            if (!string.IsNullOrWhiteSpace(exportPath))
            {
                using var key = crypto.LoadOrCreateKeys(username, passphrase).loginPrivateKey;
                crypto.ExportEncryptedKeyBundle(username, exportPath);
                Console.WriteLine($"Chaves exportadas para: {exportPath}");
                return true;
            }

            if (!string.IsNullOrWhiteSpace(importPath))
            {
                try
                {
                    crypto.ImportEncryptedKeyBundle(username, importPath, passphrase);
                }
                catch (Exception importEx)
                {
                    Console.Error.WriteLine($"[ImportKeys] Formato encriptado falhou, tentando formato legado: {importEx.Message}");
                    var (key, _) = crypto.ImportKeys(importPath);
                    using (key)
                    {
                        crypto.OverwriteLoginKey(username, passphrase, key);
                    }
                }

                var (loaded, _, _) = crypto.LoadOrCreateKeys(username, passphrase);
                loaded.Dispose();

                Console.WriteLine($"Chaves importadas de: {importPath}");
                return true;
            }
        }
        catch (Exception ex)
        {
            var safeMsg = SanitizeErrorMessage(ex.Message);
            Console.WriteLine($"Falha ao processar chaves: {safeMsg}");
            return true;
        }

        return false;
    }

    private static string SanitizeErrorMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return "Erro desconhecido";
        var sanitized = message
            .Replace(@"\\", "/")
            .Replace("C:\\", "<PATH>/")
            .Replace("D:\\", "<PATH>/")
            .Replace("E:\\", "<PATH>/");
        var colonIdx = sanitized.IndexOf(':');
        if (colonIdx > 2 && colonIdx < sanitized.Length - 1)
        {
            var beforeColon = sanitized[..colonIdx];
            if (beforeColon.Length > 2 && beforeColon[1] == ':')
            {
                sanitized = "<PATH>" + sanitized[colonIdx..];
            }
        }
        return sanitized;
    }

    private static string ReadPasswordFromConsole()
    {
        var chars = new char[256];
        int len = 0;
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (len > 0) len--;
                continue;
            }
            if (!char.IsControl(key.KeyChar) && len < chars.Length)
            {
                chars[len++] = key.KeyChar;
            }
        }
        var result = new string(chars, 0, len);
        Array.Clear(chars, 0, len);
        return result;
    }

    private static string? ReadOption(string[] args, string option)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (!string.Equals(args[i], option, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (i + 1 >= args.Length)
            {
                return string.Empty;
            }

            return args[i + 1] ?? string.Empty;
        }

        return null;
    }

    private static async Task EnsureConnectedAsync(MainViewModel vm)
    {
        const int maxAttempts = 30;
        var attempt = 0;
        while (!vm.IsLoggedIn)
        {
            attempt++;
            if (attempt > maxAttempts)
            {
                Console.WriteLine($"[Login] Numero maximo de tentativas ({maxAttempts}) atingido. Desistindo.");
                return;
            }
            try
            {
                var connectTask = vm.ConnectCliAsync();
                var completed = await Task.WhenAny(connectTask, Task.Delay(TimeSpan.FromSeconds(8)));
                if (completed != connectTask)
                {
                    Console.WriteLine($"[Login] Timeout ao conectar (8s). Tentativa {attempt}/{maxAttempts}.");
                }
                else
                {
                    await connectTask;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Login] Falha ao conectar: {ex.Message}. Tentativa {attempt}/{maxAttempts}.");
            }
            var attemptTimeout = DateTimeOffset.UtcNow.AddSeconds(6);
            while (!vm.IsLoggedIn && DateTimeOffset.UtcNow < attemptTimeout)
            {
                await Task.Delay(250);
            }
            if (vm.IsLoggedIn)
            {
                return;
            }
            if (!string.IsNullOrWhiteSpace(vm.LoginStatus))
            {
                Console.WriteLine($"[Login] {vm.LoginStatus}");
            }
            Console.WriteLine($"Aguardando servidor... tentando novamente em 2s (tentativa {attempt}/{maxAttempts}).");
            await Task.Delay(2000);
        }
    }

    private static void PrintImportantChanges(MainViewModel vm, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.LoginStatus))
        {
            if (!string.IsNullOrWhiteSpace(vm.LoginStatus))
            {
                Console.WriteLine($"[Login] {vm.LoginStatus}");
            }
            return;
        }
        if (e.PropertyName is nameof(MainViewModel.HpsMiningStatus))
        {
            Console.WriteLine($"[Mining] {vm.HpsMiningStatus}");
            return;
        }
        if (e.PropertyName is nameof(MainViewModel.MinerFineStatus))
        {
            if (!string.IsNullOrWhiteSpace(vm.MinerFineStatus))
            {
                Console.WriteLine($"[Fine] {vm.MinerFineStatus}");
            }
            return;
        }
        if (e.PropertyName is nameof(MainViewModel.Status))
        {
            Console.WriteLine($"[Status] {vm.Status}");
        }
    }

    private static async Task HandleEconomyCommandsAsync(MinerFlags flags)
    {
        var server = flags.Server ?? CliPrompts.AskText("Servidor (host:porta)");
        var ssl = flags.Ssl ?? CliPrompts.AskYes("Usar SSL/TLS");
        var username = flags.User ?? CliPrompts.AskText("Usuario");

        Console.WriteLine("HPS Miner CLI v2.0 - $HPS Economy");
        Console.WriteLine("==================================");
        Console.WriteLine();

        var api = new ServerApiClient();

        if (flags.Economy)
        {
            Console.WriteLine("--- Relatório Econômico ---");
            var result = await api.FetchJsonPathAsync(server, ssl, "/economy/report");
            if (result is null)
                Console.WriteLine("Falha ao obter relatório econômico.");
            else
                PrintJson(result.Value);
            Console.WriteLine();
        }

        if (flags.Balance)
        {
            Console.WriteLine($"--- Saldo de Vouchers ({username}) ---");
            var safeUsername = Uri.EscapeDataString(username ?? "");
            var result = await api.FetchJsonPathAsync(server, ssl, $"/vouchers/user?username={safeUsername}");
            if (result is null)
                Console.WriteLine("Falha ao obter saldo.");
            else
                PrintJson(result.Value);
            Console.WriteLine();
        }

        if (flags.PhpsMarket)
        {
            Console.WriteLine("--- Mercado pHPS ---");
            var result = await api.FetchJsonPathAsync(server, ssl, "/phps/market");
            if (result is null)
                Console.WriteLine("Falha ao obter dados do mercado pHPS.");
            else
                PrintJson(result.Value);
            Console.WriteLine();
        }

        if (flags.PhpsBuy != null)
        {
            Console.WriteLine($"--- Compra Título pHPS ({flags.PhpsBuy} HPS) ---");
            if (!int.TryParse(flags.PhpsBuy, out var price) || price <= 0)
            {
                Console.WriteLine("Preço inválido. Use um número inteiro positivo.");
            }
            else
            {
                var result = await api.PostJsonAsync(server, ssl, "/phps/title/purchase", new { price });
                if (result is null)
                    Console.WriteLine("Falha na compra do título pHPS.");
                else
                    PrintJson(result.Value);
            }
            Console.WriteLine();
        }

        if (flags.PhpsRedeem != null)
        {
            Console.WriteLine($"--- Resgate Título pHPS ({flags.PhpsRedeem}) ---");
            var result = await api.PostJsonAsync(server, ssl, "/phps/title/redeem", new { title_id = flags.PhpsRedeem });
            if (result is null)
                Console.WriteLine("Falha no resgate do título pHPS.");
            else
                PrintJson(result.Value);
            Console.WriteLine();
        }
    }


    private static void PrintJson(JsonElement el)
    {
        if (el.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in el.EnumerateObject())
            {
                var val = prop.Value;
                if (val.ValueKind == JsonValueKind.String)
                    Console.WriteLine($"  {prop.Name}: {val.GetString()}");
                else if (val.ValueKind is JsonValueKind.Number)
                    Console.WriteLine($"  {prop.Name}: {val.GetRawText()}");
                else if (val.ValueKind is JsonValueKind.Array or JsonValueKind.Object)
                    Console.WriteLine($"  {prop.Name}: {val}");
                else
                    Console.WriteLine($"  {prop.Name}: {val.GetRawText()}");
            }
        }
        else
        {
            Console.WriteLine($"  {el}");
        }
    }
}

public class MinerFlags
{
    public string? Server { get; set; }
    public string? User { get; set; }
    public bool? Ssl { get; set; }
    public bool? AutoSign { get; set; }
    public bool? AutoAccept { get; set; }
    public bool? AutoFine { get; set; }
    public bool? FinePromise { get; set; }
    public bool? Continuous { get; set; }
    public int Threads { get; set; }
    public bool? StartMining { get; set; }
    public bool SignPending { get; set; }
    public bool FinalizePow { get; set; }
    public bool CheckFines { get; set; }
    public bool Economy { get; set; }
    public bool Balance { get; set; }
    public bool PhpsMarket { get; set; }
    public string? PhpsBuy { get; set; }
    public string? PhpsRedeem { get; set; }
    public bool FeeQuotes { get; set; }
    public bool FeeMarket { get; set; }
    public double? FeeConfigMin { get; set; }
    public double? FeeConfigMax { get; set; }
    public double? FeeConfigVolatility { get; set; }
    public bool? FeeConfigEnabled { get; set; }
}
