using System.ComponentModel;
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

        Console.WriteLine("HPS Miner (CLI)");
        Console.WriteLine("================");

        var vm = new MainViewModel(new CliFileDialogService(), new CliPromptService(), new CliContractDialogService(), MinerCryptoDir, useUiDispatcher: false, minerMode: true);
        vm.ShowTourOnStartup = false;

        vm.ServerAddress = CliPrompts.AskText("Servidor (host:porta)");
        vm.UseSsl = CliPrompts.AskYes("Usar SSL/TLS");
        vm.Username = CliPrompts.AskText("Usuario");
        vm.KeyPassphrase = CliPrompts.AskPassword("Senha");

        vm.AutoSignTransfers = CliPrompts.AskYes("Auto-assinar pendencias");
        vm.AutoAcceptMinerSelection = CliPrompts.AskYes("Auto-aceitar selecao de minerador");

        var autoFine = CliPrompts.AskYes("Ativar pagamento automatico de multas");
        vm.MinerAutoPayFine = autoFine;
        if (!autoFine)
        {
            vm.MinerFinePromise = CliPrompts.AskYes("Ativar promessa automatica de multa");
        }

        vm.IsContinuousMiningEnabled = CliPrompts.AskYes("Ativar mineracao continua");
        vm.PowThreads = CliPrompts.AskInt("Threads de mineracao PoW", 1, vm.MaxPowThreads, vm.PowThreads);
        (vm.SavePowSettingsCommand as RelayCommand)?.Execute(null);

        vm.PropertyChanged += (_, e) => PrintImportantChanges(vm, e);

        Console.WriteLine("Conectando...");
        await EnsureConnectedAsync(vm);

        if (vm.IsLoggedIn)
        {
            Console.WriteLine("Logado com sucesso.");
            if (!vm.IsContinuousMiningEnabled && CliPrompts.AskYes("Iniciar mineracao agora"))
            {
                (vm.StartHpsMintCommand as AsyncRelayCommand)?.Execute(null);
            }
        }

        var shutdownRequested = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        ConsoleCancelEventHandler? cancelHandler = null;
        cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("Encerrando...");
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

    private static bool TryHandleKeyMode(string[] args)
    {
        var exportPath = ReadOption(args, "--export-keys");
        var importPath = ReadOption(args, "--import-keys");
        if (string.IsNullOrWhiteSpace(exportPath) && string.IsNullOrWhiteSpace(importPath))
        {
            return false;
        }

        var username = ReadOption(args, "--username");
        var passphrase = ReadOption(args, "--key-pass");
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(passphrase))
        {
            Console.WriteLine("Uso: --cli [--export-keys <arquivo> | --import-keys <arquivo>] --username <usuario> --key-pass <senha>");
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
                catch
                {
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
            Console.WriteLine($"Falha ao processar chaves: {ex.Message}");
            return true;
        }

        return false;
    }

    private static string ReadOption(string[] args, string option)
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

        return string.Empty;
    }

    private static async Task EnsureConnectedAsync(MainViewModel vm)
    {
        while (!vm.IsLoggedIn)
        {
            try
            {
                var connectTask = vm.ConnectCliAsync();
                var completed = await Task.WhenAny(connectTask, Task.Delay(TimeSpan.FromSeconds(8)));
                if (completed != connectTask)
                {
                    Console.WriteLine("[Login] Timeout ao conectar (8s).");
                }
                else
                {
                    await connectTask;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Login] Falha ao conectar: {ex.Message}");
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
            Console.WriteLine("Aguardando servidor... tentando novamente em 2s.");
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
}
