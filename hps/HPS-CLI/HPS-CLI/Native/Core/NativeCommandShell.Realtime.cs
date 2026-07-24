using System.Text;
using System.Text.Json;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Globalization;
using Hps.Cli.Native.Socket;
using Hps.Cli.Native.Storage;

namespace Hps.Cli.Native.Core;

public sealed partial class NativeCommandShell
{
    private async Task<int> RunDnsRegister(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            _display.PrintError("uso: dns-reg <domain> <content_hash>");
            return 2;
        }
        var domain = args[0].Trim().ToLowerInvariant();
        var contentHash = args[1].Trim();
        if (!IsValidDomain(domain))
        {
            _display.PrintError("dominio invalido. use letras, numeros, pontos e hifen");
            return 2;
        }
        if (!LooksLikeHash(contentHash))
        {
            _display.PrintError("hash de conteudo invalido");
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

        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["DOMAIN"] = domain,
            ["CONTENT_HASH"] = contentHash,
            ["PUBLIC_KEY"] = _service.PublicKeyBase64(),
            ["TS"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
        };
        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
            return 6;
        }
        var contractTemplate = _service.BuildContractTemplate("register_dns", details);
        var contractSigned = _service.SignContractTemplate(contractTemplate);
        var ddnsBase = _service.CreateDdnsFile(domain, contentHash);
        var ddnsBaseBytes = Encoding.UTF8.GetBytes(ddnsBase);
        var ddnsFullBytes = ddnsBaseBytes.Concat(Encoding.UTF8.GetBytes(contractSigned)).ToArray();
        var headerEnd = Encoding.UTF8.GetBytes("### :END START");
        var signatureBase = ddnsBaseBytes;
        var markerIndex = ddnsBaseBytes.AsSpan().IndexOf(headerEnd);
        if (markerIndex >= 0)
        {
            var start = markerIndex + headerEnd.Length;
            signatureBase = ddnsBaseBytes[start..];
        }
        var signatureB64 = Convert.ToBase64String(_service.SignContent(signatureBase));

        _service.SaveDdnsToStorage(domain, ddnsBaseBytes, new DdnsRecord
        {
            Domain = domain,
            ContentHash = contentHash,
            Timestamp = DateTimeOffset.UtcNow,
            Signature = signatureB64,
            PublicKey = _service.PublicKeyBase64(),
            Verified = true
        });

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var (nonce, rate) = await session.SolvePowAsync("dns", ct).ConfigureAwait(false);
        var result = await session.EmitAndWaitAsync(
            "register_dns",
            new
            {
                domain,
                ddns_content = Convert.ToBase64String(ddnsFullBytes),
                signature = signatureB64,
                public_key = _service.PublicKeyBase64(),
                pow_nonce = nonce,
                hashrate_observed = rate
            },
            "dns_result",
            TimeSpan.FromSeconds(90),
            ct).ConfigureAwait(false);

        if (result.TryGetProperty("pending", out var pending) && pending.ValueKind == JsonValueKind.True)
        {
            _display.PrintWarning("dns-reg pendente de confirmacao monetaria no servidor");
            return 0;
        }
        if (!ReadSuccess(result))
        {
            _display.PrintError(ReadError(result));
            return 5;
        }

        _service.SaveDns(domain, contentHash);
        _service.IncrementStat("dns_registered");
        _display.PrintSuccess("dns registrado com sucesso");
        return 0;
    }

    private async Task<int> RunNetwork(string[] args, CancellationToken ct)
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

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var result = await session.EmitAndWaitAsync("get_network_state", new { }, "network_state", TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);
        if (result.TryGetProperty("error", out var err) && !string.IsNullOrWhiteSpace(err.GetString()))
        {
            _display.PrintError(err.GetString()!);
            return 5;
        }
        Console.WriteLine(result.GetRawText());
        return 0;
    }

    private async Task<int> RunSecurity(string[] args, CancellationToken ct)
    {
        if (args.Length < 1)
        {
            _display.PrintError("uso: security <content_hash>");
            return 2;
        }
        var hash = args[0].Trim().ToLowerInvariant();
        if (!LooksLikeHash(hash))
        {
            _display.PrintError("hash invalido");
            return 2;
        }

        var local = _service.LoadCachedContent(hash);
        if (local is null)
        {
            var server = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(server))
            {
                _display.PrintError("conteudo nao encontrado localmente e sem servidor ativo");
                return 3;
            }
            var content = await _http.FetchContentAsync(server, hash, ct).ConfigureAwait(false);
            if (!content.Ok)
            {
                _display.PrintError(content.Error);
                return 4;
            }
            if (!_service.IsCryptoUnlocked)
            {
                _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
                return 6;
            }
            _service.SaveContentToStorage(hash, content.Data, new ContentCacheRecord
            {
                ContentHash = hash,
                MimeType = content.Mime,
                LastAccessed = DateTimeOffset.UtcNow
            });
            local = _service.LoadCachedContent(hash);
        }
        if (local is null)
        {
            _display.PrintError("falha ao carregar conteudo");
            return 5;
        }

        var computed = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(local.Value.Content)).ToLowerInvariant();
        var ok = string.Equals(computed, hash, StringComparison.OrdinalIgnoreCase);
        var relatedContracts = _service.ListContracts(500)
            .Where(x => string.Equals(x.ContentHash, hash, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.Timestamp)
            .ToList();

        _display.PrintInfo($"hash={hash}");
        _display.PrintInfo($"integrity={(ok ? "ok" : "fail")} computed={computed}");
        _display.PrintInfo($"mime={local.Value.Metadata.MimeType} bytes={local.Value.Content.LongLength}");
        _display.PrintInfo($"contracts={relatedContracts.Count}");
        foreach (var c in relatedContracts.Take(10))
        {
            Console.WriteLine($"{c.ContractId} | action={c.ActionType} | user={c.Username} | verified={c.Verified}");
        }
        return ok ? 0 : 7;
    }

    private async Task<int> RunReport(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            _display.PrintError("uso: report <content_hash> <reported_user>");
            return 2;
        }
        var hash = args[0].Trim().ToLowerInvariant();
        var reportedUser = args[1].Trim();
        if (!LooksLikeHash(hash) || string.IsNullOrWhiteSpace(reportedUser))
        {
            _display.PrintError("uso: report <content_hash> <reported_user>");
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

        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CONTENT_HASH"] = hash,
            ["REPORTED_USER"] = reportedUser,
            ["REPORTER"] = user,
            ["TIMESTAMP"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
        };
        var contract = _service.SignContractTemplate(_service.BuildContractTemplate("report_content", details));

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var (nonce, rate) = await session.SolvePowAsync("report", ct).ConfigureAwait(false);
        var result = await session.EmitAndWaitAsync(
            "report_content",
            new
            {
                content_hash = hash,
                reported_user = reportedUser,
                contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contract)),
                pow_nonce = nonce,
                hashrate_observed = rate
            },
            "report_result",
            TimeSpan.FromSeconds(90),
            ct).ConfigureAwait(false);

        if (result.TryGetProperty("pending", out var pending) && pending.ValueKind == JsonValueKind.True)
        {
            _display.PrintWarning("report pendente de confirmacao monetaria no servidor");
            return 0;
        }
        if (!ReadSuccess(result))
        {
            _display.PrintError(ReadError(result));
            return 5;
        }
        _service.IncrementStat("content_reported");
        _display.PrintSuccess("conteudo reportado com sucesso");
        return 0;
    }

    private async Task<int> RunActions(string[] args, CancellationToken ct)
    {
        if (args.Length < 1)
        {
            _display.PrintSection("HPS Actions");
            _display.PrintInfo("actions transfer-file <content_hash> <target_user>");
            _display.PrintInfo("actions transfer-domain <domain> <new_owner>");
            return 0;
        }
        var sub = args[0].ToLowerInvariant();
        if (sub == "transfer-file")
        {
            if (args.Length < 3)
            {
                _display.PrintError("uso: actions transfer-file <content_hash> <target_user>");
                return 2;
            }
            var contentHash = args[1].Trim().ToLowerInvariant();
            var transferTargetUser = args[2].Trim();
            if (!LooksLikeHash(contentHash) || string.IsNullOrWhiteSpace(transferTargetUser))
            {
                _display.PrintError("hash ou usuario invalido");
                return 2;
            }
            var cached = _service.LoadCachedContent(contentHash);
            if (cached is null)
            {
                _display.PrintError("conteudo nao encontrado no cache local. baixe antes de transferir");
                return 3;
            }
            var title = BuildHpsTransferTitle("file", transferTargetUser);
            return await UploadContentBytesWithActionAsync(
                title,
                cached.Value.Metadata.Description,
                string.IsNullOrWhiteSpace(cached.Value.Metadata.MimeType) ? "application/octet-stream" : cached.Value.Metadata.MimeType,
                cached.Value.Content,
                "transfer_content",
                ct).ConfigureAwait(false);
        }
        if (sub == "transfer-domain")
        {
            if (args.Length < 3)
            {
                _display.PrintError("uso: actions transfer-domain <domain> <new_owner>");
                return 2;
            }
            var domain = args[1].Trim().ToLowerInvariant();
            var newOwner = args[2].Trim();
            if (!IsValidDomain(domain) || string.IsNullOrWhiteSpace(newOwner))
            {
                _display.PrintError("dominio ou novo dono invalido");
                return 2;
            }
            var title = BuildHpsDnsChangeTitle();
            var payload = BuildDomainTransferPayload(domain, newOwner, _service.CurrentUser);
            return await UploadContentBytesWithActionAsync(
                title,
                string.Empty,
                "text/plain",
                payload,
                "transfer_domain",
                ct).ConfigureAwait(false);
        }
        if (sub == "transfer-api")
        {
            if (args.Length < 4)
            {
                _display.PrintError("uso: actions transfer-api <app_name> <target_user> <file_path>");
                return 2;
            }
            var appName = args[1].Trim();
            var transferTargetUser = args[2].Trim();
            var filePath = args[3].Trim();
            if (string.IsNullOrWhiteSpace(appName) || string.IsNullOrWhiteSpace(transferTargetUser) || string.IsNullOrWhiteSpace(filePath))
            {
                _display.PrintError("app, usuario ou arquivo invalido");
                return 2;
            }
            var resolvedPath = Path.GetFullPath(filePath);
            var currentDir = Path.GetFullPath(".");
            if (!resolvedPath.StartsWith(currentDir, StringComparison.OrdinalIgnoreCase))
            {
                _display.PrintError("caminho do arquivo invalido (fora do diretorio atual)");
                return 2;
            }
            if (!File.Exists(resolvedPath))
            {
                _display.PrintError("arquivo nao encontrado: " + resolvedPath);
                return 2;
            }
            var contentBytes = await File.ReadAllBytesAsync(resolvedPath, ct).ConfigureAwait(false);
            var mimeType = InferMimeType(resolvedPath);
            var title = BuildHpsTransferTitle("api_app", transferTargetUser, appName);
            return await UploadContentBytesWithActionAsync(
                title,
                string.Empty,
                mimeType,
                contentBytes,
                "transfer_api_app",
                ct).ConfigureAwait(false);
        }
        if (sub == "api-app")
        {
            if (args.Length < 3)
            {
                _display.PrintError("uso: actions api-app <app_name> <file_path>");
                return 2;
            }
            var appName = args[1].Trim();
            var filePath = args[2].Trim();
            if (string.IsNullOrWhiteSpace(appName) || string.IsNullOrWhiteSpace(filePath))
            {
                _display.PrintError("app ou arquivo invalido");
                return 2;
            }
            if (!File.Exists(filePath))
            {
                _display.PrintError("arquivo nao encontrado: " + filePath);
                return 2;
            }
            var contentBytes = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
            var mimeType = InferMimeType(filePath);
            var title = BuildHpsApiTitle(appName);
            return await UploadContentBytesWithActionAsync(
                title,
                string.Empty,
                mimeType,
                contentBytes,
                "upload_file",
                ct).ConfigureAwait(false);
        }
        _display.PrintError("subcomando desconhecido. use: actions transfer-file|transfer-domain|transfer-api|api-app");
        return 2;
    }

    private async Task<int> RunTransferHpsAsync(string targetUser, long amount, CancellationToken ct)
    {
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("nenhum servidor ativo. use 'servers add' e 'use'.");
            return 4;
        }

        var vouchers = _service.ListSpendableVouchers(server, 2000)
            .Where(v => !v.Invalidated &&
                        !string.Equals(v.Status, "spent", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(v.Status, "reserved", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(v => v.Value)
            .ToList();
        var selected = new List<string>();
        long sum = 0;
        foreach (var v in vouchers)
        {
            if (v.Value <= 0)
            {
                continue;
            }
            selected.Add(v.VoucherId);
            sum += v.Value;
            if (sum >= amount)
            {
                break;
            }
        }
        if (sum < amount || selected.Count == 0)
        {
            _display.PrintError($"saldo insuficiente para transferir {amount} HPS");
            return 3;
        }

        var user = _service.CurrentUser;
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("usuario/servidor nao definidos");
            return 4;
        }
        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
            return 6;
        }

        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["TARGET_USER"] = targetUser,
            ["AMOUNT"] = amount.ToString(),
            ["VOUCHER_IDS"] = JsonSerializer.Serialize(selected)
        };
        var contract = _service.SignContractTemplate(_service.BuildContractTemplate("transfer_hps", details));

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var (nonce, rate) = await session.SolvePowAsync("hps_transfer", ct).ConfigureAwait(false);
        var result = await session.EmitAndWaitAsync(
            "transfer_hps",
            new
            {
                target_user = targetUser,
                amount,
                voucher_ids = selected,
                contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contract)),
                pow_nonce = nonce,
                hashrate_observed = rate
            },
            "hps_transfer_ack",
            TimeSpan.FromSeconds(90),
            ct).ConfigureAwait(false);

        if (result.TryGetProperty("pending", out var pending) && pending.ValueKind == JsonValueKind.True)
        {
            _display.PrintWarning("transferencia pendente de confirmacao monetaria no servidor");
            return 0;
        }
        if (!ReadSuccess(result))
        {
            _display.PrintError(ReadError(result));
            return 5;
        }

        _display.PrintSuccess("transferencia HPS enviada");
        return 0;
    }

    private async Task<int> UploadContentBytesWithActionAsync(
        string title,
        string description,
        string mimeType,
        byte[] content,
        string contractAction,
        CancellationToken ct)
    {
        if (content is null || content.Length == 0)
        {
            _display.PrintError("conteudo vazio");
            return 2;
        }
        var user = _service.CurrentUser;
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("usuario/servidor nao definidos");
            return 4;
        }
        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
            return 6;
        }

        var fileHash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["FILE_NAME"] = title,
            ["FILE_SIZE"] = content.Length.ToString(),
            ["FILE_HASH"] = fileHash,
            ["TITLE"] = title,
            ["MIME"] = mimeType,
            ["DESCRIPTION"] = description ?? string.Empty,
            ["PUBLIC_KEY"] = _service.PublicKeyBase64()
        };
        var (transferType, transferTo, transferApp) = ParseTransferTitle(title);
        if (title == BuildHpsDnsChangeTitle())
        {
            var (domain, _) = ParseDomainTransferPayload(content);
            if (!string.IsNullOrWhiteSpace(domain))
            {
                details["DOMAIN"] = domain;
            }
        }
        if (!string.IsNullOrWhiteSpace(transferTo))
        {
            details["TRANSFER_TO"] = transferTo;
        }
        if (!string.IsNullOrWhiteSpace(transferType))
        {
            details["TRANSFER_TYPE"] = transferType;
        }
        if (!string.IsNullOrWhiteSpace(transferApp))
        {
            details["APP"] = transferApp;
        }

        var contract = _service.SignContractTemplate(_service.BuildContractTemplate(contractAction, details));
        var fullContent = content.Concat(Encoding.UTF8.GetBytes(contract)).ToArray();
        var signatureB64 = Convert.ToBase64String(_service.SignContent(content));
        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var (nonce, rate) = await session.SolvePowAsync("upload", ct).ConfigureAwait(false);
        var result = await session.EmitAndWaitAsync(
            "publish_content",
            new
            {
                content_hash = fileHash,
                title,
                description = description ?? string.Empty,
                mime_type = mimeType,
                size = content.LongLength,
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
            _display.PrintWarning("acao pendente de confirmacao monetaria no servidor");
            return 0;
        }
        if (!ReadSuccess(result))
        {
            _display.PrintError(ReadError(result));
            return 5;
        }

        _service.SaveContentToStorage(fileHash, content, new ContentCacheRecord
        {
            ContentHash = fileHash,
            MimeType = mimeType,
            FileName = title,
            Title = title,
            Description = description ?? string.Empty
        });
        _ = await SyncWalletStateAsync(session, ct).ConfigureAwait(false);
        _service.IncrementStat("content_uploaded");
        _service.IncrementStat("data_sent_bytes", content.LongLength);
        _display.PrintSuccess($"acao enviada com sucesso hash={fileHash}");
        return 0;
    }

    private static string BuildHpsTransferTitle(string transferType, string targetUser, string? appName = null)
    {
        if (transferType == "api_app" && !string.IsNullOrWhiteSpace(appName))
        {
            return $"(HPS!transfer){{type={transferType}, to={targetUser}, app={appName}}}";
        }
        return $"(HPS!transfer){{type={transferType}, to={targetUser}}}";
    }

    private static string BuildHpsApiTitle(string appName) => $"(HPS!api){{app}}:{{\"{appName}\"}}";

    private static string ExtractAppName(string title)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return string.Empty;
        }
        var m = System.Text.RegularExpressions.Regex.Match(title, @"\(HPS!api\)\{app\}:\{""([^""]+)""\}");
        if (m.Success)
        {
            return m.Groups[1].Value.Trim();
        }
        var m2 = System.Text.RegularExpressions.Regex.Match(title, @"\(HPS!api\)\{app=([^}]+)\}");
        if (m2.Success)
        {
            return m2.Groups[1].Value.Trim();
        }
        return string.Empty;
    }

    private static string InferMimeType(string filePath)
    {
        var ext = Path.GetExtension(filePath)?.ToLowerInvariant();
        return ext switch
        {
            ".html" or ".htm" => "text/html",
            ".css" => "text/css",
            ".js" => "application/javascript",
            ".json" => "application/json",
            ".xml" => "application/xml",
            ".pdf" => "application/pdf",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".svg" => "image/svg+xml",
            ".ico" => "image/x-icon",
            ".webp" => "image/webp",
            ".mp4" => "video/mp4",
            ".webm" => "video/webm",
            ".mp3" => "audio/mpeg",
            ".wav" => "audio/wav",
            ".ogg" => "audio/ogg",
            ".woff" => "font/woff",
            ".woff2" => "font/woff2",
            ".ttf" => "font/ttf",
            ".zip" => "application/zip",
            ".gz" => "application/gzip",
            ".tar" => "application/x-tar",
            ".txt" => "text/plain",
            ".md" => "text/markdown",
            ".csv" => "text/csv",
            ".yml" or ".yaml" => "application/x-yaml",
            _ => "application/octet-stream"
        };
    }

    private static string BuildHpsDnsChangeTitle() => "(HPS!dns_change){change_dns_owner=true, proceed=true}";

    private static byte[] BuildDomainTransferPayload(string domain, string newOwner, string currentUser)
    {
        var lines = new[]
        {
            "# HSYST P2P SERVICE",
            "### START:",
            $"# USER: {currentUser}",
            "### :END START",
            "### DNS:",
            $"# NEW_DNAME: DOMAIN = {domain}",
            $"# NEW_DOWNER: OWNER = {newOwner}",
            "### :END DNS",
            "### MODIFY:",
            "# change_dns_owner = true",
            "# proceed = true",
            "### :END MODIFY"
        };
        return Encoding.UTF8.GetBytes(string.Join("\n", lines));
    }

    private static (string TransferType, string TargetUser, string AppName) ParseTransferTitle(string title)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return (string.Empty, string.Empty, string.Empty);
        }
        var m = System.Text.RegularExpressions.Regex.Match(title, @"\(HPS!transfer\)\{type=([^,}]+),\s*to=([^,}]+)(?:,\s*app=([^}]+))?\}");
        if (!m.Success)
        {
            return (string.Empty, string.Empty, string.Empty);
        }
        var transferType = m.Groups[1].Value.Trim().ToLowerInvariant();
        var targetUser = m.Groups[2].Value.Trim();
        var appName = m.Groups.Count > 3 ? m.Groups[3].Value.Trim() : string.Empty;
        return (transferType, targetUser, appName);
    }

    private static (string Domain, string NewOwner) ParseDomainTransferPayload(byte[] content)
    {
        var text = Encoding.UTF8.GetString(content ?? []);
        var domain = string.Empty;
        var newOwner = string.Empty;
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("# NEW_DNAME:", StringComparison.Ordinal))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2)
                {
                    domain = parts[1].Trim();
                }
            }
            else if (line.StartsWith("# NEW_DOWNER:", StringComparison.Ordinal))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2)
                {
                    newOwner = parts[1].Trim();
                }
            }
        }
        return (domain, newOwner);
    }



    private async Task<int> RunWallet(string[] args, CancellationToken ct)
    {
        if (args.Length == 0)
        {
            var currentServer = _service.GetCurrentServer();
            var localVouchers = _service.ListSpendableVouchers(currentServer, 5000);
            var balance = localVouchers
                .Where(v => !v.Invalidated &&
                            string.Equals(v.Status, "valid", StringComparison.OrdinalIgnoreCase))
                .Sum(v => v.Value);
            _display.PrintSection("Carteira HPS");
            _display.PrintInfo($"Servidor: {currentServer}");
            _display.PrintInfo($"Saldo local: {balance} HPS");
            _display.PrintInfo($"Vouchers locais: {localVouchers.Count}");
            _display.PrintInfo($"Auto-mint: {(_walletAutoMintEnabled ? "on" : "off")}");
            _display.PrintInfo($"Monitor assinaturas: {(_walletSignatureMonitorEnabled ? "on" : "off")}");
            _display.PrintInfo($"Assinatura auto: {(_walletSignatureAutoEnabled ? "on" : "off")}");
            var fineMode = _walletFineAutoEnabled ? "auto" : _walletFinePromiseEnabled ? "promessa" : "manual";
            _display.PrintInfo($"Multa: {fineMode}");
            _display.PrintInfo("wallet refresh");
            _display.PrintInfo("wallet list");
            _display.PrintInfo("wallet show <voucher_id>");
            _display.PrintInfo("wallet mint [--reason TEXT]");
            _display.PrintInfo("wallet auto-mint on|off");
            _display.PrintInfo("wallet transfer <target_user> <amount>");
            _display.PrintInfo("wallet signature-monitor on|off");
            _display.PrintInfo("wallet signature-auto on|off");
            _display.PrintInfo("wallet auto-select on|off");
            _display.PrintInfo("wallet fine-auto on|off");
            _display.PrintInfo("wallet fine-promise on|off");
            _display.PrintInfo("wallet sign-transfer <transfer_id>");
            return 0;
        }

        var action = args[0].ToLowerInvariant();
        if (action == "mint")
        {
            var reason = "mining";
            for (var i = 1; i < args.Length; i++)
            {
                if (args[i] == "--reason" && i + 1 < args.Length)
                {
                    reason = args[++i];
                }
            }
            return await MintHpsVoucherAsync(reason, ct).ConfigureAwait(false);
        }
        if (action == "auto-mint")
        {
            if (args.Length < 2 || !TryParseOnOff(args[1], out var on))
            {
                _display.PrintError("uso: wallet auto-mint on|off");
                return 2;
            }
            _walletAutoMintEnabled = on;
            _display.PrintInfo(_walletAutoMintEnabled ? "auto-mint ativado" : "auto-mint desativado");
            if (_walletAutoMintEnabled)
            {
                StartAutoMintLoop();
            }
            else
            {
                StopAutoMintLoop();
            }
            return 0;
        }
        if (action == "fine-auto")
        {
            if (args.Length < 2 || !TryParseOnOff(args[1], out var on))
            {
                _display.PrintError("uso: wallet fine-auto on|off");
                return 2;
            }
            _walletFineAutoEnabled = on;
            if (on)
            {
                _walletFinePromiseEnabled = false;
            }
            _display.PrintInfo(_walletFineAutoEnabled ? "multa automatica ativada" : "multa automatica desativada");
            return 0;
        }
        if (action == "fine-promise")
        {
            if (args.Length < 2 || !TryParseOnOff(args[1], out var on))
            {
                _display.PrintError("uso: wallet fine-promise on|off");
                return 2;
            }
            _walletFinePromiseEnabled = on;
            if (on)
            {
                _walletFineAutoEnabled = false;
            }
            _display.PrintInfo(_walletFinePromiseEnabled ? "promessa de multa ativada" : "promessa de multa desativada");
            return 0;
        }
        if (action == "transfer")
        {
            if (args.Length < 3)
            {
                _display.PrintError("uso: wallet transfer <target_user> <amount>");
                return 2;
            }
            if (!long.TryParse(args[2], out var amount) || amount <= 0)
            {
                _display.PrintError("uso: wallet transfer <target_user> <amount>");
                return 2;
            }
            return await RunTransferHpsAsync(args[1].Trim(), amount, ct).ConfigureAwait(false);
        }
        if (action == "signature-monitor")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: wallet signature-monitor on|off");
                return 2;
            }
            if (!TryParseOnOff(args[1], out var monitorDefined))
            {
                _display.PrintError("uso: wallet signature-monitor on|off");
                return 2;
            }
            _walletSignatureMonitorEnabled = monitorDefined;
            if (_walletSignatureMonitorEnabled)
            {
                _display.PrintSuccess("monitoramento de assinaturas ativado");
                StartSignatureMonitorLoop();
                TriggerSignatureMonitorCheck(ct, _walletSignatureAutoEnabled);
            }
            else
            {
                StopSignatureMonitorLoop();
                _display.PrintInfo("monitoramento de assinaturas desativado");
            }
            return 0;
        }
        if (action == "signature-auto")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: wallet signature-auto on|off");
                return 2;
            }
            if (!TryParseOnOff(args[1], out var autoDefined))
            {
                _display.PrintError("uso: wallet signature-auto on|off");
                return 2;
            }
            _walletSignatureAutoEnabled = autoDefined;
            if (_walletSignatureAutoEnabled)
            {
                _walletSignatureMonitorEnabled = true;
                StartSignatureMonitorLoop();
                _display.PrintSuccess("assinatura automatica ativada");
                TriggerSignatureMonitorCheck(ct, autoSign: true);
            }
            else
            {
                _display.PrintInfo("assinatura automatica desativada");
            }
            return 0;
        }
        if (action == "auto-select")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: wallet auto-select on|off");
                return 2;
            }
            if (!TryParseOnOff(args[1], out var autoSelect))
            {
                _display.PrintError("uso: wallet auto-select on|off");
                return 2;
            }
            _walletSignatureAutoEnabled = autoSelect;
            _walletSignatureMonitorEnabled = autoSelect;
            if (_walletSignatureMonitorEnabled)
            {
                StartSignatureMonitorLoop();
            }
            else
            {
                StopSignatureMonitorLoop();
            }
            _display.PrintInfo(_walletSignatureAutoEnabled ? "auto-select ativado" : "auto-select desativado");
            return 0;
        }
        if (action == "sign-transfer")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: wallet sign-transfer <transfer_id>");
                return 2;
            }
            var transferId = args[1].Trim();
            if (string.IsNullOrWhiteSpace(transferId))
            {
                _display.PrintError("transfer_id obrigatorio");
                return 2;
            }

            var currentUser = _service.CurrentUser;
            var currentServer = _service.RequireCurrentServer();
            if (string.IsNullOrWhiteSpace(currentUser) || string.IsNullOrWhiteSpace(currentServer))
            {
                _display.PrintError("usuario/servidor nao definidos");
                return 4;
            }
            if (!_service.IsCryptoUnlocked)
            {
                _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
                return 6;
            }

            await using var signSession = await HpsRealtimeSession.ConnectAuthenticatedAsync(currentServer, currentUser, _service, _ctx, _display, ct).ConfigureAwait(false);
            JsonElement target = default;
            var hasTarget = false;
            try
            {
                var minerTransferPayload = await signSession.EmitAndWaitAsync(
                    "get_miner_transfer",
                    new { transfer_id = transferId },
                    "miner_transfer",
                    TimeSpan.FromSeconds(12),
                    ct).ConfigureAwait(false);
                if (ReadSuccess(minerTransferPayload) &&
                    minerTransferPayload.TryGetProperty("transfer", out var transferObj) &&
                    transferObj.ValueKind == JsonValueKind.Object)
                {
                    target = transferObj;
                    hasTarget = true;
                }
                else if (minerTransferPayload.TryGetProperty("error", out var minerError) && !string.IsNullOrWhiteSpace(minerError.GetString()))
                {
                    _display.PrintWarning("get_miner_transfer: " + minerError.GetString());
                }
            }
            catch (TimeoutException)
            {
                _display.PrintWarning("get_miner_transfer indisponivel, tentando fallback");
            }

            if (!hasTarget)
            {
                var pending = await signSession.EmitAndWaitAsync("get_pending_transfers", new { }, "pending_transfers", TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);
                if (pending.TryGetProperty("error", out var pendingErr) && !string.IsNullOrWhiteSpace(pendingErr.GetString()))
                {
                    _display.PrintError(pendingErr.GetString()!);
                    return 5;
                }
                if (!pending.TryGetProperty("transfers", out var transfers) || transfers.ValueKind != JsonValueKind.Array)
                {
                    _display.PrintError("nenhuma transferencia pendente");
                    return 5;
                }
                var candidate = transfers.EnumerateArray().FirstOrDefault(x =>
                    x.TryGetProperty("transfer_id", out var id) &&
                    string.Equals(id.GetString(), transferId, StringComparison.OrdinalIgnoreCase));
                if (candidate.ValueKind != JsonValueKind.Object)
                {
                    _display.PrintError("transferencia nao encontrada");
                    return 5;
                }
                target = candidate;
            }

            var lockedVouchers = target.TryGetProperty("locked_voucher_ids", out var locked)
                ? ParseJsonStringArray(locked)
                : [];

            var transferType = target.TryGetProperty("transfer_type", out var tType) ? tType.GetString() ?? string.Empty : string.Empty;
            var sender = target.TryGetProperty("sender", out var tSender) ? tSender.GetString() ?? string.Empty : string.Empty;
            var receiver = target.TryGetProperty("receiver", out var tReceiver) ? tReceiver.GetString() ?? string.Empty : string.Empty;
            var contractId = target.TryGetProperty("contract_id", out var tContract) ? tContract.GetString() ?? string.Empty : string.Empty;
            var amount = target.TryGetProperty("amount", out var tAmount) ? tAmount.ToString() : "0";
            var feeAmount = target.TryGetProperty("fee_amount", out var tFeeAmount) ? tFeeAmount.ToString() : "0";
            var feeSource = target.TryGetProperty("fee_source", out var tFeeSource) ? tFeeSource.GetString() ?? string.Empty : string.Empty;
            var interServerPayload = target.TryGetProperty("inter_server_payload", out var interServerPayloadElement)
                ? interServerPayloadElement
                : (target.TryGetProperty("inter_server", out var interServerElement) ? interServerElement : default);

            var voucherAuditJson = "[]";
            var voucherPowAuditJson = "[]";
            var voucherTraceJson = "[]";
            Dictionary<string, string>? interServerEvidenceDetails = null;
            if (lockedVouchers.Count > 0)
            {
                var audit = await _http.AuditVouchersAsync(currentServer, lockedVouchers, ct).ConfigureAwait(false);
                if (!audit.Ok)
                {
                    _display.PrintError("falha ao auditar vouchers: " + audit.Error);
                    return 5;
                }
                var reportData = BuildVoucherReportData(audit.RawJson, lockedVouchers, transferType.Equals("exchange_in", StringComparison.OrdinalIgnoreCase));
                if (!reportData.Ok)
                {
                    _display.PrintError("falha ao processar auditoria de vouchers: " + reportData.Error);
                    return 5;
                }
                voucherAuditJson = reportData.VoucherAuditJson;
                voucherPowAuditJson = reportData.VoucherPowAuditJson;
                voucherTraceJson = reportData.VoucherTraceJson;
            }
            if (transferType.Equals("exchange_in", StringComparison.OrdinalIgnoreCase))
            {
                var evidence = await BuildExchangeInterServerEvidenceDetailsAsync(interServerPayload, sender, ct).ConfigureAwait(false);
                if (!evidence.Ok)
                {
                    _display.PrintError("falha na evidencia inter-servidor: " + evidence.Error);
                    return 5;
                }
                interServerEvidenceDetails = evidence.Details;
            }

            var signatureDetails = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["TRANSFER_ID"] = transferId,
                ["TRANSFER_TYPE"] = transferType,
                ["SENDER"] = sender,
                ["RECEIVER"] = receiver,
                ["AMOUNT"] = amount
            };
            var signatureContract = _service.SignContractTemplate(_service.BuildContractTemplate("transfer_signature", signatureDetails));

            var reportDetails = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["TRANSFER_ID"] = transferId,
                ["TRANSFER_TYPE"] = transferType,
                ["SENDER"] = sender,
                ["RECEIVER"] = receiver,
                ["AMOUNT"] = amount,
                ["FEE_AMOUNT"] = feeAmount,
                ["FEE_SOURCE"] = feeSource,
                ["CONTRACT_ID"] = contractId,
                ["LOCKED_VOUCHERS"] = JsonSerializer.Serialize(lockedVouchers),
                ["VOUCHER_AUDIT"] = voucherAuditJson,
                ["VOUCHER_POW_AUDIT"] = voucherPowAuditJson,
                ["VOUCHER_TRACE"] = voucherTraceJson
            };
            if (interServerEvidenceDetails is not null)
            {
                foreach (var kv in interServerEvidenceDetails)
                {
                    reportDetails[kv.Key] = kv.Value;
                }
            }
            var reportContract = _service.SignContractTemplate(_service.BuildContractTemplate("miner_signature_report", reportDetails));

            var ack = await signSession.EmitAndWaitAsync(
                "sign_transfer",
                new
                {
                    transfer_id = transferId,
                    contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signatureContract)),
                    report_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(reportContract))
                },
                "miner_signature_ack",
                TimeSpan.FromSeconds(90),
                ct).ConfigureAwait(false);

            if (!ReadSuccess(ack))
            {
                _display.PrintError(ReadError(ack));
                return 5;
            }

            var pendingAck = ack.TryGetProperty("pending", out var pendingProp) && pendingProp.ValueKind == JsonValueKind.True;
            var ackMessage = ack.TryGetProperty("message", out var messageProp) ? messageProp.GetString() ?? string.Empty : string.Empty;
            if (pendingAck)
            {
                _display.PrintInfo(string.IsNullOrWhiteSpace(ackMessage)
                    ? $"assinatura recebida pelo servidor para transferencia {transferId}. processando"
                    : ackMessage);

                try
                {
                    var finalAck = await signSession.WaitForEventAsync(
                        "miner_signature_ack",
                        TimeSpan.FromSeconds(45),
                        ct,
                        payload =>
                        {
                            var payloadTransferId = payload.TryGetProperty("transfer_id", out var payloadIdProp)
                                ? payloadIdProp.GetString() ?? string.Empty
                                : string.Empty;
                            if (!string.Equals(payloadTransferId, transferId, StringComparison.OrdinalIgnoreCase))
                            {
                                return false;
                            }
                            var isPending = payload.TryGetProperty("pending", out var payloadPendingProp) && payloadPendingProp.ValueKind == JsonValueKind.True;
                            return !isPending;
                        }).ConfigureAwait(false);

                    if (!ReadSuccess(finalAck))
                    {
                        _display.PrintError(ReadError(finalAck));
                        return 5;
                    }

                    var finalMessage = finalAck.TryGetProperty("message", out var finalMessageProp)
                        ? finalMessageProp.GetString() ?? string.Empty
                        : string.Empty;
                    _display.PrintSuccess(string.IsNullOrWhiteSpace(finalMessage)
                        ? $"assinatura concluida para transferencia {transferId}"
                        : finalMessage);
                    Console.WriteLine(finalAck.GetRawText());
                    return 0;
                }
                catch (TimeoutException)
                {
                    _display.PrintWarning($"transferencia {transferId} segue em processamento no servidor");
                    Console.WriteLine(ack.GetRawText());
                    return 0;
                }
            }

            _display.PrintSuccess(string.IsNullOrWhiteSpace(ackMessage)
                ? $"assinatura enviada para transferencia {transferId}"
                : ackMessage);
            Console.WriteLine(ack.GetRawText());
            return 0;
        }
        if (action == "list")
        {
            var list = _service.ListSpendableVouchers(_service.RequireCurrentServer(), 200);
            if (list.Count == 0)
            {
                _display.PrintInfo("sem vouchers locais");
                return 0;
            }
            foreach (var v in list)
            {
                Console.WriteLine($"{v.VoucherId} | value={v.Value} | status={v.Status} | invalidated={v.Invalidated}");
            }
            return 0;
        }
        if (action == "show")
        {
            if (args.Length < 2)
            {
                _display.PrintError("uso: wallet show <voucher_id>");
                return 2;
            }
            var id = args[1];
            var rec = _service.ListSpendableVouchers(_service.RequireCurrentServer(), 2000)
                .FirstOrDefault(v => v.VoucherId.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (rec is null)
            {
                _display.PrintError("voucher nao encontrado");
                return 3;
            }
            Console.WriteLine(JsonSerializer.Serialize(rec, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        if (action != "refresh")
        {
            _display.PrintInfo("wallet refresh|list|show <voucher_id>");
            _display.PrintInfo("wallet mint [--reason TEXT]");
            _display.PrintInfo("wallet auto-mint on|off");
            _display.PrintInfo("wallet transfer <target_user> <amount>");
            _display.PrintInfo("wallet signature-monitor on|off");
            _display.PrintInfo("wallet signature-auto on|off");
            _display.PrintInfo("wallet auto-select on|off");
            _display.PrintInfo("wallet fine-auto on|off");
            _display.PrintInfo("wallet fine-promise on|off");
            _display.PrintInfo("wallet sign-transfer <transfer_id>");
            return 0;
        }

        var user = _service.CurrentUser;
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("usuario/servidor nao definidos");
            return 4;
        }

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var walletTask = SyncWalletStateAsync(session, ct);
        var economyTask = session.EmitAndWaitAsync("request_economy_report", new { }, "economy_report", TimeSpan.FromSeconds(45), ct);
        var walletSync = await walletTask.ConfigureAwait(false);
        var economyPayload = await economyTask.ConfigureAwait(false);
        _display.PrintSuccess($"wallet sincronizada: {walletSync.Synced} voucher(s)");
        Console.WriteLine(economyPayload.GetRawText());
        if (_walletAutoMintEnabled)
        {
            _ = await MintHpsVoucherAsync("mining", ct, silent: true).ConfigureAwait(false);
        }
        if (_walletFineAutoEnabled || _walletFinePromiseEnabled)
        {
            _ = await TryPayMinerFineAsync(ct, promiseMode: _walletFinePromiseEnabled, silent: true).ConfigureAwait(false);
        }
        if (_walletSignatureMonitorEnabled)
        {
            TriggerSignatureMonitorCheck(ct, _walletSignatureAutoEnabled);
        }
        return 0;
    }

    private void TriggerSignatureMonitorCheck(CancellationToken ct, bool autoSign)
    {
        if (Interlocked.CompareExchange(ref _signatureMonitorWorkerRunning, 1, 0) != 0)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await CheckMinerPendingSignaturesAsync(ct, autoSign).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _display.PrintWarning("signature-monitor: " + ex.Message);
            }
            finally
            {
                Volatile.Write(ref _signatureMonitorWorkerRunning, 0);
            }
        });
    }

    private void StartSignatureMonitorLoop()
    {
        if (_walletSignatureMonitorTask is { IsCompleted: false })
        {
            return;
        }

        _walletSignatureMonitorCts?.Cancel();
        _walletSignatureMonitorCts?.Dispose();
        _walletSignatureMonitorCts = new CancellationTokenSource();
        var token = _walletSignatureMonitorCts.Token;
        _walletSignatureMonitorTask = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                TriggerSignatureMonitorCheck(token, _walletSignatureAutoEnabled);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(8), token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }, token);
    }

    private void StopSignatureMonitorLoop()
    {
        try
        {
            _walletSignatureMonitorCts?.Cancel();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] StopSignatureMonitorLoop cancel failed: {ex.Message}");
        }
    }

    private async Task<int> MintHpsVoucherAsync(string reason, CancellationToken ct, bool silent = false)
    {
        var user = _service.CurrentUser;
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(server))
        {
            if (!silent)
            {
                _display.PrintError("usuario/servidor nao definidos");
            }
            return 4;
        }
        if (!_service.IsCryptoUnlocked)
        {
            if (!silent)
            {
                _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
            }
            return 6;
        }

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["REASON"] = string.IsNullOrWhiteSpace(reason) ? "mining" : reason
        };
        var contract = _service.SignContractTemplate(_service.BuildContractTemplate("hps_mint", details));
        var (nonce, rate) = await session.SolvePowAsync("hps_mint", ct).ConfigureAwait(false);

        var first = await session.EmitAndWaitAnyAsync(
            "mint_hps_voucher",
            new
            {
                pow_nonce = nonce,
                hashrate_observed = rate,
                reason = details["REASON"],
                contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contract))
            },
            ["hps_voucher_offer", "hps_voucher_withheld", "hps_voucher_error"],
            TimeSpan.FromSeconds(90),
            ct).ConfigureAwait(false);

        if (first.EventName == "hps_voucher_error")
        {
            if (!silent)
            {
                _display.PrintError(ReadError(first.Payload));
            }
            return 5;
        }
        if (first.EventName == "hps_voucher_withheld")
        {
            if (!silent)
            {
                _display.PrintWarning("mint registrado como withheld (multa/pendencia ativa)");
                Console.WriteLine(first.Payload.GetRawText());
            }
            return 0;
        }

        var voucherId = first.Payload.TryGetProperty("voucher_id", out var voucherIdElement) ? voucherIdElement.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(voucherId) ||
            !first.Payload.TryGetProperty("payload", out var payloadElement) ||
            payloadElement.ValueKind != JsonValueKind.Object)
        {
            if (!silent)
            {
                _display.PrintError("oferta de voucher invalida");
            }
            return 5;
        }

        var payloadCanonical = first.Payload.TryGetProperty("payload_canonical", out var payloadCanonicalElement)
            ? payloadCanonicalElement.GetString() ?? string.Empty
            : string.Empty;
        var ownerSignature = string.IsNullOrWhiteSpace(payloadCanonical)
            ? _service.SignCanonicalPayloadBase64(JsonSerializer.Deserialize<Dictionary<string, object?>>(payloadElement.GetRawText()) ?? [])
            : Convert.ToBase64String(_ctx.KeyManager.SignPayload(payloadCanonical));

        var second = await session.EmitAndWaitAnyAsync(
            "confirm_hps_voucher",
            new
            {
                voucher_id = voucherId,
                owner_signature = ownerSignature,
                payload_signed_text = string.IsNullOrWhiteSpace(payloadCanonical) ? payloadElement.GetRawText() : payloadCanonical
            },
            ["hps_voucher_issued", "hps_voucher_error"],
            TimeSpan.FromSeconds(90),
            ct).ConfigureAwait(false);

        if (second.EventName == "hps_voucher_error")
        {
            if (!silent)
            {
                _display.PrintError(ReadError(second.Payload));
            }
            return 5;
        }

        if (second.EventName == "hps_voucher_issued" &&
            second.Payload.TryGetProperty("voucher", out var voucherElement))
        {
            using var vouchersDoc = JsonDocument.Parse("[" + voucherElement.GetRawText() + "]");
            _service.SaveWalletSync(vouchersDoc.RootElement);
        }
        try
        {
            _ = await SyncWalletStateAsync(session, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] SyncWalletState after mint failed: {ex.Message}");
        }
        if (!silent)
        {
            _display.PrintSuccess($"mint concluido: voucher {voucherId}");
        }
        return 0;
    }

    private async Task<int> TryPayMinerFineAsync(CancellationToken ct, bool promiseMode, bool silent = false)
    {
        var user = _service.CurrentUser;
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(server))
        {
            return 4;
        }
        if (!_service.IsCryptoUnlocked)
        {
            return 6;
        }

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var quote = await session.EmitAndWaitAsync(
            "request_miner_fine",
            new { },
            "miner_fine_quote",
            TimeSpan.FromSeconds(20),
            ct).ConfigureAwait(false);
        if (!ReadSuccess(quote))
        {
            if (!silent)
            {
                _display.PrintWarning("falha ao obter cotacao de multa");
            }
            return 5;
        }

        var fineAmount = quote.TryGetProperty("fine_amount", out var fineAmountElement)
            ? (fineAmountElement.TryGetInt32(out var i) ? i : (int)Math.Round(fineAmountElement.GetDouble()))
            : 0;
        if (fineAmount <= 0)
        {
            if (!silent)
            {
                _display.PrintInfo("sem multas pendentes");
            }
            return 0;
        }

        var voucherIds = new List<string>();
        if (!promiseMode)
        {
            long total = 0;
            foreach (var v in _service.ListSpendableVouchers(server, 3000)
                         .Where(v => !v.Invalidated &&
                                     string.Equals(v.Status, "valid", StringComparison.OrdinalIgnoreCase))
                         .OrderByDescending(v => v.Value))
            {
                if (v.Value <= 0)
                {
                    continue;
                }
                voucherIds.Add(v.VoucherId);
                total += v.Value;
                if (total >= fineAmount)
                {
                    break;
                }
            }
            if (total < fineAmount)
            {
                if (!silent)
                {
                    _display.PrintWarning($"saldo insuficiente para multa ({fineAmount} HPS)");
                }
                return 3;
            }
        }

        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["AMOUNT"] = fineAmount.ToString()
        };
        var contract = _service.SignContractTemplate(_service.BuildContractTemplate("miner_fine", details));
        var ack = await session.EmitAndWaitAsync(
            "pay_miner_fine",
            new
            {
                voucher_ids = voucherIds,
                use_withheld = false,
                promise = promiseMode,
                contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contract))
            },
            "miner_fine_ack",
            TimeSpan.FromSeconds(90),
            ct).ConfigureAwait(false);
        if (!ReadSuccess(ack))
        {
            if (!silent)
            {
                _display.PrintError(ReadError(ack));
            }
            return 5;
        }
        if (!silent)
        {
            _display.PrintSuccess("multa processada com sucesso");
        }
        return 0;
    }

    private async Task<(int Synced, int Claimed)> SyncWalletStateAsync(HpsRealtimeSession session, CancellationToken ct)
    {
        var walletPayload = await session.EmitAndWaitAsync(
            "request_hps_wallet",
            new { },
            "hps_wallet_sync",
            TimeSpan.FromSeconds(45),
            ct).ConfigureAwait(false);

        if (walletPayload.TryGetProperty("error", out var walletError) && !string.IsNullOrWhiteSpace(walletError.GetString()))
        {
            throw new InvalidOperationException(walletError.GetString());
        }

        var synced = 0;
        if (walletPayload.TryGetProperty("vouchers", out var vouchers))
        {
            synced = _service.SaveWalletSync(vouchers);
        }

        var claimed = 0;
        if (walletPayload.TryGetProperty("pending_offers", out var pendingOffers))
        {
            claimed = await ClaimPendingVoucherOffersAsync(session, pendingOffers, ct).ConfigureAwait(false);
            if (claimed > 0)
            {
                var refreshed = await session.EmitAndWaitAsync(
                    "request_hps_wallet",
                    new { },
                    "hps_wallet_sync",
                    TimeSpan.FromSeconds(45),
                    ct).ConfigureAwait(false);
                if (refreshed.TryGetProperty("vouchers", out var refreshedVouchers))
                {
                    synced = _service.SaveWalletSync(refreshedVouchers);
                }
            }
        }

        return (synced, claimed);
    }

    private async Task<int> ClaimPendingVoucherOffersAsync(HpsRealtimeSession session, JsonElement pendingOffers, CancellationToken ct)
    {
        if (pendingOffers.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        var claimed = 0;
        foreach (var offer in pendingOffers.EnumerateArray().Take(16))
        {
            var voucherId = offer.TryGetProperty("voucher_id", out var voucherIdElement) ? voucherIdElement.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(voucherId) ||
                !offer.TryGetProperty("payload", out var payloadElement) ||
                payloadElement.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var payloadCanonical = offer.TryGetProperty("payload_canonical", out var payloadCanonicalElement)
                ? payloadCanonicalElement.GetString() ?? string.Empty
                : string.Empty;
            var ownerSignature = string.IsNullOrWhiteSpace(payloadCanonical)
                ? _service.SignCanonicalPayloadBase64(JsonSerializer.Deserialize<Dictionary<string, object?>>(payloadElement.GetRawText()) ?? [])
                : Convert.ToBase64String(_ctx.KeyManager.SignPayload(payloadCanonical));
            var confirm = await session.EmitAndWaitAnyAsync(
                "confirm_hps_voucher",
                new
                {
                    voucher_id = voucherId,
                    owner_signature = ownerSignature,
                    payload_signed_text = string.IsNullOrWhiteSpace(payloadCanonical) ? payloadElement.GetRawText() : payloadCanonical
                },
                ["hps_voucher_issued", "hps_voucher_error"],
                TimeSpan.FromSeconds(45),
                ct).ConfigureAwait(false);

            if (confirm.EventName != "hps_voucher_issued")
            {
                continue;
            }

            if (confirm.Payload.TryGetProperty("voucher", out var voucherElement))
            {
                using var vouchersDoc = JsonDocument.Parse("[" + voucherElement.GetRawText() + "]");
                _service.SaveWalletSync(vouchersDoc.RootElement);
                claimed++;
            }
        }

        return claimed;
    }

    private async Task CheckMinerPendingSignaturesAsync(CancellationToken ct, bool autoSign)
    {
        var user = _service.CurrentUser;
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(server) || !_service.IsCryptoUnlocked)
        {
            return;
        }

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        JsonElement payload;
        try
        {
            payload = await session.EmitAndWaitAsync(
                "get_miner_pending_transfers",
                new { },
                "miner_pending_transfers",
                TimeSpan.FromSeconds(8),
                ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            _display.PrintWarning("signature-monitor: evento get_miner_pending_transfers indisponivel no servidor");
            return;
        }
        if (!ReadSuccess(payload))
        {
            if (payload.TryGetProperty("error", out var err) && !string.IsNullOrWhiteSpace(err.GetString()))
            {
                _display.PrintWarning("signature-monitor: " + err.GetString());
            }
            return;
        }
        if (!payload.TryGetProperty("transfers", out var transfers) || transfers.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        var pendingIds = new List<string>();
        foreach (var transfer in transfers.EnumerateArray())
        {
            var id = transfer.TryGetProperty("transfer_id", out var idElement) ? idElement.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }
            pendingIds.Add(id);
        }
        if (pendingIds.Count == 0)
        {
            _display.PrintInfo("sem assinaturas pendentes para minerador");
            return;
        }

        foreach (var pendingId in pendingIds)
        {
            _display.PrintWarning($"assinatura pendente detectada: {pendingId}. use: wallet sign-transfer {pendingId}");
        }

        if (!autoSign)
        {
            return;
        }
        foreach (var pendingId in pendingIds)
        {
            await RunWallet(["sign-transfer", pendingId], ct).ConfigureAwait(false);
        }
    }

    private void StartAutoMintLoop()
    {
        StopAutoMintLoop();
        _walletAutoMintCts = new CancellationTokenSource();
        var token = _walletAutoMintCts.Token;
        _walletAutoMintTask = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                if (string.IsNullOrWhiteSpace(_service.CurrentUser) ||
                    string.IsNullOrWhiteSpace(_service.RequireCurrentServer()) ||
                    !_service.IsCryptoUnlocked)
                {
                    try { await Task.Delay(TimeSpan.FromSeconds(30), token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    continue;
                }
                try
                {
                    await MintHpsVoucherAsync("mining", token, silent: true).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[WARN] auto-mint iteration failed: {ex.Message}");
                }

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(20), token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }, token);
    }

    private void StopAutoMintLoop()
    {
        try
        {
            _walletAutoMintCts?.Cancel();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] StopAutoMintLoop cancel failed: {ex.Message}");
        }
        _walletAutoMintCts?.Dispose();
        _walletAutoMintCts = null;
        _walletAutoMintTask = null;
    }

    private static bool TryParseOnOff(string value, out bool defined)
    {
        var v = (value ?? string.Empty).Trim().ToLowerInvariant();
        if (v is "on" or "true" or "1" or "yes" or "y" or "s")
        {
            defined = true;
            return true;
        }
        if (v is "off" or "false" or "0" or "no" or "n")
        {
            defined = false;
            return true;
        }
        defined = false;
        return false;
    }

    private static List<string> ParseJsonStringArray(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            return element.EnumerateArray()
                .Select(x => x.GetString() ?? string.Empty)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();
        }
        var raw = element.ValueKind == JsonValueKind.String ? element.GetString() ?? string.Empty : element.ToString();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return [];
        }
        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return [];
            }
            return doc.RootElement.EnumerateArray()
                .Select(x => x.GetString() ?? string.Empty)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] ParseJsonStringArray failed: {ex.Message}");
            return [];
        }
    }

    private (bool Ok, string VoucherAuditJson, string VoucherPowAuditJson, string VoucherTraceJson, string Error) BuildVoucherReportData(
        string auditRawJson,
        IReadOnlyCollection<string> expectedVoucherIds,
        bool preferExchangeIssuerSources)
    {
        try
        {
            using var doc = JsonDocument.Parse(auditRawJson);
            if (!doc.RootElement.TryGetProperty("vouchers", out var vouchers) || vouchers.ValueKind != JsonValueKind.Array)
            {
                return (false, "[]", "[]", "[]", "payload de auditoria sem 'vouchers'");
            }

            var expectedSet = new HashSet<string>(expectedVoucherIds.Where(x => !string.IsNullOrWhiteSpace(x)), StringComparer.OrdinalIgnoreCase);
            var foundSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var voucherAudit = new List<Dictionary<string, object?>>();
            var voucherPowAudit = new List<Dictionary<string, object?>>();
            var voucherTrace = new List<Dictionary<string, object?>>();

            foreach (var item in vouchers.EnumerateArray())
            {
                var voucherId = item.TryGetProperty("voucher_id", out var voucherIdElement) ? voucherIdElement.GetString() ?? string.Empty : string.Empty;
                if (string.IsNullOrWhiteSpace(voucherId) || !expectedSet.Contains(voucherId))
                {
                    continue;
                }
                foundSet.Add(voucherId);

                var payload = item.TryGetProperty("payload", out var payloadElement) && payloadElement.ValueKind == JsonValueKind.Object
                    ? payloadElement
                    : default;
                var status = item.TryGetProperty("status", out var statusElement) ? statusElement.GetString() ?? string.Empty : string.Empty;
                var invalidated = item.TryGetProperty("invalidated", out var invalidatedElement) && invalidatedElement.ValueKind == JsonValueKind.True;
                var issuerServer = item.TryGetProperty("issuer_server", out var issuerServerElement) ? issuerServerElement.GetString() ?? string.Empty : string.Empty;

                voucherAudit.Add(new Dictionary<string, object?>
                {
                    ["voucher_id"] = voucherId,
                    ["status"] = status,
                    ["invalidated"] = invalidated,
                    ["issuer_server"] = issuerServer
                });

                var powOk = payload.ValueKind == JsonValueKind.Object && VerifyVoucherPowPayload(payload, voucherId);
                voucherPowAudit.Add(new Dictionary<string, object?>
                {
                    ["voucher_id"] = voucherId,
                    ["pow_ok"] = powOk
                });

                var sourceVouchers = ExtractTraceSourceVouchers(item);
                if (preferExchangeIssuerSources && payload.ValueKind == JsonValueKind.Object &&
                    payload.TryGetProperty("conditions", out var conditions) && conditions.ValueKind == JsonValueKind.Object)
                {
                    var conditionType = conditions.TryGetProperty("type", out var cType) ? cType.GetString() ?? string.Empty : string.Empty;
                    if (conditionType.Equals("exchange", StringComparison.OrdinalIgnoreCase) &&
                        conditions.TryGetProperty("issuer_voucher_ids", out var issuerVoucherIds))
                    {
                        var issuerSources = ParseJsonStringArray(issuerVoucherIds);
                        if (issuerSources.Count > 0)
                        {
                            sourceVouchers = issuerSources;
                        }
                    }
                }
                voucherTrace.Add(new Dictionary<string, object?>
                {
                    ["voucher_id"] = voucherId,
                    ["source_vouchers"] = sourceVouchers
                });
            }

            var missing = expectedSet.Where(x => !foundSet.Contains(x)).ToArray();
            if (missing.Length > 0)
            {
                return (false, "[]", "[]", "[]", $"vouchers ausentes na auditoria: {string.Join(",", missing)}");
            }

            return (
                true,
                JsonSerializer.Serialize(voucherAudit),
                JsonSerializer.Serialize(voucherPowAudit),
                JsonSerializer.Serialize(voucherTrace),
                string.Empty);
        }
        catch (Exception ex)
        {
            return (false, "[]", "[]", "[]", ex.Message);
        }
    }

    private static bool VerifyVoucherPowPayload(JsonElement payload, string voucherId)
    {
        if (!payload.TryGetProperty("pow", out var powInfo) || powInfo.ValueKind != JsonValueKind.Object)
        {
            return false;
        }
        var challenge = powInfo.TryGetProperty("challenge", out var challengeElement) ? challengeElement.GetString() ?? string.Empty : string.Empty;
        var nonceRaw = powInfo.TryGetProperty("nonce", out var nonceElement) ? nonceElement.ToString() : string.Empty;
        var targetBits = powInfo.TryGetProperty("target_bits", out var targetBitsElement) ? ParseIntSafe(targetBitsElement.ToString()) : 0;
        var actionType = powInfo.TryGetProperty("action_type", out var actionTypeElement) ? actionTypeElement.GetString() ?? string.Empty : string.Empty;
        var powVoucherId = powInfo.TryGetProperty("voucher_id", out var powVoucherIdElement) ? powVoucherIdElement.GetString() ?? string.Empty : string.Empty;

        if (string.IsNullOrWhiteSpace(challenge) || string.IsNullOrWhiteSpace(nonceRaw) || targetBits <= 0)
        {
            return false;
        }
        if (!string.IsNullOrWhiteSpace(powVoucherId) && !powVoucherId.Equals(voucherId, StringComparison.Ordinal))
        {
            return false;
        }
        if (targetBits < MinPowBitsForAction(actionType))
        {
            return false;
        }

        if (!ulong.TryParse(nonceRaw, out var nonce))
        {
            return false;
        }

        byte[] challengeBytes;
        try
        {
            challengeBytes = Convert.FromBase64String(challenge);
        }
        catch
        {
            return false;
        }

        var data = new byte[challengeBytes.Length + 8];
        Buffer.BlockCopy(challengeBytes, 0, data, 0, challengeBytes.Length);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(challengeBytes.Length), nonce);
        var sum = SHA256.HashData(data);
        var lzb = LeadingZeroBits(sum);
        if (lzb < targetBits)
        {
            return false;
        }
        if (actionType.Equals("hps_mint", StringComparison.Ordinal))
        {
            var challengeText = Encoding.UTF8.GetString(challengeBytes);
            if (!challengeText.StartsWith("HPSMINT:" + voucherId + ":", StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static int LeadingZeroBits(ReadOnlySpan<byte> hash)
    {
        var total = 0;
        foreach (var b in hash)
        {
            if (b == 0)
            {
                total += 8;
                continue;
            }
            for (var i = 7; i >= 0; i--)
            {
                if (((b >> i) & 1) == 0)
                {
                    total++;
                }
                else
                {
                    return total;
                }
            }
        }
        return total;
    }

    private static int MinPowBitsForAction(string actionType)
    {
        return actionType switch
        {
            "upload" => 8,
            "dns" => 6,
            "report" => 6,
            "hps_mint" => 12,
            "login" => 12,
            "usage_contract" => 10,
            "contract_transfer" => 10,
            "contract_reset" => 10,
            "contract_certify" => 10,
            "hps_transfer" => 10,
            _ => 1
        };
    }

    private List<string> ExtractTraceSourceVouchers(JsonElement voucherAuditItem)
    {
        var results = new List<string>();
        if (!voucherAuditItem.TryGetProperty("trace_contracts", out var traceContracts) || traceContracts.ValueKind != JsonValueKind.Array)
        {
            return results;
        }

        foreach (var traceContract in traceContracts.EnumerateArray())
        {
            var actionType = traceContract.TryGetProperty("action_type", out var actionTypeElement)
                ? actionTypeElement.GetString() ?? string.Empty
                : string.Empty;
            var contractContentB64 = traceContract.TryGetProperty("contract_content", out var contractContentElement)
                ? contractContentElement.GetString() ?? string.Empty
                : string.Empty;
            if (string.IsNullOrWhiteSpace(actionType) || string.IsNullOrWhiteSpace(contractContentB64))
            {
                continue;
            }

            string contractText;
            try
            {
                contractText = Encoding.UTF8.GetString(Convert.FromBase64String(contractContentB64));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[WARN] ExtractTraceSourceVouchers Base64 decode failed: {ex.Message}");
                continue;
            }
            var details = _service.ExtractContractDetailsMap(contractText);

            if (actionType is "hps_spend_refund" or "miner_fine_refund" or "hps_transfer_custody_refund")
            {
                var raw = details.GetValueOrDefault("VOUCHERS", string.Empty);
                foreach (var id in ParseStringArrayFromJsonText(raw))
                {
                    if (!string.IsNullOrWhiteSpace(id))
                    {
                        results.Add(id);
                    }
                }
                continue;
            }
            if (actionType == "hps_transfer_refund")
            {
                var sourceId = details.GetValueOrDefault("ORIGINAL_VOUCHER_ID", string.Empty);
                if (!string.IsNullOrWhiteSpace(sourceId))
                {
                    results.Add(sourceId);
                }
            }
        }

        return results
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> ParseStringArrayFromJsonText(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return [];
        }
        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return [];
            }
            return doc.RootElement.EnumerateArray()
                .Select(x => x.GetString() ?? string.Empty)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[WARN] ParseJsonStringArray failed: {ex.Message}");
            return [];
        }
    }

    private static int ParseIntSafe(string raw)
    {
        if (int.TryParse(raw, out var parsed))
        {
            return parsed;
        }
        if (double.TryParse(raw, out var d))
        {
            return (int)d;
        }
        return 0;
    }

    private async Task<(bool Ok, Dictionary<string, string> Details, string Error)> BuildExchangeInterServerEvidenceDetailsAsync(
        JsonElement interServerPayload,
        string fallbackIssuer,
        CancellationToken ct)
    {
        try
        {
            if (interServerPayload.ValueKind != JsonValueKind.Object)
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "payload inter-servidor ausente");
            }

            var issuer = interServerPayload.TryGetProperty("issuer", out var issuerElement)
                ? issuerElement.GetString() ?? string.Empty
                : string.Empty;
            if (string.IsNullOrWhiteSpace(issuer))
            {
                issuer = fallbackIssuer ?? string.Empty;
            }
            var reservedId = GetJsonString(interServerPayload, "issuer_reserved_contract_id");
            var outId = GetJsonString(interServerPayload, "issuer_out_contract_id");
            var ownerKeyId = GetJsonString(interServerPayload, "issuer_owner_key_contract_id");
            var lineageCloseId = GetJsonString(interServerPayload, "issuer_lineage_close_contract_id");
            var exchangeContractId = GetJsonString(interServerPayload, "exchange_contract_id");
            var exchangeContractHash = GetJsonString(interServerPayload, "exchange_contract_hash");
            var exchangeContractB64 = GetJsonString(interServerPayload, "exchange_contract_content");
            var interServerPayloadRaw = interServerPayload.GetRawText();
            var exchangeTokenRaw = GetJsonRaw(interServerPayload, "exchange_token");
            var exchangeSignature = GetJsonString(interServerPayload, "exchange_signature");
            var issuerVoucherIds = interServerPayload.TryGetProperty("issuer_voucher_ids", out var issuerVoucherIdsElement)
                ? ParseJsonStringArray(issuerVoucherIdsElement)
                : [];

            if (string.IsNullOrWhiteSpace(issuer) ||
                string.IsNullOrWhiteSpace(reservedId) ||
                string.IsNullOrWhiteSpace(outId) ||
                string.IsNullOrWhiteSpace(ownerKeyId) ||
                string.IsNullOrWhiteSpace(exchangeContractId) ||
                string.IsNullOrWhiteSpace(exchangeContractHash) ||
                string.IsNullOrWhiteSpace(exchangeContractB64))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "dados inter-servidor incompletos");
            }

            var serverInfo = await _http.GetServerInfoAsync(issuer, ct).ConfigureAwait(false);
            if (!serverInfo.Ok)
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "nao foi possivel obter server_info do emissor: " + serverInfo.Error);
            }
            string issuerPublicKey;
            try
            {
                using var infoDoc = JsonDocument.Parse(serverInfo.RawJson);
                issuerPublicKey = infoDoc.RootElement.TryGetProperty("public_key", out var keyElement)
                    ? keyElement.GetString() ?? string.Empty
                    : string.Empty;
            }
            catch (Exception ex)
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "server_info invalido: " + ex.Message);
            }
            if (string.IsNullOrWhiteSpace(issuerPublicKey))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "chave publica do emissor ausente");
            }

            var reservedContract = await _http.FetchContractAsync(issuer, reservedId, ct).ConfigureAwait(false);
            var outContract = await _http.FetchContractAsync(issuer, outId, ct).ConfigureAwait(false);
            var ownerKeyContract = await _http.FetchContractAsync(issuer, ownerKeyId, ct).ConfigureAwait(false);
            var lineageCloseContract = string.IsNullOrWhiteSpace(lineageCloseId)
                ? (Ok: true, Content: string.Empty, Error: string.Empty)
                : await _http.FetchContractAsync(issuer, lineageCloseId, ct).ConfigureAwait(false);
            if (!reservedContract.Ok || !outContract.Ok || !ownerKeyContract.Ok || !lineageCloseContract.Ok)
            {
                var err = reservedContract.Ok
                    ? (outContract.Ok
                        ? (ownerKeyContract.Ok ? lineageCloseContract.Error : ownerKeyContract.Error)
                        : outContract.Error)
                    : reservedContract.Error;
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "falha ao buscar contratos do emissor: " + err);
            }

            if (!_service.VerifyContractSignatureWithKey(reservedContract.Content, issuerPublicKey))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "assinatura invalida no contrato reservado");
            }
            if (!_service.VerifyContractSignatureWithKey(outContract.Content, issuerPublicKey))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "assinatura invalida no contrato de saida");
            }
            if (!_service.VerifyContractSignatureWithKey(ownerKeyContract.Content, issuerPublicKey))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "assinatura invalida no contrato de chave do owner");
            }
            if (!string.IsNullOrWhiteSpace(lineageCloseId) && !_service.VerifyContractSignatureWithKey(lineageCloseContract.Content, issuerPublicKey))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "assinatura invalida no contrato de fechamento de linhagem");
            }

            var ownerKeyDetails = _service.ExtractContractDetailsMap(ownerKeyContract.Content);
            var ownerPublicKey = ownerKeyDetails.GetValueOrDefault("OWNER_PUBLIC_KEY", string.Empty);
            if (string.IsNullOrWhiteSpace(ownerPublicKey))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "OWNER_PUBLIC_KEY ausente no contrato do emissor");
            }

            string exchangeContractText;
            try
            {
                exchangeContractText = Encoding.UTF8.GetString(Convert.FromBase64String(exchangeContractB64));
            }
            catch (Exception ex)
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "conteudo do contrato de cambio invalido: " + ex.Message);
            }
            var localExchangeHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(exchangeContractText))).ToLowerInvariant();
            if (!localExchangeHash.Equals(exchangeContractHash, StringComparison.OrdinalIgnoreCase))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "hash do contrato de cambio nao confere");
            }
            if (!_service.VerifyContractSignatureWithKey(exchangeContractText, ownerPublicKey))
            {
                return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "assinatura do contrato de cambio invalida");
            }

            var issuerVoucherAudit = "[]";
            if (issuerVoucherIds.Count > 0)
            {
                var issuerAudit = await _http.AuditVouchersAsync(issuer, issuerVoucherIds, ct).ConfigureAwait(false);
                if (!issuerAudit.Ok)
                {
                    return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "falha ao auditar vouchers do emissor: " + issuerAudit.Error);
                }
                try
                {
                    using var issuerDoc = JsonDocument.Parse(issuerAudit.RawJson);
                    if (issuerDoc.RootElement.TryGetProperty("vouchers", out var issuerVouchers) && issuerVouchers.ValueKind == JsonValueKind.Array)
                    {
                        issuerVoucherAudit = issuerVouchers.GetRawText();
                    }
                }
                catch (Exception ex)
                {
                    return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), "auditoria do emissor invalida: " + ex.Message);
                }
            }

            var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["INTER_SERVER_ISSUER"] = issuer,
                ["INTER_SERVER_PAYLOAD"] = interServerPayloadRaw,
                ["ISSUER_PUBLIC_KEY"] = issuerPublicKey,
                ["ISSUER_SERVER_INFO"] = serverInfo.RawJson,
                ["ISSUER_VALIDATE_TOKEN"] = exchangeTokenRaw,
                ["ISSUER_VALIDATE_SIGNATURE"] = exchangeSignature,
                ["ISSUER_VOUCHER_IDS"] = JsonSerializer.Serialize(issuerVoucherIds),
                ["ISSUER_VOUCHER_AUDIT"] = issuerVoucherAudit,
                ["ISSUER_RESERVED_CONTRACT_ID"] = reservedId,
                ["ISSUER_RESERVED_CONTRACT"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(reservedContract.Content)),
                ["ISSUER_OUT_CONTRACT_ID"] = outId,
                ["ISSUER_OUT_CONTRACT"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(outContract.Content)),
                ["ISSUER_OWNER_KEY_CONTRACT_ID"] = ownerKeyId,
                ["ISSUER_OWNER_KEY_CONTRACT"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(ownerKeyContract.Content)),
                ["ISSUER_LINEAGE_CLOSE_CONTRACT_ID"] = lineageCloseId,
                ["ISSUER_LINEAGE_CLOSE_CONTRACT"] = string.IsNullOrWhiteSpace(lineageCloseContract.Content) ? string.Empty : Convert.ToBase64String(Encoding.UTF8.GetBytes(lineageCloseContract.Content)),
                ["CLIENT_EXCHANGE_CONTRACT_ID"] = exchangeContractId,
                ["CLIENT_EXCHANGE_CONTRACT_HASH"] = exchangeContractHash,
                ["CLIENT_EXCHANGE_CONTRACT"] = exchangeContractB64
            };
            return (true, details, string.Empty);
        }
        catch (Exception ex)
        {
            return (false, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), ex.Message);
        }
    }

    private static string GetJsonString(JsonElement payload, string property)
    {
        return payload.TryGetProperty(property, out var element) ? element.GetString() ?? string.Empty : string.Empty;
    }

    private static string GetJsonRaw(JsonElement payload, string property)
    {
        if (!payload.TryGetProperty(property, out var element))
        {
            return string.Empty;
        }
        return element.ValueKind == JsonValueKind.String
            ? element.GetString() ?? string.Empty
            : element.GetRawText();
    }

    private static bool ReadSuccess(JsonElement payload) =>
        payload.TryGetProperty("success", out var s) && s.ValueKind == JsonValueKind.True;

    private static string ReadError(JsonElement payload) =>
        payload.TryGetProperty("error", out var e) ? e.GetString() ?? "erro desconhecido" : "erro desconhecido";

    private static bool IsValidDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || domain.Length < 3 || domain.Length > 63)
        {
            return false;
        }
        if (domain.StartsWith('-') || domain.EndsWith('-') || domain.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }
        foreach (var c in domain)
        {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')
            {
                continue;
            }
            return false;
        }
        return true;
    }

    private async Task<int> RunCancel(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            _display.PrintError("uso: cancel content <hash> | cancel dns <domain> | cancel flow <kind> <target>");
            return 2;
        }
        var sub = args[0].ToLowerInvariant();
        var target = args[1].Trim();
        var server = _service.RequireCurrentServer();
        var user = _service.CurrentUser;
        if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(user))
        {
            _display.PrintError("usuario/servidor nao definidos");
            return 3;
        }

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);

        if (sub == "content")
        {
            await session.EmitAsync("cancel_content", new { content_hash = target }, ct).ConfigureAwait(false);
            _display.PrintSuccess($"cancelamento de conteudo solicitado: {target}");
        }
        else if (sub == "dns")
        {
            await session.EmitAsync("cancel_dns", new { domain = target }, ct).ConfigureAwait(false);
            _display.PrintSuccess($"cancelamento de dns solicitado: {target}");
        }
        else if (sub == "flow")
        {
            var kind = args.Length > 2 ? args[2] : target;
            await session.EmitAsync("cancel_flow", new { kind, target }, ct).ConfigureAwait(false);
            _display.PrintSuccess($"cancelamento de fluxo solicitado: {kind}:{target}");
        }
        else
        {
            _display.PrintError("uso: cancel content <hash> | cancel dns <domain> | cancel flow <kind> <target>");
            return 2;
        }
        return 0;
    }

    private async Task<int> RunFraudReport(string[] args, CancellationToken ct)
    {
        if (args.Length < 2)
        {
            _display.PrintError("uso: fraud-report <server_address> <reason>");
            return 2;
        }
        var serverAddress = args[0].Trim();
        var reason = string.Join(' ', args.Skip(1)).Trim();
        var user = _service.CurrentUser;
        var server = _service.RequireCurrentServer();
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(server))
        {
            _display.PrintError("usuario/servidor nao definidos");
            return 3;
        }
        if (!_service.IsCryptoUnlocked)
        {
            _display.PrintError("cofre nao desbloqueado. use: keys unlock <username>");
            return 6;
        }

        var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SERVER_ADDRESS"] = serverAddress,
            ["REASON"] = reason,
            ["REPORTER"] = user,
            ["TIMESTAMP"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
        };
        var contract = _service.SignContractTemplate(_service.BuildContractTemplate("fraud_report", details));

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);
        var result = await session.EmitAndWaitAsync(
            "submit_fraud_report",
            new
            {
                reports = new[]
                {
                    new
                    {
                        server_address = serverAddress,
                        contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(contract)),
                        contract_id = Guid.NewGuid().ToString("N")
                    }
                }
            },
            "fraud_report_ack",
            TimeSpan.FromSeconds(60),
            ct).ConfigureAwait(false);

        if (!ReadSuccess(result))
        {
            _display.PrintError(ReadError(result));
            return 5;
        }

        _display.PrintSuccess("relatorio de fraude enviado");
        return 0;
    }

    private async Task<int> RunFee(string[] args, CancellationToken ct)
    {
        var sub = args.FirstOrDefault()?.ToLowerInvariant() ?? "help";
        var server = _service.RequireCurrentServer();
        var user = _service.CurrentUser;
        if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(user))
        {
            _display.PrintError("servidor/usuario nao definidos. use 'login' primeiro.");
            return 3;
        }

        await using var session = await HpsRealtimeSession.ConnectAuthenticatedAsync(server, user, _service, _ctx, _display, ct).ConfigureAwait(false);

        switch (sub)
        {
            case "quotes":
            {
                _display.PrintInfo("solicitando cotacoes de taxas...");
                var result = await session.EmitAndWaitAsync(
                    "get_fee_quotes", new { },
                    "fee_quotes",
                    TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                if (result.ValueKind == JsonValueKind.Array)
                {
                    foreach (var quote in result.EnumerateArray())
                    {
                        Console.WriteLine($"  Minerador: {GetJsonString(quote, "miner")}");
                        Console.WriteLine($"  Taxa: {GetJsonDouble(quote, "fee_rate"):F4}");
                        Console.WriteLine($"  Volatilidade: {GetJsonDouble(quote, "volatility"):F2}");
                        Console.WriteLine($"  Multiplicador Base: {GetJsonDouble(quote, "base_multiplier"):F4}");
                        var contract = GetJsonString(quote, "contract");
                        if (!string.IsNullOrWhiteSpace(contract))
                            Console.WriteLine($"  Contrato: {contract[..Math.Min(contract.Length, 80)]}");
                        Console.WriteLine();
                    }
                }
                else
                {
                    Console.WriteLine(result.GetRawText());
                }
                return 0;
            }
            case "market":
            {
                _display.PrintInfo("solicitando dados do mercado...");
                var result = await session.EmitAndWaitAsync(
                    "request_market_data", new { },
                    "market_data",
                    TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                Console.WriteLine($"Oferta/Demanda: {GetJsonDouble(result, "supply_demand_ratio"):F4}");
                Console.WriteLine($"Taxa Media: {GetJsonDouble(result, "avg_fee_rate"):F4}");
                Console.WriteLine($"Total Mineradores: {GetJsonInt(result, "total_miners")}");
                Console.WriteLine($"Cap. Mercado: {GetJsonDouble(result, "total_market_cap"):F2}");
                return 0;
            }
            case "config":
            {
                double? minFee = null, maxFee = null, volatility = null;
                bool? enabled = null;
                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i].ToLowerInvariant())
                    {
                        case "--min":
                            if (i + 1 < args.Length && double.TryParse(args[++i], out var mn)) minFee = mn;
                            break;
                        case "--max":
                            if (i + 1 < args.Length && double.TryParse(args[++i], out var mx)) maxFee = mx;
                            break;
                        case "--volatility":
                            if (i + 1 < args.Length && double.TryParse(args[++i], out var vol)) volatility = vol;
                            break;
                        case "--enable":
                            enabled = true;
                            break;
                        case "--disable":
                            enabled = false;
                            break;
                    }
                }
                _display.PrintInfo("enviando configuracao de taxas...");
                var result = await session.EmitAndWaitAsync(
                    "set_miner_fee_config",
                    new
                    {
                        min_fee_per_tx = minFee ?? 0.0,
                        max_fee_per_tx = maxFee ?? 5.0,
                        fee_volatility_enabled = enabled ?? true,
                        volatility = volatility ?? 0.5
                    },
                    "miner_fee_config_ack",
                    TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                var success = result.TryGetProperty("success", out var suc) && suc.GetBoolean();
                if (success)
                    _display.PrintSuccess("configuracao de taxa salva");
                else
                    _display.PrintError(GetJsonString(result, "error"));
                return success ? 0 : 5;
            }
            default:
                _display.PrintError("uso: fee quotes|market|config [--min N] [--max N] [--volatility N] [--enable|--disable]");
                return 2;
        }
    }

    private static double GetJsonDouble(JsonElement el, string key)
    {
        return el.TryGetProperty(key, out var p) && p.ValueKind == JsonValueKind.Number ? p.GetDouble() : 0.0;
    }

    private static int GetJsonInt(JsonElement el, string key)
    {
        return el.TryGetProperty(key, out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : 0;
    }
}
