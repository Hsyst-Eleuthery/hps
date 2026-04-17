using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HpsBrowser.Models;
using HpsBrowser.Services;

namespace HpsBrowser.ViewModels;

public sealed partial class MainViewModel
{
    private Voucher? ParseVoucher(JsonElement element)
    {
        try
        {
            var voucherId = element.GetProperty("voucher_id").GetString() ?? string.Empty;
            var issuer = element.GetProperty("issuer").GetString() ?? string.Empty;
            var owner = element.GetProperty("owner").GetString() ?? string.Empty;
            var value = element.TryGetProperty("value", out var valueProp) ? valueProp.GetInt32() : 0;
            var reason = element.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? string.Empty : string.Empty;
            var issuedAt = element.TryGetProperty("issued_at", out var issuedProp) ? issuedProp.GetDouble() : 0;
            Dictionary<string, object> payload;
            if (element.TryGetProperty("payload", out var payloadProp))
            {
                if (payloadProp.ValueKind == JsonValueKind.String)
                {
                    var payloadJson = payloadProp.GetString() ?? "{}";
                    payload = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson) ?? new Dictionary<string, object>();
                }
                else
                {
                    payload = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadProp.GetRawText()) ?? new Dictionary<string, object>();
                }
            }
            else
            {
                payload = new Dictionary<string, object>();
            }

            var signatures = element.TryGetProperty("signatures", out var sigProp)
                ? JsonSerializer.Deserialize<Dictionary<string, string>>(sigProp.GetRawText()) ?? new Dictionary<string, string>()
                : new Dictionary<string, string>();
            if (signatures.Count == 0)
            {
                if (element.TryGetProperty("issuer_signature", out var issuerSigProp))
                {
                    signatures["issuer"] = issuerSigProp.GetString() ?? string.Empty;
                }
                if (element.TryGetProperty("owner_signature", out var ownerSigProp))
                {
                    signatures["owner"] = ownerSigProp.GetString() ?? string.Empty;
                }
            }
            var status = element.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? "active" : "active";
            var invalidated = element.TryGetProperty("invalidated", out var invProp) && invProp.GetBoolean();

            return new Voucher
            {
                VoucherId = voucherId,
                Issuer = issuer,
                Owner = owner,
                Value = value,
                Reason = reason,
                IssuedAt = issuedAt,
                Payload = payload,
                IssuerSignature = signatures.TryGetValue("issuer", out var issuerSig) ? issuerSig : string.Empty,
                OwnerSignature = signatures.TryGetValue("owner", out var ownerSig) ? ownerSig : string.Empty,
                Status = status,
                Invalidated = invalidated
            };
        }
        catch
        {
            return null;
        }
    }

    private ContractInfo? ParseContract(JsonElement element)
    {
        try
        {
            var contractId = element.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var actionType = element.TryGetProperty("action_type", out var actionProp) ? actionProp.GetString() ?? string.Empty : string.Empty;
            var contentHash = element.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
            var domain = element.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() ?? string.Empty : string.Empty;
            var username = element.TryGetProperty("username", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty;
            var verified = element.TryGetProperty("verified", out var verProp) && verProp.GetBoolean();
            var hasIntegrityOk = element.TryGetProperty("integrity_ok", out var intProp);
            var integrityOk = hasIntegrityOk ? intProp.GetBoolean() : verified;
            var violationReason = element.TryGetProperty("violation_reason", out var reasonProp) ? reasonProp.GetString() ?? string.Empty : string.Empty;
            var signature = element.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() ?? string.Empty : string.Empty;
            var timestamp = element.TryGetProperty("timestamp", out var tsProp) ? tsProp.GetDouble() : 0;
            var contractContent = string.Empty;
            if (element.TryGetProperty("contract_content", out var contentProp) && contentProp.ValueKind == JsonValueKind.String)
            {
                var contentB64 = contentProp.GetString();
                if (!string.IsNullOrWhiteSpace(contentB64))
                {
                    try
                    {
                        contractContent = Encoding.UTF8.GetString(Convert.FromBase64String(contentB64));
                    }
                    catch
                    {
                        contractContent = contentB64;
                    }
                }
            }

            var contract = new ContractInfo
            {
                ContractId = contractId,
                ActionType = actionType,
                ContentHash = contentHash,
                Domain = domain,
                Username = username,
                Verified = verified ? "Sim" : "Não",
                IntegrityOk = integrityOk || verified,
                ViolationReason = violationReason,
                IsContractViolation = !string.IsNullOrWhiteSpace(violationReason) || (hasIntegrityOk && !integrityOk && !verified),
                ContractContent = contractContent,
                ContractTitle = ExtractContractTitle(contractContent),
                Signature = signature,
                Timestamp = timestamp
            };
            ApplyLocalContractValidation(contract);
            return contract;
        }
        catch
        {
            return null;
        }
    }

    private void ApplyLocalContractValidation(ContractInfo contract)
    {
        if (contract is null)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(contract.ContractContent) || string.IsNullOrWhiteSpace(contract.Signature))
        {
            return;
        }
        var publicKey = ResolveContractPublicKey(contract);
        if (string.IsNullOrWhiteSpace(publicKey))
        {
            return;
        }
        var signedText = GetSignedContractText(contract.ContractContent);
        if (string.IsNullOrWhiteSpace(signedText))
        {
            return;
        }
        if (!TryVerifyContractSignature(publicKey, signedText, contract.Signature))
        {
            if (contract.IntegrityOk && string.Equals(contract.Verified, "Sim", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            contract.Verified = "Não";
            contract.IntegrityOk = false;
            if (string.IsNullOrWhiteSpace(contract.ViolationReason))
            {
                contract.ViolationReason = "invalid_signature";
            }
            contract.IsContractViolation = true;
            return;
        }
        if (string.IsNullOrWhiteSpace(contract.ViolationReason))
        {
            contract.Verified = "Sim";
            contract.IntegrityOk = true;
        }
    }

    private string ResolveContractPublicKey(ContractInfo contract)
    {
        if (contract is null)
        {
            return string.Empty;
        }
        if (string.IsNullOrWhiteSpace(contract.ContractContent))
        {
            return string.Empty;
        }
        var key = ExtractContractDetail(contract.ContractContent, "PUBLIC_KEY");
        if (!string.IsNullOrWhiteSpace(key))
        {
            return key;
        }
        key = ExtractContractDetail(contract.ContractContent, "OWNER_PUBLIC_KEY");
        if (!string.IsNullOrWhiteSpace(key))
        {
            return key;
        }
        key = ExtractContractDetail(contract.ContractContent, "ISSUER_PUBLIC_KEY");
        if (!string.IsNullOrWhiteSpace(key))
        {
            return key;
        }
        var username = contract.Username?.Trim().ToLowerInvariant();
        if ((username == "custody" || username == "system") && _serverPublicKeys.TryGetValue(ServerAddress, out var serverKey))
        {
            return serverKey ?? string.Empty;
        }
        return string.Empty;
    }

    private static string ExtractContractTitle(string contractText)
    {
        if (string.IsNullOrWhiteSpace(contractText))
        {
            return string.Empty;
        }

        var candidates = new[]
        {
            "TITLE",
            "FILE_NAME",
            "APP",
            "APP_NAME",
            "DOMAIN"
        };

        foreach (var key in candidates)
        {
            var value = ExtractContractDetail(contractText, key);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }

    private static string ExtractContractDetail(string contractText, string key)
    {
        if (string.IsNullOrWhiteSpace(contractText) || string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }
        var prefix = "# " + key.Trim().ToUpperInvariant() + ":";
        var lines = contractText.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.StartsWith(prefix, StringComparison.Ordinal))
            {
                var parts = line.Split(':', 2);
                if (parts.Length == 2)
                {
                    return parts[1].Trim();
                }
            }
        }
        return string.Empty;
    }

    private static string GetSignedContractText(string contractText)
    {
        if (string.IsNullOrWhiteSpace(contractText))
        {
            return string.Empty;
        }
        var text = contractText.Replace("\r\n", "\n").Replace("\r", "\n");
        var lines = text.Split('\n').ToList();
        if (lines.Count > 0 && lines[^1] == string.Empty)
        {
            lines.RemoveAt(lines.Count - 1);
        }
        var filtered = new List<string>(lines.Count);
        foreach (var line in lines)
        {
            if (line.TrimStart().StartsWith("# SIGNATURE:", StringComparison.Ordinal))
            {
                continue;
            }
            filtered.Add(line);
        }
        return string.Join("\n", filtered);
    }

    private static bool TryVerifyContractSignature(string publicKeyValue, string signedText, string signatureB64)
    {
        try
        {
            using var key = CryptoUtils.LoadPublicKey(publicKeyValue);
            if (key is null)
            {
                return false;
            }
            var sig = Convert.FromBase64String(signatureB64);
            if (CryptoUtils.VerifySignature(key, signedText, sig))
            {
                return true;
            }
            if (CryptoUtils.VerifySignaturePssHashLen(key, signedText, sig))
            {
                return true;
            }
            if (CryptoUtils.VerifySignaturePssMax(key, signedText, sig))
            {
                return true;
            }
            if (CryptoUtils.VerifySignaturePssAuto(key, signedText, sig))
            {
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private string BuildContractDetails(ContractInfo info)
    {
        var timestampStr = info.Timestamp > 0
            ? DateTimeOffset.FromUnixTimeSeconds((long)info.Timestamp).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            : string.Empty;
        var contractHash = string.IsNullOrWhiteSpace(info.ContractContent)
            ? string.Empty
            : _contentService.ComputeSha256HexBytes(Encoding.UTF8.GetBytes(info.ContractContent));

        var lines = new List<string>
        {
            $"ID: {info.ContractId}",
            $"Ação: {info.ActionType}",
            $"Hash do conteúdo: {info.ContentHash}",
            $"Domínio: {info.Domain}",
            $"Usuário: {info.Username}",
            $"Verificado: {info.Verified}",
            $"Integridade OK: {(info.IntegrityOk ? "Sim" : "Não")}",
            $"Motivo violação: {info.ViolationReason}",
            $"Data: {timestampStr}",
            $"Hash do contrato: {contractHash}",
            $"Assinatura: {info.Signature}",
            "",
            "Contrato:",
            info.ContractContent ?? string.Empty
        };

        return string.Join("\n", lines);
    }

    private sealed record PendingDnsRegistration(
        string Domain,
        byte[] DdnsContent,
        string SignatureB64,
        string PublicKeyB64
    );

    private sealed record PendingUsageContract(string ContractText);

    private sealed record PendingHpsTransfer(
        string TargetUser,
        int Amount,
        List<string> VoucherIds,
        string ContractText
    );

    public sealed record PendingTransferInfo(
        string TransferId,
        string TransferType,
        string OriginalOwner,
        string TargetUser,
        string ContentHash,
        string Domain,
        string AppName
    );

    private sealed record PendingInventoryTransfer(InventoryItem Item, string Owner);

    private sealed record PendingUpload(
        string ContentHash,
        string Title,
        string Description,
        string MimeType,
        int Size,
        string SignatureB64,
        string PublicKeyB64,
        string ContentB64
    );

    private static string ComputeNodeId(string sessionId)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sessionId));
        return Convert.ToHexString(hash).ToLowerInvariant()[..32];
    }

    private static string ComputeClientIdentifier(string sessionId)
    {
        var machineId = GetMachineId();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(machineId + sessionId));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string GetMachineId()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var address = nic.GetPhysicalAddress()?.ToString();
            if (!string.IsNullOrWhiteSpace(address))
            {
                return address;
            }
        }

        return Environment.MachineName;
    }
}
