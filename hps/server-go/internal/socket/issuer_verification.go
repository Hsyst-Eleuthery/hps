package socket

import (
	"encoding/base64"
	"net/http"
	"strings"

	"hpsserver/internal/core"
	"hpsserver/internal/socketio"
)

func (s *Server) verifyIssuerBinding(targetType, targetID string, force bool) map[string]any {
	binding := s.server.LoadIssuerBinding(targetType, targetID)
	if binding == nil {
		return map[string]any{"status": "missing", "detail": "binding_not_found"}
	}
	issuerServer := trim(asString(binding["issuer_server"]))
	issuerPublicKey := trim(asString(binding["issuer_public_key"]))
	issuerContractID := trim(asString(binding["issuer_contract_id"]))
	originalOwner := trim(asString(binding["original_owner"]))
	if originalOwner == "" {
		originalOwner = core.CustodyUsername
	}
	existing := s.server.GetIssuerVerification(targetType, targetID)
	if !force && existing != nil {
		status := asString(existing["status"])
		if status == "confirmed" || status == "timeout" || status == "local" {
			return existing
		}
	}
	if issuerServer == "" || issuerContractID == "" {
		contractID := s.server.BuildIssuerVerificationContract("check_for_files_in", targetType, targetID, s.server.Address, issuerContractID, "local", "local_issuer", originalOwner)
		s.server.SetContractCertification(targetType, targetID, originalOwner, s.server.Address)
		s.server.UpsertIssuerVerification(targetType, targetID, s.server.Address, base64.StdEncoding.EncodeToString(s.server.PublicKeyPEM), issuerContractID, originalOwner, "local", "local_issuer", contractID, "", "")
		return s.server.GetIssuerVerification(targetType, targetID)
	}

	okInfo, infoPayload, errMsg := s.server.MakeRemoteRequestJSON(issuerServer, "/server_info", http.MethodGet, nil)
	if !okInfo {
		return s.registerIssuerTimeout(targetType, targetID, issuerServer, issuerPublicKey, issuerContractID, originalOwner, defaultStr(errMsg, "issuer_timeout"))
	}
	remoteKey := trim(asString(infoPayload["public_key"]))
	if issuerPublicKey != "" && remoteKey != "" && !strings.EqualFold(strings.TrimSpace(remoteKey), strings.TrimSpace(issuerPublicKey)) {
		contractID := s.server.BuildIssuerVerificationContract("check_for_files_in", targetType, targetID, issuerServer, issuerContractID, "failed", "issuer_public_key_mismatch", originalOwner)
		s.server.UpsertIssuerVerification(targetType, targetID, issuerServer, issuerPublicKey, issuerContractID, originalOwner, "failed", "issuer_public_key_mismatch", contractID, "", "")
		return s.server.GetIssuerVerification(targetType, targetID)
	}
	contractBytes := s.server.GetContractBytes(issuerContractID)
	if len(contractBytes) == 0 {
		okRaw, rawContract, rawErr := s.server.MakeRemoteRequestBytes(issuerServer, "/contract/"+issuerContractID, http.MethodGet)
		if !okRaw || len(rawContract) == 0 {
			return s.registerIssuerTimeout(targetType, targetID, issuerServer, defaultStr(issuerPublicKey, remoteKey), issuerContractID, originalOwner, defaultStr(rawErr, "issuer_contract_timeout"))
		}
		contractBytes = rawContract
	}
	valid, _, contractInfo := core.ValidateContractStructure(contractBytes)
	if !valid || contractInfo == nil {
		contractID := s.server.BuildIssuerVerificationContract("check_for_files_in", targetType, targetID, issuerServer, issuerContractID, "failed", "issuer_contract_invalid", originalOwner)
		s.server.UpsertIssuerVerification(targetType, targetID, issuerServer, defaultStr(issuerPublicKey, remoteKey), issuerContractID, originalOwner, "failed", "issuer_contract_invalid", contractID, "", "")
		return s.server.GetIssuerVerification(targetType, targetID)
	}
	if contractInfo.User != core.CustodyUsername || !s.server.VerifyContractSignature(contractBytes, contractInfo.User, contractInfo.Signature, defaultStr(issuerPublicKey, remoteKey)) {
		contractID := s.server.BuildIssuerVerificationContract("check_for_files_in", targetType, targetID, issuerServer, issuerContractID, "failed", "issuer_contract_signature_invalid", originalOwner)
		s.server.UpsertIssuerVerification(targetType, targetID, issuerServer, defaultStr(issuerPublicKey, remoteKey), issuerContractID, originalOwner, "failed", "issuer_contract_signature_invalid", contractID, "", "")
		return s.server.GetIssuerVerification(targetType, targetID)
	}
	expectedAction := "content_issuer_attest"
	if targetType == "domain" {
		expectedAction = "dns_issuer_attest"
	}
	if contractInfo.Action != expectedAction ||
		!strings.EqualFold(core.ExtractContractDetail(contractInfo, "TARGET_TYPE"), targetType) ||
		!strings.EqualFold(core.ExtractContractDetail(contractInfo, "TARGET_ID"), targetID) {
		contractID := s.server.BuildIssuerVerificationContract("check_for_files_in", targetType, targetID, issuerServer, issuerContractID, "failed", "issuer_contract_target_mismatch", originalOwner)
		s.server.UpsertIssuerVerification(targetType, targetID, issuerServer, defaultStr(issuerPublicKey, remoteKey), issuerContractID, originalOwner, "failed", "issuer_contract_target_mismatch", contractID, "", "")
		return s.server.GetIssuerVerification(targetType, targetID)
	}

	path := "/sync/content?content_hash=" + targetID
	keyName := "content_hash"
	if targetType == "domain" {
		path = "/sync/dns?domain=" + targetID
		keyName = "domain"
	}
	okMeta, metaPayload, metaErr := s.server.MakeRemoteRequestJSON(issuerServer, path, http.MethodGet, nil)
	if !okMeta {
		return s.registerIssuerTimeout(targetType, targetID, issuerServer, defaultStr(issuerPublicKey, remoteKey), issuerContractID, originalOwner, defaultStr(metaErr, "issuer_metadata_timeout"))
	}
	items := castSliceMap(metaPayload["items"])
	if len(items) == 0 || !strings.EqualFold(asString(items[0][keyName]), targetID) {
		contractID := s.server.BuildIssuerVerificationContract("check_for_files_in", targetType, targetID, issuerServer, issuerContractID, "failed", "issuer_metadata_missing", originalOwner)
		s.server.UpsertIssuerVerification(targetType, targetID, issuerServer, defaultStr(issuerPublicKey, remoteKey), issuerContractID, originalOwner, "failed", "issuer_metadata_missing", contractID, "", "")
		return s.server.GetIssuerVerification(targetType, targetID)
	}

	contractID := s.server.BuildIssuerVerificationContract("check_for_files_in", targetType, targetID, issuerServer, issuerContractID, "confirmed", "issuer_confirmed", originalOwner)
	s.server.SetContractCertification(targetType, targetID, originalOwner, issuerServer)
	s.server.UpsertIssuerVerification(targetType, targetID, issuerServer, defaultStr(issuerPublicKey, remoteKey), issuerContractID, originalOwner, "confirmed", "issuer_confirmed", contractID, "", "")
	return s.server.GetIssuerVerification(targetType, targetID)
}

func (s *Server) registerIssuerTimeout(targetType, targetID, issuerServer, issuerPublicKey, issuerContractID, originalOwner, detail string) map[string]any {
	existing := s.server.GetIssuerVerification(targetType, targetID)
	exceptionContractID := ""
	debtContractID := ""
	if existing != nil {
		exceptionContractID = asString(existing["exception_contract_id"])
		debtContractID = asString(existing["debt_contract_id"])
	}
	if exceptionContractID == "" {
		exceptionContractID = s.server.BuildIssuerVerificationContract("check_for_files_except", targetType, targetID, issuerServer, issuerContractID, "timeout", detail, originalOwner)
	}
	s.server.SetContractCertification(targetType, targetID, originalOwner, core.CustodyUsername)
	s.server.UpsertIssuerVerification(targetType, targetID, issuerServer, issuerPublicKey, issuerContractID, originalOwner, "timeout", detail, "", exceptionContractID, debtContractID)
	return s.server.GetIssuerVerification(targetType, targetID)
}

func (s *Server) handleFundPhpsDebt(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("phps_fund_result", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	debtID := trim(asString(data["debt_id"]))
	voucherIDs := toStringSlice(data["voucher_ids"])
	contractContentB64 := asString(data["contract_content"])
	contractContent, err := base64.StdEncoding.DecodeString(contractContentB64)
	if debtID == "" || err != nil || len(contractContent) == 0 {
		conn.Emit("phps_fund_result", map[string]any{"success": false, "error": "Dados inválidos"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("phps_fund_result", map[string]any{"success": false, "error": "Contrato inválido: " + errMsg})
		return
	}
	if contractInfo.Action != "phps_fund" || contractInfo.User != client.Username || !s.server.VerifyContractSignature(contractContent, client.Username, contractInfo.Signature, client.PublicKey) {
		conn.Emit("phps_fund_result", map[string]any{"success": false, "error": "Assinatura contratual inválida"})
		return
	}
	contractDebtID := trim(core.ExtractContractDetail(contractInfo, "DEBT_ID"))
	paidAmount := int(asFloat(core.ExtractContractDetail(contractInfo, "AMOUNT")))
	if !strings.EqualFold(contractDebtID, debtID) || paidAmount <= 0 {
		conn.Emit("phps_fund_result", map[string]any{"success": false, "error": "Contrato não corresponde à dívida"})
		return
	}
	contractID := s.server.SaveContract("phps_fund", "", "", client.Username, contractInfo.Signature, contractContent)
	payload, fundErr := s.server.FundPhpsDebt(client.Username, client.PublicKey, debtID, contractID, voucherIDs, paidAmount)
	if fundErr != "" {
		conn.Emit("phps_fund_result", map[string]any{"success": false, "error": fundErr})
		return
	}
	conn.Emit("phps_fund_result", payload)
}
