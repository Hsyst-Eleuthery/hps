package socket

import (
	"encoding/base64"
	"log"
	"net/http"
	"strings"

	"hpsserver/internal/core"
	"hpsserver/internal/socketio"
)

func (s *Server) assignPendingJobToMiner(jobID, targetType, targetID, requestKind, requesterUsername, originalOwner, issuerServer, issuerPublicKey, issuerContractID string) bool {
	miner := s.selectOnlineMinerForIssuerJob()
	if miner == "" {
		return false
	}
	nowTs := nowSec()
	_, _ = s.server.DB.Exec(`UPDATE issuer_verification_jobs SET assigned_miner = ?, status = ?, updated_at = ?, deadline = ? WHERE job_id = ? AND status = ?`,
		miner, "assigned", nowTs, nowTs+60.0, jobID, "pending")
	s.emitToUser(miner, "miner_issuer_verification_request", map[string]any{
		"job_id":             jobID,
		"target_type":        targetType,
		"target_id":          targetID,
		"request_kind":       requestKind,
		"requester_username": requesterUsername,
		"original_owner":     originalOwner,
		"issuer_server":      issuerServer,
		"issuer_public_key":  issuerPublicKey,
		"issuer_contract_id": issuerContractID,
		"deadline":           nowTs + 60.0,
	})
	log.Printf("issuer job assigned: job=%s miner=%s target=%s/%s", jobID, miner, targetType, targetID)
	return true
}

func (s *Server) selectOnlineMinerForIssuerJob() string {
	type candidate struct {
		username string
		pending  int
	}
	candidates := make([]candidate, 0)
	seen := make(map[string]struct{})
	s.mu.Lock()
	for _, state := range s.clients {
		if state == nil || !state.Authenticated || !strings.EqualFold(trim(state.NodeType), "miner") {
			continue
		}
		username := trim(state.Username)
		if username == "" {
			continue
		}
		if _, ok := seen[username]; ok {
			continue
		}
		seen[username] = struct{}{}
		pending := 0
		_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM issuer_verification_jobs WHERE assigned_miner = ? AND status IN (?, ?)`, username, "assigned", "pending").Scan(&pending)
		candidates = append(candidates, candidate{username: username, pending: pending})
	}
	s.mu.Unlock()
	if len(candidates) == 0 {
		return ""
	}
	best := candidates[0]
	for _, item := range candidates[1:] {
		if item.pending < best.pending || (item.pending == best.pending && strings.Compare(item.username, best.username) < 0) {
			best = item
		}
	}
	return best.username
}

func (s *Server) ensureIssuerVerificationJob(targetType, targetID, requestKind, requesterUsername, requestContractID string, force bool) map[string]any {
	targetType = strings.ToLower(trim(targetType))
	targetID = trim(targetID)
	if targetType == "dns" {
		targetType = "domain"
	}
	if targetType == "" || targetID == "" {
		return map[string]any{"status": "missing", "detail": "invalid_target"}
	}
	verification := s.server.GetIssuerVerification(targetType, targetID)
	if verification != nil {
		status := asString(verification["status"])
		if !force && (status == "confirmed" || status == "timeout" || status == "local") {
			return map[string]any{"status": status, "verification": verification}
		}
	}
	binding := s.server.LoadIssuerBinding(targetType, targetID)
	if binding == nil {
		return map[string]any{"status": "missing", "detail": "binding_not_found"}
	}
	issuerServer := trim(asString(binding["issuer_server"]))
	issuerPublicKey := trim(asString(binding["issuer_public_key"]))
	issuerContractID := trim(asString(binding["issuer_contract_id"]))
	originalOwner := trim(asString(binding["original_owner"]))
	if originalOwner == "" {
		originalOwner = requesterUsername
	}
	if issuerServer == "" || issuerContractID == "" || strings.EqualFold(issuerServer, s.server.Address) || strings.EqualFold(issuerServer, s.server.BindAddress) || strings.EqualFold(issuerServer, s.server.AddressURL()) {
		result := s.verifyIssuerBinding(targetType, targetID, true)
		return map[string]any{"status": asString(result["status"]), "verification": result}
	}
	var jobID, status, assignedMiner, resultStatus string
	err := s.server.DB.QueryRow(`SELECT job_id, status, assigned_miner, result_status
		FROM issuer_verification_jobs
		WHERE target_type = ? AND target_id = ? AND request_kind = ?
		ORDER BY created_at DESC LIMIT 1`, targetType, targetID, requestKind).
		Scan(&jobID, &status, &assignedMiner, &resultStatus)
	if err == nil && !force {
		if status == "pending" || status == "assigned" {
			return map[string]any{
				"status":         "pending",
				"job_id":         jobID,
				"assigned_miner": assignedMiner,
			}
		}
		if status == "completed" {
			return map[string]any{
				"status": resultStatus,
				"job_id": jobID,
			}
		}
	}
	jobID = core.NewUUID()
	nowTs := nowSec()
	_, _ = s.server.DB.Exec(`INSERT INTO issuer_verification_jobs
		(job_id, target_type, target_id, request_kind, requester_username, original_owner, issuer_server, issuer_public_key, issuer_contract_id, request_contract_id, assigned_miner, status, created_at, updated_at, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?)`,
		jobID, targetType, targetID, requestKind, requesterUsername, originalOwner, issuerServer, issuerPublicKey, issuerContractID, requestContractID, "pending", nowTs, nowTs, nowTs+60.0)
	return map[string]any{
		"status": "pending",
		"job_id": jobID,
	}
}

func (s *Server) assignPendingIssuerVerificationJobs() {
	// Expire stale assigned jobs whose deadline has passed
	staleRows, err := s.server.DB.Query(`SELECT job_id, target_type, target_id, requester_username, original_owner, issuer_server, issuer_public_key, issuer_contract_id
		FROM issuer_verification_jobs WHERE status = ? AND deadline < ?`, "assigned", nowSec())
	if err == nil {
		for staleRows.Next() {
			var jobID, targetType, targetID, requesterUsername, originalOwner, issuerServer, issuerPublicKey, issuerContractID string
			_ = staleRows.Scan(&jobID, &targetType, &targetID, &requesterUsername, &originalOwner, &issuerServer, &issuerPublicKey, &issuerContractID)
			_, _ = s.server.DB.Exec(`UPDATE issuer_verification_jobs SET status = ?, result_status = ?, result_detail = ?, updated_at = ? WHERE job_id = ?`, "completed", "timeout", "issuer_assigned_miner_timeout", nowSec(), jobID)
			s.emitIssuerVerificationUpdate(jobID)
		}
		staleRows.Close()
	}
	// Expire pending jobs older than 120s with no miner available
	expiredIDs := make([]string, 0)
	expiredRows, err := s.server.DB.Query(`SELECT job_id FROM issuer_verification_jobs WHERE status = ? AND created_at < ? AND (assigned_miner = '' OR assigned_miner IS NULL)`, "pending", nowSec()-120.0)
	if err == nil {
		for expiredRows.Next() {
			var jobID string
			_ = expiredRows.Scan(&jobID)
			expiredIDs = append(expiredIDs, jobID)
		}
		expiredRows.Close()
	}
	for _, jobID := range expiredIDs {
		_, _ = s.server.DB.Exec(`UPDATE issuer_verification_jobs SET status = ?, result_status = ?, result_detail = ?, updated_at = ? WHERE job_id = ?`, "completed", "timeout", "issuer_no_miner_available", nowSec(), jobID)
		s.emitIssuerVerificationUpdate(jobID)
	}
	rows, err := s.server.DB.Query(`SELECT job_id, target_type, target_id, request_kind, requester_username, original_owner, issuer_server, issuer_public_key, issuer_contract_id
		FROM issuer_verification_jobs WHERE status = ? ORDER BY created_at ASC LIMIT 100`, "pending")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var jobID, targetType, targetID, requestKind, requesterUsername, originalOwner, issuerServer, issuerPublicKey, issuerContractID string
		if rows.Scan(&jobID, &targetType, &targetID, &requestKind, &requesterUsername, &originalOwner, &issuerServer, &issuerPublicKey, &issuerContractID) != nil {
			continue
		}
		if !s.assignPendingJobToMiner(jobID, targetType, targetID, requestKind, requesterUsername, originalOwner, issuerServer, issuerPublicKey, issuerContractID) {
			log.Printf("issuer ticker: no miner, server verifying directly job=%s target=%s/%s", jobID, targetType, targetID)
			verification := s.verifyIssuerBinding(targetType, targetID, true)
			resultStatus := asString(verification["status"])
			resultDetail := asString(verification["detail"])
			_, _ = s.server.DB.Exec(`UPDATE issuer_verification_jobs SET status = ?, result_status = ?, result_detail = ?, updated_at = ? WHERE job_id = ?`,
				"completed", resultStatus, resultDetail, nowSec(), jobID)
			s.emitIssuerVerificationUpdate(jobID)
		}
	}
}

func (s *Server) emitIssuerVerificationUpdate(jobID string) {
	var requester, targetType, targetID, resultStatus, resultDetail string
	err := s.server.DB.QueryRow(`SELECT requester_username, target_type, target_id, result_status, result_detail
		FROM issuer_verification_jobs WHERE job_id = ?`, jobID).Scan(&requester, &targetType, &targetID, &resultStatus, &resultDetail)
	if err != nil || requester == "" {
		return
	}
	verification := s.server.GetIssuerVerification(targetType, targetID)
	s.emitToUser(requester, "issuer_verification_update", map[string]any{
		"job_id":       jobID,
		"target_type":  targetType,
		"target_id":    targetID,
		"status":       resultStatus,
		"detail":       resultDetail,
		"verification": verification,
		"market":       s.server.BuildPhpsMarketPayload(requester),
	})
}

func (s *Server) handleSubmitIssuerVerificationReport(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("issuer_verification_report_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	jobID := trim(asString(data["job_id"]))
	contractB64 := asString(data["contract_content"])
	if jobID == "" || contractB64 == "" {
		conn.Emit("issuer_verification_report_ack", map[string]any{"success": false, "error": "Missing job_id or contract"})
		return
	}
	var targetType, targetID, requestKind, requesterUsername, originalOwner, issuerServer, issuerPublicKey, issuerContractID, assignedMiner, status string
	err := s.server.DB.QueryRow(`SELECT target_type, target_id, request_kind, requester_username, original_owner, issuer_server, issuer_public_key, issuer_contract_id, assigned_miner, status
		FROM issuer_verification_jobs WHERE job_id = ?`, jobID).
		Scan(&targetType, &targetID, &requestKind, &requesterUsername, &originalOwner, &issuerServer, &issuerPublicKey, &issuerContractID, &assignedMiner, &status)
	if err != nil {
		conn.Emit("issuer_verification_report_ack", map[string]any{"success": false, "error": "Job not found"})
		return
	}
	if !strings.EqualFold(assignedMiner, client.Username) || status != "assigned" {
		conn.Emit("issuer_verification_report_ack", map[string]any{"success": false, "error": "Job not assigned to this miner"})
		return
	}
	contractBytes, err := base64.StdEncoding.DecodeString(contractB64)
	if err != nil {
		conn.Emit("issuer_verification_report_ack", map[string]any{"success": false, "error": "Invalid base64 contract"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractBytes)
	if !valid || contractInfo == nil {
		conn.Emit("issuer_verification_report_ack", map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
		return
	}
	if contractInfo.Action != "issuer_verification_report" || contractInfo.User != client.Username || !s.server.VerifyContractSignature(contractBytes, client.Username, contractInfo.Signature, client.PublicKey) {
		conn.Emit("issuer_verification_report_ack", map[string]any{"success": false, "error": "Invalid report signature"})
		return
	}
	if !strings.EqualFold(core.ExtractContractDetail(contractInfo, "JOB_ID"), jobID) ||
		!strings.EqualFold(core.ExtractContractDetail(contractInfo, "TARGET_TYPE"), targetType) ||
		!strings.EqualFold(core.ExtractContractDetail(contractInfo, "TARGET_ID"), targetID) {
		conn.Emit("issuer_verification_report_ack", map[string]any{"success": false, "error": "Job target mismatch"})
		return
	}
	reportResult := strings.ToLower(trim(core.ExtractContractDetail(contractInfo, "RESULT_STATUS")))
	reportDetail := trim(core.ExtractContractDetail(contractInfo, "DETAIL"))
	reportContractID := s.server.SaveContract("issuer_verification_report", jobID, "", client.Username, contractInfo.Signature, contractBytes)

	finalStatus := "failed"
	finalDetail := reportDetail
	timeoutConfirmContractID := ""
	switch reportResult {
	case "confirmed":
		verification := s.verifyIssuerBinding(targetType, targetID, true)
		finalStatus = asString(verification["status"])
		finalDetail = defaultStr(asString(verification["detail"]), reportDetail)
	case "timeout":
		okInfo, _, errMsg := s.server.MakeRemoteRequestJSON(issuerServer, "/server_info", http.MethodGet, nil)
		if okInfo {
			finalStatus = "failed"
			finalDetail = "issuer_reachable_after_timeout_report"
		} else {
			verification := s.registerIssuerTimeout(targetType, targetID, issuerServer, issuerPublicKey, issuerContractID, originalOwner, defaultStr(errMsg, reportDetail))
			finalStatus = asString(verification["status"])
			finalDetail = defaultStr(asString(verification["detail"]), reportDetail)
			timeoutConfirmContractID = s.server.BuildIssuerVerificationContract("issuer_timeout_confirmed", targetType, targetID, issuerServer, issuerContractID, "timeout", finalDetail, originalOwner)
		}
	default:
		finalStatus = "failed"
		if finalDetail == "" {
			finalDetail = "miner_report_failed"
		}
	}
	_, _ = s.server.DB.Exec(`UPDATE issuer_verification_jobs
		SET status = ?, result_status = ?, result_detail = ?, result_contract_id = ?, timeout_confirm_contract_id = ?, updated_at = ?
		WHERE job_id = ?`, "completed", finalStatus, finalDetail, reportContractID, timeoutConfirmContractID, nowSec(), jobID)

	if requestKind == "recheck" && strings.EqualFold(finalStatus, "confirmed") {
		confirmContractID := s.server.BuildIssuerVerificationContract("issuer_recheck_confirmed", targetType, targetID, issuerServer, issuerContractID, "confirmed", finalDetail, requesterUsername)
		s.server.IssueCustodyRefundWithDebt(requesterUsername, core.IssuerRecheckFee, "issuer_recheck", targetType, targetID, confirmContractID)
	}
	s.emitIssuerVerificationUpdate(jobID)
	conn.Emit("issuer_verification_report_ack", map[string]any{
		"success":       true,
		"job_id":        jobID,
		"status":        finalStatus,
		"detail":        finalDetail,
		"result_status": reportResult,
	})
}

func (s *Server) issuerVerificationGate(targetType, targetID, requesterUsername string) map[string]any {
	job := s.ensureIssuerVerificationJob(targetType, targetID, "access", requesterUsername, "", false)
	status := asString(job["status"])
	if status == "confirmed" || status == "local" || status == "timeout" {
		return map[string]any{"allowed": true, "status": status, "verification": job["verification"]}
	}
	if status == "missing" {
		return map[string]any{"allowed": false, "status": "missing", "error": asString(job["detail"])}
	}
	if status == "pending" || status == "assigned" {
		alreadyAssigned := trim(asString(job["assigned_miner"]))
		if alreadyAssigned != "" {
			return map[string]any{
				"allowed":        false,
				"status":         "pending",
				"job_id":         asString(job["job_id"]),
				"assigned_miner": alreadyAssigned,
			}
		}
		// No miner yet — try to assign immediately
		jobID := asString(job["job_id"])
		if jobID != "" {
			var dbTargetType, dbTargetID, dbRequestKind, dbRequesterUsername, dbOriginalOwner, dbIssuerServer, dbIssuerPublicKey, dbIssuerContractID string
			err := s.server.DB.QueryRow(`SELECT target_type, target_id, request_kind, requester_username, original_owner, issuer_server, issuer_public_key, issuer_contract_id
				FROM issuer_verification_jobs WHERE job_id = ?`, jobID).
				Scan(&dbTargetType, &dbTargetID, &dbRequestKind, &dbRequesterUsername, &dbOriginalOwner, &dbIssuerServer, &dbIssuerPublicKey, &dbIssuerContractID)
			if err == nil && s.assignPendingJobToMiner(jobID, dbTargetType, dbTargetID, dbRequestKind, dbRequesterUsername, dbOriginalOwner, dbIssuerServer, dbIssuerPublicKey, dbIssuerContractID) {
				return map[string]any{
					"allowed":        false,
					"status":         "pending",
					"job_id":         jobID,
					"assigned_miner": s.selectOnlineMinerForIssuerJob(),
				}
			}
		}
		// No miner available — server verifies the remote issuer directly
		log.Printf("issuer gate: no miner, server verifying directly target=%s/%s requester=%s", targetType, targetID, requesterUsername)
		verification := s.verifyIssuerBinding(targetType, targetID, true)
		resultStatus := asString(verification["status"])
		resultDetail := asString(verification["detail"])
		if jobID != "" {
			_, _ = s.server.DB.Exec(`UPDATE issuer_verification_jobs SET status = ?, result_status = ?, result_detail = ?, updated_at = ? WHERE job_id = ?`,
				"completed", resultStatus, resultDetail, nowSec(), jobID)
			s.emitIssuerVerificationUpdate(jobID)
		}
		return map[string]any{
			"allowed":      true,
			"status":       resultStatus,
			"verification": verification,
		}
	}
	// For any completed/failed job or any other status not covered above,
	// allow the DNS to proceed rather than leaving the client hanging.
	return map[string]any{
		"allowed": true,
		"status":  status,
		"verification": job["verification"],
	}
}

func (s *Server) handleRequestIssuerRecheck(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "issuer_recheck_result")
	if !ok {
		return
	}
	okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
		actx.ClientIdentifier, actx.Username, "issuer_recheck",
		asString(data["pow_nonce"]), asFloat(data["hashrate_observed"]), castMap(data["hps_payment"]),
	)
	if !okAuth {
		conn.Emit("issuer_recheck_result", map[string]any{"success": false, "error": defaultStr(authErr, "Pagamento inválido")})
		if shouldBan {
			s.banClientAndNotify(actx.ClientIdentifier, 300, "Invalid issuer recheck authorization")
		}
		return
	}
	if pendingInfo != nil {
		payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": actx.PublicKey}
		transferID := asString(pendingInfo["transfer_id"])
		s.queuePendingMonetaryAction(conn, transferID, "request_issuer_recheck", actx.Username, actx.ClientIdentifier, payload, "issuer_recheck_result")
		return
	}

	contractContentB64 := asString(data["contract_content"])
	contractContent, err := base64.StdEncoding.DecodeString(contractContentB64)
	if err != nil || len(contractContent) == 0 {
		conn.Emit("issuer_recheck_result", map[string]any{"success": false, "error": "Contrato inválido"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("issuer_recheck_result", map[string]any{"success": false, "error": "Contrato inválido: " + errMsg})
		return
	}
	if contractInfo.Action != "issuer_recheck" {
		conn.Emit("issuer_recheck_result", map[string]any{"success": false, "error": "Ação contratual inválida"})
		return
	}
	if contractInfo.User != actx.Username || !s.server.VerifyContractSignature(contractContent, actx.Username, contractInfo.Signature, actx.PublicKey) {
		conn.Emit("issuer_recheck_result", map[string]any{"success": false, "error": "Assinatura contratual inválida"})
		return
	}
	targetType := strings.ToLower(trim(core.ExtractContractDetail(contractInfo, "TARGET_TYPE")))
	targetID := trim(core.ExtractContractDetail(contractInfo, "TARGET_ID"))
	if targetType == "dns" {
		targetType = "domain"
	}
	if targetType == "" || targetID == "" {
		conn.Emit("issuer_recheck_result", map[string]any{"success": false, "error": "TARGET_TYPE ou TARGET_ID ausentes"})
		return
	}
	binding := s.server.LoadIssuerBinding(targetType, targetID)
	if binding == nil {
		conn.Emit("issuer_recheck_result", map[string]any{"success": false, "error": "Item não encontrado"})
		return
	}
	owner := trim(asString(binding["original_owner"]))
	if owner != "" && !strings.EqualFold(owner, actx.Username) {
		conn.Emit("issuer_recheck_result", map[string]any{"success": false, "error": "Somente a pessoa dona original pode pedir revogação"})
		return
	}
	requestContractID := s.server.SaveContract("issuer_recheck", "", "", actx.Username, contractInfo.Signature, contractContent)
	job := s.ensureIssuerVerificationJob(targetType, targetID, "recheck", actx.Username, requestContractID, true)
	conn.Emit("issuer_recheck_result", map[string]any{
		"success":     true,
		"pending":     true,
		"status":      "pending",
		"job_id":      asString(job["job_id"]),
		"message":     "Revogação enviada. Aguardando relatório do minerador.",
		"target_type": targetType,
		"target_id":   targetID,
	})
}

func (s *Server) handleGetPhpsMarket(conn socketio.Conn, _ map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("phps_market", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	conn.Emit("phps_market", s.server.BuildPhpsMarketPayload(client.Username))
}
