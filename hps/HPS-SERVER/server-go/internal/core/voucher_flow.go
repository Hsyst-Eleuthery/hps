package core

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) BuildHpsVoucherPayload(owner, ownerPublicKey string, value int, reason string, powInfo map[string]any, conditions map[string]any, voucherID string) map[string]any {
	// H-04 FIX: Validate value bounds
	if value < 1 {
		value = 1
	}
	if value > SupplyCap {
		value = SupplyCap
	}
	
	// H-04 FIX: Sanitize reason - remove control characters
	reason = sanitizeString(reason)
	
	if powInfo == nil {
		powInfo = map[string]any{}
	}
	if conditions == nil {
		conditions = map[string]any{}
	}
	conditions = s.EnrichVoucherConditions(conditions)
	if voucherID == "" {
		voucherID = NewUUID()
	}
	lineage := s.ResolveVoucherLineage(voucherID, conditions)
	dkvhps := s.BuildVoucherDkvhps(ownerPublicKey, lineage)
	return map[string]any{
		"voucher_type":              "HPS",
		"version":                   1,
		"voucher_id":                voucherID,
		"value":                     value,
		"issuer":                    s.Address,
		"issuer_public_key":         base64Encode(s.PublicKeyPEM),
		"owner":                     owner,
		"owner_public_key":          ownerPublicKey,
		"reason":                    reason,
		"issued_at":                 now(),
		"pow":                       powInfo,
		"conditions":                conditions,
		"dkvhps":                    dkvhps,
		"lineage_root_voucher_id":   lineage.RootVoucherID,
		"lineage_parent_voucher_id": lineage.ParentVoucherID,
		"lineage_parent_hash":       lineage.ParentHash,
		"lineage_depth":             lineage.Depth,
		"lineage_origin":            lineage.Origin,
	}
}

func (s *Server) CreateVoucherOffer(owner, ownerPublicKey string, value int, reason string, powInfo map[string]any, conditions map[string]any, voucherID string) map[string]any {
	return s.CreateVoucherOfferWithStatus(owner, ownerPublicKey, value, reason, powInfo, conditions, voucherID, "pending")
}

const maxPendingVoucherOffersPerUser = 50

func (s *Server) CreateVoucherOfferWithStatus(owner, ownerPublicKey string, value int, reason string, powInfo map[string]any, conditions map[string]any, voucherID, status string) map[string]any {
	// Enforce per-user pending offer limit to prevent unbounded growth
	var pendingCount int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM hps_voucher_offers WHERE owner = ? AND status = 'pending'`, owner).Scan(&pendingCount)
	if pendingCount >= maxPendingVoucherOffersPerUser {
		log.Printf("voucher offer rejected: user %s has %d pending offers (limit %d)", owner, pendingCount, maxPendingVoucherOffersPerUser)
		return map[string]any{
			"offer_id":      "",
			"voucher_id":    "",
			"persist_error": "too many pending voucher offers",
		}
	}
	payload := s.BuildHpsVoucherPayload(owner, ownerPublicKey, value, reason, powInfo, conditions, voucherID)
	payloadCanonical := CanonicalJSON(payload)
	offerID := NewUUID()
	nowTs := now()
	expiresAt := nowTs + 600
	if status == "" {
		status = "pending"
	}
	if err := s.BeginTx(); err != nil {
		log.Printf("voucher offer begin failed offer_id=%s err=%v", offerID, err)
		return map[string]any{
			"offer_id":      offerID,
			"voucher_id":    payload["voucher_id"],
			"persist_error": "failed to start transaction: " + err.Error(),
		}
	}
	if _, err := s.TxExec(`INSERT OR REPLACE INTO hps_voucher_offers
		(offer_id, voucher_id, owner, payload, value, reason, issued_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		offerID, payload["voucher_id"], owner, payloadCanonical, payload["value"], reason, nowTs, expiresAt, status); err != nil {
		s.RollbackTx()
		log.Printf("voucher offer persist failed offer_id=%s voucher_id=%v owner=%s err=%v",
			offerID,
			payload["voucher_id"],
			owner,
			err,
		)
		return map[string]any{
			"offer_id":          offerID,
			"voucher_id":        payload["voucher_id"],
			"payload":           payload,
			"payload_canonical": payloadCanonical,
			"expires_at":        expiresAt,
			"session_id":        nil,
			"persist_error":     err.Error(),
		}
	}
	s.CommitTx()
	return map[string]any{
		"offer_id":          offerID,
		"voucher_id":        payload["voucher_id"],
		"payload":           payload,
		"payload_canonical": payloadCanonical,
		"expires_at":        expiresAt,
		"session_id":        nil,
	}
}

func (s *Server) FinalizeVoucher(voucherID, ownerSignature string) map[string]any {
	voucher, _ := s.FinalizeVoucherDetailed(voucherID, ownerSignature, "")
	return voucher
}

func (s *Server) FinalizeVoucherDetailed(voucherID, ownerSignature, ownerSignedPayloadText string) (map[string]any, string) {
	txErr := s.BeginTx()
	if txErr != nil {
		return nil, "Failed to start transaction"
	}
	rolledBack := false
	rollback := func() { if !rolledBack { s.RollbackTx(); rolledBack = true } }
	defer rollback()

	var payloadText, owner, status string
	err := s.TxQueryRow(`SELECT payload, owner, status FROM hps_voucher_offers WHERE voucher_id = ?`, voucherID).Scan(&payloadText, &owner, &status)
	if err != nil {
		return nil, "Voucher offer not found"
	}
	if status != "pending" {
		return nil, "Voucher offer is not pending"
	}
	payload := map[string]any{}
	if err := json.Unmarshal([]byte(payloadText), &payload); err != nil {
		return nil, "Voucher payload is invalid"
	}
	lineageMeta := s.ResolveVoucherLineage(voucherID, mapValue(payload["conditions"]))
	ownerPublicKey := ""
	if v, ok := payload["owner_public_key"].(string); ok {
		ownerPublicKey = v
	}
	if strings.TrimSpace(ownerSignedPayloadText) != "" {
		if !payloadSignedTextMatchesOffer(payloadText, ownerSignedPayloadText) {
			return nil, "Owner signed payload does not match voucher offer"
		}
		if !VerifyRawTextSignature(ownerSignedPayloadText, ownerSignature, ownerPublicKey) {
			return nil, "Owner signature does not match signed payload text"
		}
	} else if !VerifyPayloadSignatureFlexible(payload, payloadText, ownerSignature, ownerPublicKey) {
		return nil, "Owner signature does not match voucher payload"
	}
	issuerSignature := s.SignPayload(payload)
	voucher := map[string]any{
		"voucher_type": "HPS",
		"payload":      payload,
		"signatures": map[string]any{
			"owner":  ownerSignature,
			"issuer": issuerSignature,
		},
	}
	AttachVoucherIntegrity(voucher)
	nowTs := now()
	// Verify supply chain integrity before creating voucher
	// Check if parent voucher (if any) is in the supply chain
	sourceIDs := lineageMeta.SourceVoucherIDs
	for _, srcID := range sourceIDs {
		if srcID != "" && !s.VerifyVoucherSupplyChain(srcID) {
			return nil, "Parent voucher " + srcID + " not found in supply chain"
		}
	}
	_, _ = s.TxExec(`INSERT OR REPLACE INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature,
		 owner_signature, status, session_id, lineage_root_voucher_id, lineage_parent_voucher_id,
		 lineage_parent_hash, lineage_depth, lineage_origin, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		voucherID,
		asString(payload["issuer"]),
		owner,
		asInt(payload["value"]),
		asString(payload["reason"]),
		asFloat(payload["issued_at"]),
		CanonicalJSON(payload),
		issuerSignature,
		ownerSignature,
		"valid",
		nil,
		defaultString(asString(payload["lineage_root_voucher_id"]), lineageMeta.RootVoucherID),
		defaultString(asString(payload["lineage_parent_voucher_id"]), lineageMeta.ParentVoucherID),
		defaultString(asString(payload["lineage_parent_hash"]), lineageMeta.ParentHash),
		maxInt(asInt(payload["lineage_depth"]), lineageMeta.Depth),
		defaultString(asString(payload["lineage_origin"]), lineageMeta.Origin),
		0,
		nowTs,
	)
	_, _ = s.TxExec(`UPDATE hps_voucher_offers SET status = ? WHERE voucher_id = ?`, "issued", voucherID)
	s.StoreVoucherFile(voucherID, voucher)
	contractID := s.SaveServerContract("voucher_issue", []ContractDetail{
		{Key: "VOUCHER_ID", Value: asString(payload["voucher_id"])},
		{Key: "OWNER", Value: asString(payload["owner"])},
		{Key: "ISSUER", Value: asString(payload["issuer"])},
		{Key: "VALUE", Value: asInt(payload["value"])},
		{Key: "REASON", Value: asString(payload["reason"])},
		{Key: "ISSUED_AT", Value: asFloat(payload["issued_at"])},
	}, asString(payload["voucher_id"]))
	// Record supply chain entry for this voucher
	if _, _, chainErr := s.RecordVoucherSupplyChain(
		voucherID,
		asInt(payload["value"]),
		owner,
		nowTs,
		contractID,
	); chainErr != nil {
		return nil, "Supply chain recording failed: " + chainErr.Error()
	}
	// Cache PoW status for this voucher
	powInfo := mapValue(payload["pow"])
	powActionType := asString(powInfo["action_type"])
	hasDirectPow := false
	if powOK, _, powDetails := s.VerifyVoucherPowPayload(payload); powOK {
		hasDirectPow = asString(powDetails["action_type"]) == "hps_mint"
	}
	s.CacheVoucherPowStatus(voucherID, hasDirectPow, powActionType)
	if details := BuildLineageTransitionDetails(lineageMeta, voucherID); len(details) > 0 {
		_ = s.SaveServerContract("voucher_lineage_transition", details, voucherID)
	}
	s.CommitTx()
	rolledBack = true
	return voucher, ""
}

func payloadSignedTextMatchesOffer(offerPayloadText, signedPayloadText string) bool {
	offerPayloadText = strings.TrimSpace(offerPayloadText)
	signedPayloadText = strings.TrimSpace(signedPayloadText)
	if offerPayloadText == "" || signedPayloadText == "" {
		return false
	}
	if offerPayloadText == signedPayloadText {
		return true
	}
	var signedPayload map[string]any
	if err := json.Unmarshal([]byte(signedPayloadText), &signedPayload); err != nil {
		return false
	}
	return CanonicalJSON(signedPayload) == offerPayloadText
}

func (s *Server) StoreVoucherFile(voucherID string, voucher map[string]any) {
	voucherDir := filepath.Join(s.FilesDir, "vouchers")
	_ = os.MkdirAll(voucherDir, 0o755)
	voucherPath := filepath.Join(voucherDir, voucherID+".hps")
	_ = s.WriteEncryptedFile(voucherPath, s.EncodeVoucherFileForStorage(voucher))
}

func (s *Server) GetHpsVoucherValueFromBits(targetBits int) int {
	unit := s.HpsVoucherUnitBits
	if unit <= 0 {
		unit = 8
	}
	value := (targetBits + unit - 1) / unit
	if value < 1 {
		value = 1
	}
	maxV := s.HpsVoucherMaxValue
	if maxV <= 0 {
		maxV = 50
	}
	if value > maxV {
		value = maxV
	}
	return value
}
