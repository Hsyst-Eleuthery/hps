package core

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) BuildHpsVoucherPayload(owner, ownerPublicKey string, value int, reason string, powInfo map[string]any, conditions map[string]any, voucherID string) map[string]any {
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

func (s *Server) CreateVoucherOfferWithStatus(owner, ownerPublicKey string, value int, reason string, powInfo map[string]any, conditions map[string]any, voucherID, status string) map[string]any {
	payload := s.BuildHpsVoucherPayload(owner, ownerPublicKey, value, reason, powInfo, conditions, voucherID)
	payloadCanonical := CanonicalJSON(payload)
	offerID := NewUUID()
	nowTs := now()
	expiresAt := nowTs + 600
	if status == "" {
		status = "pending"
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO hps_voucher_offers
		(offer_id, voucher_id, owner, payload, value, reason, issued_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		offerID, payload["voucher_id"], owner, payloadCanonical, payload["value"], reason, nowTs, expiresAt, status)
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
	var payloadText, owner, status string
	err := s.DB.QueryRow(`SELECT payload, owner, status FROM hps_voucher_offers WHERE voucher_id = ?`, voucherID).Scan(&payloadText, &owner, &status)
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
	log.Printf("voucher finalize debug voucher_id=%s offer_hash=%s signed_hash=%s signed_present=%t owner_key_len=%d",
		voucherID,
		shortTextHash(payloadText),
		shortTextHash(ownerSignedPayloadText),
		strings.TrimSpace(ownerSignedPayloadText) != "",
		len(ownerPublicKey),
	)
	if strings.TrimSpace(ownerSignedPayloadText) != "" {
		if !payloadSignedTextMatchesOffer(payloadText, ownerSignedPayloadText) {
			log.Printf("voucher finalize mismatch voucher_id=%s reason=signed_payload_offer_mismatch offer_hash=%s signed_hash=%s",
				voucherID,
				shortTextHash(payloadText),
				shortTextHash(ownerSignedPayloadText),
			)
			return nil, "Owner signed payload does not match voucher offer"
		}
		if !VerifyRawTextSignature(ownerSignedPayloadText, ownerSignature, ownerPublicKey) {
			log.Printf("voucher finalize mismatch voucher_id=%s reason=signature_invalid_for_signed_text signed_hash=%s signature_len=%d",
				voucherID,
				shortTextHash(ownerSignedPayloadText),
				len(ownerSignature),
			)
			return nil, "Owner signature does not match signed payload text"
		}
	} else if !VerifyPayloadSignatureFlexible(payload, payloadText, ownerSignature, ownerPublicKey) {
		log.Printf("voucher finalize mismatch voucher_id=%s reason=signature_invalid_for_payload canonical_hash=%s raw_hash=%s signature_len=%d",
			voucherID,
			shortTextHash(CanonicalJSON(payload)),
			shortTextHash(payloadText),
			len(ownerSignature),
		)
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
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO hps_vouchers
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
	_, _ = s.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE voucher_id = ?`, "issued", voucherID)
	s.StoreVoucherFile(voucherID, voucher)
	_ = s.SaveServerContract("voucher_issue", []ContractDetail{
		{Key: "VOUCHER_ID", Value: asString(payload["voucher_id"])},
		{Key: "OWNER", Value: asString(payload["owner"])},
		{Key: "ISSUER", Value: asString(payload["issuer"])},
		{Key: "VALUE", Value: asInt(payload["value"])},
		{Key: "REASON", Value: asString(payload["reason"])},
		{Key: "ISSUED_AT", Value: asFloat(payload["issued_at"])},
	}, asString(payload["voucher_id"]))
	if details := BuildLineageTransitionDetails(lineageMeta, voucherID); len(details) > 0 {
		_ = s.SaveServerContract("voucher_lineage_transition", details, voucherID)
	}
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
