package core

import (
	"encoding/base64"
	"errors"
	"strings"
)

type ContractInfo struct {
	Action    string
	User      string
	Signature string
	Details   map[string][]string
}

func ValidateContractStructure(contractContent []byte) (bool, string, *ContractInfo) {
	text := string(contractContent)
	if !strings.HasPrefix(text, "# HSYST P2P SERVICE") {
		return false, "Cabeçalho HSYST não encontrado", nil
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	info := &ContractInfo{Details: map[string][]string{}}
	currentSection := ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "## CONTRACT:") {
			continue
		}
		if strings.HasPrefix(line, "## :END CONTRACT") {
			break
		}
		if strings.HasPrefix(line, "### ") {
			if strings.HasSuffix(line, ":") {
				currentSection = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "### "), ":"))
				if _, ok := info.Details[currentSection]; !ok {
					info.Details[currentSection] = []string{}
				}
			} else if strings.HasPrefix(line, "### :END ") {
				currentSection = ""
			}
			continue
		}
		if strings.HasPrefix(line, "# ") {
			if currentSection == "start" {
				if strings.HasPrefix(line, "# USER:") {
					info.User = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				} else if strings.HasPrefix(line, "# SIGNATURE:") {
					info.Signature = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				}
			} else if currentSection == "details" {
				if strings.HasPrefix(line, "# ACTION:") {
					info.Action = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				} else {
					info.Details[currentSection] = append(info.Details[currentSection], line)
				}
			} else if currentSection != "" {
				info.Details[currentSection] = append(info.Details[currentSection], line)
			}
		}
	}
	if info.Action == "" {
		return false, "Ação não especificada no contrato", nil
	}
	if info.User == "" {
		return false, "Usuário não especificado no contrato", nil
	}
	if info.Signature == "" {
		return false, "Assinatura não fornecida no contrato", nil
	}
	return true, "", info
}

func ExtractContractDetail(info *ContractInfo, key string) string {
	if info == nil {
		return ""
	}
	lines := info.Details["details"]
	prefix := "# " + key + ":"
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

func GetSignedContractText(contractContent []byte) (string, error) {
	// Mirror Python splitlines() behavior used by the browser/server signer:
	// normalize line endings and discard trailing line break marker.
	text := strings.ReplaceAll(string(contractContent), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "# SIGNATURE:") {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n"), nil
}

func DecodeContractContent(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty")
	}
	return base64.StdEncoding.DecodeString(value)
}
