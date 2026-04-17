package main

type Config struct {
	Server    string
	TLS       bool
	User      string
	Pass      string
	Listen    string
	CryptoDir string
	DataDir   string
}

type DNSResponse struct {
	Success     bool   `json:"success"`
	Error       string `json:"error"`
	Domain      string `json:"domain"`
	ContentHash string `json:"content_hash"`
}
