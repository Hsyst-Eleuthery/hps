package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func ReadConfig() Config {
	r := bufio.NewReader(os.Stdin)
	fmt.Println("HPS Proxy (CLI)")
	fmt.Println("================")

	server := askTextDefault(r, "Servidor HPS (host:porta)", "localhost:8080")
	tls := askBoolDefault(r, "Usar TLS", false)
	user := askText(r, "Usuario")
	pass := askPassword(r)
	listen := askTextDefault(r, "Endereco proxy local", "127.0.0.1:19090")
	home, _ := os.UserHomeDir()
	defaultCryptoDir := filepath.Join(home, ".hps_proxy")
	cryptoDir := askTextDefault(r, "Diretorio de chaves local", defaultCryptoDir)
	defaultDataDir := filepath.Join(defaultCryptoDir, "data")
	dataDir := askTextDefault(r, "Diretorio de dados local", defaultDataDir)

	fmt.Printf("\nConfig: servidor=%s tls=%v usuario=%s proxy=%s crypto=%s data=%s\n\n", server, tls, user, listen, cryptoDir, dataDir)
	return Config{
		Server:    server,
		TLS:       tls,
		User:      user,
		Pass:      pass,
		Listen:    listen,
		CryptoDir: cryptoDir,
		DataDir:   dataDir,
	}
}

func askText(r *bufio.Reader, label string) string {
	for {
		fmt.Printf("%s: ", label)
		s, _ := r.ReadString('\n')
		s = strings.TrimSpace(s)
		if s != "" {
			return s
		}
	}
}

func askTextDefault(r *bufio.Reader, label, def string) string {
	fmt.Printf("%s [%s]: ", label, def)
	s, _ := r.ReadString('\n')
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

func askBoolDefault(r *bufio.Reader, label string, def bool) bool {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	fmt.Printf("%s (%s): ", label, hint)
	s, _ := r.ReadString('\n')
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return def
	}
	return s == "y" || s == "yes" || s == "1" || s == "true"
}

func askPassword(r *bufio.Reader) []byte {
	fmt.Print("Senha: ")
	// SECURITY FIX: Use term.ReadPassword to read without echoing
	if password, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil {
		fmt.Println() // New line after password input
		return password
	}
	// Fallback to buffered reader if term.ReadPassword fails
	s, _ := r.ReadString('\n')
	return []byte(strings.TrimSpace(s))
}
