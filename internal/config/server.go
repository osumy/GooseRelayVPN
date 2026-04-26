package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Server is the DO exit server config.
type Server struct {
	ListenAddr string `json:"listen_addr"`
	AESKeyHex  string `json:"aes_key_hex"`
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*Server, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Server
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:8443"
	}
	if len(c.AESKeyHex) != 64 {
		return nil, fmt.Errorf("config: aes_key_hex must be 64 hex chars (got %d)", len(c.AESKeyHex))
	}
	return &c, nil
}
