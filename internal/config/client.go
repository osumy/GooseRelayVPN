// Package config defines the JSON config structures for the client and server
// binaries.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Client is the relay-tunnel client config.
type Client struct {
	ListenAddr string `json:"listen_addr"`
	GoogleIP   string `json:"google_ip"`   // "ip:443"
	SNIHost    string `json:"sni_host"`    // e.g. "www.google.com"
	ScriptURL  string `json:"script_url"`  // https://script.google.com/macros/s/.../exec
	AESKeyHex  string `json:"aes_key_hex"` // 64-char hex
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Client
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:1080"
	}
	if c.ScriptURL == "" {
		return nil, fmt.Errorf("config: script_url is required")
	}
	if len(c.AESKeyHex) != 64 {
		return nil, fmt.Errorf("config: aes_key_hex must be 64 hex chars (got %d)", len(c.AESKeyHex))
	}
	return &c, nil
}
