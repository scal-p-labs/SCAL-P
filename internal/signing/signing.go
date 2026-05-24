package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

const keyRelPath = ".scalp/signing.key"

type Signer struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func LoadOrGenerate(dir string) (*Signer, error) {
	path := filepath.Join(dir, keyRelPath)
	data, err := os.ReadFile(path)
	if err == nil {
		return loadKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	return generateKey(dir)
}

func loadKey(data []byte) (*Signer, error) {
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid signing key size: %d", len(data))
	}
	priv := ed25519.PrivateKey(data)
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{PrivateKey: priv, PublicKey: pub}, nil
}

func generateKey(dir string) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	path := filepath.Join(dir, keyRelPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, fmt.Errorf("write signing key: %w", err)
	}
	slog.Info("scalp: signing key generated", "fingerprint", fmt.Sprintf("%x", pub))
	return &Signer{PrivateKey: priv, PublicKey: pub}, nil
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.PrivateKey, data), nil
}

func EncodeKey(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

func DecodeKey(encoded string) (ed25519.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(data))
	}
	return ed25519.PublicKey(data), nil
}

func Verify(publicKey ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(publicKey, data, sig)
}
