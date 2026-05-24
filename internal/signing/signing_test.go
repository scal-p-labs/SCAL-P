package signing_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scal-p/internal/signing"
)

func TestLoadOrGenerate(t *testing.T) {
	t.Run("generates new key in empty dir", func(t *testing.T) {
		dir := t.TempDir()
		s, err := signing.LoadOrGenerate(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(s.PrivateKey) != ed25519.PrivateKeySize {
			t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(s.PrivateKey))
		}
		if len(s.PublicKey) != ed25519.PublicKeySize {
			t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(s.PublicKey))
		}
	})

	t.Run("loads existing key", func(t *testing.T) {
		dir := t.TempDir()
		s1, err := signing.LoadOrGenerate(dir)
		if err != nil {
			t.Fatal(err)
		}

		s2, err := signing.LoadOrGenerate(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(s2.PrivateKey) != ed25519.PrivateKeySize {
			t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(s2.PrivateKey))
		}
		// Verify same key was loaded
		if s1.PublicKey[0] != s2.PublicKey[0] {
			t.Error("loaded different key than generated")
		}
	})

	t.Run("key file has correct permissions", func(t *testing.T) {
		dir := t.TempDir()
		_, err := signing.LoadOrGenerate(dir)
		if err != nil {
			t.Fatal(err)
		}
		keyPath := filepath.Join(dir, ".scalp", "signing.key")
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("key file not found: %v", err)
		}
		if info.Mode()&0o077 != 0 {
			t.Errorf("key file has too permissive permissions: %o", info.Mode())
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	t.Run("sign and verify roundtrip", func(t *testing.T) {
		dir := t.TempDir()
		s, err := signing.LoadOrGenerate(dir)
		if err != nil {
			t.Fatal(err)
		}

		data := []byte("hello world")
		sig, err := s.Sign(data)
		if err != nil {
			t.Fatalf("sign error: %v", err)
		}
		if len(sig) != ed25519.SignatureSize {
			t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
		}

		if !signing.Verify(s.PublicKey, data, sig) {
			t.Error("signature verification failed")
		}
	})

	t.Run("verify rejects tampered data", func(t *testing.T) {
		dir := t.TempDir()
		s, err := signing.LoadOrGenerate(dir)
		if err != nil {
			t.Fatal(err)
		}

		data := []byte("original")
		sig, err := s.Sign(data)
		if err != nil {
			t.Fatal(err)
		}

		if signing.Verify(s.PublicKey, []byte("tampered"), sig) {
			t.Error("verified tampered data, should have failed")
		}
	})

	t.Run("verify with different key fails", func(t *testing.T) {
		dir := t.TempDir()
		s, err := signing.LoadOrGenerate(dir)
		if err != nil {
			t.Fatal(err)
		}

		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		data := []byte("test")
		sig, err := s.Sign(data)
		if err != nil {
			t.Fatal(err)
		}

		if signing.Verify(otherPub, data, sig) {
			t.Error("verified with wrong key, should have failed")
		}
	})
}

func TestEncodeDecodeKey(t *testing.T) {
	dir := t.TempDir()
	s, err := signing.LoadOrGenerate(dir)
	if err != nil {
		t.Fatal(err)
	}

	encoded := signing.EncodeKey(s.PublicKey)
	if !strings.HasPrefix(encoded, "") && len(encoded) == 0 {
		t.Error("empty encoded key")
	}

	decoded, err := signing.DecodeKey(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if len(decoded) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(decoded))
	}

	for i := range s.PublicKey {
		if s.PublicKey[i] != decoded[i] {
			t.Error("decode produced different key")
			break
		}
	}
}
