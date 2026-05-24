package lockfile

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"scal-p/internal/ctxutil"
	"scal-p/internal/ioutil"
	"scal-p/internal/signing"
)

// Lockfile contains hashes for installed packages.
type Lockfile struct {
	LockVersion int                  `json:"lockVersion"`
	GeneratedAt string               `json:"generatedAt"`
	SigningKey  string               `json:"signing_key,omitempty"`
	Signature   string               `json:"signature,omitempty"`
	Packages    map[string]LockEntry `json:"packages"`
}

// LockEntry represents a locked package entry.
type LockEntry struct {
	Resolved   string `json:"resolved"`
	Integrity  string `json:"integrity"`
	VerifiedAt string `json:"verifiedAt"`
}

// Load reads the lockfile from disk or returns a default empty lockfile.
func Load(ctx context.Context, path string) (Lockfile, error) {
	if err := ctxutil.Check(ctx); err != nil {
		return Lockfile{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Lockfile{LockVersion: 2, Packages: map[string]LockEntry{}}, nil
		}
		return Lockfile{}, fmt.Errorf("read lockfile: %w", err)
	}

	var lf Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return Lockfile{}, fmt.Errorf("decode lockfile: %w", err)
	}
	if lf.Packages == nil {
		lf.Packages = map[string]LockEntry{}
	}
	lf.LockVersion = cmp.Or(lf.LockVersion, 2)
	return lf, nil
}

// Save writes the lockfile to disk atomically, signing it if a signing key is available.
func Save(ctx context.Context, path string, lf Lockfile) error {
	if err := ctxutil.Check(ctx); err != nil {
		return err
	}

	signLockfile(&lf, filepath.Dir(path))

	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("encode lockfile: %w", err)
	}
	return ioutil.WriteFileAtomic(path, data)
}

// signLockfile signs the lockfile's packages with an ed25519 key.
// It is a no-op if signing fails or no key is available.
func signLockfile(lf *Lockfile, dir string) {
	signer, err := signing.LoadOrGenerate(dir)
	if err != nil {
		slog.Debug("signing key not available, skipping lockfile signature", "err", err)
		return
	}

	pkgData, err := json.Marshal(lf.Packages)
	if err != nil {
		slog.Debug("signing marshal", "err", err)
		return
	}

	sig, err := signer.Sign(pkgData)
	if err != nil {
		slog.Debug("signing sign", "err", err)
		return
	}

	lf.SigningKey = signing.EncodeKey(signer.PublicKey)
	lf.Signature = base64.StdEncoding.EncodeToString(sig)
}

// VerifySignature checks the ed25519 signature on the lockfile.
// Returns nil if the lockfile is unsigned or the signature is valid.
func VerifySignature(lf *Lockfile) error {
	if lf.SigningKey == "" || lf.Signature == "" {
		return nil
	}

	pubKey, err := signing.DecodeKey(lf.SigningKey)
	if err != nil {
		return fmt.Errorf("lockfile signing key: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(lf.Signature)
	if err != nil {
		return fmt.Errorf("lockfile signature decode: %w", err)
	}

	pkgData, err := json.Marshal(lf.Packages)
	if err != nil {
		return fmt.Errorf("lockfile marshal for verify: %w", err)
	}

	if !signing.Verify(pubKey, pkgData, sigBytes) {
		return fmt.Errorf("lockfile signature verification failed")
	}
	return nil
}

// PublicKeyFromSigningKey reads the signing key file and returns the public key.
// Returns an error if the key does not exist or is invalid.
func PublicKeyFromSigningKey(dir string) (ed25519.PublicKey, error) {
	signer, err := signing.LoadOrGenerate(dir)
	if err != nil {
		return nil, err
	}
	return signer.PublicKey, nil
}
