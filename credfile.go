package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// credFile is the on-disk credential format. It holds a private key.
type credFile struct {
	V            int    `json:"v"`
	RPID         string `json:"rpId"`
	CredentialID string `json:"credentialId"`
	PrivateKey   string `json:"privateKey"`
	UserHandle   string `json:"userHandle"`
	SignCount    uint32 `json:"signCount"`
}

func (file credFile) encode() []byte {
	data, _ := json.Marshal(file) // strings and ints always marshal
	return append(data, '\n')
}

// createCredFile writes a new mode-0600 file and fails if path exists,
// including as a dangling symlink.
func createCredFile(path string, file credFile) error {
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fail(exitCredFile, "credential file %s already exists", path)
	} else if err != nil {
		return fail(exitUsage, "create credential: %v", err)
	}
	_, err = handle.Write(file.encode())
	if err = errors.Join(err, handle.Sync(), handle.Close()); err != nil {
		os.Remove(path)
		return fail(exitUsage, "write credential: %v", err)
	}
	return nil
}

// lockedCred is a credential file held open under an exclusive flock. Every
// assert takes the lock before reading, so the file is updated in place and
// never needs a rename.
type lockedCred struct {
	handle       *os.File
	file         credFile
	credentialID []byte
	userHandle   []byte
	pkcs8        []byte
}

func lockCredFile(path string) (*lockedCred, error) {
	handle, err := os.OpenFile(path, os.O_RDWR, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fail(exitCredFile, "credential file %s does not exist", path)
	} else if err != nil {
		return nil, fail(exitCredFile, "credential file: %v", err)
	}
	if err := syscall.Flock(int(handle.Fd()), syscall.LOCK_EX); err != nil {
		handle.Close()
		return nil, fail(exitUsage, "lock credential file: %v", err)
	}
	cred := &lockedCred{handle: handle}
	if err := cred.load(path); err != nil {
		handle.Close()
		return nil, err
	}
	return cred, nil
}

func (cred *lockedCred) close() { cred.handle.Close() }

func (cred *lockedCred) load(path string) error {
	data, err := io.ReadAll(cred.handle)
	if err != nil {
		return fail(exitCredFile, "read credential: %v", err)
	}
	corrupt := fail(exitCredFile, "credential file %s is corrupt", path)
	if json.Unmarshal(data, &cred.file) != nil || cred.file.V != 1 || cred.file.RPID == "" {
		return corrupt
	}
	if cred.credentialID, err = b64.DecodeString(cred.file.CredentialID); err != nil || len(cred.credentialID) == 0 {
		return corrupt
	}
	if cred.userHandle, err = b64.DecodeString(cred.file.UserHandle); err != nil || len(cred.userHandle) == 0 {
		return corrupt
	}
	if cred.pkcs8, err = b64.DecodeString(cred.file.PrivateKey); err != nil {
		return corrupt
	}
	// Check the key here: virtualwebauthn panics on a bad one.
	key, err := x509.ParsePKCS8PrivateKey(cred.pkcs8)
	if ecKey, ok := key.(*ecdsa.PrivateKey); err != nil || !ok || ecKey.Curve != elliptic.P256() {
		return corrupt
	}
	return nil
}

// save rewrites the file in place under the lock. The counter only grows, so
// the new contents cover the old; Truncate only matters for edited files.
func (cred *lockedCred) save(file credFile) error {
	data := file.encode()
	if _, err := cred.handle.WriteAt(data, 0); err != nil {
		return fail(exitUsage, "save credential: %v", err)
	}
	if err := cred.handle.Truncate(int64(len(data))); err != nil {
		return fail(exitUsage, "save credential: %v", err)
	}
	if err := cred.handle.Sync(); err != nil {
		return fail(exitUsage, "save credential: %v", err)
	}
	cred.file = file
	return nil
}
