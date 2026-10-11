package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/descope/virtualwebauthn"
)

const algES256 = -7

// WebAuthn JSON uses unpadded base64url throughout.
var b64 = base64.RawURLEncoding

// readOptions reads options JSON, unwrapping {"publicKey": ...} if present.
func readOptions(stdin io.Reader) ([]byte, error) {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fail(exitUsage, "read options: %v", err)
	}
	var wrapper struct {
		PublicKey json.RawMessage `json:"publicKey"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fail(exitOptions, "options are not a JSON object: %v", err)
	}
	if wrapper.PublicKey != nil {
		return wrapper.PublicKey, nil
	}
	return data, nil
}

func decodeChallenge(value string) ([]byte, error) {
	challenge, err := b64.DecodeString(value)
	if err != nil || len(challenge) == 0 {
		return nil, fail(exitOptions, "challenge is missing or not base64url")
	}
	return challenge, nil
}

func attest(path, origin, host string, data []byte) ([]byte, error) {
	var options struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		PubKeyCredParams []struct {
			Alg int `json:"alg"`
		} `json:"pubKeyCredParams"`
	}
	if err := json.Unmarshal(data, &options); err != nil {
		return nil, fail(exitOptions, "invalid creation options: %v", err)
	}
	challenge, err := decodeChallenge(options.Challenge)
	if err != nil {
		return nil, err
	}
	userHandle, err := b64.DecodeString(options.User.ID)
	if err != nil || len(userHandle) == 0 {
		return nil, fail(exitOptions, "user.id is missing or not base64url")
	}
	rpID, err := resolveRPID(options.RP.ID, host)
	if err != nil {
		return nil, err
	}
	es256 := false
	for _, param := range options.PubKeyCredParams {
		if param.Alg == algES256 {
			es256 = true
		}
	}
	if !es256 {
		return nil, fail(exitRefused, "pubKeyCredParams does not offer ES256 (-7)")
	}

	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	// Save before printing, so a server never accepts a key we did not keep.
	if err := createCredFile(path, credFile{
		V:            1,
		RPID:         rpID,
		CredentialID: b64.EncodeToString(credential.ID),
		PrivateKey:   b64.EncodeToString(credential.Key.Data),
		UserHandle:   b64.EncodeToString(userHandle),
	}); err != nil {
		return nil, err
	}
	response := virtualwebauthn.CreateAttestationResponse(
		virtualwebauthn.RelyingParty{ID: rpID, Origin: origin},
		virtualwebauthn.Authenticator{},
		credential,
		virtualwebauthn.AttestationOptions{Challenge: challenge, RelyingPartyID: rpID},
	)
	return []byte(response), nil
}

func assert(path, origin, host string, data []byte) ([]byte, error) {
	var options struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	if err := json.Unmarshal(data, &options); err != nil {
		return nil, fail(exitOptions, "invalid request options: %v", err)
	}
	challenge, err := decodeChallenge(options.Challenge)
	if err != nil {
		return nil, err
	}
	rpID, err := resolveRPID(options.RPID, host)
	if err != nil {
		return nil, err
	}

	cred, err := lockCredFile(path)
	if err != nil {
		return nil, err
	}
	defer cred.close()
	if cred.file.RPID != rpID {
		return nil, fail(exitRefused, "credential is for RP ID %q, not %q", cred.file.RPID, rpID)
	}
	if len(options.AllowCredentials) > 0 {
		allowed := false
		for _, entry := range options.AllowCredentials {
			id, err := b64.DecodeString(entry.ID)
			if err == nil && bytes.Equal(id, cred.credentialID) {
				allowed = true
			}
		}
		if !allowed {
			return nil, fail(exitRefused, "allowCredentials does not include this credential")
		}
	}

	// Persist the new counter before printing, so no response ever reuses one.
	file := cred.file
	file.SignCount++
	if err := cred.save(file); err != nil {
		return nil, err
	}
	credential := virtualwebauthn.NewCredentialWithImportedKey(virtualwebauthn.KeyTypeEC2, cred.pkcs8)
	credential.ID = cred.credentialID
	credential.Counter = file.SignCount
	response := virtualwebauthn.CreateAssertionResponse(
		virtualwebauthn.RelyingParty{ID: rpID, Origin: origin},
		virtualwebauthn.Authenticator{Options: virtualwebauthn.AuthenticatorOptions{UserHandle: cred.userHandle}},
		credential,
		virtualwebauthn.AssertionOptions{Challenge: challenge, RelyingPartyID: rpID},
	)
	return []byte(response), nil
}
