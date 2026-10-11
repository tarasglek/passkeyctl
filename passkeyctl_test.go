package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://app.example.com"
)

type testUser struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u *testUser) WebAuthnID() []byte                         { return u.id }
func (u *testUser) WebAuthnName() string                       { return "alice" }
func (u *testUser) WebAuthnDisplayName() string                { return "Alice" }
func (u *testUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func newServer(t *testing.T, rpID, origin string) *webauthn.WebAuthn {
	t.Helper()
	server, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Test",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func runCLI(t *testing.T, input []byte, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, bytes.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// register runs a full registration ceremony and returns the credential file.
func register(t *testing.T, server *webauthn.WebAuthn, user *testUser, origin string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cred.json")
	creation, session, err := server.BeginRegistration(user)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, mustJSON(t, creation), "attest", "--cred", path, "--origin", origin)
	if code != 0 {
		t.Fatalf("attest exit %d: %s", code, stderr)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(stdout))
	if err != nil {
		t.Fatalf("server could not parse attestation: %v\n%s", err, stdout)
	}
	credential, err := server.CreateCredential(user, *session, parsed)
	if err != nil {
		t.Fatalf("server rejected attestation: %v", err)
	}
	user.credentials = append(user.credentials, *credential)
	return path
}

func login(t *testing.T, server *webauthn.WebAuthn, user *testUser, path, origin string) (*webauthn.Credential, string) {
	t.Helper()
	assertion, session, err := server.BeginLogin(user)
	if err != nil {
		t.Fatal(err)
	}
	// Bare options, without the {"publicKey": ...} wrapper.
	code, stdout, stderr := runCLI(t, mustJSON(t, assertion.Response), "assert", "--cred", path, "--origin", origin)
	if code != 0 {
		t.Fatalf("assert exit %d: %s", code, stderr)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(stdout))
	if err != nil {
		t.Fatalf("server could not parse assertion: %v\n%s", err, stdout)
	}
	credential, err := server.ValidateLogin(user, *session, parsed)
	if err != nil {
		t.Fatalf("server rejected assertion: %v", err)
	}
	return credential, stdout + stderr
}

func readCred(t *testing.T, path string) credFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file credFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestRegisterAndLoginRoundTrip(t *testing.T) {
	server := newServer(t, testRPID, testOrigin)
	user := &testUser{id: []byte("user-1234")}
	path := register(t, server, user, testOrigin)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential file mode %o, want 600", info.Mode().Perm())
	}
	file := readCred(t, path)
	if file.V != 1 || file.RPID != testRPID || file.SignCount != 0 || file.PrivateKey == "" {
		t.Fatalf("unexpected credential file: %+v", file)
	}
	if file.UserHandle != base64.RawURLEncoding.EncodeToString(user.id) {
		t.Fatalf("user handle %q was not stored as raw user.id bytes", file.UserHandle)
	}

	for want := uint32(1); want <= 2; want++ {
		credential, output := login(t, server, user, path, testOrigin)
		if credential.Authenticator.SignCount != want {
			t.Fatalf("server saw sign count %d, want %d", credential.Authenticator.SignCount, want)
		}
		if strings.Contains(output, file.PrivateKey) {
			t.Fatal("private key leaked to output")
		}
		user.credentials[0] = *credential
	}
	if got := readCred(t, path).SignCount; got != 2 {
		t.Fatalf("file sign count %d, want 2", got)
	}
}

func TestDiscoverableLoginReturnsUserHandle(t *testing.T) {
	server := newServer(t, testRPID, testOrigin)
	user := &testUser{id: []byte("discoverable-user")}
	path := register(t, server, user, testOrigin)

	assertion, session, err := server.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, mustJSON(t, assertion), "assert", "--cred", path, "--origin", testOrigin)
	if code != 0 {
		t.Fatalf("assert exit %d: %s", code, stderr)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(stdout))
	if err != nil {
		t.Fatal(err)
	}
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, user.id) {
			return nil, errors.New("unknown user handle")
		}
		return user, nil
	}
	if _, err := server.ValidateDiscoverableLogin(handler, *session, parsed); err != nil {
		t.Fatalf("server rejected discoverable assertion: %v", err)
	}
}

func TestRPIDDefaultsToOriginHost(t *testing.T) {
	origin := "https://app.example.com"
	server := newServer(t, "app.example.com", origin)
	user := &testUser{id: []byte("default-rp")}
	path := filepath.Join(t.TempDir(), "cred.json")

	creation, session, err := server.BeginRegistration(user)
	if err != nil {
		t.Fatal(err)
	}
	creation.Response.RelyingParty.ID = ""
	code, stdout, stderr := runCLI(t, mustJSON(t, creation), "attest", "--cred", path, "--origin", origin)
	if code != 0 {
		t.Fatalf("attest exit %d: %s", code, stderr)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(stdout))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := server.CreateCredential(user, *session, parsed)
	if err != nil {
		t.Fatalf("server rejected attestation: %v", err)
	}
	user.credentials = append(user.credentials, *credential)
	if got := readCred(t, path).RPID; got != "app.example.com" {
		t.Fatalf("rpId %q, want origin host", got)
	}

	assertion, session, err := server.BeginLogin(user)
	if err != nil {
		t.Fatal(err)
	}
	assertion.Response.RelyingPartyID = ""
	code, stdout, stderr = runCLI(t, mustJSON(t, assertion), "assert", "--cred", path, "--origin", origin)
	if code != 0 {
		t.Fatalf("assert exit %d: %s", code, stderr)
	}
	parsedAssertion, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(stdout))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.ValidateLogin(user, *session, parsedAssertion); err != nil {
		t.Fatalf("server rejected assertion: %v", err)
	}
}

func TestLocalhostHTTPOrigin(t *testing.T) {
	origin := "http://localhost:8080"
	server := newServer(t, "localhost", origin)
	user := &testUser{id: []byte("local")}
	path := register(t, server, user, origin)
	login(t, server, user, path, origin)
}

func TestParallelAssertsUseDistinctCounters(t *testing.T) {
	server := newServer(t, testRPID, testOrigin)
	user := &testUser{id: []byte("parallel")}
	path := register(t, server, user, testOrigin)
	assertion, _, err := server.BeginLogin(user)
	if err != nil {
		t.Fatal(err)
	}
	options := mustJSON(t, assertion)

	const runs = 8
	counters := make(chan uint32, runs)
	var wg sync.WaitGroup
	for range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var stdout, stderr bytes.Buffer
			if code := run([]string{"assert", "--cred", path, "--origin", testOrigin}, bytes.NewReader(options), &stdout, &stderr); code != 0 {
				t.Errorf("assert exit %d: %s", code, stderr.String())
				return
			}
			parsed, err := protocol.ParseCredentialRequestResponseBody(&stdout)
			if err != nil {
				t.Error(err)
				return
			}
			counters <- parsed.Response.AuthenticatorData.Counter
		}()
	}
	wg.Wait()
	close(counters)
	seen := map[uint32]bool{}
	for counter := range counters {
		if seen[counter] {
			t.Fatalf("counter %d reused", counter)
		}
		seen[counter] = true
	}
	if len(seen) != runs || readCred(t, path).SignCount != runs {
		t.Fatalf("counters %v, file sign count %d", seen, readCred(t, path).SignCount)
	}
}

const (
	creationOptions = `{"challenge":"AAEC","rp":{"id":"example.com","name":"Test"},` +
		`"user":{"id":"dXNlcg","name":"alice","displayName":"Alice"},` +
		`"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`
	requestOptions = `{"challenge":"AAEC","rpId":"example.com"}`
)

func TestExitCodes(t *testing.T) {
	server := newServer(t, testRPID, testOrigin)
	user := &testUser{id: []byte("exit-codes")}
	existing := register(t, server, user, testOrigin)
	before := readCred(t, existing)
	missing := filepath.Join(t.TempDir(), "missing.json")

	dangling := filepath.Join(t.TempDir(), "dangling.json")
	if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := func() string { return filepath.Join(t.TempDir(), "new.json") }

	cases := []struct {
		name  string
		input string
		args  []string
		want  int
	}{
		{"no command", "", nil, 1},
		{"unknown command", "", []string{"sign"}, 1},
		{"missing flags", creationOptions, []string{"attest"}, 1},
		{"plain http remote origin", creationOptions, []string{"attest", "--cred", fresh(), "--origin", "http://example.com"}, 1},
		{"origin with path", creationOptions, []string{"attest", "--cred", fresh(), "--origin", "https://example.com/login"}, 1},
		{"invalid json", "{", []string{"attest", "--cred", fresh(), "--origin", testOrigin}, 2},
		{"missing challenge", `{"rp":{"id":"example.com"},"user":{"id":"dXNlcg","name":"a"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`,
			[]string{"attest", "--cred", fresh(), "--origin", testOrigin}, 2},
		{"bad challenge encoding", `{"challenge":"***","rpId":"example.com"}`, []string{"assert", "--cred", existing, "--origin", testOrigin}, 2},
		{"no ES256", strings.Replace(creationOptions, "-7", "-257", 1), []string{"attest", "--cred", fresh(), "--origin", testOrigin}, 3},
		{"rp id not origin domain", creationOptions, []string{"attest", "--cred", fresh(), "--origin", "https://evil.example"}, 3},
		{"lookalike rp id suffix", creationOptions, []string{"attest", "--cred", fresh(), "--origin", "https://notexample.com"}, 3},
		{"rp id suffix of an IP", strings.Replace(creationOptions, `"id":"example.com"`, `"id":"0.0.1"`, 1),
			[]string{"attest", "--cred", fresh(), "--origin", "http://127.0.0.1:8080"}, 3},
		{"attest existing file", creationOptions, []string{"attest", "--cred", existing, "--origin", testOrigin}, 4},
		{"attest dangling symlink", creationOptions, []string{"attest", "--cred", dangling, "--origin", testOrigin}, 4},
		{"assert missing file", requestOptions, []string{"assert", "--cred", missing, "--origin", testOrigin}, 4},
		{"assert corrupt file", requestOptions, []string{"assert", "--cred", corrupt, "--origin", testOrigin}, 4},
		{"assert other credential", `{"challenge":"AAEC","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"b3RoZXI"}]}`,
			[]string{"assert", "--cred", existing, "--origin", testOrigin}, 3},
		{"assert other rp id", `{"challenge":"AAEC","rpId":"other.example"}`, []string{"assert", "--cred", existing, "--origin", "https://other.example"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, []byte(tc.input), tc.args...)
			if code != tc.want {
				t.Fatalf("exit %d, want %d (stderr %q)", code, tc.want, stderr)
			}
			if code != 0 && (stdout != "" || strings.Count(strings.TrimSpace(stderr), "\n") != 0 || stderr == "") {
				t.Fatalf("failure must print one stderr line and no stdout: stdout %q stderr %q", stdout, stderr)
			}
		})
	}
	if readCred(t, existing) != before {
		t.Fatal("refused commands changed the credential file")
	}
}
