# passkeyctl

A software passkey for testing WebAuthn flows from the shell. It plays the
authenticator (the part a browser asks via `navigator.credentials`) and nothing
else: it makes no HTTP requests and never sees cookies or sessions.

```sh
passkeyctl attest --cred FILE --origin URL < creation-options.json > credential.json
passkeyctl assert --cred FILE --origin URL < request-options.json  > credential.json
```

Your test fetches options from the server, pipes them through `passkeyctl`, and
posts the output back:

```sh
app=https://app.example; cred=$HOME/.config/e2e/alice.json
curl -sS -b jar -c jar "$app/register/options" |
  passkeyctl attest --cred "$cred" --origin "$app" |
  curl -sS -b jar -c jar -H 'content-type: application/json' --data @- "$app/register/verify"
```

Login is the same with `assert`. Options may be bare
`PublicKeyCredentialCreationOptionsJSON` / `PublicKeyCredentialRequestOptionsJSON`
or wrapped as `{"publicKey": ...}`. Input and output use unpadded base64url,
as WebAuthn JSON does; output is standard `PublicKeyCredential` JSON. Pass
`--origin` exactly as the browser would report it (no default port).

For browser UI tests, use the browser's own virtual authenticator (Chrome
DevTools `WebAuthn` domain); `passkeyctl` is for fast, browserless tests.

## Behavior

- `attest` creates `FILE` with mode 0600 and refuses to overwrite anything
  already at that path.
- `assert` requires `FILE`. It increments and saves the signature counter
  before printing, under a file lock, so parallel logins never reuse a value.
- One ES256 credential per file. Use one file per test user.
- User presence and user verification are always reported.

## Checks

- `--origin` is `https://host[:port]`, or `http://` on `localhost` or a
  loopback IP. Paths, queries and fragments are rejected.
- The RP ID (from the options, defaulting to the origin host) equals the origin
  host or, for a domain name, is a parent domain of it. The public suffix list
  is not consulted; the server's own RP ID hash check still applies.
- The challenge is present. Its value is the server's business.
- `attest`: `pubKeyCredParams` must offer ES256 (`-7`).
- `assert`: the file's RP ID must match, and `allowCredentials` must be empty
  (discoverable login) or contain this credential.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Usage or I/O error |
| 2 | Options are not valid JSON, or lack a usable challenge or `user.id` |
| 3 | Refused: RP ID, algorithm or credential does not match |
| 4 | Credential file unusable: exists on `attest`, missing or corrupt on `assert` |

Errors are one line on stderr.

## Credential file

```json
{"v":1,"rpId":"example.com","credentialId":"<b64url>","privateKey":"<b64url PKCS#8>",
 "userHandle":"<b64url>","signCount":2}
```

It holds a private key and is never printed. Restoring an older copy rolls back
the counter; servers then reject logins as a possible cloned authenticator.

## Build and test

```sh
go build ./...
go test ./...
```

Tests run every ceremony against an independent server library
(`go-webauthn/webauthn`). Unix only (uses `flock`).
