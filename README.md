# secure-input

Request environment values from a person without sending private values through
an AI context. The CLI prints a single-use browser link, waits for submission,
and writes a mode-0600 `.env` file. Values are masked in CLI output unless the
person explicitly clears **Keep private**.

## Usage

```sh
secure-input serve --addr :8787
secure-input request --server http://localhost:8787 --out .env \
  --reason 'Configure the service' --var API_TOKEN --var REGION --public REGION
```

End-to-end encryption is **enabled by default**, including for variables marked
public. The `private` setting controls CLI output to the AI, not encryption.
Use HTTPS outside localhost. The browser must support X25519 in Web Crypto;
unsupported browsers and insecure origins fail closed, without sending plaintext.

To deliberately use the legacy plaintext protocol:

```sh
secure-input request --server https://your-server.example --out .env \
  --reason 'Configure the service' --var API_TOKEN --no-encryption
```

The CLI and page warn that the server can read values in this mode. There is no
automatic plaintext fallback, including when connecting to an older server.

### Request now, pull later

```sh
secure-input request --server https://your-server.example --out .env \
  --reason 'Configure the service' --var API_TOKEN --no-wait
# Later, using the printed request id and the same output path:
secure-input pull --server https://your-server.example --id REQUEST_ID --out .env
```

`--no-wait` saves the private key, original spec, server URL, and request id to
`OUT.secure-input-key.json` with mode 0600. It refuses to overwrite an existing
file. Keep this file private and never commit or share it. `pull` checks the file
before consuming a result and removes it after successfully saving the `.env`,
a decline, or an expired/consumed response. A pending pull keeps it for retry.
On Windows, protect the containing directory with an owner-only ACL; POSIX mode
bits alone do not provide Windows access control.

Use `--key-file PATH` on both commands to choose another location, or to retain
a key for an interrupted waiting request. Without `--no-wait` or `--key-file`,
the key stays in process memory and cannot be recovered after the CLI exits.
Local files are not securely erased; normal filesystem/backup protections apply.
Delete stale key files after abandoned requests. To pull a legacy plaintext
request, explicitly pass `--no-encryption`.

Results still expire and are consumed on the first completed pull. As before,
a lost result response or a failure writing the `.env` after consumption requires
a new request. Preserving a private key alone cannot recover a consumed result.

## Encryption protocol (v1)

This is a versioned application protocol using standard cryptographic primitives,
not Ed25519 (which is a signature algorithm) and not an HPKE implementation:

1. The CLI generates a fresh **X25519** key pair for every request. Only the raw
   32-byte public key is sent in `encryption: {version: 1, publicKey: BASE64}`.
   The server echoes this configuration; the CLI rejects a missing or changed
   echo, then pins the public key in the printed URL's `#e2ee=...` fragment.
2. The form receives the public key. Its JavaScript checks the fragment, if
   present, against the supplied configuration and generates a fresh ephemeral
   X25519 pair for every submission attempt.
3. The browser derives a shared secret with X25519, then a 32-byte AES key with
   **HKDF-SHA-256**. The salt is a fresh random 12-byte nonce. HKDF `info` is the
   UTF-8 encoding of `secure-input/v1`, request id, recipient public key, and
   ephemeral public key, joined by NUL bytes. Both keys use canonical padded
   standard base64 in this context.
4. **AES-256-GCM**, with that nonce and a 128-bit tag, encrypts the UTF-8 JSON
   `{entries: [{key, value, private}, ...]}`. The additional authenticated data
   is identical to HKDF `info`, binding the ciphertext to the request and keys.
5. The browser posts only `{encrypted: {version, ephemeralPublicKey, nonce,
   ciphertext}}`. Binary fields use canonical padded standard base64; ciphertext
   includes the appended GCM tag. The relay validates the envelope and size but
   stores/returns no plaintext entries for an encrypted request.
6. The CLI authenticates and decrypts locally, validates keys, duplicates, lengths
   and privacy defaults against its original spec, then writes the `.env`.

Legacy API callers may omit `encryption` to request plaintext explicitly. An
individual request cannot switch modes: encrypted requests reject plaintext or
mixed submissions, and plaintext requests reject encrypted envelopes. Metadata
(reason, requested variable names/descriptions/default privacy flags, timestamps),
public keys, ciphertext sizes, and access patterns remain visible to the server.

The protocol uses [Go's standard-library X25519](https://pkg.go.dev/crypto/ecdh)
and [Web Crypto's X25519, HKDF and AES-GCM](https://www.w3.org/TR/webcrypto-2/).
It introduces no Go or browser cryptography dependencies.

### Trust boundary

This protects submitted values from a passive relay, its stored request data,
and ordinary server-side request-body logging **when the intended client code
runs**. It does not make a malicious web server safe: the server delivers the HTML
and JavaScript and can replace them to steal values before encryption or skip the
key check. The URL fragment helps honest code detect key substitution or a mode
mismatch; it does not authenticate server-delivered JavaScript. Strong protection
against an actively malicious host requires an independently trusted client and
an authenticated way to obtain the CLI public key.

The CLI/receiving machine, browser, browser extensions, and delivery of the link
must also be trusted. The link is a bearer capability: anyone who has it can
submit or decline, and the request id permits consuming the result. Encryption
adds confidentiality and ciphertext integrity, **not sender authentication**;
anyone with the public key can encrypt a fresh submission. A malicious relay can
forge a new submission, withhold, replace, or consume results, or return a false
status. Never treat a received value as independently verified identity. Use TLS
and do not share request links. This is not post-quantum encryption, and the code
has not undergone an independent cryptographic audit.

## Development

Go 1.26.2 or newer is required. Node 22+ enables tests that run the exact embedded
browser crypto code and decrypt its output in Go:

```sh
go test -race ./...
go vet ./...
SECURE_INPUT_REQUIRE_NODE=1 go test ./...
go build .
```

The CI test workflow installs Node and requires the interoperability test. It
also installs Playwright 1.62.1 and Chromium and runs `node web/browser_test.cjs`
against the built CLI and a local test server, covering encryption, retry,
key pinning, unavailable crypto, submit/decline races, and explicit plaintext. The
Go suite also covers authentication failure, request binding, downgrade refusal,
malformed envelopes, server ciphertext-only storage, private-key file safety,
and default-encrypted / explicitly-plaintext CLI flows.
