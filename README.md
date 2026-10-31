# Xentree Connect

Single-sign-on, webhooks and offboarding between your platform and Xentree.

`xentree-connect` is one small static binary that:

- **generates and protects** the signing key for your integration (ES256 / ECDSA P-256),
- **registers** the integration with your Xentree organization,
- **checks** that the clock, key permissions and API access are healthy (`health`), and
- **bridges closed SaaS platforms** that can't run a plugin, closed platforms (`gateway`).

| You run… | Use |
| --- | --- |
| Moodle (or another system where you can install code) | [`init`](#moodle) — the platform signs launches itself |
| A closed SaaS platform | [`gateway`](#closed-saas--platform) — a service you host signs for it |

---

## Install

**Linux and macOS**

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://get.xentree.ai/connect | sh
```

Run as root it installs to `/usr/local/bin`; otherwise to `~/.local/bin`. To run the setup wizard straight away:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://get.xentree.ai/connect | sh -s -- --init
```

Options: `--version v1.2.3`, `--bin-dir DIR`, `--help`.

**Windows (PowerShell)**

```powershell
irm https://get.xentree.ai/connect.ps1 | iex
# with options:
& ([scriptblock]::Create((irm https://get.xentree.ai/connect.ps1))) -Init -Version v1.2.3
```

Installs to `%USERPROFILE%\.xentree\bin` and adds it to your user `PATH` (open a new terminal afterwards).

**What the installers do.** They download the binary for your platform and `SHA256SUMS` over HTTPS (TLS 1.2+), refuse to continue unless the checksum matches, and only then make the file executable and move it into place. There is no option to skip verification. If the download is cut off, nothing runs.

**Platforms.** Linux x86_64 and aarch64 (static builds — they run on glibc and musl distributions alike), macOS Intel and Apple Silicon, Windows x64 (also runs on Windows on ARM through emulation).

**Verify a download independently.** When releases are built from a public repository, binaries carry build-provenance attestations (GitHub does not offer these for private repositories):

```sh
gh attestation verify xentree-connect-x86_64-unknown-linux-musl --repo godfreu/xentree-connect
```

**Build from source** (a current stable Rust toolchain; developed with 1.86. Releases are built from the committed `Cargo.lock`):

```sh
git clone https://github.com/godfreu/xentree-connect && cd xentree-connect
cargo build --release --locked      # binary: target/release/xentree-connect
```

---

## Quick start

```sh
export XENTREE_ADMIN_TOKEN=...      # an Organization Administrator's bearer token (or paste it at the masked prompt)
xentree-connect init                # generate a key, register the integration
xentree-connect health              # confirm everything is in order
```

`init` asks for your Xentree URL (default `https://my.xentree.ai`, or your custom domain), checks the system clock, lists the organizations your token administers, detects your platform, and then:

1. generates an ES256 key pair and stores the private key with owner-only permissions,
2. registers the integration (public key only) with Xentree,
3. writes `xentree-connect.json` next to the key — URLs, IDs and key location, **no secrets**.

The private key is written to disk *before* registration. If registration fails (for example a duplicate client ID), the key is kept; fix the problem and re-run with `--reuse-key` to register the same key.

Scripted use: `xentree-connect init --yes --org org_123 --issuer https://platform.example.com` (never prompts; the token must come from `XENTREE_ADMIN_TOKEN`).

Add `--lang id` to any command for Indonesian output; by default the language is taken from `$LC_ALL`, `$LC_MESSAGES` or `$LANG`.

---

## Moodle

Moodle signs launch assertions itself, so it needs to **read the private key**. Moodle runs as the web-server user (`www-data` on Debian/Ubuntu, `apache` on RHEL, `nginx`, `_www` on macOS), so the key is stored in `moodledata` — outside the web root — and made readable by that group only.

1. **Install** on the Moodle server (as root):

   ```sh
   curl --proto '=https' --tlsv1.2 -fsSL https://get.xentree.ai/connect | sudo sh
   ```

2. **Run `init` from the Moodle root** — the directory containing `config.php`:

   ```sh
   cd /var/www/html/moodle
   sudo xentree-connect init
   ```

   Paste your admin token at the masked prompt. Run it as root (or as a member of the web-server group): giving a file to another group needs that privilege. `init` will:

   - recognise the Moodle site and use its `$CFG->wwwroot` as the **issuer**;
   - store the key at `<dataroot>/keys/xentree_private.pem` (for example `/var/www/moodledata/keys/`), creating the `keys` directory as `0750`;
   - give the file to the web-server group with mode **`0640`** — group-readable, nobody else — and show you the location and permissions to confirm before writing anything;
   - register the integration and save `xentree-connect.json` in the same directory.

   Override anything it guessed: `--key-dir /path`, `--key-group www-data` (name or gid), `--issuer https://…`.

3. **Install and configure the Xentree Connect Moodle plugin** (component `local_xentreeconnect`) following the plugin's own instructions. Give it the key path, issuer, audience and client ID that `init` printed.

4. **Verify** — from the Moodle root, as root:

   ```sh
   cd /var/www/html/moodle && sudo xentree-connect health
   sudo -u www-data test -r /var/www/moodledata/keys/xentree_private.pem && echo "web server can read the key"
   ```

   `health` finds the config in the Moodle key directory, so it checks the key against the group-readable policy `init` set (and *flags* it if someone later loosens it).

Notes: the key file must never be inside the web root or in version control. If you move Moodle or `moodledata`, move the key with it and update the path in the plugin and in `xentree-connect.json`.

---

## Closed SaaS Platforms

Cloased platforms don't let you install code, so they can't hold a signing key. `xentree-connect gateway` is a small service **you host** that holds the key and does three jobs:

| Endpoint | Listener | Purpose |
| --- | --- | --- |
| `GET`/`POST /launch` | public | Signs a 30-second assertion for the signed-in employee and returns a page that posts it to Xentree. |
| `POST /webhook` | public | Receives Xentree's events, verifies them, de-duplicates, and (optionally) forwards them to your platform. |
| `POST /deprovision/{user_id}` | **internal** | Releases an offboarded employee's seat. |
| `GET /health` | both | Liveness probe: `{"status":"healthy","kid":"…"}`. |

```
 employee ──► [your SSO / reverse proxy] ──► gateway :8080 /launch ──► page auto-posts to Xentree
 Xentree  ──────────────────────────────────► gateway :8080 /webhook ──► your platform (optional relay)
 platform offboarding workflow ──► gateway :8081 /deprovision/{id}  (private network only)
```

### 1. Register the integration

On any machine (a laptop is fine), run `init` with the details of your platform. The issuer is a URL you choose to identify your integration, with no trailing slash; the audience defaults to `xentree`:

```sh
xentree-connect init --issuer https://platform.example.com --name "Your-Vendor-Platform" --client-id Your-Vendor-Platform-prod
```

Copy the private key and `xentree-connect.json` to the gateway host (see the permissions note below).

### 2. Run the gateway

Generate the shared secret that callers must present, and decide where the webhook secret will come from (step 4):

```sh
export XENTREE_GATEWAY_SECRET="$(openssl rand -hex 32)"     # at least 32 characters is enforced
export XENTREE_WEBHOOK_SECRET="whsec_…"                      # from step 4
xentree-connect gateway --config /etc/xentree/xentree-connect.json \
  --relay-webhook-url https://platform.example.com/api/xentree-events
```

The gateway refuses to start if the key file is readable by anyone but its owner, or doesn't match the key registered with Xentree. It speaks **plain HTTP**: put it behind a TLS-terminating proxy or load balancer before exposing it.

**Docker** (example; adapt to your environment):

```dockerfile
FROM alpine:3.20 AS fetch
RUN apk add --no-cache curl ca-certificates
RUN curl --proto '=https' --tlsv1.2 -fsSL https://get.xentree.ai/connect | sh -s -- --bin-dir /out

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=fetch /out/xentree-connect /usr/local/bin/xentree-connect
USER nonroot
ENTRYPOINT ["xentree-connect"]
CMD ["gateway", "--config", "/etc/xentree/xentree-connect.json", "--internal-bind", "0.0.0.0:8081"]
```

```sh
docker build -t xentree-connect-gateway .

# The key must be owned by the container user (uid 65532) with mode 0600, and "key_path" in
# xentree-connect.json must be the path *inside* the container (e.g. /etc/xentree/xentree_private.pem).
sudo chown 65532:65532 xentree_private.pem xentree-connect.json && sudo chmod 600 xentree_private.pem
docker run -d --name xentree-gateway \
  -e XENTREE_GATEWAY_SECRET -e XENTREE_WEBHOOK_SECRET \
  -v "$PWD:/etc/xentree:ro" -p 8080:8080 \
  xentree-connect-gateway
```

Publish only port `8080`. Port `8081` (`/deprovision`) must be reachable only from your platform/automation network — here, a private Docker network. The gateway warns at start-up that the internal listener isn't on loopback; inside a private network that is expected. The Dockerfile is an example and has not been built against a published release yet. Use `GET /health` for Kubernetes or load-balancer probes.

**On a VM**, run it under systemd as a dedicated user that owns the key (`0600`), with the two secrets in an `EnvironmentFile` readable only by root.

### 3. Add the launch tile in the closed platform

You want a tile or menu link that, for the signed-in employee, ends up at `https://<your-gateway>/launch`. **How the employee's identity reaches the gateway is the one decision that matters for security**, because the gateway signs whatever user it is told:

- **Recommended — proxy-asserted identity.** Put the gateway behind a reverse proxy or access gateway that authenticates employees against your corporate identity provider and passes the verified user ID in a header you control. Start the gateway with `--trusted-identity-header X-Remote-User` (or the header your proxy sets, e.g. `Cf-Access-Authenticated-User-Email`). The user is then taken **from that header**; a request that also names a different `user_id` is rejected. The proxy must overwrite the header on every request (so a client can't forge it) and must be the only route to the gateway. Illustrative nginx + oauth2-proxy sketch:

  ```nginx
  location = /launch {
      auth_request /oauth2/auth;
      auth_request_set $employee $upstream_http_x_auth_request_user;
      proxy_set_header X-Remote-User $employee;   # replaces anything the client sent
      proxy_pass http://gateway:8080;
  }
  location /webhook { proxy_pass http://gateway:8080; }   # authenticated by Xentree's signature instead
  ```

- **Backend call.** If your own portal or middleware already knows who the employee is, it can call `GET /launch?user_id=EMP123` with `Authorization: Bearer $XENTREE_GATEWAY_SECRET` and return the page it receives to the employee's browser. The secret never reaches the browser.

- **Avoid: a secret in the tile URL.** `--allow-query-secret` lets a link like `/launch?user_id=…&secret=…` work, but then *anyone who can see that link can sign in as any user ID they type*. It is off by default and prints a warning when enabled.

Which of these your platform tenant can drive (custom navigation entries, SSO to external URLs, passing the employee ID) depends on your edition and configuration. The names of the menus differ between tenants, so follow vendor's own administration documentation for adding a custom link, and point it at the proxy-protected `/launch` URL.

### 4. Wire the webhook

Tell Xentree where to send events. Your organization ID and client record ID are in `xentree-connect.json`.

```sh
curl -sS -X POST "https://my.xentree.ai/api/admin/organizations/$ORG_ID/connect-clients/$CLIENT_RECORD_ID/webhooks" \
  -H "Authorization: Bearer $XENTREE_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"https://connect.example.com/webhook","events":["erpi.session.completed","connect.consent.revoked"]}'
```

The response contains a `signing_secret`. **It is shown once** — store it as `XENTREE_WEBHOOK_SECRET` and restart the gateway. If you lose it, rotate the secret in Xentree.

Behaviour: every request is checked against `X-Xentree-Signature` (`t=<timestamp>,v1=<hex HMAC-SHA256>`) with a 5-minute window; bodies over 1 MB are refused; a repeated event `id` is acknowledged but processed only once; the acknowledgement is sent *before* the event is relayed to `--relay-webhook-url` (3 attempts), so a slow platform never delays Xentree.

**Rotating the secret.** After Xentree rotates, the old secret stays valid there for 24 hours. Run the gateway with both so no event is lost, then drop the old one:

```sh
XENTREE_WEBHOOK_SECRET=<new> XENTREE_PREVIOUS_WEBHOOK_SECRET=<old> \
XENTREE_PREVIOUS_SECRET_ROTATED_AT=<unix seconds of the rotation> xentree-connect gateway …
```

(A restart is required to change secrets.)

### 5. Offboarding

When an employee leaves, have your platform workflow call the **internal** listener:

```sh
curl -sS -X POST -H "Authorization: Bearer $XENTREE_GATEWAY_SECRET" http://gateway.internal:8081/deprovision/EMP123
# {"status":"ok","seat_released":true}
```

`seat_released` is `false` when the user is an organization admin or still has another active binding; `status` can be `no_active_binding`. Every call uses a fresh single-use assertion, so retrying a failed call is safe. Keep an audit trail on your side: the gateway doesn't queue or persist requests.

---

## Health check

```sh
xentree-connect health                 # English
xentree-connect health --lang id       # Indonesian
```

```
Xentree Connect health check

OK       Config: Loaded /var/www/moodledata/keys/xentree-connect.json
OK       Clock: Offset +176 ms (±109 ms) via NTP pool.ntp.org
OK       Key file: …/xentree_private.pem is protected (group-readable gid 33); key id leysRdx…
OK       API: Reached https://my.xentree.ai/; token accepted, 1 organization(s) administered.

All checks passed.
```

| Check | OK | WARNING | CRITICAL |
| --- | --- | --- | --- |
| Clock | offset ≤ 1 s | 1–10 s (or can't be measured) | > 10 s |
| Key file | exists, valid, permissions match the declared policy | key differs from the one in the config | missing, unreadable, invalid, or permissions too open |
| API | token accepted | rate-limited | token rejected or unreachable |

The clock is measured with NTP (UDP 123) and, where that is blocked, from the HTTPS `Date` header. The API check runs only when `XENTREE_ADMIN_TOKEN` is set; otherwise it is skipped. The exit code is **0 unless something is CRITICAL**, so it is safe to run from cron or a monitoring agent.

Flags: `--config FILE`, `--key FILE`, `--key-group GID` (Unix), `--base-url URL`, `--lang en|id`.

---

## Reference

**Environment variables**

| Variable | Used by | Purpose |
| --- | --- | --- |
| `XENTREE_ADMIN_TOKEN` | `init`, `health` | Organization Administrator bearer token. Read from the environment only — there is deliberately no flag, so it never appears in shell history or the process list. |
| `XENTREE_GATEWAY_SECRET` | `gateway` | Shared secret for `/launch` and `/deprovision` (≥ 32 characters). |
| `XENTREE_WEBHOOK_SECRET` | `gateway` | Xentree webhook signing secret. |
| `XENTREE_PREVIOUS_WEBHOOK_SECRET`, `XENTREE_PREVIOUS_SECRET_ROTATED_AT` | `gateway` | Previous secret and rotation time (Unix seconds), valid for 24 h. |
| `RUST_LOG` | `gateway` | Log level (default `info`). |

**`gateway` flags:** `--config`, `--bind` (default `0.0.0.0:8080`), `--internal-bind` (default `127.0.0.1:8081`), `--gateway-secret`, `--relay-webhook-url`, `--webhook-secret`, `--previous-webhook-secret`, `--previous-secret-rotated-at`, `--trusted-identity-header` (repeatable), `--allow-query-secret`. Run `xentree-connect gateway --help`.

**`init` flags:** `--base-url`, `--org`, `--name`, `--client-id`, `--issuer`, `--audience`, `--auto-enroll`, `--dir`, `--key-dir`, `--key-group`, `--reuse-key`, `--yes`. Run `xentree-connect init --help`.

**Default key locations** (when `init` has no platform opinion): the per-user config directory — `~/.config/xentree-connect` on Linux, `~/Library/Application Support/ai.Xentree.xentree-connect` on macOS, `%APPDATA%\Xentree\xentree-connect\config` on Windows.

---

## Security design

- **ES256 (ECDSA P-256) keys**, generated with `ring` from the operating system's random source. No RSA code is in the signing path, which removes the RSA timing-attack class (RUSTSEC-2023-0071) entirely.
- **Key storage.** The private key is created owner-only *at creation time* (mode `0600` on Unix; a protected single-user ACL on Windows), written to a temporary file, flushed, verified and renamed into place atomically — there is no moment when it is world-readable, and a symlink at the destination is never followed. A deliberate group-readable setup (Moodle) is an explicit, verified policy (`0640`, named group), never a side effect. If permissions can't be applied or verified, the command fails rather than continuing. Existing keys are never overwritten.
- **In memory.** Key material is held in buffers that are zeroed when released (best-effort: the cryptographic library keeps its own copy).
- **Short-lived, single-use assertions.** Each launch or deprovision assertion lives 30 seconds (Xentree allows at most 60), carries a fresh random `jti`, and a deprovision assertion is explicitly marked `purpose: deprovision` — a launch assertion can't be used to offboard anyone.
- **Clock calibration.** Xentree accepts no clock skew, so the gateway measures its clock against NTP (falling back to the HTTPS `Date` header with round-trip compensation and CDN-cache detection) at start-up and every 30 minutes, and rounds the correction so an assertion can only be dated slightly in the past, never in the future.
- **Webhooks.** HMAC-SHA256 over `timestamp.body`, compared in constant time, checked against both the current and the previous secret during rotation, with a 5-minute replay window and event-ID de-duplication. Unauthenticated requests can't fill the de-duplication cache.
- **Gateway access control.** The gateway secret must be at least 32 characters and is compared via constant-time digests. Credentials in URLs are off by default; proxy identity headers are trusted only if you name them, and a proxy-authenticated user can only launch as themselves. `/deprovision` exists only on the internal listener and *also* requires the secret.
- **Network hygiene.** Xentree and webhook-relay URLs must be `https` (plain `http` only for localhost), redirects are never followed with credentials, IDs in URLs are percent-encoded, and the launch page is served with a strict Content-Security-Policy (the single inline script is pinned by hash; the form can only post to Xentree), `no-store`, `no-referrer`, `nosniff` and `X-Frame-Options: DENY`.
- **Supply chain.** Releases are built in CI from the committed `Cargo.lock` after the test suite passes on Linux, macOS and Windows, with a `SHA256SUMS` file and, for public repositories, build-provenance attestations; installers verify that checksum before installing.

### Known limitations

- The gateway does not terminate TLS and does not rate-limit failed authentication attempts — use a proxy for both.
- De-duplication and relay retries are held in memory: they reset on restart and aren't shared between replicas. A relayed event that fails all attempts is logged and dropped (Xentree has already been acknowledged).
- Changing webhook or gateway secrets requires a restart.
- The installers' checksum protects against corruption and tampering of a single file, not against a compromised release host; use `gh attestation verify` where that matters (public repositories only).

---

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `insecure permissions on …` | The key file is readable by more than its policy allows. `chmod 600` it (or `0640` with the right group for Moodle) and re-run `health`. |
| `A key already exists at …` | `init` won't overwrite a key. Use `--reuse-key` to register it, or a different `--key-dir`. |
| Registration says the client ID is taken | Choose another with `--client-id`; the generated key is kept and `--reuse-key` registers it. |
| Xentree answers `401 Invalid Connect launch assertion` | Usually the clock (`xentree-connect health`), or `issuer`/`audience` not matching what is registered, or the registered key differs from the one in use. |
| Gateway: `… holds key … but the config registered …` | The key file isn't the one that was registered. Restore the right key or register the current one with `init --reuse-key`. |
| Gateway returns `401` on `/launch` | Missing/incorrect bearer secret, an identity header that isn't listed in `--trusted-identity-header`, or a secret in the URL without `--allow-query-secret`. |
| Gateway returns `502` on `/deprovision` | Xentree rejected our assertion (check the clock and key) or couldn't be reached; the response includes `upstream_status`. |
| Group assignment fails during `init` | You aren't root or a member of the target group. Re-run with `sudo`. |

---

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`: it checks the tag matches `Cargo.toml`, runs tests and clippy on Linux, macOS and Windows, builds all platforms, writes `SHA256SUMS`, attests the artifacts (public repositories only), and creates a **draft** GitHub Release. Nothing is public until you publish the draft — which is also the moment the installers' `latest` pointer moves to it. The release also carries `install.sh` and `install.ps1`; publish them at the installer URLs (`get.xentree.ai/connect`, `…/connect.ps1`).
