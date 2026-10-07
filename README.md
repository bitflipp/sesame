<p align="center"><img src="icon.svg" alt="sesame icon" width="128" height="128"></p>

# sesame

**Tiny email one-time-token and passkey SSO for [Caddy](https://caddyserver.com)'s `forward_auth`.**

No external database and no identity provider. Users sign in with a numeric code sent over SMTP — or,
once they have registered one, with a passkey — and get a signed session cookie that works across all
your subdomains. Access is controlled per host with a few lines of TOML. `sesame` is a single Go
binary with one config file; passkeys, when enabled, live in one local key/value file next to it.

## Features

- **Passwordless login**: a numeric one-time code is sent by email (SMTP over STARTTLS, TLS, or plain).
- **Passkeys (WebAuthn)**: optional discoverable credentials for usernameless, phishing-resistant
  sign-in. Users register and manage their own passkeys from the index page after signing in; the
  email code remains available for bootstrapping and recovery.
- **Single sign-on** across every app under one `cookie_domain`.
- **Per-host authorization** by user or group, with wildcard domains. Hosts without a rule are denied.
- **Stateless sessions**: HMAC-signed cookies that hold only the email. Name and groups are re-read
  from the config on each request, so removing a user revokes their sessions immediately.
- **Abuse protection**: per-email and per-IP rate limits, attempt-limited codes, same-origin checks.
- **Multilingual**: English and German pages and emails. The language follows a switcher cookie, then the
  browser's `Accept-Language`, then `default_language`. To add one, drop in `locales/<lang>.toml` and
  `templates/mail.<lang>.txt`.
- **Small**: one Go binary, one config file, four direct dependencies, no cgo.

## How it works

1. An unauthenticated request hits Caddy, which asks sesame's `/verify`. Sesame answers `302` to the login portal.
2. The user enters their email. If it is in the allowlist, a code is sent. They can also press
   **Sign in with a passkey** to skip the code when they have registered one.
3. The user enters the code (or completes the passkey prompt) and receives a session cookie shared across `cookie_domain`.
4. `/verify` checks the `[[access]]` rules for the requested host (`X-Forwarded-Host`). It returns `403` if
   nothing matches, otherwise `200` with the headers `Remote-User`, `Remote-Email`, `Remote-Name` and `Remote-Groups`.
5. Once signed in, the index page shows the user's account details and passkeys, and lets them add or remove passkeys.

## Quick start

```sh
go build -o sesame .
```

Point Caddy at it ([`Caddyfile.example`](Caddyfile.example)):

```caddyfile
auth.example.com {
	reverse_proxy 127.0.0.1:9091
}

app.example.com {
	forward_auth 127.0.0.1:9091 {
		uri /verify
		copy_headers Remote-User Remote-Email Remote-Name Remote-Groups
	}
	reverse_proxy 127.0.0.1:8080
}
```

Then write a config and run it:

```sh
cp config.example.toml sesame.toml
sed -i "s|change-me-to-at-least-32-random-bytes!|$(openssl rand -base64 32)|" sesame.toml
$EDITOR sesame.toml             # listen, external_url, cookie_domain, [smtp], [[users]], [[access]]
./sesame -config sesame.toml
```

The portal is served at `external_url`; every other host is protected by adding an `[[access]]` rule
and putting it behind `forward_auth`. To keep the secret out of the config file, set `secret_file`
instead of `secret`.

## Configuration

See [`config.example.toml`](config.example.toml) for every option and its default. The essentials:

```toml
listen       = "127.0.0.1:9091"
external_url = "https://auth.example.com"   # where the login portal is served
secret       = "change-me-to-at-least-32-random-bytes!"  # 32+ bytes, or use secret_file = "..."

[smtp]                          # see config.example.toml; host and from are required
host     = "smtp.example.com"
tls      = "starttls"
username = "auth@example.com"
password = "app-password"
from     = "Sesame <auth@example.com>"

[session]
cookie_domain = "example.com"   # parent domain shared by the portal and all apps

[passkey]                       # optional; omit to disable passkeys
store = "/var/lib/sesame/passkeys.db"

[[users]]
email  = "alice@example.org"
groups = ["dev"]

[[access]]
domain  = "app.example.com"     # exact host or "*.example.com"
subject = ["group:dev"]         # "user:<email>", "group:<name>", or "*"
```

`rp_id` defaults to `session.cookie_domain`, which is what lets one passkey cover the portal and its
siblings. `store` must point at a writable path; sesame creates the file (mode `0600`) on first start.
SMTP is configured in the `[smtp]` block: `host`, optional `port` (defaults to 587 for `starttls`,
465 for `tls`, 25 for `none`), `tls`, `username`, `password` and `from`. Unknown keys are rejected at
startup, so a typo fails loudly rather than silently taking a default.

## Endpoints

| Path       | Purpose                                                       |
|------------|---------------------------------------------------------------|
| `/`        | Account details, passkey management, and sign-out button      |
| `/verify`  | `forward_auth` target for Caddy                               |
| `/login`   | Email form and the passkey sign-in button                     |
| `/token`   | Code entry form                                               |
| `/passkeys/register/begin` / `.../finish` | Passkey registration ceremony (`POST`, signed in) |
| `/passkeys/login/begin` / `.../finish`    | Usernameless passkey login ceremony (`POST`)      |
| `/passkeys/delete` | Remove one of your passkeys (`POST`, signed in)       |
| `/passkeys.js` | Page script that drives the passkey ceremonies            |
| `/lang`    | `?set=de&rd=/path` stores the language cookie and redirects   |
| `/logout`  | `POST` signs out; `GET` just redirects home                   |
| `/healthz` | Health check                                                  |
| `/icon.svg`, `/apple-touch-icon.png` | Embedded icons for browsers and home screens |

Errors, including the `403` that `/verify` returns to Caddy, are rendered as friendly HTML pages.
The passkey endpoints answer JSON instead, since only the page script calls them.

### Security notes

- Caddy's `copy_headers` overwrites any client-supplied `Remote-*` headers, so upstreams can trust
  them as long as they are only reachable through Caddy.
- `X-Forwarded-For` is only believed from peers listed in `trusted_proxies`; if the proxy is missing
  from that list, sesame logs a warning once and every client shares one per-IP rate limit.
- After signing in, sesame only redirects to the portal itself or to a host with an `[[access]]` rule,
  so a crafted `rd` cannot bounce users to another site.
- Set `session.cookie_domain` to the registrable domain (`example.com`), not a public suffix such as
  `com` or `co.uk`; single-label domains are rejected at startup.
- The example `secret` from `config.example.toml` is rejected; generate a random one. A secret with
  very few distinct bytes is flagged with a startup warning.
- `smtp.tls = "none"` sends codes unencrypted and warns at startup; use `starttls` or `tls` unless the
  relay is on localhost.
- Pending codes live in memory, so a restart invalidates unredeemed codes.
- Passkeys are client-side discoverable credentials, so sign-in needs no username and reveals whether
  an account exists only by failing generically. The relying party ID defaults to `session.cookie_domain`
  and is checked at startup to be the portal host or a parent of it.
- The passkey store holds credential IDs, public keys and opaque random user handles — never private
  keys. It is created `0600`; keep it on a path only sesame can read.
- Registering a passkey requires a signed-in session, and deleting one checks ownership. In-flight
  ceremonies live in memory, expire after five minutes and are single-use. Starting a login ceremony
  is rate limited per client IP, so cheap requests cannot grow that state without bound.

## Requirements

- Go 1.27 or newer (to build) and an SMTP server for sending codes
- Caddy, or any reverse proxy with a `forward_auth`-style subrequest
- HTTPS for passkeys (browsers only run WebAuthn in a secure context; `localhost` counts)

## Development

```sh
go vet ./...      # must be clean
go test ./...     # hermetic suite: httptest servers and a fake SMTP listener on loopback
go build -o sesame .
```

The suite needs no network, no config file and no environment variables. `templates/` and `locales/`
are embedded with `go:embed`, so rebuild after editing them and don't trust an already-running binary
when checking markup or copy. Contributions follow [`AGENTS.md`](AGENTS.md): new pages or emails need
a template, keys in `locales/en.toml` and `locales/de.toml`, and a `templates/mail.<lang>.txt`. Add a
test with each behavior change.

Parts of this project were written with AI assistance. The models involved:

- Claude Sonnet 5.5
- DeepSeek Flash

## License

[MIT](LICENSE)
