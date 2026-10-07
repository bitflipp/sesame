<p align="center"><img src="icon.svg" alt="sesame icon" width="128" height="128"></p>

# sesame

A tiny email one-time-token SSO for [Caddy](https://caddyserver.com)'s `forward_auth`.

No database and no identity provider. Users type their email address, receive a numeric code over SMTP, and get a signed session cookie that works across all your subdomains. Access is controlled per host with a few lines of TOML. `sesame` is a single Go binary with one config file.

## Features

- **Passwordless login**: a numeric one-time code is sent by email (SMTP over STARTTLS, TLS, or plain).
- **Single sign-on** across every app under one `cookie_domain`.
- **Per-host authorization** by user or group, with wildcard domains. Hosts without a rule are denied.
- **Stateless sessions**: HMAC-signed cookies that hold only the email. Name and groups are re-read
  from the config on each request, so removing a user revokes their sessions immediately.
- **Abuse protection**: per-email and per-IP rate limits, attempt-limited codes, same-origin checks.
- **Multilingual**: English and German pages and emails. The language follows a switcher cookie, then the
  browser's `Accept-Language`, then `default_language`. To add one, drop in `locales/<lang>.toml` and
  `templates/mail.<lang>.txt`.
- **Small**: one Go binary, one config file, one dependency

## How it works

1. An unauthenticated request hits Caddy, which asks sesame's `/verify`. Sesame answers `302` to the login portal.
2. The user enters their email. If it is in the allowlist, a code is sent.
3. The user enters the code and receives a session cookie shared across `cookie_domain`.
4. `/verify` checks the `[[access]]` rules for the requested host (`X-Forwarded-Host`). It returns `403` if
   nothing matches, otherwise `200` with the headers `Remote-User`, `Remote-Email`, `Remote-Name` and `Remote-Groups`.

## Usage

```sh
go build -o sesame .
cp config.example.toml sesame.toml   # edit to taste
./sesame -config sesame.toml
```

Then add Caddy configuration like [`Caddyfile.example`](Caddyfile.example):

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

## Configuration

See [`config.example.toml`](config.example.toml) for all options. The essentials:

```toml
listen       = "127.0.0.1:9091"
external_url = "https://auth.example.com"   # where the login portal is served
secret       = "change-me-to-at-least-32-random-bytes!"  # or secret_file = "..."

[session]
cookie_domain = "example.com"   # parent domain shared by the portal and all apps

[[users]]
email  = "alice@example.org"
groups = ["dev"]

[[access]]
domain  = "app.example.com"     # exact host or "*.example.com"
subject = ["group:dev"]         # "user:<email>", "group:<name>", or "*"
```

## Endpoints

| Path       | Purpose                                                       |
|------------|---------------------------------------------------------------|
| `/`        | Login state and sign-out button                               |
| `/verify`  | `forward_auth` target for Caddy                               |
| `/login`   | Email form                                                    |
| `/token`   | Code entry form                                               |
| `/lang`    | `?set=de&rd=/path` stores the language cookie and redirects   |
| `/logout`  | `POST` signs out; `GET` just redirects home                   |
| `/healthz` | Health check                                                  |

Errors, including the `403` that `/verify` returns to Caddy, are rendered as friendly HTML pages.

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

## Requirements

- Go (to build) and an SMTP server for sending codes
- Caddy, or any reverse proxy with a `forward_auth`-style subrequest

## Running the tests

```sh
go test ./...
```

## License

[MIT](LICENSE)
