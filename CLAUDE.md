# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```
go build -o sesame . && ./sesame -config sesame.toml   # run (copy config.example.toml first)
go test ./...                                          # all tests (sesame_test.go)
go test -run TestName .                                # single test
go vet ./...
```

Single Go package (`main`), one external dependency (BurntSushi/toml). HTML templates and the email text (`templates/mail.txt`) in `templates/` are embedded via `go:embed`, so rebuild after editing them.

## Architecture

Email one-time-token SSO meant to sit behind Caddy's `forward_auth` (see `Caddyfile.example`). See README.md for the flow and endpoints.

- `main.go` — flag parsing, `http.Server` setup, graceful shutdown; starts the `Server.Run` background sweeper.
- `config.go` — TOML config, `validate()` (defaults + all checks), and authorization: `Lookup` (user allowlist), `Authorize` (`[[access]]` rules; additive, hosts with no matching rule are denied), `domainMatches` (exact or `*.` wildcard).
- `auth.go` — `Server` (routing in `ServeHTTP`), HMAC-signed stateless cookies (`sign`/`parse`, a "kind" separates the session cookie from the `_pending` cookie), `/verify` handler, `clientIP` (honors `X-Forwarded-For` only from `trusted_proxies`), `safeRedirect`.
- `login.go` — login/token/logout/index handlers and template rendering; `errorWriter` converts error responses (incl. the 403 from `/verify`) into HTML error pages.
- `otp.go` — in-memory `OTPStore`: issuing with per-email and per-IP hourly rate limits, attempt-limited verification, sweeping.
- `mail.go` — `Sender` interface, `buildMessage` (renders `templates/mail.txt`: `subject` and `body` blocks) and `SMTPSender`. Tests inject a fake sender or a fake SMTP server (`mail_test.go`).

Key design points:
- Session cookies hold only the email; name/groups are re-read from config on every request, so removing a user revokes their sessions.
- Pending OTPs are in memory only; restart invalidates them.
- `/verify` returns `Remote-User/Email/Name/Groups` headers on 200 and relies on Caddy's `copy_headers` to overwrite client-supplied ones.
