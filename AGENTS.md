# AGENTS.md

Guidance for AI coding agents working in this repository. The project overview (flow, endpoints,
config reference) lives in `README.md`; don't duplicate it here.

## Verify your work

Single Go module (`package main`), one external dependency (`github.com/BurntSushi/toml`).

```sh
go vet ./...                       # must be clean
go test ./...                      # whole suite, ~0.2s
go test -run TestFullLoginFlow .   # a single test
go build -o sesame .               # then: ./sesame -config sesame.toml
```

- The suite is hermetic: `httptest` servers and a fake SMTP listener on loopback. No network, no
  config file, no environment variables. If a new test needs any of those, that is a design smell
  worth raising before you write it.
- In a sandboxed environment Go may fail with `read-only file system` on its build cache. Point
  `GOCACHE` at a writable **absolute** path (a relative one is rejected), for example
  `GOCACHE="$PWD/.git/gocache" go test ./...`, which persists and does not dirty the worktree. On a
  normal machine the default cache works and this does not apply.
- There is no CI configuration in this repository. `go vet` plus `go test ./...` locally is the
  entire gate, so run both before claiming something works.
- `templates/` and `locales/` are embedded with `go:embed`. **Rebuild after editing them**, and do
  not trust an already-running binary when checking markup or copy.
- `./sesame` and `./sesame.toml` are gitignored. Never commit a real secret or SMTP password.

## Layout

- `main.go` — flag parsing, `http.Server`, graceful shutdown; starts `Server.Run` (background sweeper).
- `config.go` — TOML loading, `validate()` (defaults + every check), and authorization: `Lookup`
  (user allowlist), `Authorize` (`[[access]]` rules; additive; hosts with no matching rule are
  denied), `domainMatches` (exact or `*.` wildcard).
- `auth.go` — `Server` (routing in `ServeHTTP`), HMAC-signed stateless cookies (`sign`/`parse`, a
  `kind` separates the session cookie from the `_pending` cookie), the `/verify` handler, `clientIP`
  (honors `X-Forwarded-For` only from `trusted_proxies`, warns once when it ignores one),
  `safeLocalPath`/`safeRedirect`.
- `login.go` — login/token/logout/index handlers and template rendering; `errorWriter` converts
  error responses (including the 403 from `/verify`) into HTML error pages.
- `i18n.go` — embedded `locales/*.toml` catalogs (flat keys, `en` is the fallback), `Localizer.T`,
  language detection (`sesame_lang` cookie, then `Accept-Language`, then `default_language`) and the
  `/lang` switcher.
- `otp.go` — in-memory `OTPStore`: issuing with per-email and per-IP hourly rate limits,
  attempt-limited verification, sweeping.
- `mail.go` — `Sender` interface, `buildMessage` (renders `templates/mail.<lang>.txt`, falling back
  to `en`: `subject` and `body` blocks) and `SMTPSender`.

Tests: `sesame_test.go` (handlers and flows), `security_test.go` (CSRF, redirects, headers, rate
limits), `i18n_test.go` (catalog parity, language matching), `mail_test.go` (message building,
fake SMTP), `coverage_test.go` (edge paths, sweeper). Tests inject a fake sender or a fake SMTP
server rather than reaching for a real one.

## Invariants: ask before changing

These are security boundaries. They are cheap to change and expensive to get subtly wrong, so
propose the change and wait for a decision instead of picking a plausible-looking variant.

- **Cookie signing and format** (`sign`/`parse`, the session/`_pending` `kind` split). Changing the
  signed payload or `kind` handling can invalidate every live session or let one cookie be accepted
  as the other.
- **Authorization semantics** (`Lookup`, `Authorize`, `domainMatches`, `user:`/`group:`/`*` subjects,
  wildcards, deny-by-default). Any loosening here is an access-control vulnerability.
- **Proxy trust** (`clientIP`, `trusted_proxies`, `X-Forwarded-For`). Believing a spoofable header
  collapses every client into one rate-limit bucket.
- **The `/verify` → Caddy contract**: 200 with `Remote-User`/`Remote-Email`/`Remote-Name`/
  `Remote-Groups`, 403 otherwise, and Caddy's `copy_headers` overwriting client-supplied values.
  Downstream apps trust these headers.
- **Redirect safety** (`safeLocalPath`, `safeRedirect`, the `rd` parameter): redirect targets stay on
  the portal host or a host with an `[[access]]` rule.
- **Same-origin / CSRF checks** and the token attempt and rate-limit limits.
- **Config schema.** Prefer additive keys with defaults in `validate()`; a breaking rename invalidates
  every existing `sesame.toml`.
- **Dependencies.** One today on purpose. Adding a second is a maintainer decision.

## Conventions

- **Identity lives in config, not the cookie.** Session cookies hold only the email; name and groups
  are re-read from config on every request, which is what makes removing a user revoke their sessions
  immediately. Don't "optimize" this into the cookie.
- **Pending OTPs are in memory only.** A restart invalidating unredeemed codes is intended.
- **Never hardcode English in handlers or templates.** UI strings go through `Localizer.T` with keys
  present in *every* catalog; `TestCatalogParity` fails if a language drifts.
- **Errors become HTML pages** via `errorWriter`, including `/verify`'s 403.
- New pages or emails mean: a template, keys in `locales/en.toml` and `locales/de.toml`, and
  `templates/mail.<lang>.txt` for email copy.
- Match the existing style: small handlers, table-driven tests, `httptest` for HTTP, fake senders for
  mail. Add a test with each behavior change.

## Working agreement

- **Proceed without asking** on internal refactors, added tests, template/CSS work, and new
  translations — verify with `go vet` and `go test ./...` and report what you ran.
- **Ask first** for anything in the invariants list, a new dependency, a non-additive config change,
  or a change in scope beyond what was requested.
- **Don't commit or push unless asked.** Keep commits single-purpose, in the style of the existing
  history.
- Definition of done: `go vet` clean, `go test ./...` green, and an honest summary of what changed,
  what you verified, and what you assumed. If you could not verify something, say so plainly.
