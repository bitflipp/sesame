# sesame

Tiny email one-time-token SSO for Caddy's `forward_auth`.

1. Unauthenticated request → `/verify` answers `302` to the login portal.
2. User enters their email; if allowed, a numeric code is sent via SMTP.
3. User enters the code → signed session cookie (shared across `cookie_domain`).
4. `/verify` checks the `[[access]]` rules for the requested host (`X-Forwarded-Host`): `403` if the user's email or groups don't match any rule (hosts with no rule are denied), otherwise `200` with `Remote-User`, `Remote-Email`, `Remote-Name`, `Remote-Groups`.

Sessions are stateless HMAC-signed cookies (they only hold the email; name and groups are
re-read from the config on each request, so removing a user revokes them). Pending codes live
in memory, so a restart invalidates unredeemed codes.

```
go build -o sesame . && ./sesame -config sesame.toml
```

See `config.example.toml` and `Caddyfile.example`. Caddy's `copy_headers` overwrites any
client-supplied `Remote-*` headers, so upstreams can trust them as long as they are only
reachable through Caddy. Endpoints: `/` (login state and sign-out button), `/verify`, `/login`, `/token`, `/logout` (POST signs out; GET just redirects home), `/healthz`. Errors, including the `403` that `/verify` returns to Caddy, are rendered as friendly HTML pages.
