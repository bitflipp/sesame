package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOTPSweep(t *testing.T) {
	now := time.Now()
	s := NewOTPStore(TokenConfig{Length: 6, TTL: time.Minute, MaxAttempts: 3, RateLimitPerHour: 5})
	s.now = func() time.Time { return now }
	s.Issue("a@x", "1.1.1.1")
	s.Sweep()
	if len(s.entries) != 1 || len(s.issued) != 2 {
		t.Fatalf("fresh state swept: %d entries, %d counters", len(s.entries), len(s.issued))
	}
	now = now.Add(2 * time.Hour)
	s.Sweep()
	if len(s.entries) != 0 || len(s.issued) != 0 {
		t.Errorf("stale state kept: %d entries, %d counters", len(s.entries), len(s.issued))
	}
}

func TestRandomDigits(t *testing.T) {
	d, err := randomDigits(64)
	if err != nil || len(d) != 64 || strings.Trim(d, "0123456789") != "" {
		t.Errorf("randomDigits = %q, %v", d, err)
	}
}

func TestClientIP(t *testing.T) {
	s, _ := newTestServer(t)
	for _, tc := range []struct{ remote, xff, want string }{
		{"203.0.113.9:1234", "", "203.0.113.9"},
		{"203.0.113.9:1234", "6.6.6.6", "203.0.113.9"}, // untrusted peer: XFF ignored
		{"127.0.0.1:1234", "", "127.0.0.1"},
		{"127.0.0.1:1234", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		{"127.0.0.1:1234", "garbage", "127.0.0.1"},
		{"[::1]:1234", "198.51.100.7", "198.51.100.7"},
		{"nonsense", "", "nonsense"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := s.clientIP(r); got != tc.want {
			t.Errorf("clientIP(%q, %q) = %q, want %q", tc.remote, tc.xff, got, tc.want)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "c.toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := `
external_url = "https://auth.example.com"
secret = "` + strings.Repeat("k", 32) + `"
[session]
cookie_domain = "example.com"
[smtp]
host = "localhost"
from = "a@example.com"
[[users]]
email = "a@example.com"
[[access]]
domain = "app.example.com"
subject = ["*"]
`
	c, err := LoadConfig(write(good))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Lookup("a@example.com"); !ok {
		t.Error("user missing after load")
	}
	if _, err := LoadConfig(write(good + "bogus = 1\n")); err == nil || !strings.Contains(err.Error(), "unknown config keys") {
		t.Errorf("unknown key: %v", err)
	}
	if _, err := LoadConfig(write(strings.Replace(good, "32", "1", 1) + "x = [")); err == nil {
		t.Error("syntax error accepted")
	}
	if _, err := LoadConfig(write(strings.Replace(good, strings.Repeat("k", 32), "short", 1))); err == nil {
		t.Error("invalid config accepted")
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing.toml")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		" Alice@Example.com ": "alice@example.com",
		"a@b.test":            "a@b.test",
	} {
		if got, err := normalizeEmail(in); err != nil || got != want {
			t.Errorf("normalizeEmail(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "nope", "Name <a@b.test>", "a@b.test\r\nBcc: x@y.test", strings.Repeat("a", 250) + "@b.test"} {
		if _, err := normalizeEmail(in); err == nil {
			t.Errorf("normalizeEmail(%q) accepted", in)
		}
	}
}

func TestLoginForm(t *testing.T) {
	s, _ := newTestServer(t)
	rd := "https://app.example.com/x"
	w := do(s, "GET", "/login?rd="+url.QueryEscape(rd), nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "app.example.com/x") {
		t.Errorf("anonymous: %d %s", w.Code, w.Body)
	}
	// Signed in: bounce to rd, or home when rd is missing or unsafe.
	c := sessionCookie(s, "alice@example.com")
	for target, want := range map[string]string{
		"/login?rd=" + url.QueryEscape(rd): rd,
		"/login":                           "/",
		"/login?rd=" + url.QueryEscape("https://evil.com/"): "/",
	} {
		w = do(s, "GET", target, nil, c)
		if w.Code != http.StatusFound || w.Header().Get("Location") != want {
			t.Errorf("%s: %d %q, want %q", target, w.Code, w.Header().Get("Location"), want)
		}
	}
}

func TestLoginInvalidEmail(t *testing.T) {
	s, f := newTestServer(t)
	w := do(s, "POST", "/login", url.Values{"email": {"not-an-email"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "valid email") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	if cookieByName(w, "sesame_pending") != nil {
		t.Error("pending cookie set for invalid email")
	}
	select {
	case m := <-f.codes:
		t.Errorf("mail sent: %s", m)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestLoginRateLimited(t *testing.T) {
	s, f := newTestServer(t)
	n := s.cfg.Token.RateLimitPerHour
	for i := 0; i < n+2; i++ {
		w := do(s, "POST", "/login", url.Values{"email": {"alice@example.com"}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("attempt %d: %d (responses must not reveal the limit)", i, w.Code)
		}
	}
	for i := 0; i < n; i++ {
		<-f.codes
	}
	select {
	case m := <-f.codes:
		t.Errorf("mail sent past the limit: %s", m)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestTokenForm(t *testing.T) {
	s, _ := newTestServer(t)
	// No pending cookie: back to login, preserving rd.
	rd := "https://app.example.com/x"
	w := do(s, "GET", "/token?rd="+url.QueryEscape(rd), nil)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusSeeOther || loc.Path != "/login" || loc.Query().Get("rd") != rd {
		t.Errorf("no pending: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = do(s, "POST", "/token", url.Values{"token": {"1"}})
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
		t.Errorf("post without pending: %d %q", w.Code, w.Header().Get("Location"))
	}
	// With pending cookie: form shows the address.
	w = do(s, "POST", "/login", url.Values{"email": {"alice@example.com"}})
	pending := cookieByName(w, "sesame_pending")
	w = do(s, "GET", "/token", nil, pending)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alice@example.com") {
		t.Errorf("token form: %d %s", w.Code, w.Body)
	}
	// A session cookie must not work as a pending cookie.
	sc := sessionCookie(s, "alice@example.com")
	w = do(s, "GET", "/token", nil, &http.Cookie{Name: "sesame_pending", Value: sc.Value})
	if w.Code != http.StatusSeeOther {
		t.Errorf("session cookie accepted as pending: %d", w.Code)
	}
}

func TestTokenSuccessWithoutRedirect(t *testing.T) {
	s, f := newTestServer(t)
	pending := cookieByName(do(s, "POST", "/login", url.Values{"email": {"alice@example.com"}}), "sesame_pending")
	_, code, _ := strings.Cut(<-f.codes, " ")
	w := do(s, "POST", "/token", url.Values{"token": {code}}, pending)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Errorf("%d %q", w.Code, w.Header().Get("Location"))
	}
	// Pending cookie is cleared, and the code can't be replayed.
	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "sesame_pending" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("pending cookie not cleared")
	}
	if w = do(s, "POST", "/token", url.Values{"token": {code}}, pending); w.Code != http.StatusUnauthorized {
		t.Errorf("replay: %d", w.Code)
	}
}

func TestTokenCrossSiteRejected(t *testing.T) {
	s, _ := newTestServer(t)
	r := httptest.NewRequest("POST", "/token", strings.NewReader("token=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d", w.Code)
	}
}

func TestRenderError(t *testing.T) {
	s, _ := newTestServer(t)
	for code, want := range map[int]string{
		http.StatusTooManyRequests: "Slow down",
		http.StatusBadGateway:      "Something went wrong",
		http.StatusTeapot:          "could not be completed",
	} {
		w := httptest.NewRecorder()
		s.renderError(w, httptest.NewRequest("GET", "/", nil), code)
		if w.Code != code || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%d: %d %s", code, w.Code, w.Body)
		}
	}
}

func TestVerifyEdgeCases(t *testing.T) {
	s, _ := newTestServer(t)
	// Tampered session cookie is treated as signed out.
	c := sessionCookie(s, "alice@example.com")
	c.Value += "x"
	r := httptest.NewRequest("GET", "/verify", nil)
	r.AddCookie(c)
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Errorf("tampered cookie: %d", w.Code)
	}
	// Wildcard-only user may not reach hosts outside their rules.
	r = httptest.NewRequest("GET", "/verify", nil)
	r.AddCookie(sessionCookie(s, "alice@example.com"))
	r.Header.Set("X-Forwarded-Host", "unlisted.example.com")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("unlisted host: %d", w.Code)
	}
}

func TestRunStops(t *testing.T) {
	s, _ := newTestServer(t)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { s.Run(stop); close(done) }()
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}
