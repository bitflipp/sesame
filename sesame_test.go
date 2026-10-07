package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeSender struct {
	codes chan string
}

func (f *fakeSender) SendToken(to, code string, _ time.Duration, _ string) error {
	f.codes <- to + " " + code
	return nil
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	c := &Config{
		ExternalURL: "https://auth.example.com",
		Secret:      strings.Repeat("k", 32),
		Session:     SessionConfig{CookieDomain: "example.com"},
		SMTP:        SMTPConfig{Host: "localhost", From: "Sesame <a@example.com>"},
		Access: []AccessRule{
			{Domain: "app.example.com", Subject: []string{"group:dev"}},
			{Domain: "*.internal.example.com", Subject: []string{"user:Bob@corp.test", "user:alice@example.com"}},
			{Domain: "open.example.com", Subject: []string{"*"}},
		},
		Users: []User{
			{Email: "Alice@Example.com", Name: "Alice", Groups: []string{"admins", "dev"}},
			{Email: "bob@corp.test"},
		},
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func newTestServer(t *testing.T) (*Server, *fakeSender) {
	f := &fakeSender{codes: make(chan string, 10)}
	s, err := NewServer(testConfig(t), f)
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

func do(s *Server, method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	// Behave like a browser: same-origin non-GET requests carry Origin.
	r.Header.Set("Origin", "https://auth.example.com")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestConfigValidation(t *testing.T) {
	good := testConfig(t)
	if _, ok := good.Lookup("alice@example.com"); !ok {
		t.Error("explicit user not found")
	}
	if _, ok := good.Lookup("bob@corp.test"); !ok {
		t.Error("second user not found")
	}
	if _, ok := good.Lookup("carol@corp.test"); ok {
		t.Error("same-domain stranger allowed")
	}
	if _, ok := good.Lookup("eve@evil.test"); ok {
		t.Error("unlisted user allowed")
	}
	mutations := map[string]func(*Config){
		"short secret": func(c *Config) { c.Secret = "short" },
		"bad url":      func(c *Config) { c.ExternalURL = "auth.example.com" },
		"wrong domain": func(c *Config) { c.Session.CookieDomain = "other.org" },
		"no access":    func(c *Config) { c.Users = nil },
		"no rules":     func(c *Config) { c.Access = nil },
		"bad subject":  func(c *Config) { c.Access[0].Subject = []string{"role:x"} },
		"bad domain":   func(c *Config) { c.Access[0].Domain = "a.*.com" },
		"bad tls":      func(c *Config) { c.SMTP.TLS = "magic" },
	}
	for name, mut := range mutations {
		c := &Config{
			ExternalURL: "https://auth.example.com", Secret: strings.Repeat("k", 32),
			Session: SessionConfig{CookieDomain: "example.com"},
			SMTP:    SMTPConfig{Host: "h", From: "a@example.com"},
			Users:   []User{{Email: "a@example.com"}},
			Access:  []AccessRule{{Domain: "app.example.com", Subject: []string{"*"}}},
		}
		mut(c)
		if c.validate() == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestOTPStore(t *testing.T) {
	now := time.Now()
	s := NewOTPStore(TokenConfig{Length: 8, TTL: time.Minute, MaxAttempts: 3, RateLimitPerHour: 2})
	s.now = func() time.Time { return now }

	code, _ := s.Issue("a@x", "1.1.1.1")
	if len(code) != 8 {
		t.Fatalf("code length %d", len(code))
	}
	if s.Verify("a@x", "00000000") && code != "00000000" {
		t.Error("wrong code accepted")
	}
	if !s.Verify("a@x", code) {
		t.Error("right code rejected")
	}
	if s.Verify("a@x", code) {
		t.Error("code reused")
	}

	code, _ = s.Issue("a@x", "1.1.1.1")
	if _, err := s.Issue("a@x", "1.1.1.1"); err != ErrRateLimited {
		t.Error("expected rate limit")
	}
	now = now.Add(2 * time.Minute)
	if s.Verify("a@x", code) {
		t.Error("expired code accepted")
	}

	now = now.Add(time.Hour)
	code, err := s.Issue("a@x", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.Verify("a@x", "x")
	}
	if s.Verify("a@x", code) {
		t.Error("code survived max attempts")
	}
}

func TestCookieSigning(t *testing.T) {
	s, _ := newTestServer(t)
	v := s.sign(claims{Kind: kindSession, Email: "alice@example.com", Expires: s.now().Add(time.Hour).Unix()})
	if _, err := s.parse(v, kindSession); err != nil {
		t.Fatal(err)
	}
	if _, err := s.parse(v, kindPending); err == nil {
		t.Error("session cookie accepted as pending")
	}
	if _, err := s.parse(v+"x", kindSession); err == nil {
		t.Error("tampered signature accepted")
	}
	old := s.sign(claims{Kind: kindSession, Email: "alice@example.com", Expires: s.now().Add(-time.Second).Unix()})
	if _, err := s.parse(old, kindSession); err == nil {
		t.Error("expired cookie accepted")
	}
}

func TestSafeRedirect(t *testing.T) {
	s, _ := newTestServer(t)
	for rd, want := range map[string]bool{
		"https://app.example.com/x?y=1":   true, // access rule
		"https://auth.example.com/":       true, // the portal itself
		"https://x.internal.example.com/": true, // wildcard access rule
		"https://example.com/":            false,
		"https://evil.com/":               false,
		"https://example.com.evil.com/":   false,
		"https://evilexample.com/":        false,
		"//evil.com":                      false,
		"javascript:alert(1)":             false,
		"https://a@evil.com/":             false,
		"/relative":                       false,
	} {
		if got := s.safeRedirect(rd) != ""; got != want {
			t.Errorf("safeRedirect(%q) = %v, want %v", rd, got, want)
		}
	}
}

func TestVerifyUnauthenticated(t *testing.T) {
	s, _ := newTestServer(t)
	r := httptest.NewRequest("GET", "/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Uri", "/a?b=c")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "auth.example.com" || loc.Path != "/login" || loc.Query().Get("rd") != "https://app.example.com/a?b=c" {
		t.Errorf("bad redirect %s", loc)
	}
}

func cookieByName(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestFullLoginFlow(t *testing.T) {
	s, f := newTestServer(t)
	rd := "https://app.example.com/secret"

	w := do(s, "POST", "/login", url.Values{"email": {"Alice@example.com"}, "rd": {rd}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status %d", w.Code)
	}
	pending := cookieByName(w, "sesame_pending")
	if pending == nil {
		t.Fatal("no pending cookie")
	}
	var to, code string
	select {
	case m := <-f.codes:
		to, code, _ = strings.Cut(m, " ")
	case <-time.After(time.Second):
		t.Fatal("no mail sent")
	}
	if to != "alice@example.com" {
		t.Errorf("mailed %q", to)
	}

	// wrong code
	w = do(s, "POST", "/token", url.Values{"token": {"nope"}, "rd": {rd}}, pending)
	if w.Code != http.StatusUnauthorized || cookieByName(w, "sesame") != nil {
		t.Fatalf("wrong code: status %d", w.Code)
	}
	// right code (spaces tolerated)
	w = do(s, "POST", "/token", url.Values{"token": {code[:4] + " " + code[4:]}, "rd": {rd}}, pending)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != rd {
		t.Fatalf("token: status %d loc %q", w.Code, w.Header().Get("Location"))
	}
	session := cookieByName(w, "sesame")
	if session == nil || session.Domain != "example.com" || !session.HttpOnly || !session.Secure {
		t.Fatalf("bad session cookie %+v", session)
	}

	// forward_auth check
	r := httptest.NewRequest("GET", "/verify", nil)
	r.AddCookie(session)
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("verify status %d", w.Code)
	}
	for h, want := range map[string]string{
		"Remote-User": "alice@example.com", "Remote-Email": "alice@example.com",
		"Remote-Name": "Alice", "Remote-Groups": "admins,dev",
	} {
		if got := w.Header().Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

func TestNoEnumeration(t *testing.T) {
	s, f := newTestServer(t)
	a := do(s, "POST", "/login", url.Values{"email": {"alice@example.com"}})
	b := do(s, "POST", "/login", url.Values{"email": {"nobody@evil.test"}})
	if a.Code != b.Code || a.Header().Get("Location") != b.Header().Get("Location") {
		t.Error("responses differ")
	}
	<-f.codes
	select {
	case m := <-f.codes:
		t.Errorf("mail sent to unlisted address: %s", m)
	case <-time.After(50 * time.Millisecond):
	}
	// pending cookie for unlisted address can never be redeemed
	w := do(s, "POST", "/token", url.Values{"token": {"12345678"}}, cookieByName(b, "sesame_pending"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status %d", w.Code)
	}
}

func TestRemovedUserLosesAccess(t *testing.T) {
	s, _ := newTestServer(t)
	v := s.sign(claims{Kind: kindSession, Email: "gone@example.com", Expires: s.now().Add(time.Hour).Unix()})
	w := do(s, "GET", "/verify", nil, &http.Cookie{Name: "sesame", Value: v})
	if w.Code != http.StatusFound {
		t.Errorf("status %d", w.Code)
	}
}

func TestCrossSiteRejected(t *testing.T) {
	s, _ := newTestServer(t)
	r := httptest.NewRequest("POST", "/login", strings.NewReader("email=alice@example.com"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d", w.Code)
	}
}

func TestAuthorize(t *testing.T) {
	c := testConfig(t)
	alice, _ := c.Lookup("alice@example.com")
	bob, _ := c.Lookup("bob@corp.test")
	for _, tc := range []struct {
		u    User
		host string
		want bool
	}{
		{alice, "app.example.com", true},
		{alice, "APP.example.com:443", true},
		{bob, "app.example.com", false},
		{alice, "x.internal.example.com", true},
		{bob, "x.internal.example.com", true},
		{bob, "internal.example.com", false},
		{alice, "evilapp.example.com", false},
		{bob, "open.example.com", true},
		{alice, "unlisted.example.com", false},
		{alice, "", false},
	} {
		if got := c.Authorize(tc.u, tc.host); got != tc.want {
			t.Errorf("Authorize(%s, %q) = %v, want %v", tc.u.Email, tc.host, got, tc.want)
		}
	}
}

func TestVerifyForbidden(t *testing.T) {
	s, _ := newTestServer(t)
	v := s.sign(claims{Kind: kindSession, Email: "bob@corp.test", Expires: s.now().Add(time.Hour).Unix()})
	r := httptest.NewRequest("GET", "/verify", nil)
	r.AddCookie(&http.Cookie{Name: "sesame", Value: v})
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d", w.Code)
	}
	if w.Header().Get("Remote-User") != "" {
		t.Error("identity headers leaked on denial")
	}
}

func TestSameOrigin(t *testing.T) {
	s, _ := newTestServer(t)
	for _, tc := range []struct {
		site, origin string
		want         bool
	}{
		{"same-origin", "null", true}, // Origin is "null" under Referrer-Policy: no-referrer
		{"same-origin", "", true},
		{"cross-site", "https://auth.example.com", false},
		{"same-site", "", false},
		{"", "", false}, // neither header: fail closed
		{"", "https://auth.example.com", true},
		{"", "https://evil.com", false},
		{"", "null", false},
	} {
		r := httptest.NewRequest("POST", "http://internal:9091/login", nil) // Host rewritten by proxy
		if tc.site != "" {
			r.Header.Set("Sec-Fetch-Site", tc.site)
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if got := s.sameOrigin(r); got != tc.want {
			t.Errorf("site=%q origin=%q: got %v, want %v", tc.site, tc.origin, got, tc.want)
		}
	}
}

func TestCSPAllowsPostLoginRedirect(t *testing.T) {
	s, _ := newTestServer(t)
	w := do(s, "GET", "/login", nil)
	if csp := w.Header().Get("Content-Security-Policy"); strings.Contains(csp, "form-action") {
		t.Errorf("form-action would block the redirect to the app: %s", csp)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _ := newTestServer(t)
	for _, path := range []string{"/login", "/", "/nope"} {
		w := do(s, "GET", path, nil)
		for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Cross-Origin-Opener-Policy", "Permissions-Policy"} {
			if w.Header().Get(h) == "" {
				t.Errorf("%s: missing %s", path, h)
			}
		}
	}
	s.cfg.secureCookie = false
	if h := do(s, "GET", "/login", nil).Header().Get("Strict-Transport-Security"); h != "" {
		t.Errorf("HSTS set over http: %q", h)
	}
	s.cfg.secureCookie = true
	if h := do(s, "GET", "/login", nil).Header().Get("Strict-Transport-Security"); h == "" || strings.Contains(h, "includeSubDomains") {
		t.Errorf("HSTS over https: %q", h)
	}
}

func sessionCookie(s *Server, email string) *http.Cookie {
	v := s.sign(claims{Kind: kindSession, Email: email, Expires: s.now().Add(time.Hour).Unix()})
	return &http.Cookie{Name: "sesame", Value: v}
}

func TestIndex(t *testing.T) {
	s, _ := newTestServer(t)
	w := do(s, "GET", "/", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "signed out") {
		t.Errorf("anonymous index: %d %s", w.Code, w.Body)
	}
	w = do(s, "GET", "/", nil, sessionCookie(s, "alice@example.com"))
	b := w.Body.String()
	if w.Code != 200 || !strings.Contains(b, "alice@example.com") || !strings.Contains(b, "admins, dev") || !strings.Contains(b, `action="/logout"`) {
		t.Errorf("signed-in index: %d %s", w.Code, b)
	}
	// The account details and the sign-out control form one group; without a
	// passkey store that is the only group on the page.
	if !strings.Contains(b, "Your account") || strings.Count(b, `class="group"`) != 1 {
		t.Errorf("account group missing or not alone: %s", b)
	}
}

func TestLogout(t *testing.T) {
	s, _ := newTestServer(t)
	c := sessionCookie(s, "alice@example.com")
	w := do(s, "POST", "/logout", url.Values{}, c)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("logout: %d %q", w.Code, w.Header().Get("Location"))
	}
	var cleared *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "sesame" {
			cleared = ck
		}
	}
	if cleared == nil || cleared.MaxAge >= 0 || cleared.Value != "" || cleared.Domain != "example.com" {
		t.Errorf("session not cleared: %+v", cleared)
	}
	// GET must not log out.
	if w = do(s, "GET", "/logout", nil, c); cookieByName(w, "sesame") != nil {
		t.Error("GET /logout cleared the session")
	}
	// Cross-site POST is rejected.
	r := httptest.NewRequest("POST", "/logout", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.AddCookie(c)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || cookieByName(w, "sesame") != nil {
		t.Errorf("cross-site logout: %d", w.Code)
	}
}

func TestFriendlyErrors(t *testing.T) {
	s, _ := newTestServer(t)
	for _, tc := range []struct {
		method, path string
		code         int
		want         string
	}{
		{"GET", "/nope", 404, "Page not found"},
		{"PUT", "/login", 405, "Not allowed"},
		{"DELETE", "/", 405, "Not allowed"},
	} {
		w := do(s, tc.method, tc.path, nil)
		if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.want) ||
			!strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s %s: %d %q %s", tc.method, tc.path, w.Code, w.Header().Get("Content-Type"), w.Body)
		}
	}
	// forward_auth denial carries the friendly body too.
	r := httptest.NewRequest("GET", "/verify", nil)
	r.AddCookie(sessionCookie(s, "bob@corp.test"))
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "Access denied") || !strings.Contains(w.Body.String(), "https://auth.example.com") {
		t.Errorf("verify 403: %d %s", w.Code, w.Body)
	}
}

func TestCookieDomainRejectsTopLevelDomain(t *testing.T) {
	base := func(ext, domain string) *Config {
		return &Config{
			ExternalURL: ext,
			Secret:      strings.Repeat("k", 32),
			Session:     SessionConfig{CookieDomain: domain},
			SMTP:        SMTPConfig{Host: "localhost", From: "a@example.com"},
			Users:       []User{{Email: "a@example.com"}},
			Access:      []AccessRule{{Domain: "app.example.com", Subject: []string{"*"}}},
		}
	}
	if err := base("https://auth.example.com", "com").validate(); err == nil {
		t.Error("top-level cookie_domain accepted")
	}
	// A single-label portal host (e.g. an intranet name) may keep its own host.
	if err := base("http://auth", "auth").validate(); err != nil {
		t.Errorf("single-label deployment rejected: %v", err)
	}
}

func TestPlaceholderSecretRejected(t *testing.T) {
	c := &Config{
		ExternalURL: "https://auth.example.com",
		Secret:      placeholderSecret,
		Session:     SessionConfig{CookieDomain: "example.com"},
		SMTP:        SMTPConfig{Host: "localhost", From: "a@example.com"},
		Users:       []User{{Email: "a@example.com"}},
		Access:      []AccessRule{{Domain: "app.example.com", Subject: []string{"*"}}},
	}
	if err := c.validate(); err == nil {
		t.Error("placeholder secret accepted")
	}
}

func TestSameOriginFailsClosed(t *testing.T) {
	s, _ := newTestServer(t)
	r := httptest.NewRequest("POST", "/login", strings.NewReader("email=alice@example.com"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("POST with no Fetch Metadata and no Origin: status %d, want 403", w.Code)
	}
}
