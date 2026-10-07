package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSafeLocalPath covers the guard that keeps /lang redirects local. Browsers
// strip ASCII tab, CR and LF before parsing a URL, so those must be rejected
// rather than normalized, and http.Redirect's path.Clean never runs when the
// value fails url.Parse — which is exactly the case controls create.
func TestSafeLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/":                "/",
		"/login?rd=x":      "/login?rd=x",
		"/x#frag":          "/x#frag",
		"/%2F%2Fevil.test": "/%2F%2Fevil.test", // literal percent: stays a path
		"":                 "",
		"\t/x":             "",
		"//x":              "",
		"///x":             "",
		`/\x`:              "",
		"/x\ty":            "",
		"/x\x7fy":          "",
		"/x\x00y":          "",
		"/x\x0by":          "",
		"https://x/":       "",
	} {
		if got := safeLocalPath(in); got != want {
			t.Errorf("safeLocalPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLangRedirectsStayLocal drives the whole handler with hostile rd values and
// asserts the Location can never leave the portal host or carry a raw control
// byte that a browser would strip into a "//host" URL.
func TestLangRedirectsStayLocal(t *testing.T) {
	s, _ := newTestServer(t)
	probes := []string{
		"/\t/evil.test",
		"/\t\t/evil.test",
		"/\t//evil.test",
		"/\n/evil.test",
		"/\r/evil.test",
		"/\v/evil.test",
		"/\x00/evil.test",
		"/\x7f/evil.test",
		"/\u0085/evil.test",
		"/\u2028/evil.test",
		"/%09/evil.test",   // one decode -> literal "%09"
		"/%2509/evil.test", // double encoded
		"/%0d%0a/evil.test",
		"/%2F/evil.test",
		"/%2F%2Fevil.test",
		"/%5c/evil.test",
		"/.%2e//evil.test",
		"/..//evil.test",
		"/\\evil.test",
		`/\\evil.test`,
		"//evil.test",
		"///evil.test",
		"https://evil.test/",
		"http://evil.test/",
		"https:/evil.test",
		`https://auth.example.com\@evil.test/`,
		"https://auth.example.com@evil.test/",
		"https://auth.example.com.evil.test/",
		"https://auth.example.com%2f@evil.test/",
		"https://auth.example.com#@evil.test",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"",
	}
	for _, rd := range probes {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", "/lang?set=de&rd="+url.QueryEscape(rd), nil))
		loc := w.Header().Get("Location")
		if w.Code != http.StatusSeeOther {
			t.Errorf("rd=%q status=%d", rd, w.Code)
			continue
		}
		if strings.HasPrefix(loc, "//") {
			t.Errorf("rd=%q -> protocol-relative Location %q", rd, loc)
		}
		if u, err := url.Parse(loc); err != nil {
			t.Errorf("rd=%q -> unparseable Location %q", rd, loc)
		} else if u.Host != "" && !strings.EqualFold(u.Host, "auth.example.com") {
			t.Errorf("rd=%q -> off-host Location %q", rd, loc)
		}
		for i := 0; i < len(loc); i++ {
			if loc[i] < 0x20 || loc[i] == 0x7f {
				t.Errorf("rd=%q -> Location %q contains control byte 0x%02x", rd, loc, loc[i])
				break
			}
		}
	}
}

// TestSafeRedirectTargets pins the closed set of post-login redirect targets:
// the portal itself, or a host the operator wrote an [[access]] rule for.
func TestSafeRedirectTargets(t *testing.T) {
	s, _ := newTestServer(t)
	for rd, want := range map[string]bool{
		"https://app.example.com/x":                    true,
		"https://APP.EXAMPLE.COM:8443/x":               true,
		"HTTPS://app.example.com/x":                    true,
		"https://app.example.com./x":                   true,
		"https://auth.example.com/x":                   true,
		"https://x.internal.example.com/x":             true,
		"https://open.example.com/x":                   true,
		"https://internal.example.com/":                false, // wildcard needs a label
		"https://example.com/":                         false, // cookie domain is not enough
		"https://auth.example.com.evil/":               false,
		"https://evil.com/x":                           false,
		"https://evil.com/?u=https://app.example.com/": false,
		"https://app.example.com#@evil.com":            true, // fragment only; host is allowed
		"https://app.example.com%2f@evil.com/":         false,
		"https://app.example.com\\@evil.com/":          false,
		"https://app.example.com\\evil.com/":           false,
		"https://app%2Eexample.com/x":                  false, // url.Parse rejects the escape
		"http://app.example.com/x":                     true,
		"ftp://app.example.com/x":                      false,
		"//app.example.com/x":                          false,
		"/app.example.com/x":                           false,
	} {
		if got := s.safeRedirect(rd) != ""; got != want {
			t.Errorf("safeRedirect(%q) allowed=%v, want %v", rd, got, want)
		}
	}
}

// TestSameOriginHeaderValues exercises the CSRF gate's header parsing. Anything
// ambiguous or malformed must fail closed.
func TestSameOriginHeaderValues(t *testing.T) {
	s, _ := newTestServer(t)
	for site, want := range map[string]bool{
		"same-origin":  true,
		"none":         true,
		"cross-site":   false,
		"same-site":    false,
		"SAME-ORIGIN":  false, // non-browser value
		" same-origin": false,
		"same-origin ": false,
	} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.Header.Set("Sec-Fetch-Site", site)
		if got := s.sameOrigin(r); got != want {
			t.Errorf("Sec-Fetch-Site %q: got %v, want %v", site, got, want)
		}
	}
	for origin, want := range map[string]bool{
		"https://auth.example.com":      true,
		"https://AUTH.example.com":      true,
		"http://auth.example.com":       false, // scheme mismatch
		"https://auth.example.com:8443": false, // port mismatch
		"https://auth.example.com.evil": false,
		"null":                          false,
		"not a url":                     false,
	} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.Header.Set("Origin", origin)
		if got := s.sameOrigin(r); got != want {
			t.Errorf("Origin %q: got %v, want %v", origin, got, want)
		}
	}
}

// TestRateLimitBucketsIndependent checks that neither rate-limit bucket is
// charged when the other rejects the request, and that both recover once the
// hour-long window slides.
func TestRateLimitBucketsIndependent(t *testing.T) {
	now := time.Now()
	st := NewOTPStore(TokenConfig{Length: 8, TTL: time.Minute, MaxAttempts: 5, RateLimitPerHour: 2})
	st.now = func() time.Time { return now }

	st.Issue("a@x", "1.1.1.1")
	st.Issue("a@x", "1.1.1.1")
	if _, err := st.Issue("a@x", "2.2.2.2"); err != ErrRateLimited { // email bucket full
		t.Fatalf("email bucket not enforced: %v", err)
	}
	if n := len(st.issued["i:2.2.2.2"]); n != 0 {
		t.Errorf("email-limited request charged the IP bucket: %d", n)
	}
	if _, err := st.Issue("b@x", "1.1.1.1"); err != ErrRateLimited { // IP bucket full
		t.Fatalf("IP bucket not enforced: %v", err)
	}
	if n := len(st.issued["e:b@x"]); n != 0 {
		t.Errorf("IP-limited request charged the email bucket: %d", n)
	}
	now = now.Add(61 * time.Minute)
	if _, err := st.Issue("b@x", "1.1.1.1"); err != nil {
		t.Errorf("buckets did not expire: %v", err)
	}
	if n := len(st.issued["e:b@x"]); n != 1 {
		t.Errorf("email counter = %d, want 1", n)
	}
	if n := len(st.issued["i:1.1.1.1"]); n != 1 {
		t.Errorf("IP counter = %d, want 1", n)
	}
}

func TestClientIPUnmapped(t *testing.T) {
	s, _ := newTestServer(t)
	for _, tc := range []struct{ remote, xff, want string }{
		{"[::ffff:127.0.0.1]:1234", "", "127.0.0.1"},
		{"[::ffff:203.0.113.9]:1234", "", "203.0.113.9"},
		{"127.0.0.1:1234", " 198.51.100.7 ", "198.51.100.7"},
		{"127.0.0.1:1234", "6.6.6.6,not-an-ip", "127.0.0.1"},
		{"127.0.0.1:1234", "6.6.6.6,2001:db8::1", "2001:db8::1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := s.clientIP(r); got != tc.want {
			t.Errorf("clientIP(%q,%q) = %q, want %q", tc.remote, tc.xff, got, tc.want)
		}
	}
}
