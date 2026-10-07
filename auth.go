package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	kindSession = "s"
	kindPending = "p"
)

// claims is the signed cookie payload. Session cookies only carry the email;
// name and groups are looked up from the config on every request so config
// changes (including removals) take effect immediately.
type claims struct {
	Kind    string `json:"k"`
	Email   string `json:"e"`
	Expires int64  `json:"x"`
}

type Server struct {
	cfg    *Config
	otp    *OTPStore
	sender Sender
	mux    *http.ServeMux
	now    func() time.Time
}

func NewServer(cfg *Config, sender Sender) *Server {
	s := &Server{cfg: cfg, otp: NewOTPStore(cfg.Token), sender: sender, now: time.Now}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/verify", s.handleVerify)
	s.mux.HandleFunc("GET /login", s.handleLoginForm)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("GET /token", s.handleTokenForm)
	s.mux.HandleFunc("POST /token", s.handleTokenSubmit)
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /lang", s.handleLang)
	s.mux.HandleFunc("GET /logout", s.handleLogout)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	// No form-action: browsers apply it to redirects after a form POST, which
	// would block the redirect back to the protected app.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY") // legacy twin of frame-ancestors
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	if s.cfg.secureCookie {
		// No includeSubDomains: the apps on sibling hosts may not all be https.
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	s.mux.ServeHTTP(&errorWriter{ResponseWriter: w, s: s, r: r}, r)
}

func (s *Server) sign(c claims) string {
	p, _ := json.Marshal(c)
	body := base64.RawURLEncoding.EncodeToString(p)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.mac(body))
}

func (s *Server) mac(body string) []byte {
	h := hmac.New(sha256.New, s.cfg.secretBytes)
	h.Write([]byte(body))
	return h.Sum(nil)
}

func (s *Server) parse(value, kind string) (claims, error) {
	var c claims
	body, sig, ok := strings.Cut(value, ".")
	if !ok {
		return c, errors.New("malformed cookie")
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(body)) {
		return c, errors.New("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(raw, &c) != nil {
		return c, errors.New("malformed payload")
	}
	if c.Kind != kind || s.now().Unix() >= c.Expires {
		return c, errors.New("wrong kind or expired")
	}
	return c, nil
}

func (s *Server) pendingCookieName() string { return s.cfg.Session.CookieName + "_pending" }

func (s *Server) setCookie(w http.ResponseWriter, name, value, domain, sameSite string, maxAge int) {
	c := &http.Cookie{
		Name: name, Value: value, Path: "/", Domain: domain, MaxAge: maxAge,
		HttpOnly: true, Secure: s.cfg.secureCookie, SameSite: http.SameSiteLaxMode,
	}
	if sameSite == "strict" {
		c.SameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, c)
}

func (s *Server) setSession(w http.ResponseWriter, email string) {
	life := s.cfg.Session.Lifetime
	v := s.sign(claims{Kind: kindSession, Email: email, Expires: s.now().Add(life).Unix()})
	s.setCookie(w, s.cfg.Session.CookieName, v, s.cfg.Session.CookieDomain, "lax", int(life.Seconds()))
}

func (s *Server) setPending(w http.ResponseWriter, email string) {
	ttl := s.cfg.Token.TTL
	v := s.sign(claims{Kind: kindPending, Email: email, Expires: s.now().Add(ttl).Unix()})
	s.setCookie(w, s.pendingCookieName(), v, "", "strict", int(ttl.Seconds()))
}

// session returns the signed-in user, if the request carries a valid session
// for an address that is still allowed.
func (s *Server) session(r *http.Request) (User, bool) {
	ck, err := r.Cookie(s.cfg.Session.CookieName)
	if err != nil {
		return User{}, false
	}
	c, err := s.parse(ck.Value, kindSession)
	if err != nil {
		return User{}, false
	}
	return s.cfg.Lookup(c.Email)
}

// handleVerify implements Caddy's forward_auth contract: 2xx with identity
// headers when signed in, otherwise a redirect to the login portal.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.session(r); ok {
		if !s.cfg.Authorize(u, r.Header.Get("X-Forwarded-Host")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		name := u.Name
		if name == "" {
			name = u.Email
		}
		h := w.Header()
		h.Set("Remote-User", u.Email)
		h.Set("Remote-Email", u.Email)
		h.Set("Remote-Name", name)
		h.Set("Remote-Groups", strings.Join(u.Groups, ","))
		w.WriteHeader(http.StatusOK)
		return
	}
	proto := firstNonEmpty(r.Header.Get("X-Forwarded-Proto"), "https")
	host := r.Header.Get("X-Forwarded-Host")
	uri := firstNonEmpty(r.Header.Get("X-Forwarded-Uri"), "/")
	target := s.cfg.external.JoinPath("login")
	if host != "" {
		q := target.Query()
		q.Set("rd", proto+"://"+host+uri)
		target.RawQuery = q.Encode()
	}
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// safeRedirect returns rd if it points at the portal or any host under the
// session cookie domain, and "" otherwise (prevents open redirects).
func (s *Server) safeRedirect(rd string) string {
	u, err := url.Parse(rd)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	d := s.cfg.Session.CookieDomain
	if h != d && !strings.HasSuffix(h, "."+d) {
		return ""
	}
	return u.String()
}

// clientIP returns the peer address, or X-Forwarded-For's last hop when the
// peer is a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	for _, p := range s.cfg.trusted {
		if p.Contains(addr.Unmap()) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				if ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
					return ip.String()
				}
			}
			break
		}
	}
	return addr.String()
}

// Run starts the periodic sweep of expired tokens.
func (s *Server) Run(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.otp.Sweep()
		case <-stop:
			return
		}
	}
}

func (s *Server) logf(format string, args ...any) { log.Printf(format, args...) }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
