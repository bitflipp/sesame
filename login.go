package main

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

var pages = map[string]*template.Template{}

func init() {
	for _, p := range []string{"login", "token", "index", "error"} {
		pages[p] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+p+".html"))
	}
}

type pageData struct {
	Title string // catalog key
	L     Localizer
	Path  string // current request URI, for the language switcher
	Email string
	RD    string
	Error string // catalog key
	User  *User  // index: the signed-in user, if any
	Code  int    // error: HTTP status
	Msg   string // error: catalog key of the friendly explanation
	Home  string // error: absolute link to the portal

	PasskeysEnabled bool          // [passkey] store is configured
	Passkeys        []passkeyView // index: the signed-in user's credentials
	PasskeyNotice   string        // index: catalog key for a one-shot notice
}

// renderError writes a friendly error page for the given status.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, code int) {
	key := "error_" + strconv.Itoa(code)
	if _, ok := catalogs[fallbackLang][key+"_title"]; !ok {
		key = "error_other"
		if code >= 500 {
			key = "error_500"
		}
	}
	s.render(w, r, code, "error", pageData{Title: key + "_title", Msg: key + "_msg", Code: code, Home: s.cfg.external.String()})
}

// errorWriter swaps the plain-text bodies written by http.Error and
// http.ServeMux (404/405) for the friendly error page.
type errorWriter struct {
	http.ResponseWriter
	s       *Server
	r       *http.Request
	swapped bool
}

func (e *errorWriter) WriteHeader(code int) {
	if code >= 400 && strings.HasPrefix(e.Header().Get("Content-Type"), "text/plain") {
		e.swapped = true
		e.Header().Del("Content-Length")
		e.s.renderError(e.ResponseWriter, e.r, code)
		return
	}
	e.ResponseWriter.WriteHeader(code)
}

func (e *errorWriter) Write(b []byte) (int, error) {
	if e.swapped {
		return len(b), nil
	}
	return e.ResponseWriter.Write(b)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	d := pageData{Title: "title_index", PasskeysEnabled: s.cfg.PasskeysEnabled()}
	if u, ok := s.session(r); ok {
		d.User = &u
		if s.cfg.PasskeysEnabled() {
			if records, err := s.passkeys.List(u.Email); err != nil {
				s.logf("listing passkeys for %s: %v", u.Email, err)
			} else {
				d.Passkeys = passkeyViews(records)
			}
			switch r.URL.Query().Get("passkeys") {
			case "added":
				d.PasskeyNotice = "passkey_added"
			case "removed":
				d.PasskeyNotice = "passkey_removed"
			}
		}
	}
	s.render(w, r, http.StatusOK, "index", d)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, d pageData) {
	d.L = Localizer{s.lang(r)}
	d.Path = r.URL.RequestURI()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages[page].ExecuteTemplate(w, "layout", d); err != nil {
		s.logf("render %s: %v", page, err)
	}
}

// sameOrigin rejects cross-site form posts. Browsers that send Fetch Metadata
// are trusted on that alone; others fall back to comparing Origin with
// external_url (not the Host header, which a proxy may rewrite). A POST that
// carries neither header is rejected: browsers always send Origin on non-GET
// requests, so there is no legitimate client to accommodate.
func (s *Server) sameOrigin(r *http.Request) bool {
	if v := r.Header.Get("Sec-Fetch-Site"); v != "" {
		return v == "same-origin" || v == "none"
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	return err == nil && u.Scheme == s.cfg.external.Scheme && strings.EqualFold(u.Host, s.cfg.external.Host)
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	rd := s.safeRedirect(r.URL.Query().Get("rd"))
	if _, ok := s.session(r); ok {
		if rd != "" {
			http.Redirect(w, r, rd, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.render(w, r, http.StatusOK, "login", pageData{Title: "title_login", RD: rd, PasskeysEnabled: s.cfg.PasskeysEnabled()})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rd := s.safeRedirect(r.FormValue("rd"))
	email, err := normalizeEmail(r.FormValue("email"))
	if err != nil {
		s.render(w, r, http.StatusBadRequest, "login", pageData{Title: "title_login", RD: rd, Error: "login_invalid_email"})
		return
	}

	// The response is identical whether or not the address is allowed, and
	// mail is sent in the background so timing doesn't reveal it either.
	if _, ok := s.cfg.Lookup(email); ok {
		lang := s.lang(r)
		code, err := s.otp.Issue(email, s.clientIP(r))
		if err != nil {
			s.logf("token for %s not issued: %v", email, err)
		} else {
			go func() {
				if err := s.sender.SendToken(email, code, s.cfg.Token.TTL, lang); err != nil {
					s.logf("sending token to %s: %v", email, err)
				}
			}()
		}
	} else {
		s.logf("login attempt for unlisted address %q", email)
	}
	s.setPending(w, email)
	http.Redirect(w, r, "/token?"+url.Values{"rd": {rd}}.Encode(), http.StatusSeeOther)
}

func (s *Server) pendingEmail(r *http.Request) (string, bool) {
	ck, err := r.Cookie(s.pendingCookieName())
	if err != nil {
		return "", false
	}
	c, err := s.parse(ck.Value, kindPending)
	if err != nil {
		return "", false
	}
	return c.Email, true
}

func (s *Server) handleTokenForm(w http.ResponseWriter, r *http.Request) {
	rd := s.safeRedirect(r.URL.Query().Get("rd"))
	email, ok := s.pendingEmail(r)
	if !ok {
		http.Redirect(w, r, "/login?"+url.Values{"rd": {rd}}.Encode(), http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "token", pageData{Title: "title_token", Email: email, RD: rd})
}

func (s *Server) handleTokenSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rd := s.safeRedirect(r.FormValue("rd"))
	email, ok := s.pendingEmail(r)
	if !ok {
		http.Redirect(w, r, "/login?"+url.Values{"rd": {rd}}.Encode(), http.StatusSeeOther)
		return
	}
	code := strings.Join(strings.Fields(r.FormValue("token")), "")
	if _, allowed := s.cfg.Lookup(email); !allowed || !s.otp.Verify(email, code) {
		s.render(w, r, http.StatusUnauthorized, "token", pageData{Title: "title_token", Email: email, RD: rd, Error: "token_invalid"})
		return
	}
	s.setSession(w, email)
	s.setCookie(w, s.pendingCookieName(), "", "", "strict", -1)
	if rd == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, rd, http.StatusSeeOther)
}

// handleLogout clears the session. It is POST-only so that a third-party page
// can't sign users out via an image or link; GET just goes home.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.setCookie(w, s.cfg.Session.CookieName, "", s.cfg.Session.CookieDomain, "lax", -1)
	s.setCookie(w, s.pendingCookieName(), "", "", "strict", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
