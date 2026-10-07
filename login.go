package main

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

var pages = map[string]*template.Template{}

func init() {
	for _, p := range []string{"login", "token", "done"} {
		pages[p] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+p+".html"))
	}
}

type pageData struct {
	Email string
	RD    string
	Error string
}

func (s *Server) render(w http.ResponseWriter, status int, page string, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages[page].ExecuteTemplate(w, "layout", d); err != nil {
		s.logf("render %s: %v", page, err)
	}
}

// sameOrigin rejects cross-site form posts. Browsers that send Fetch Metadata
// are trusted on that alone; others fall back to comparing Origin with
// external_url (not the Host header, which a proxy may rewrite).
func (s *Server) sameOrigin(r *http.Request) bool {
	if v := r.Header.Get("Sec-Fetch-Site"); v != "" {
		return v == "same-origin" || v == "none"
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
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
		s.render(w, http.StatusOK, "done", pageData{})
		return
	}
	s.render(w, http.StatusOK, "login", pageData{RD: rd})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rd := s.safeRedirect(r.FormValue("rd"))
	email, err := normalizeEmail(r.FormValue("email"))
	if err != nil {
		s.render(w, http.StatusBadRequest, "login", pageData{RD: rd, Error: "Please enter a valid email address."})
		return
	}

	// The response is identical whether or not the address is allowed, and
	// mail is sent in the background so timing doesn't reveal it either.
	if _, ok := s.cfg.Lookup(email); ok {
		code, err := s.otp.Issue(email, s.clientIP(r))
		if err != nil {
			s.logf("token for %s not issued: %v", email, err)
		} else {
			go func() {
				if err := s.sender.SendToken(email, code, s.cfg.Token.TTL); err != nil {
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
	s.render(w, http.StatusOK, "token", pageData{Email: email, RD: rd})
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
		s.render(w, http.StatusUnauthorized, "token", pageData{Email: email, RD: rd, Error: "That code is invalid or has expired."})
		return
	}
	s.setSession(w, email)
	s.setCookie(w, s.pendingCookieName(), "", "", "strict", -1)
	if rd == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, rd, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.setCookie(w, s.cfg.Session.CookieName, "", s.cfg.Session.CookieDomain, "lax", -1)
	s.setCookie(w, s.pendingCookieName(), "", "", "strict", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
