package main

import (
	"crypto/hmac"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	bolt "go.etcd.io/bbolt"
)

//go:embed passkeys.js
var passkeyJS []byte

func servePasskeyJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	// No caching override: the inherited no-store keeps an upgraded binary from
	// serving a script whose protocol no longer matches the handlers.
	w.Write(passkeyJS)
}

// passkeyCeremonyTTL bounds how long an unfinished registration or login
// ceremony stays valid. The authenticator prompt is usually answered within
// seconds; five minutes leaves room for a slow user without keeping stale
// challenges around.
const passkeyCeremonyTTL = 5 * time.Minute

// passkeyBeginLimit caps login ceremonies started per client IP per
// passkeyBeginWindow. Real users start one or two; the cap only bites abuse.
const (
	passkeyBeginLimit  = 30
	passkeyBeginWindow = 5 * time.Minute
)

var (
	bucketUsers       = []byte("users")
	bucketCredentials = []byte("credentials")

	errPasskeyNotFound = errors.New("passkey not found")
)

// Passkey is one stored credential record. Credential is kept whole and
// unmodified because the library needs every field to re-verify later
// assertions; the surrounding fields are portal bookkeeping.
type Passkey struct {
	ID         []byte              `json:"id"`
	Email      string              `json:"email"`
	Name       string              `json:"name"`
	CreatedAt  time.Time           `json:"created_at"`
	LastUsedAt time.Time           `json:"last_used_at,omitempty"`
	Credential webauthn.Credential `json:"credential"`
}

// passkeyView is the subset the index page renders.
type passkeyView struct {
	IDBase64   string
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// PasskeyStore is the durable side of the feature: a single bbolt file holding
// one random user handle per email and one JSON record per credential. Public
// keys are not secrets, but the file is created 0600 anyway.
type PasskeyStore struct {
	db  *bolt.DB
	now func() time.Time
}

// OpenPasskeyStore opens (creating if needed) the passkey database.
func OpenPasskeyStore(path string) (*PasskeyStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open passkey store: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketUsers, bucketCredentials} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialise passkey store: %w", err)
	}
	return &PasskeyStore{db: db, now: time.Now}, nil
}

func (s *PasskeyStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// UserHandle returns the stable WebAuthn user handle for an email, creating one
// on first use. Handles are random and opaque so they reveal nothing and do not
// change if the signing secret is rotated.
func (s *PasskeyStore) UserHandle(email string) ([]byte, error) {
	var handle []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		if v := b.Get([]byte(email)); v != nil {
			handle = append([]byte(nil), v...)
			return nil
		}
		h := make([]byte, 32)
		if _, err := rand.Read(h); err != nil {
			return err
		}
		if err := b.Put([]byte(email), h); err != nil {
			return err
		}
		handle = h
		return nil
	})
	return handle, err
}

// List returns the credentials owned by an email, oldest first.
func (s *PasskeyStore) List(email string) ([]Passkey, error) {
	var out []Passkey
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCredentials).ForEach(func(_, v []byte) error {
			var p Passkey
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			if p.Email == email {
				out = append(out, p)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, err
}

// Get looks up a credential by its raw ID.
func (s *PasskeyStore) Get(id []byte) (Passkey, error) {
	var p Passkey
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketCredentials).Get(id)
		if v == nil {
			return errPasskeyNotFound
		}
		return json.Unmarshal(v, &p)
	})
	return p, err
}

// Put stores a credential record.
func (s *PasskeyStore) Put(p Passkey) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCredentials).Put(p.ID, raw)
	})
}

// Delete removes a credential only when it belongs to email, so one user can
// never delete another user's passkey.
func (s *PasskeyStore) Delete(email string, id []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCredentials)
		v := b.Get(id)
		if v == nil {
			return nil
		}
		var p Passkey
		if err := json.Unmarshal(v, &p); err != nil {
			return err
		}
		if p.Email != email {
			return nil
		}
		return b.Delete(id)
	})
}

// UpdateAfterLogin writes back the fields a successful assertion advances
// (signature counter and flags) and records the use.
func (s *PasskeyStore) UpdateAfterLogin(email string, cred webauthn.Credential) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCredentials)
		v := b.Get(cred.ID)
		if v == nil {
			return errPasskeyNotFound
		}
		var p Passkey
		if err := json.Unmarshal(v, &p); err != nil {
			return err
		}
		if p.Email != email {
			return errPasskeyNotFound
		}
		p.Credential = cred
		p.LastUsedAt = s.now()
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return b.Put(cred.ID, raw)
	})
}

// Credentials returns the library view of a user's credentials.
func (s *PasskeyStore) Credentials(email string) ([]webauthn.Credential, error) {
	records, err := s.List(email)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(records))
	for _, p := range records {
		creds = append(creds, p.Credential)
	}
	return creds, nil
}

// webauthnUser adapts a configured user plus its stored credentials to the
// library's User interface.
type webauthnUser struct {
	user   User
	handle []byte
	creds  []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte { return u.handle }

func (u *webauthnUser) WebAuthnName() string { return u.user.Email }

func (u *webauthnUser) WebAuthnDisplayName() string {
	if u.user.Name != "" {
		return u.user.Name
	}
	return u.user.Email
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// webauthnUser loads the user adapter for an email that is still allowed.
func (s *Server) webauthnUser(email string) (*webauthnUser, error) {
	u, ok := s.cfg.Lookup(email)
	if !ok {
		return nil, errors.New("user is not configured")
	}
	handle, err := s.passkeys.UserHandle(email)
	if err != nil {
		return nil, err
	}
	creds, err := s.passkeys.Credentials(email)
	if err != nil {
		return nil, err
	}
	return &webauthnUser{user: u, handle: handle, creds: creds}, nil
}

// ceremony is one in-flight registration or login: the library session data
// plus, for registration, the email it will belong to.
type ceremony struct {
	session webauthn.SessionData
	email   string
	expires time.Time
}

// ceremonyStore keeps in-flight ceremonies in memory. Like pending one-time
// codes they do not survive a restart, which is intended: an unfinished
// ceremony is worthless afterwards and challenges should be short-lived.
type ceremonyStore struct {
	mu  sync.Mutex
	m   map[string]ceremony
	ttl time.Duration
	now func() time.Time
}

func newCeremonyStore(ttl time.Duration) *ceremonyStore {
	return &ceremonyStore{m: map[string]ceremony{}, ttl: ttl, now: time.Now}
}

// beginLimiter is a fixed-window per-IP counter for the unauthenticated login
// begin endpoint. That endpoint allocates server-side ceremony state, so an
// unbounded caller could otherwise grow memory without ever finishing.
type beginLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
	now    func() time.Time
}

func newBeginLimiter(limit int, window time.Duration) *beginLimiter {
	return &beginLimiter{hits: map[string][]time.Time{}, limit: limit, window: window, now: time.Now}
}

func (l *beginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	recent := pruneBefore(l.hits[key], now.Add(-l.window))
	if len(recent) >= l.limit {
		l.hits[key] = recent
		return false
	}
	l.hits[key] = append(recent, now)
	return true
}

func (l *beginLimiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.window)
	for k, v := range l.hits {
		if v = pruneBefore(v, cutoff); len(v) == 0 {
			delete(l.hits, k)
		} else {
			l.hits[k] = v
		}
	}
}

func (c *ceremonyStore) put(session webauthn.SessionData, email string) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = ceremony{session: session, email: email, expires: c.now().Add(c.ttl)}
	return id, nil
}

// take returns and consumes a ceremony, so a challenge cannot be replayed.
func (c *ceremonyStore) take(id string) (ceremony, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ce, ok := c.m[id]
	if !ok {
		return ceremony{}, false
	}
	delete(c.m, id)
	if c.now().After(ce.expires) {
		return ceremony{}, false
	}
	return ce, true
}

func (c *ceremonyStore) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, ce := range c.m {
		if now.After(ce.expires) {
			delete(c.m, k)
		}
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) ceremonyCookieName() string { return s.cfg.Session.CookieName + "_webauthn" }

// ceremonyToken signs an opaque ceremony id. The MAC covers a distinct prefix
// so a ceremony cookie can never be presented as a session or pending cookie
// (and vice versa), without touching the existing cookie formats.
func (s *Server) ceremonyToken(id string) string {
	body := base64.RawURLEncoding.EncodeToString([]byte(id))
	return body + "." + base64.RawURLEncoding.EncodeToString(s.mac("webauthn\x00"+body))
}

func (s *Server) parseCeremonyToken(v string) (string, bool) {
	body, sig, ok := strings.Cut(v, ".")
	if !ok {
		return "", false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac("webauthn\x00"+body)) {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func (s *Server) ceremonyID(r *http.Request) (string, bool) {
	ck, err := r.Cookie(s.ceremonyCookieName())
	if err != nil {
		return "", false
	}
	return s.parseCeremonyToken(ck.Value)
}

func (s *Server) clearCeremony(w http.ResponseWriter) {
	s.setCookie(w, s.ceremonyCookieName(), "", "", "strict", -1)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// The status line is already sent, so an encode error has nowhere to go.
	_ = json.NewEncoder(w).Encode(v)
}

// passkeyJSONError keeps failures machine-readable for the page script. The
// message is a short code, not prose: user-facing copy is localised in the
// template and reaches the client with the page.
func (s *Server) passkeyJSONError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": code})
}

// handlePasskeyRegisterBegin starts a registration ceremony for the signed-in
// user. The returned options carry the challenge; the matching session data is
// kept server-side and linked to the browser by a signed cookie.
func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u, ok := s.session(r)
	if !ok {
		s.passkeyJSONError(w, http.StatusUnauthorized, "not_signed_in")
		return
	}
	if !s.sameOrigin(r) {
		s.passkeyJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	wu, err := s.webauthnUser(u.Email)
	if err != nil {
		s.logf("passkey register begin for %s: %v", u.Email, err)
		s.passkeyJSONError(w, http.StatusInternalServerError, "internal")
		return
	}
	creation, session, err := s.webauthn.BeginMediatedRegistration(wu, protocol.MediationDefault,
		webauthn.WithExclusions(webauthn.Credentials(wu.creds).CredentialDescriptors()),
	)
	if err != nil {
		s.logf("passkey register begin for %s: %v", u.Email, err)
		s.passkeyJSONError(w, http.StatusInternalServerError, "internal")
		return
	}
	id, err := s.ceremony.put(*session, u.Email)
	if err != nil {
		s.logf("passkey ceremony: %v", err)
		s.passkeyJSONError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.setCookie(w, s.ceremonyCookieName(), s.ceremonyToken(id), "", "strict", int(passkeyCeremonyTTL.Seconds()))
	writeJSON(w, http.StatusOK, creation)
}

// handlePasskeyRegisterFinish verifies the authenticator's response and stores
// the new credential.
func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u, ok := s.session(r)
	if !ok {
		s.passkeyJSONError(w, http.StatusUnauthorized, "not_signed_in")
		return
	}
	if !s.sameOrigin(r) {
		s.passkeyJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	id, ok := s.ceremonyID(r)
	if !ok {
		s.passkeyJSONError(w, http.StatusBadRequest, "no_ceremony")
		return
	}
	ce, ok := s.ceremony.take(id)
	if !ok || ce.email != u.Email {
		s.passkeyJSONError(w, http.StatusBadRequest, "no_ceremony")
		return
	}
	wu, err := s.webauthnUser(u.Email)
	if err != nil {
		s.passkeyJSONError(w, http.StatusInternalServerError, "internal")
		return
	}
	cred, err := s.webauthn.FinishRegistration(wu, ce.session, r)
	if err != nil {
		s.logf("passkey registration for %s rejected: %v", u.Email, err)
		s.passkeyJSONError(w, http.StatusBadRequest, "registration_failed")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if runes := []rune(name); len(runes) > 64 {
		name = string(runes[:64])
	}
	p := Passkey{ID: cred.ID, Email: u.Email, Name: name, CreatedAt: s.now(), Credential: *cred}
	if err := s.passkeys.Put(p); err != nil {
		s.logf("storing passkey for %s: %v", u.Email, err)
		s.passkeyJSONError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.clearCeremony(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": "/?passkeys=added"})
}

// handlePasskeyLoginBegin starts a usernameless (discoverable) login ceremony.
// No account is named: the authenticator returns the user handle at the end.
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		s.passkeyJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.passkeyBegins.allow(s.clientIP(r)) {
		s.passkeyJSONError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	assertion, session, err := s.webauthn.BeginDiscoverableLogin()
	if err != nil {
		s.logf("passkey login begin: %v", err)
		s.passkeyJSONError(w, http.StatusInternalServerError, "internal")
		return
	}
	id, err := s.ceremony.put(*session, "")
	if err != nil {
		s.logf("passkey ceremony: %v", err)
		s.passkeyJSONError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.setCookie(w, s.ceremonyCookieName(), s.ceremonyToken(id), "", "strict", int(passkeyCeremonyTTL.Seconds()))
	writeJSON(w, http.StatusOK, assertion)
}

// handlePasskeyLoginFinish validates the assertion and, on success, issues the
// same session cookie the email-code flow uses.
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		s.passkeyJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	id, ok := s.ceremonyID(r)
	if !ok {
		s.passkeyJSONError(w, http.StatusBadRequest, "no_ceremony")
		return
	}
	ce, ok := s.ceremony.take(id)
	if !ok {
		s.passkeyJSONError(w, http.StatusBadRequest, "no_ceremony")
		return
	}

	var email string
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		p, err := s.passkeys.Get(rawID)
		if err != nil {
			return nil, err
		}
		wu, err := s.webauthnUser(p.Email)
		if err != nil {
			return nil, err
		}
		// The handle is checked here and again by the library; requiring it
		// stops a credential from being claimed under a different account.
		if len(userHandle) > 0 && !hmac.Equal(userHandle, wu.handle) {
			return nil, errors.New("user handle does not match the credential")
		}
		email = p.Email
		return wu, nil
	}

	_, cred, err := s.webauthn.FinishPasskeyLogin(lookup, ce.session, r)
	if err != nil {
		s.logf("passkey login rejected: %v", err)
		s.passkeyJSONError(w, http.StatusUnauthorized, "login_failed")
		return
	}
	if _, ok := s.cfg.Lookup(email); !ok {
		// The user may have been removed between begin and finish.
		s.passkeyJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.passkeys.UpdateAfterLogin(email, *cred); err != nil {
		// A stale counter could allow a cloned authenticator to go unnoticed,
		// but the assertion itself was valid, so sign in and report the write.
		s.logf("updating passkey for %s after login: %v", email, err)
	}
	s.setSession(w, email)
	s.clearCeremony(w)
	rd := s.safeRedirect(r.URL.Query().Get("rd"))
	if rd == "" {
		rd = "/"
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": rd})
}

// handlePasskeyDelete removes one of the signed-in user's passkeys.
func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	u, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if id, err := base64.RawURLEncoding.DecodeString(r.FormValue("id")); err == nil {
		if err := s.passkeys.Delete(u.Email, id); err != nil {
			s.logf("deleting passkey for %s: %v", u.Email, err)
		}
	}
	http.Redirect(w, r, "/?passkeys=removed", http.StatusSeeOther)
}

// passkeyViews maps stored records to the template's view type.
func passkeyViews(records []Passkey) []passkeyView {
	views := make([]passkeyView, 0, len(records))
	for _, p := range records {
		views = append(views, passkeyView{
			IDBase64:   base64.RawURLEncoding.EncodeToString(p.ID),
			Name:       p.Name,
			CreatedAt:  p.CreatedAt,
			LastUsedAt: p.LastUsedAt,
		})
	}
	return views
}
