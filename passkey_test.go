package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	testOrigin = "https://auth.example.com"
	testRPID   = "example.com"
)

// passkeyConfig is testConfig plus an enabled passkey store in a temp dir.
func passkeyConfig(t *testing.T) *Config {
	t.Helper()
	c := &Config{
		ExternalURL: testOrigin,
		Secret:      strings.Repeat("k", 32),
		Session:     SessionConfig{CookieDomain: testRPID},
		SMTP:        SMTPConfig{Host: "localhost", From: "Sesame <a@example.com>"},
		Access:      []AccessRule{{Domain: "app.example.com", Subject: []string{"*"}}},
		Users:       []User{{Email: "alice@example.com", Name: "Alice", Groups: []string{"dev"}}},
		Passkey:     PasskeyConfig{Store: filepath.Join(t.TempDir(), "passkeys.db")},
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func newPasskeyServer(t *testing.T) (*Server, *fakeSender) {
	t.Helper()
	f := &fakeSender{codes: make(chan string, 10)}
	s, err := NewServer(passkeyConfig(t), f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, f
}

// postJSON behaves like the page script: a same-origin POST with a JSON body.
func postJSON(s *Server, target string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	r := httptest.NewRequest("POST", target, reader)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", testOrigin)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decoding %q: %v", w.Body.String(), err)
	}
}

// softAuthenticator is a minimal ES256 authenticator: enough of the WebAuthn
// response format to exercise the real library and the handlers end to end.
type softAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	handle []byte
	origin string
	rpID   string
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softAuthenticator{key: key, credID: id, origin: testOrigin, rpID: testRPID}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (a *softAuthenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	raw, err := cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: pad32(a.key.PublicKey.X.Bytes()),
		-3: pad32(a.key.PublicKey.Y.Bytes()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (a *softAuthenticator) clientData(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (a *softAuthenticator) rpIDHash() []byte {
	sum := sha256.Sum256([]byte(a.rpID))
	return sum[:]
}

// registrationResponse builds the JSON body PublicKeyCredential.toJSON() would
// produce, using the "none" attestation format.
func (a *softAuthenticator) registrationResponse(t *testing.T, challenge string, handle []byte) map[string]any {
	t.Helper()
	authData := append([]byte{}, a.rpIDHash()...)
	authData = append(authData, 0x45)                // UP | UV | AT
	authData = append(authData, 0, 0, 0, 0)          // signature counter
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = append(authData, byte(len(a.credID)>>8), byte(len(a.credID)))
	authData = append(authData, a.credID...)
	authData = append(authData, a.coseKey(t)...)

	att, err := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientData := a.clientData(t, "webauthn.create", challenge)
	return map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(att),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{},
	}
}

func (a *softAuthenticator) assertionResponse(t *testing.T, challenge string, counter uint32) map[string]any {
	t.Helper()
	authData := append([]byte{}, a.rpIDHash()...)
	authData = append(authData, 0x05) // UP | UV
	authData = append(authData, byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter))

	clientData := a.clientData(t, "webauthn.get", challenge)
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(a.handle),
		},
		"clientExtensionResults": map[string]any{},
	}
}

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
}

func TestPasskeyRegisterAndLogin(t *testing.T) {
	s, _ := newPasskeyServer(t)
	session := sessionCookie(s, "alice@example.com")

	// Register.
	w := postJSON(s, "/passkeys/register/begin", nil, session)
	if w.Code != http.StatusOK {
		t.Fatalf("register begin: %d %s", w.Code, w.Body)
	}
	var begin creationOptions
	decode(t, w, &begin)
	if begin.PublicKey.Challenge == "" || begin.PublicKey.User.ID == "" {
		t.Fatalf("incomplete creation options: %s", w.Body)
	}
	handle, err := base64.RawURLEncoding.DecodeString(begin.PublicKey.User.ID)
	if err != nil || len(handle) == 0 {
		t.Fatalf("bad user handle %q: %v", begin.PublicKey.User.ID, err)
	}
	ceremony := cookieByName(w, s.ceremonyCookieName())
	if ceremony == nil {
		t.Fatal("no ceremony cookie")
	}

	auth := newSoftAuthenticator(t)
	auth.handle = handle
	w = postJSON(s, "/passkeys/register/finish?name=Laptop", auth.registrationResponse(t, begin.PublicKey.Challenge, handle), session, ceremony)
	if w.Code != http.StatusOK {
		t.Fatalf("register finish: %d %s", w.Code, w.Body)
	}
	var ok struct {
		OK bool `json:"ok"`
	}
	decode(t, w, &ok)
	if !ok.OK {
		t.Fatalf("register finish not ok: %s", w.Body)
	}

	records, err := s.passkeys.List("alice@example.com")
	if err != nil || len(records) != 1 || records[0].Name != "Laptop" {
		t.Fatalf("stored records = %+v, err %v", records, err)
	}

	// The index lists the credential.
	w = do(s, "GET", "/", nil, session)
	if !strings.Contains(w.Body.String(), "Laptop") || !strings.Contains(w.Body.String(), "passkey") {
		t.Errorf("index does not list the passkey: %s", w.Body)
	}

	// Sign in with it, usernameless.
	w = postJSON(s, "/passkeys/login/begin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login begin: %d %s", w.Code, w.Body)
	}
	var lbegin requestOptions
	decode(t, w, &lbegin)
	loginCeremony := cookieByName(w, s.ceremonyCookieName())
	if loginCeremony == nil {
		t.Fatal("no login ceremony cookie")
	}
	w = postJSON(s, "/passkeys/login/finish?rd="+testOrigin+"/x", auth.assertionResponse(t, lbegin.PublicKey.Challenge, 0), loginCeremony)
	if w.Code != http.StatusOK {
		t.Fatalf("login finish: %d %s", w.Code, w.Body)
	}
	newSession := cookieByName(w, "sesame")
	if newSession == nil {
		t.Fatal("no session cookie after passkey login")
	}

	// That session satisfies forward_auth.
	r := httptest.NewRequest("GET", "/verify", nil)
	r.AddCookie(newSession)
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	vw := httptest.NewRecorder()
	s.ServeHTTP(vw, r)
	if vw.Code != http.StatusOK || vw.Header().Get("Remote-User") != "alice@example.com" {
		t.Fatalf("verify after passkey login: %d %q", vw.Code, vw.Header().Get("Remote-User"))
	}

	// The sign counter and last-use timestamp were written back.
	after, err := s.passkeys.Get(records[0].ID)
	if err != nil || after.LastUsedAt.IsZero() {
		t.Fatalf("credential not updated after login: %+v, %v", after, err)
	}
}

func TestPasskeyRegistrationRejectsBadChallenge(t *testing.T) {
	s, _ := newPasskeyServer(t)
	session := sessionCookie(s, "alice@example.com")
	w := postJSON(s, "/passkeys/register/begin", nil, session)
	var begin creationOptions
	decode(t, w, &begin)
	ceremony := cookieByName(w, s.ceremonyCookieName())

	auth := newSoftAuthenticator(t)
	// Sign over a challenge the server never issued.
	body := auth.registrationResponse(t, "not-the-challenge", []byte("handle"))
	w = postJSON(s, "/passkeys/register/finish", body, session, ceremony)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("forged registration accepted: %d %s", w.Code, w.Body)
	}
	if records, _ := s.passkeys.List("alice@example.com"); len(records) != 0 {
		t.Errorf("forged credential stored: %+v", records)
	}
}

func TestPasskeyLoginRejectsUnknownCredential(t *testing.T) {
	s, _ := newPasskeyServer(t)
	w := postJSON(s, "/passkeys/login/begin", nil)
	var lbegin requestOptions
	decode(t, w, &lbegin)
	ceremony := cookieByName(w, s.ceremonyCookieName())

	auth := newSoftAuthenticator(t)
	auth.handle = []byte("nobody")
	w = postJSON(s, "/passkeys/login/finish", auth.assertionResponse(t, lbegin.PublicKey.Challenge, 0), ceremony)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown credential accepted: %d %s", w.Code, w.Body)
	}
	if cookieByName(w, "sesame") != nil {
		t.Error("session issued for unknown credential")
	}
}

func TestPasskeyRegisterRequiresSession(t *testing.T) {
	s, _ := newPasskeyServer(t)
	for _, target := range []string{"/passkeys/register/begin", "/passkeys/register/finish"} {
		if w := postJSON(s, target, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without session: %d", target, w.Code)
		}
	}
}

func TestPasskeyCrossSiteRejected(t *testing.T) {
	s, _ := newPasskeyServer(t)
	for _, target := range []string{"/passkeys/login/begin", "/passkeys/login/finish"} {
		r := httptest.NewRequest("POST", target, strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s cross-site: %d", target, w.Code)
		}
	}
}

func TestPasskeyFinishWithoutCeremony(t *testing.T) {
	s, _ := newPasskeyServer(t)
	if w := postJSON(s, "/passkeys/login/finish", map[string]any{}); w.Code != http.StatusBadRequest {
		t.Errorf("login finish without ceremony: %d", w.Code)
	}
	if w := postJSON(s, "/passkeys/register/finish", map[string]any{}, sessionCookie(s, "alice@example.com")); w.Code != http.StatusBadRequest {
		t.Errorf("register finish without ceremony: %d", w.Code)
	}
}

func TestPasskeyLoginBeginRateLimited(t *testing.T) {
	s, _ := newPasskeyServer(t)
	now := time.Now()
	s.passkeyBegins.now = func() time.Time { return now }

	for i := 0; i < passkeyBeginLimit; i++ {
		if w := postJSON(s, "/passkeys/login/begin", nil); w.Code != http.StatusOK {
			t.Fatalf("begin %d: %d %s", i, w.Code, w.Body)
		}
	}
	if w := postJSON(s, "/passkeys/login/begin", nil); w.Code != http.StatusTooManyRequests {
		t.Errorf("over limit: %d %s", w.Code, w.Body)
	}

	// Another client is unaffected.
	r := httptest.NewRequest("POST", "/passkeys/login/begin", nil)
	r.Header.Set("Origin", testOrigin)
	r.RemoteAddr = "203.0.113.7:5555"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("second client limited: %d", w.Code)
	}

	// The window rolls over.
	now = now.Add(passkeyBeginWindow + time.Second)
	if w := postJSON(s, "/passkeys/login/begin", nil); w.Code != http.StatusOK {
		t.Errorf("limit did not reset: %d %s", w.Code, w.Body)
	}
}

func TestPasskeyDeleteOwnership(t *testing.T) {
	s, _ := newPasskeyServer(t)

	// A credential belonging to another user must not be deletable.
	other := Passkey{ID: []byte("other-id"), Email: "bob@example.com", CreatedAt: s.now()}
	if err := s.passkeys.Put(other); err != nil {
		t.Fatal(err)
	}
	w := do(s, "POST", "/passkeys/delete", url.Values{"id": {b64(other.ID)}}, sessionCookie(s, "alice@example.com"))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if _, err := s.passkeys.Get(other.ID); err != nil {
		t.Error("another user's passkey was deleted")
	}
}

func TestPasskeyStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenPasskeyStore(filepath.Join(dir, "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	h1, err := store.UserHandle("alice@example.com")
	if err != nil || len(h1) != 32 {
		t.Fatalf("handle = %x, %v", h1, err)
	}
	h2, _ := store.UserHandle("alice@example.com")
	if !bytes.Equal(h1, h2) {
		t.Error("user handle is not stable")
	}
	if h3, _ := store.UserHandle("bob@example.com"); bytes.Equal(h1, h3) {
		t.Error("distinct users share a handle")
	}

	p := Passkey{ID: []byte("id-1"), Email: "alice@example.com", Name: "Key", CreatedAt: time.Now()}
	if err := store.Put(p); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(p.ID)
	if err != nil || got.Name != "Key" {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if list, _ := store.List("alice@example.com"); len(list) != 1 {
		t.Errorf("List = %+v", list)
	}
	if list, _ := store.List("bob@example.com"); len(list) != 0 {
		t.Errorf("List for other user = %+v", list)
	}

	// Deleting as the wrong owner is a no-op.
	if err := store.Delete("bob@example.com", p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(p.ID); err != nil {
		t.Error("credential deleted by a non-owner")
	}
	if err := store.Delete("alice@example.com", p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(p.ID); err == nil {
		t.Error("credential not deleted by owner")
	}
	if _, err := store.Get([]byte("missing")); err == nil {
		t.Error("missing credential returned no error")
	}
}

func TestPasskeyConfigValidation(t *testing.T) {
	base := func() *Config {
		return &Config{
			ExternalURL: testOrigin, Secret: strings.Repeat("k", 32),
			Session: SessionConfig{CookieDomain: testRPID},
			SMTP:    SMTPConfig{Host: "h", From: "a@example.com"},
			Users:   []User{{Email: "a@example.com"}},
			Access:  []AccessRule{{Domain: "app.example.com", Subject: []string{"*"}}},
		}
	}
	c := base()
	c.Passkey = PasskeyConfig{Store: "/tmp/p.db"}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if !c.PasskeysEnabled() {
		t.Error("store set but passkeys disabled")
	}
	if c.Passkey.RPID != testRPID || c.Passkey.RPName == "" {
		t.Errorf("defaults not applied: %+v", c.Passkey)
	}
	if c := base(); c.validate() != nil || c.PasskeysEnabled() {
		t.Error("absent store should disable passkeys without error")
	}
	for name, mut := range map[string]func(*Config){
		"unrelated":     func(c *Config) { c.Passkey = PasskeyConfig{Store: "/tmp/p.db", RPID: "evil.test"} },
		"public suffix": func(c *Config) { c.Passkey = PasskeyConfig{Store: "/tmp/p.db", RPID: "com"} },
		"ip address":    func(c *Config) { c.Passkey = PasskeyConfig{Store: "/tmp/p.db", RPID: "127.0.0.1"} },
	} {
		c := base()
		mut(c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The portal's own host is a valid RP ID even with a leading-dot override.
	c = base()
	c.Passkey = PasskeyConfig{Store: "/tmp/p.db", RPID: "auth.example.com"}
	if err := c.validate(); err != nil {
		t.Errorf("portal host as rp_id rejected: %v", err)
	}
}

func TestPasskeyDisabledRoutes(t *testing.T) {
	s, _ := newTestServer(t) // no passkey store
	if w := postJSON(s, "/passkeys/login/begin", nil); w.Code != http.StatusNotFound {
		t.Errorf("login begin with passkeys off: %d", w.Code)
	}
	if w := do(s, "GET", "/passkeys.js", nil); w.Code != http.StatusNotFound {
		t.Errorf("script with passkeys off: %d", w.Code)
	}
	if w := do(s, "GET", "/login", nil); strings.Contains(w.Body.String(), "passkey-login") {
		t.Error("passkey button rendered with passkeys off")
	}
}

func TestPasskeyScriptServed(t *testing.T) {
	s, _ := newPasskeyServer(t)
	w := do(s, "GET", "/passkeys.js", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("script: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("content type %q", ct)
	}
	if !strings.Contains(w.Body.String(), "PublicKeyCredential") {
		t.Error("script body looks wrong")
	}
}

func TestIndexPasskeySection(t *testing.T) {
	s, _ := newPasskeyServer(t)
	session := sessionCookie(s, "alice@example.com")
	w := do(s, "GET", "/", nil, session)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "passkey-add") || !strings.Contains(body, "You have no passkeys yet") {
		t.Errorf("index passkey section: %d %s", w.Code, body)
	}
	// Account and passkeys are two separate groups, and sign-out belongs to
	// the account group rather than trailing the passkey controls.
	if strings.Count(body, `class="group"`) != 2 {
		t.Errorf("expected account and passkey groups: %s", body)
	}
	if strings.Index(body, `action="/logout"`) > strings.Index(body, "Passkeys") {
		t.Error("sign out rendered outside the account group")
	}
	if !strings.Contains(do(s, "GET", "/?passkeys=added", nil, session).Body.String(), "Passkey added") {
		t.Error("added notice missing")
	}
	if !strings.Contains(do(s, "GET", "/?passkeys=removed", nil, session).Body.String(), "Passkey removed") {
		t.Error("removed notice missing")
	}
	// Signed out: no management UI, but the script may still be referenced.
	if strings.Contains(do(s, "GET", "/", nil).Body.String(), "passkey-add") {
		t.Error("passkey management shown while signed out")
	}
}

func TestLoginPasskeyButton(t *testing.T) {
	s, _ := newPasskeyServer(t)
	w := do(s, "GET", "/login?rd="+testOrigin+"/x", nil)
	body := w.Body.String()
	if !strings.Contains(body, `id="passkey-login"`) || !strings.Contains(body, testOrigin+"/x") {
		t.Errorf("login passkey button: %s", body)
	}
	if !strings.Contains(body, `src="/passkeys.js"`) {
		t.Error("page script not included")
	}
}

func TestCeremonyStoreSweepAndExpiry(t *testing.T) {
	now := time.Now()
	c := newCeremonyStore(time.Minute)
	c.now = func() time.Time { return now }
	id, err := c.put(webauthn.SessionData{Challenge: "challenge"}, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.take(id); !ok {
		t.Fatal("fresh ceremony not found")
	}
	// take consumes it.
	if _, ok := c.take(id); ok {
		t.Error("ceremony replayed")
	}

	id, _ = c.put(webauthn.SessionData{Challenge: "challenge"}, "alice@example.com")
	now = now.Add(2 * time.Minute)
	c.sweep()
	if _, ok := c.take(id); ok {
		t.Error("expired ceremony accepted")
	}
	if len(c.m) != 0 {
		t.Errorf("sweep left %d ceremonies", len(c.m))
	}
}

func TestDeleteHandlerRemovesOwnCredential(t *testing.T) {
	s, _ := newPasskeyServer(t)
	p := Passkey{ID: []byte("own-id"), Email: "alice@example.com", CreatedAt: s.now()}
	if err := s.passkeys.Put(p); err != nil {
		t.Fatal(err)
	}
	w := do(s, "POST", "/passkeys/delete", url.Values{"id": {b64(p.ID)}}, sessionCookie(s, "alice@example.com"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/?passkeys=removed" {
		t.Fatalf("delete: %d %q", w.Code, w.Header().Get("Location"))
	}
	if _, err := s.passkeys.Get(p.ID); err == nil {
		t.Error("credential not deleted")
	}
	// Cross-site delete is refused.
	r := httptest.NewRequest("POST", "/passkeys/delete", strings.NewReader("id="+b64(p.ID)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.AddCookie(sessionCookie(s, "alice@example.com"))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site delete: %d", rec.Code)
	}
}
