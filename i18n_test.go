package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCatalogParity(t *testing.T) {
	for lang, m := range catalogs {
		for k := range catalogs[fallbackLang] {
			if m[k] == "" {
				t.Errorf("%s: missing key %q", lang, k)
			}
		}
		for k := range m {
			if _, ok := catalogs[fallbackLang][k]; !ok {
				t.Errorf("%s: extra key %q", lang, k)
			}
		}
	}
}

func TestMatchLanguage(t *testing.T) {
	for header, want := range map[string]string{
		"":                     "",
		"de":                   "de",
		"de-AT,en;q=0.5":       "de",
		"en;q=0.4, de;q=0.9":   "de",
		"fr, en;q=0.8":         "en",
		"fr, es":               "",
		"de;q=0, en":           "en",
		"de;q=bogus, en;q=0.1": "en",
		"DE-ch":                "de",
	} {
		if got := matchLanguage(header); got != want {
			t.Errorf("%q: got %q want %q", header, got, want)
		}
	}
}

func TestLanguageSelection(t *testing.T) {
	s, _ := newTestServer(t)
	get := func(path string, hdr map[string]string, ck *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		if ck != nil {
			r.AddCookie(ck)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := get("/login", nil, nil); !strings.Contains(w.Body.String(), "Send code") || !strings.Contains(w.Body.String(), `lang="en"`) {
		t.Errorf("default: %s", w.Body)
	}
	w := get("/login", map[string]string{"Accept-Language": "de-DE,de;q=0.9"}, nil)
	if !strings.Contains(w.Body.String(), "Code senden") || !strings.Contains(w.Body.String(), `<html lang="de">`) {
		t.Errorf("header: %s", w.Body)
	}
	// cookie beats header
	w = get("/login", map[string]string{"Accept-Language": "de"}, &http.Cookie{Name: langCookie, Value: "en"})
	if !strings.Contains(w.Body.String(), "Send code") {
		t.Errorf("cookie: %s", w.Body)
	}
	// error pages are localized too, including 404s from the mux
	if w := get("/nope", map[string]string{"Accept-Language": "de"}, nil); w.Code != 404 || !strings.Contains(w.Body.String(), "Seite nicht gefunden") {
		t.Errorf("404: %d %s", w.Code, w.Body)
	}
}

func TestLangSwitcher(t *testing.T) {
	s, _ := newTestServer(t)
	for rd, want := range map[string]string{
		"/login?rd=x":        "/login?rd=x",
		"//evil.test":        "/",
		`/\evil.test`:        "/",
		"https://evil.test/": "/",
		"":                   "/",
	} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", "/lang?set=de&rd="+url.QueryEscape(rd), nil))
		if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || loc != want {
			t.Errorf("rd %q: %d %q want %q", rd, w.Code, loc, want)
		}
		if !strings.Contains(w.Header().Get("Set-Cookie"), langCookie+"=de") {
			t.Errorf("rd %q: cookie not set: %v", rd, w.Header())
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/lang?set=xx", nil))
	if w.Header().Get("Set-Cookie") != "" {
		t.Error("unsupported language must not set a cookie")
	}
}

func TestGermanMail(t *testing.T) {
	b, err := buildMessage("a@example.com", "b@corp.test", "123", 10*time.Minute, "de", time.Now())
	if err != nil || !strings.Contains(string(b), "Subject: Dein Anmeldecode: 123") || !strings.Contains(string(b), "10 Minuten") {
		t.Errorf("%v\n%s", err, b)
	}
	b, _ = buildMessage("a@example.com", "b@corp.test", "123", time.Minute, "xx", time.Now())
	if !strings.Contains(string(b), "Subject: Your sign-in code") {
		t.Errorf("fallback: %s", b)
	}
}
