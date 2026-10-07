package main

import (
	"embed"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed locales/*.toml
var localeFS embed.FS

const (
	fallbackLang = "en"
	langCookie   = "sesame_lang"
)

// catalogs maps a language code to its flat key -> text table.
var catalogs = loadCatalogs()

func loadCatalogs() map[string]map[string]string {
	files, err := localeFS.ReadDir("locales")
	if err != nil {
		panic(err)
	}
	out := map[string]map[string]string{}
	for _, f := range files {
		var m map[string]string
		b, err := localeFS.ReadFile(path.Join("locales", f.Name()))
		if err != nil {
			panic(err)
		}
		if err := toml.Unmarshal(b, &m); err != nil {
			panic(fmt.Sprintf("%s: %v", f.Name(), err))
		}
		out[strings.TrimSuffix(f.Name(), ".toml")] = m
	}
	if out[fallbackLang] == nil {
		panic("missing fallback locale " + fallbackLang)
	}
	return out
}

// Localizer translates catalog keys for one language.
type Localizer struct{ Lang string }

// T returns the text for key, falling back to English and then to the key.
func (l Localizer) T(key string, args ...any) string {
	s, ok := catalogs[l.Lang][key]
	if !ok {
		if s, ok = catalogs[fallbackLang][key]; !ok {
			return key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// LangOption is an entry of the language switcher.
type LangOption struct {
	Code, Name string
	Current    bool
}

// Options lists the languages for the switcher; empty when only one exists.
func (l Localizer) Options() []LangOption {
	var out []LangOption
	for code, m := range catalogs {
		out = append(out, LangOption{code, m["lang_name"], code == l.Lang})
	}
	if len(out) < 2 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// matchLanguage picks the first supported language from an Accept-Language
// header, honoring q-values and ignoring region subtags ("de-AT" -> "de").
func matchLanguage(header string) string {
	type cand struct {
		lang string
		q    float64
	}
	var cands []cand
	for _, part := range strings.Split(header, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			q = f
		}
		base, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(tag)), "-")
		if _, ok := catalogs[base]; ok && q > 0 {
			cands = append(cands, cand{base, q})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].q > cands[j].q })
	if len(cands) == 0 {
		return ""
	}
	return cands[0].lang
}

// lang resolves the request language: cookie, then Accept-Language, then the
// configured default.
func (s *Server) lang(r *http.Request) string {
	if ck, err := r.Cookie(langCookie); err == nil {
		if _, ok := catalogs[ck.Value]; ok {
			return ck.Value
		}
	}
	if l := matchLanguage(r.Header.Get("Accept-Language")); l != "" {
		return l
	}
	return s.cfg.DefaultLanguage
}

// handleLang stores the chosen language and returns to the page it came from.
func (s *Server) handleLang(w http.ResponseWriter, r *http.Request) {
	if l := r.URL.Query().Get("set"); catalogs[l] != nil {
		s.setCookie(w, langCookie, l, "", "lax", 365*24*3600)
	}
	rd := r.URL.Query().Get("rd")
	if p := safeLocalPath(rd); p != "" {
		http.Redirect(w, r, p, http.StatusSeeOther)
		return
	}
	if rd = s.safeRedirect(rd); rd == "" {
		rd = "/"
	}
	http.Redirect(w, r, rd, http.StatusSeeOther)
}
