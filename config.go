package main

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Listen          string   `toml:"listen"`
	ExternalURL     string   `toml:"external_url"`
	Secret          string   `toml:"secret"`
	SecretFile      string   `toml:"secret_file"`
	TrustedProxies  []string `toml:"trusted_proxies"`
	DefaultLanguage string   `toml:"default_language"`

	Session SessionConfig `toml:"session"`
	Token   TokenConfig   `toml:"token"`
	SMTP    SMTPConfig    `toml:"smtp"`
	Access  []AccessRule  `toml:"access"`
	Users   []User        `toml:"users"`

	// derived by validate
	external     *url.URL
	trusted      []netip.Prefix
	secretBytes  []byte
	users        map[string]User
	secureCookie bool
}

type SessionConfig struct {
	CookieName   string        `toml:"cookie_name"`
	CookieDomain string        `toml:"cookie_domain"`
	Lifetime     time.Duration `toml:"lifetime"`
}

type TokenConfig struct {
	Length           int           `toml:"length"`
	TTL              time.Duration `toml:"ttl"`
	MaxAttempts      int           `toml:"max_attempts"`
	RateLimitPerHour int           `toml:"rate_limit_per_hour"`
}

type SMTPConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	TLS      string `toml:"tls"` // starttls | tls | none
	Username string `toml:"username"`
	Password string `toml:"password"`
	From     string `toml:"from"`
}

// AccessRule grants the listed subjects access to a protected host. Domain is
// an exact host or a "*.example.com" wildcard. Subjects are "user:<email>",
// "group:<name>" or "*" (any signed-in user). Hosts matched by no rule are denied.
type AccessRule struct {
	Domain  string   `toml:"domain"`
	Subject []string `toml:"subject"`
}

type User struct {
	Email  string   `toml:"email"`
	Name   string   `toml:"name"`
	Groups []string `toml:"groups"`
}

func LoadConfig(path string) (*Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, err
	}
	if u := md.Undecoded(); len(u) > 0 {
		return nil, fmt.Errorf("unknown config keys: %v", u)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9091"
	}
	u, err := url.Parse(c.ExternalURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("external_url must be an absolute http(s) URL")
	}
	c.external = u
	c.secureCookie = u.Scheme == "https"

	secret := c.Secret
	if c.SecretFile != "" {
		if secret != "" {
			return errors.New("set only one of secret and secret_file")
		}
		b, err := os.ReadFile(c.SecretFile)
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(b))
	}
	if len(secret) < 32 {
		return errors.New("secret must be at least 32 bytes")
	}
	c.secretBytes = []byte(secret)

	if c.DefaultLanguage == "" {
		c.DefaultLanguage = fallbackLang
	}
	if _, ok := catalogs[c.DefaultLanguage]; !ok {
		return fmt.Errorf("default_language: unsupported language %q", c.DefaultLanguage)
	}

	if len(c.TrustedProxies) == 0 {
		c.TrustedProxies = []string{"127.0.0.0/8", "::1/128"}
	}
	for _, p := range c.TrustedProxies {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			addr, aerr := netip.ParseAddr(p)
			if aerr != nil {
				return fmt.Errorf("trusted_proxies: %q is not an IP or CIDR", p)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		c.trusted = append(c.trusted, pfx)
	}

	s := &c.Session
	if s.CookieName == "" {
		s.CookieName = "sesame"
	}
	s.CookieDomain = strings.ToLower(strings.TrimPrefix(s.CookieDomain, "."))
	if s.CookieDomain == "" {
		return errors.New("session.cookie_domain is required (the parent domain shared by the portal and your apps)")
	}
	if h := strings.ToLower(c.external.Hostname()); h != s.CookieDomain && !strings.HasSuffix(h, "."+s.CookieDomain) {
		return errors.New("session.cookie_domain must be the host of external_url or a parent of it")
	}
	if s.Lifetime == 0 {
		s.Lifetime = 12 * time.Hour
	}

	t := &c.Token
	if t.Length == 0 {
		t.Length = 8
	}
	if t.Length < 6 || t.Length > 16 {
		return errors.New("token.length must be between 6 and 16")
	}
	if t.TTL == 0 {
		t.TTL = 10 * time.Minute
	}
	if t.MaxAttempts == 0 {
		t.MaxAttempts = 5
	}
	if t.RateLimitPerHour == 0 {
		t.RateLimitPerHour = 5
	}

	m := &c.SMTP
	if m.Host == "" {
		return errors.New("smtp.host is required")
	}
	if m.TLS == "" {
		m.TLS = "starttls"
	}
	switch m.TLS {
	case "starttls", "tls", "none":
	default:
		return errors.New(`smtp.tls must be "starttls", "tls" or "none"`)
	}
	if m.Port == 0 {
		m.Port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[m.TLS]
	}
	if _, err := mail.ParseAddress(m.From); err != nil {
		return fmt.Errorf("smtp.from: %w", err)
	}

	c.users = map[string]User{}
	for i, u := range c.Users {
		e, err := normalizeEmail(u.Email)
		if err != nil {
			return fmt.Errorf("users[%d]: %w", i, err)
		}
		u.Email = e
		c.users[e] = u
	}
	if len(c.users) == 0 {
		return errors.New("configure at least one [[users]] entry")
	}
	if len(c.Access) == 0 {
		return errors.New("configure at least one [[access]] rule (hosts without a rule are denied)")
	}
	for i := range c.Access {
		r := &c.Access[i]
		r.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
		if r.Domain == "" || strings.ContainsAny(r.Domain, "/: ") || (strings.Contains(r.Domain, "*") && !strings.HasPrefix(r.Domain, "*.")) {
			return fmt.Errorf("access[%d]: invalid domain %q", i, r.Domain)
		}
		if len(r.Subject) == 0 {
			return fmt.Errorf("access[%d]: subject must not be empty", i)
		}
		for j, sub := range r.Subject {
			kind, val, _ := strings.Cut(sub, ":")
			switch {
			case sub == "*":
			case kind == "user" && val != "":
				r.Subject[j] = "user:" + strings.ToLower(val)
			case kind == "group" && val != "":
			default:
				return fmt.Errorf(`access[%d]: invalid subject %q (want "user:<email>", "group:<name>" or "*")`, i, sub)
			}
		}
	}
	return nil
}

// Lookup returns the configured user for an email address.
func (c *Config) Lookup(email string) (User, bool) {
	u, ok := c.users[email]
	return u, ok
}

func normalizeEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 || strings.ContainsAny(s, "\r\n") {
		return "", errors.New("invalid email address")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s {
		return "", errors.New("invalid email address")
	}
	return strings.ToLower(s), nil
}

// Authorize reports whether user may access the given host.
func (c *Config) Authorize(u User, host string) bool {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	for _, r := range c.Access {
		if !domainMatches(r.Domain, host) {
			continue
		}
		for _, sub := range r.Subject {
			kind, val, _ := strings.Cut(sub, ":")
			switch {
			case sub == "*":
				return true
			case kind == "user" && val == u.Email:
				return true
			case kind == "group" && slices.Contains(u.Groups, val):
				return true
			}
		}
	}
	return false
}

func domainMatches(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*"); ok {
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}
