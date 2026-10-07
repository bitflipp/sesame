package main

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
)

var ErrRateLimited = errors.New("too many token requests")

type otpEntry struct {
	code     string
	expires  time.Time
	attempts int
}

// OTPStore keeps pending one-time tokens and issue-rate counters in memory.
type OTPStore struct {
	mu          sync.Mutex
	entries     map[string]*otpEntry
	issued      map[string][]time.Time
	length      int
	ttl         time.Duration
	maxAttempts int
	perHour     int
	now         func() time.Time
}

func NewOTPStore(t TokenConfig) *OTPStore {
	return &OTPStore{
		entries:     map[string]*otpEntry{},
		issued:      map[string][]time.Time{},
		length:      t.Length,
		ttl:         t.TTL,
		maxAttempts: t.MaxAttempts,
		perHour:     t.RateLimitPerHour,
		now:         time.Now,
	}
}

// Issue creates a fresh token for email, replacing any pending one. Both the
// email and the client IP are rate limited. Neither counter is charged unless
// both are under the limit, so a request rejected by one bucket cannot consume
// quota from the other.
func (s *OTPStore) Issue(email, ip string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	cutoff := now.Add(-time.Hour)
	emailKey, ipKey := "e:"+email, "i:"+ip
	recentEmail := pruneBefore(s.issued[emailKey], cutoff)
	recentIP := pruneBefore(s.issued[ipKey], cutoff)
	if len(recentEmail) >= s.perHour || len(recentIP) >= s.perHour {
		if len(recentEmail) > 0 {
			s.issued[emailKey] = recentEmail
		}
		if len(recentIP) > 0 {
			s.issued[ipKey] = recentIP
		}
		return "", ErrRateLimited
	}
	s.issued[emailKey] = append(recentEmail, now)
	s.issued[ipKey] = append(recentIP, now)
	code, err := randomDigits(s.length)
	if err != nil {
		return "", err
	}
	s.entries[email] = &otpEntry{code: code, expires: now.Add(s.ttl)}
	return code, nil
}

// Verify checks a submitted token. A token is single use and is invalidated
// after too many wrong guesses.
func (s *OTPStore) Verify(email, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[email]
	if !ok {
		return false
	}
	if s.now().After(e.expires) {
		delete(s.entries, email)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(e.code), []byte(code)) == 1 {
		delete(s.entries, email)
		return true
	}
	if e.attempts++; e.attempts >= s.maxAttempts {
		delete(s.entries, email)
	}
	return false
}

// Sweep drops expired entries and stale rate-limit counters.
func (s *OTPStore) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.entries {
		if now.After(e.expires) {
			delete(s.entries, k)
		}
	}
	for k, v := range s.issued {
		if v = pruneBefore(v, now.Add(-time.Hour)); len(v) == 0 {
			delete(s.issued, k)
		} else {
			s.issued[k] = v
		}
	}
}

func pruneBefore(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}

func randomDigits(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		// 250 is the largest multiple of 10 below 256; reject the rest to avoid modulo bias.
		for b[i] >= 250 {
			var r [1]byte
			if _, err := rand.Read(r[:]); err != nil {
				return "", err
			}
			b[i] = r[0]
		}
		b[i] = '0' + b[i]%10
	}
	return string(b), nil
}
