package main

import (
	"crypto/tls"
	_ "embed"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type Sender interface {
	SendToken(to, code string, ttl time.Duration) error
}

//go:embed templates/mail.txt
var mailTemplateText string

var mailTemplate = template.Must(template.New("mail").Parse(mailTemplateText))

// buildMessage renders the sign-in email (headers and body) with CRLF line endings.
func buildMessage(from, to, code string, ttl time.Duration, now time.Time) ([]byte, error) {
	data := struct {
		Code    string
		Minutes int
	}{code, int(ttl.Minutes())}
	var subject, body strings.Builder
	if err := mailTemplate.ExecuteTemplate(&subject, "subject", data); err != nil {
		return nil, err
	}
	if err := mailTemplate.ExecuteTemplate(&body, "body", data); err != nil {
		return nil, err
	}
	head := []string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject.String(),
		"Date: " + now.Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"",
	}
	text := strings.ReplaceAll(body.String(), "\r\n", "\n")
	return []byte(strings.Join(head, "\r\n") + strings.ReplaceAll(text, "\n", "\r\n")), nil
}

type SMTPSender struct {
	cfg SMTPConfig
}

func (s *SMTPSender) SendToken(to, code string, ttl time.Duration) error {
	from, err := mail.ParseAddress(s.cfg.From)
	if err != nil {
		return err
	}
	msg, err := buildMessage(s.cfg.From, to, code, ttl, time.Now())
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	tlsCfg := &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}
	d := net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	if s.cfg.TLS == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if s.cfg.TLS == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if s.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
