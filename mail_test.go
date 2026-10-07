package main

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildMessage(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	b, err := buildMessage("Sesame <a@example.com>", "bob@corp.test", "12345678", 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(b)
	for _, want := range []string{
		"From: Sesame <a@example.com>\r\n",
		"To: bob@corp.test\r\n",
		"Subject: Your sign-in code: 12345678\r\n",
		"Date: Fri, 02 Jan 2026 03:04:05 +0000\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n\r\nYour one-time sign-in code is:\r\n\r\n    12345678\r\n\r\n",
		"It expires in 10 minutes.",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%q", want, msg)
		}
	}
	if strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n") {
		t.Error("bare LF in message")
	}
	if !strings.HasSuffix(msg, "ignore this message.\r\n") {
		t.Errorf("unexpected ending: %q", msg[len(msg)-30:])
	}
}

// fakeSMTP accepts one plain SMTP session and returns the DATA payload.
func fakeSMTP(t *testing.T) (port int, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { c.Write([]byte(s + "\r\n")) }
		say("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					got <- data.String()
					say("250 queued")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				say("250 ok")
			case cmd == "DATA":
				inData = true
				say("354 go")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("500 unknown")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

func TestSMTPSenderSendToken(t *testing.T) {
	port, got := fakeSMTP(t)
	s := &SMTPSender{cfg: SMTPConfig{Host: "127.0.0.1", Port: port, TLS: "none", From: "Sesame <a@example.com>"}}
	if err := s.SendToken("bob@corp.test", "87654321", 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if !strings.Contains(m, "To: bob@corp.test") || !strings.Contains(m, "87654321") || !strings.Contains(m, "5 minutes") {
			t.Errorf("bad message: %q", m)
		}
	case <-time.After(time.Second):
		t.Fatal("no message received")
	}
}

func TestSMTPSenderErrors(t *testing.T) {
	bad := &SMTPSender{cfg: SMTPConfig{Host: "127.0.0.1", Port: 1, TLS: "none", From: "not an address"}}
	if bad.SendToken("a@b.test", "1", time.Minute) == nil {
		t.Error("expected error for bad From")
	}
	// Port 1 on loopback is closed: dial must fail.
	down := &SMTPSender{cfg: SMTPConfig{Host: "127.0.0.1", Port: 1, TLS: "none", From: "a@example.com"}}
	if down.SendToken("a@b.test", "1", time.Minute) == nil {
		t.Error("expected dial error")
	}
}
