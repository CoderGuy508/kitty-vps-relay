package main

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testRelay(t *testing.T) (*relayService, string) {
	t.Helper()
	service := &relayService{
		config: config{
			staticAccessKey:       "test-only-local-relay-access-key-123456",
			defaultMaxTunnels:     65,
			allowedTargetSuffixes: []string{"moomoo.io"},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		active: make(map[string]int), consumedTickets: make(map[string]time.Time),
	}
	service.upgrader.CheckOrigin = func(r *http.Request) bool { return service.originAllowed(r.Header.Get("Origin")) }
	server := httptest.NewServer(http.HandlerFunc(service.handleRelay))
	t.Cleanup(server.Close)
	return service, "ws" + strings.TrimPrefix(server.URL, "http") + "/relay?key=" + service.config.staticAccessKey
}

func TestBrowserTokenProtocolAcknowledged(t *testing.T) {
	service, endpoint := testRelay(t)
	protocol := "kitty-bot-token." + base64.RawURLEncoding.EncodeToString([]byte("test-game-token"))
	dialer := websocket.Dialer{Subprotocols: []string{protocol}, HandshakeTimeout: time.Second}
	conn, response, err := dialer.Dial(endpoint, http.Header{"Origin": []string{"https://sandbox.moomoo.io"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Gorilla accepts an empty negotiated protocol; browsers explicitly reject
	// it. Assert the browser requirement, not merely a successful Go Dial.
	if conn.Subprotocol() != protocol || response.Header.Get("Sec-WebSocket-Protocol") != protocol {
		t.Fatal("browser handshake did not acknowledge the requested protocol")
	}
	if len(service.upgrader.Subprotocols) != 0 {
		t.Fatal("shared upgrader was mutated")
	}
}

func TestConcurrentProtocolsRemainIsolated(t *testing.T) {
	service, endpoint := testRelay(t)
	var group sync.WaitGroup
	for _, token := range []string{"test-a", "test-b", "test-c", "test-d"} {
		group.Add(1)
		go func(token string) {
			defer group.Done()
			protocol := "kitty-bot-token." + base64.RawURLEncoding.EncodeToString([]byte(token))
			dialer := websocket.Dialer{Subprotocols: []string{protocol}, HandshakeTimeout: time.Second}
			conn, _, err := dialer.Dial(endpoint, http.Header{"Origin": []string{"https://sandbox.moomoo.io"}})
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			if conn.Subprotocol() != protocol {
				t.Error("another tunnel's protocol was selected")
			}
		}(token)
	}
	group.Wait()
	if len(service.upgrader.Subprotocols) != 0 {
		t.Fatal("shared upgrader was mutated")
	}
}

func TestInvalidAuthAndOriginRemainRejected(t *testing.T) {
	_, endpoint := testRelay(t)
	valid := "kitty-bot-token." + base64.RawURLEncoding.EncodeToString([]byte("test-token"))
	for _, tc := range []struct {
		name, url, origin string
		protocols         []string
		status            int
	}{
		{"missing token", endpoint, "https://sandbox.moomoo.io", nil, 401},
		{"duplicate token", endpoint, "https://sandbox.moomoo.io", []string{valid, valid}, 401},
		{"invalid token", endpoint, "https://sandbox.moomoo.io", []string{"kitty-bot-token.%%%"}, 401},
		{"wrong credential", strings.Replace(endpoint, "test-only-local-relay-access-key-123456", "invalid", 1), "https://sandbox.moomoo.io", []string{valid}, 401},
		{"wrong origin", endpoint, "https://example.com", []string{valid}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer := websocket.Dialer{Subprotocols: tc.protocols, HandshakeTimeout: time.Second}
			conn, response, err := dialer.Dial(tc.url, http.Header{"Origin": []string{tc.origin}})
			if conn != nil {
				conn.Close()
			}
			if response != nil && response.Body != nil {
				defer response.Body.Close()
			}
			if err == nil || response == nil || response.StatusCode != tc.status {
				t.Fatalf("expected rejection %d", tc.status)
			}
		})
	}
}
