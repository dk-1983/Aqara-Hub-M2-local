package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	return &App{dir: t.TempDir(), auth: sha256.Sum256([]byte("panel-secret")), cfg: Config{Host: "localhost", Port: 1883, Prefix: "aqara/test", ClientID: "test", Password: "mqtt-secret", Username: "bridge"}}
}
func req(a *App, method, path, body string, auth, csrf bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	if auth {
		r.SetBasicAuth("admin", "panel-secret")
	}
	if csrf {
		r.Header.Set("X-Aqara-Panel", "1")
	}
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	return w
}
func TestAuthAndRedaction(t *testing.T) {
	a := testApp(t)
	if w := req(a, "GET", "/api/status", "", false, false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := req(a, "GET", "/api/status", "", true, false)
	if w.Code != 200 || strings.Contains(w.Body.String(), "mqtt-secret") || !strings.Contains(w.Body.String(), "password_saved") {
		t.Fatal(w.Body.String())
	}
}
func TestConfigPasswordAndCSRF(t *testing.T) {
	a := testApp(t)
	body := `{"host":"localhost","port":1883,"username":"bridge","prefix":"aqara/test","client_id":"test","enabled":false}`
	if w := req(a, "POST", "/api/config", body, true, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := req(a, "POST", "/api/config", body, true, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	b, e := os.ReadFile(filepath.Join(a.dir, "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	var c Config
	json.Unmarshal(b, &c)
	if c.Password != "mqtt-secret" {
		t.Fatal("password lost")
	}
	body = strings.TrimSuffix(body, "}") + `,"clear_password":true}`
	if w := req(a, "POST", "/api/config", body, true, true); w.Code != 200 {
		t.Fatal(w.Code)
	}
	a.mu.Lock()
	p := a.cfg.Password
	a.mu.Unlock()
	if p != "" {
		t.Fatal("password not cleared")
	}
}
func TestInvalidConfigNoMutation(t *testing.T) {
	a := testApp(t)
	w := req(a, "POST", "/api/config", `{"host":"x","port":99999,"prefix":"#","client_id":"test"}`, true, true)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	if _, e := os.Stat(filepath.Join(a.dir, "config.json")); !os.IsNotExist(e) {
		t.Fatal("invalid settings persisted")
	}
}
func TestCrossOriginRejected(t *testing.T) {
	a := testApp(t)
	r := httptest.NewRequest("POST", "https://localhost/api/config", strings.NewReader("{}"))
	r.SetBasicAuth("admin", "panel-secret")
	r.Header.Set("X-Aqara-Panel", "1")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func frame(c net.Conn) (byte, []byte, error) {
	var b [1]byte
	if _, e := io.ReadFull(c, b[:]); e != nil {
		return 0, nil, e
	}
	h := b[0]
	n, m := 0, 1
	for i := 0; i < 4; i++ {
		if _, e := io.ReadFull(c, b[:]); e != nil {
			return 0, nil, e
		}
		n += int(b[0]&127) * m
		if b[0]&128 == 0 {
			v := make([]byte, n)
			_, e := io.ReadFull(c, v)
			return h, v, e
		}
		m *= 128
	}
	return 0, nil, fmt.Errorf("invalid frame")
}
func TestMQTTConnectionTest(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		h, b, e := frame(c)
		if e != nil || h != 16 || !strings.Contains(string(b), "mqtt-secret") {
			done <- fmt.Errorf("bad connect")
			return
		}
		_, e = c.Write([]byte{32, 2, 0, 0})
		done <- e
		frame(c)
	}()
	a := testApp(t)
	a.cfg.Port = listener.Addr().(*net.TCPAddr).Port
	body := fmt.Sprintf(`{"host":"127.0.0.1","port":%d,"username":"bridge","prefix":"aqara/test","client_id":"test"}`, a.cfg.Port)
	w := req(a, http.MethodPost, "/api/test", body, true, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestRootPasswordExplicitAccess(t *testing.T) {
	a := testApp(t)
	os.WriteFile(filepath.Join(a.dir, "root-password.txt"), []byte("root-test-secret"), 0600)
	for _, path := range []string{"/api/status", "/api/about", "/"} {
		w := req(a, "GET", path, "", true, false)
		if strings.Contains(w.Body.String(), "root-test-secret") {
			t.Fatal("Root secret leaked")
		}
	}
	if w := req(a, "GET", "/api/root-password", "", true, false); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := req(a, "POST", "/api/root-password", "{}", false, true); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := req(a, "POST", "/api/root-password", "{}", true, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := req(a, "POST", "/api/root-password", "{}", true, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "root-test-secret") {
		t.Fatal("Explicit reveal failed")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("Root password cacheable")
	}
}

func TestPanelPasswordChangePersists(t *testing.T) {
	a := testApp(t)
	w := req(a, "POST", "/api/password", `{"current":"panel-secret","new":"new-panel-password-123","repeat":"new-panel-password-123"}`, true, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if a.passwordOK("panel-secret") || !a.passwordOK("new-panel-password-123") {
		t.Fatal("password transition failed")
	}
	fresh := &App{dir: a.dir}
	if e := fresh.loadAuth(); e != nil {
		t.Fatal(e)
	}
	if !fresh.passwordOK("new-panel-password-123") || fresh.passwordOK("panel-secret") {
		t.Fatal("password reload failed")
	}
	b, _ := os.ReadFile(filepath.Join(a.dir, "auth.sha256"))
	if strings.Contains(string(b), "new-panel-password-123") {
		t.Fatal("plaintext password on disk")
	}
}
func TestRootCopyUpdateOnly(t *testing.T) {
	a := testApp(t)
	w := req(a, "POST", "/api/root-password-copy", `{"Password":"copied-value","Repeat":"copied-value"}`, true, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	b, e := os.ReadFile(filepath.Join(a.dir, "root-password.txt"))
	if e != nil || string(b) != "copied-value" {
		t.Fatal("copy save failed")
	}
	if !a.passwordOK("panel-secret") {
		t.Fatal("panel password unexpectedly changed")
	}
}
func TestNetworkValidation(t *testing.T) {
	good := NetworkConfig{Mode: "static", IP: "10.0.0.66", Mask: "255.255.240.0", Gateway: "10.0.0.3", DNS: []string{"10.0.0.3"}}
	if e := validateNetwork(good); e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"10.0.0.0", "10.0.15.255", "127.0.0.1", "bad;reboot"} {
		v := good
		v.IP = ip
		if validateNetwork(v) == nil {
			t.Fatal("accepted", ip)
		}
	}
	v := good
	v.Gateway = "192.168.1.1"
	if validateNetwork(v) == nil {
		t.Fatal("outside gateway accepted")
	}
	v = good
	v.Mask = "255.0.255.0"
	if validateNetwork(v) == nil {
		t.Fatal("noncontiguous mask accepted")
	}
	a := testApp(t)
	w := req(a, "POST", "/api/network/apply", `{"mode":"static","ip":"bad"}`, true, true)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
func TestBridgeForwardsActualMQTT(t *testing.T) {
	local, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer local.Close()
	remote, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer remote.Close()
	original := localBrokerURL
	localBrokerURL = "tcp://" + local.Addr().String()
	defer func() { localBrokerURL = original }()
	received := make(chan string, 1)
	serve := func(ln net.Listener, source bool) {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(8 * time.Second))
		if _, _, e = frame(c); e != nil {
			return
		}
		c.Write([]byte{32, 2, 0, 0})
		for {
			h, b, e := frame(c)
			if e != nil {
				return
			}
			switch h >> 4 {
			case 8:
				c.Write([]byte{144, 3, b[0], b[1], 0})
				if source {
					topic := "zigbee/send"
					payload := `{"cmd":"report","params":[{"res_name":"0.3.85","value":40}]}`
					data := append([]byte{0, byte(len(topic))}, []byte(topic)...)
					data = append(data, []byte(payload)...)
					c.Write(append([]byte{48, byte(len(data))}, data...))
				}
			case 3:
				n := int(b[0])<<8 | int(b[1])
				topic := string(b[2 : 2+n])
				offset := 2 + n
				if (h>>1)&3 == 1 {
					c.Write([]byte{64, 2, b[offset], b[offset+1]})
					offset += 2
				}
				select {
				case received <- topic + " " + string(b[offset:]):
				default:
				}
			case 12:
				c.Write([]byte{208, 0})
			case 14:
				return
			}
		}
	}
	go serve(local, true)
	go serve(remote, false)
	a := testApp(t)
	a.cfg.Host = "127.0.0.1"
	a.cfg.Port = remote.Addr().(*net.TCPAddr).Port
	a.cfg.Enabled = true
	a.runBridge()
	defer func() { a.mu.Lock(); a.cfg.Enabled = false; a.mu.Unlock(); a.runBridge() }()
	select {
	case got := <-received:
		if !strings.HasPrefix(got, "aqara/test/zigbee/send ") || !strings.Contains(got, `"value":40`) {
			t.Fatal(got)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("no forwarded MQTT packet")
	}
}
func TestHTTPAndProxyOrigin(t *testing.T) {
	a := testApp(t)
	for _, tc := range []struct {
		origin string
		want   int
	}{{"http://hub.local", 400}, {"https://hub.local", 400}, {"https://evil.example", 403}, {"http://hub.local.evil", 403}, {"null", 403}} {
		r := httptest.NewRequest("POST", "http://hub.local/api/devices/parameter", strings.NewReader("not-json"))
		r.SetBasicAuth("admin", "panel-secret")
		r.Header.Set("X-Aqara-Panel", "1")
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.origin, w.Code, tc.want)
		}
	}
}
