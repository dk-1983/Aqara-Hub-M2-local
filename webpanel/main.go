package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

//go:embed index.html devices.html maintenance.html update-worker.sh
var assets embed.FS

type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`
	TLS         bool   `json:"tls"`
	CA          string `json:"ca,omitempty"`
	Prefix      string `json:"prefix"`
	ClientID    string `json:"client_id"`
	Enabled     bool   `json:"enabled"`
	HADiscovery bool   `json:"ha_discovery"`
}
type Update struct {
	Config
	ClearPassword bool `json:"clear_password"`
}
type Status struct {
	Local     bool   `json:"local"`
	Remote    bool   `json:"remote"`
	Message   string `json:"message"`
	Forwarded uint64 `json:"forwarded"`
	LastEvent string `json:"last_event"`
}
type App struct {
	updateMu   sync.Mutex
	authMu     sync.Mutex
	authSalt   []byte
	authRounds int
	authCache  [32]byte
	authCached bool
	netMu      sync.Mutex
	mu         sync.Mutex
	op         sync.Mutex
	cfg        Config
	status     Status
	dir        string
	auth       [32]byte
	local      mqtt.Client
	remote     mqtt.Client
	ha         *haBridge
	devices    *deviceManager
}

func atomicWrite(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e == nil {
		defer d.Close()
		_ = d.Sync()
	}
	return nil
}
func validate(c Config) error {
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("Порт должен быть от 1 до 65535")
	}
	if c.Host == "" || len(c.Host) > 253 || strings.ContainsAny(c.Host, "/\\ \t\r\n?#@") {
		return errors.New("Укажите имя сервера или IP без схемы и пути")
	}
	if len(c.Username) > 256 || len(c.Password) > 4096 {
		return errors.New("Слишком длинный логин или пароль")
	}
	if c.Password != "" && c.Username == "" {
		return errors.New("Для пароля укажите имя пользователя")
	}
	if c.Prefix == "" || len(c.Prefix) > 160 || strings.ContainsAny(c.Prefix, "+#\x00") || strings.HasPrefix(c.Prefix, "/") || strings.HasSuffix(c.Prefix, "/") {
		return errors.New("Некорректный префикс тем")
	}
	if c.ClientID == "" || len(c.ClientID) > 64 || strings.ContainsAny(c.ClientID, " \r\n\x00") {
		return errors.New("Некорректный Client ID")
	}
	if c.TLS && c.CA != "" {
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM([]byte(c.CA)) {
			return errors.New("CA должен быть сертификатом PEM")
		}
	}
	return nil
}
func randomID() string {
	b := make([]byte, 8)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func remoteOptions(c Config, test bool) (*mqtt.ClientOptions, error) {
	scheme := "tcp"
	if c.TLS {
		scheme = "ssl"
	}
	opts := mqtt.NewClientOptions().AddBroker(scheme + "://" + net.JoinHostPort(c.Host, fmt.Sprint(c.Port)))
	id := c.ClientID
	if test {
		id += "-test-" + randomID()
	}
	opts.SetClientID(id).SetUsername(c.Username).SetPassword(c.Password).SetCleanSession(true)
	opts.SetConnectTimeout(6 * time.Second).SetWriteTimeout(5 * time.Second).SetKeepAlive(30 * time.Second).SetPingTimeout(8 * time.Second).SetAutoReconnect(!test).SetConnectRetry(false)
	if c.TLS {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.Host}
		if c.CA != "" {
			tc.RootCAs = x509.NewCertPool()
			if !tc.RootCAs.AppendCertsFromPEM([]byte(c.CA)) {
				return nil, errors.New("invalid CA")
			}
		}
		opts.SetTLSConfig(tc)
	}
	return opts, nil
}

var localBrokerURL = "tcp://127.0.0.1:1883"

func (a *App) runBridge() {
	a.op.Lock()
	defer a.op.Unlock()
	a.mu.Lock()
	oldL, oldR := a.local, a.remote
	oldHA := a.ha
	a.ha = nil
	a.local = nil
	a.remote = nil
	c := a.cfg
	a.status.Local = false
	a.status.Remote = false
	a.status.Message = "Мост выключен"
	a.mu.Unlock()
	if oldHA != nil {
		oldHA.close()
	}
	if oldL != nil {
		oldL.Disconnect(100)
	}
	if oldR != nil {
		oldR.Disconnect(100)
	}
	if !c.Enabled {
		return
	}
	opts, e := remoteOptions(c, false)
	if e != nil {
		return
	}
	var ha *haBridge
	if c.HADiscovery {
		ha = newHABridge(c)
		if a.devices != nil {
			ha.preference = a.devices.preference
		}
		opts.SetWill(c.Prefix+"/bridge/availability", "offline", 1, true)
	}
	opts.SetOnConnectHandler(func(cl mqtt.Client) {
		a.mu.Lock()
		if a.remote == cl {
			a.status.Remote = true
			a.status.Message = "Внешний MQTT подключён"
		}
		a.mu.Unlock()
		if ha != nil {
			ha.connected(cl)
		}
	})
	opts.SetConnectionLostHandler(func(cl mqtt.Client, e error) {
		a.mu.Lock()
		if a.remote == cl {
			a.status.Remote = false
			a.status.Message = "Соединение с внешним MQTT потеряно; повторное подключение"
		}
		a.mu.Unlock()
	})
	r := mqtt.NewClient(opts)
	lo := mqtt.NewClientOptions().AddBroker(localBrokerURL).SetClientID("aqara-panel-local").SetAutoReconnect(true).SetConnectRetry(false).SetConnectTimeout(5 * time.Second).SetWriteTimeout(5 * time.Second)
	lo.SetOnConnectHandler(func(cl mqtt.Client) {
		t := cl.Subscribe("zigbee/send", 0, func(_ mqtt.Client, m mqtt.Message) {
			if len(m.Payload()) > 65536 {
				return
			}
			a.mu.Lock()
			active := a.local == cl && a.remote == r
			a.mu.Unlock()
			if !active {
				return
			}
			if ha != nil {
				ha.process(m.Payload())
			}
			if !r.IsConnectionOpen() {
				return
			}
			token := r.Publish(c.Prefix+"/zigbee/send", 1, false, append([]byte(nil), m.Payload()...))
			if token.WaitTimeout(5*time.Second) && token.Error() == nil {
				a.mu.Lock()
				a.status.Forwarded++
				a.status.LastEvent = time.Now().Format(time.RFC3339)
				a.mu.Unlock()
			}
		})
		ok := t.WaitTimeout(5*time.Second) && t.Error() == nil
		a.mu.Lock()
		if a.local == cl {
			a.status.Local = ok
			if !ok {
				a.status.Message = "Ошибка подписки на внутренний MQTT"
			}
		}
		a.mu.Unlock()
		if ha != nil {
			ha.localReady(ok)
		}
	})
	lo.SetConnectionLostHandler(func(cl mqtt.Client, e error) {
		a.mu.Lock()
		if a.local == cl {
			a.status.Local = false
		}
		a.mu.Unlock()
		if ha != nil {
			ha.localReady(false)
		}
	})
	l := mqtt.NewClient(lo)
	a.mu.Lock()
	a.local = l
	a.remote = r
	a.ha = ha
	a.status.Message = "Подключение…"
	a.mu.Unlock()
	if ha != nil {
		ha.localReady(false)
		go ha.watch()
	}
	t := r.Connect()
	if !t.WaitTimeout(8*time.Second) || t.Error() != nil {
		a.mu.Lock()
		a.status.Message = "Не удалось подключиться к внешнему MQTT; повтор через 20 секунд"
		a.mu.Unlock()
		// Initial failures are retried by the maintenance loop.
	}
	t = l.Connect()
	if !t.WaitTimeout(7*time.Second) || t.Error() != nil {
		a.mu.Lock()
		a.status.Local = false
		a.status.Message = "Не удалось подключиться к MQTT хаба"
		a.mu.Unlock()
	}
}
func (a *App) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || !a.passwordOK(p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Aqara Local", charset="UTF-8"`)
			http.Error(w, "Требуется вход", 401)
			return
		}
		if r.Method != "GET" {
			if r.Header.Get("X-Aqara-Panel") != "1" {
				http.Error(w, "Forbidden", 403)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && origin != "https://"+r.Host && origin != "http://"+r.Host {
				http.Error(w, "Forbidden", 403)
				return
			}
			if !strings.HasPrefix(r.URL.Path, "/api/update/") {
				if _, err := os.Stat(filepath.Join(a.dir, ".web-update", "transaction")); err == nil {
					http.Error(w, "Дождитесь завершения обновления", http.StatusConflict)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func (a *App) readUpdate(w http.ResponseWriter, r *http.Request) (Config, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	var u Update
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(&u); e != nil {
		return Config{}, errors.New("Некорректные настройки")
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return Config{}, errors.New("Лишние данные")
	}
	a.mu.Lock()
	current := a.cfg
	a.mu.Unlock()
	if u.Password == "" && !u.ClearPassword {
		u.Password = current.Password
	}
	return u.Config, validate(u.Config)
}
func (a *App) handler() http.Handler {
	m := http.NewServeMux()
	a.devicesRoutes(m)
	a.updateRoutes(m)
	m.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method", 405)
			return
		}
		b, _ := assets.ReadFile("devices.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	m.HandleFunc("/api/password", a.changePassword)
	m.HandleFunc("/api/network", a.networkGet)
	m.HandleFunc("/api/network/apply", a.networkApply)
	m.HandleFunc("/api/network/confirm", a.networkConfirm)
	m.HandleFunc("/api/root-password-copy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method", 405)
			return
		}
		var v struct {
			Password string
			Repeat   string
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&v) != nil || v.Password == "" || len(v.Password) > 512 || v.Password != v.Repeat || strings.ContainsAny(v.Password, "\r\n\x00") {
			http.Error(w, "Введите копию пароля и совпадающий повтор", 400)
			return
		}
		if atomicWrite(filepath.Join(a.dir, "root-password.txt"), []byte(v.Password)) != nil {
			http.Error(w, "Не удалось сохранить копию", 500)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "message": "Копия root-пароля обновлена. Системный пароль не изменялся."})
	})
	info := systemInfo()
	m.HandleFunc("/api/about", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method", 405)
			return
		}
		writeJSON(w, info)
	})
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Method != "GET" {
			http.NotFound(w, r)
			return
		}
		b, _ := assets.ReadFile("index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	m.HandleFunc("/api/root-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method", 405)
			return
		}
		b, e := os.ReadFile(filepath.Join(a.dir, "root-password.txt"))
		if e != nil {
			http.Error(w, "Сохранённый пароль root не установлен в панели", 404)
			return
		}
		if len(b) > 1024 {
			http.Error(w, "Некорректный файл пароля", 500)
			return
		}
		writeJSON(w, map[string]string{"username": "admin", "password": strings.TrimSpace(string(b)), "scope": "UART · UID 0", "note": "Сохранённая копия. После смены пароля вне панели обновите этот файл."})
	})
	m.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method", 405)
			return
		}
		a.mu.Lock()
		s := a.status
		c := a.cfg
		has := c.Password != ""
		c.Password = ""
		a.mu.Unlock()
		writeJSON(w, map[string]any{"config": c, "password_saved": has, "status": s, "autostart": a.autostartStatus()})
	})
	m.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method", 405)
			return
		}
		a.op.Lock()
		c, e := a.readUpdate(w, r)
		if e != nil {
			a.op.Unlock()
			http.Error(w, e.Error(), 400)
			return
		}
		b, e := json.MarshalIndent(c, "", "  ")
		if e == nil {
			e = atomicWrite(filepath.Join(a.dir, "config.json"), b)
		}
		if e != nil {
			a.op.Unlock()
			http.Error(w, "Не удалось сохранить конфигурацию", 500)
			return
		}
		a.mu.Lock()
		a.cfg = c
		a.mu.Unlock()
		a.op.Unlock()
		go a.runBridge()
		writeJSON(w, map[string]any{"ok": true})
	})
	m.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method", 405)
			return
		}
		c, e := a.readUpdate(w, r)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		opts, e := remoteOptions(c, true)
		if e != nil {
			http.Error(w, "Ошибка TLS", 400)
			return
		}
		cl := mqtt.NewClient(opts)
		defer cl.Disconnect(0)
		t := cl.Connect()
		if !t.WaitTimeout(8*time.Second) || t.Error() != nil {
			http.Error(w, "Подключение не удалось. Проверьте адрес, порт, учётные данные и CA для TLS.", 502)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "message": "MQTT принял подключение. Права публикации и приёма этим тестом не проверяются."})
	})
	return a.authorize(m)
}
func provision(dir, ip string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for _, n := range []string{"panel-password.txt", "auth.sha256", "server.key", "server.crt"} {
		if _, e := os.Stat(filepath.Join(dir, n)); e == nil {
			return errors.New("refusing to overwrite existing identity")
		}
	}
	password := randomID() + randomID()
	sum := sha256.Sum256([]byte(password))
	if e := atomicWrite(filepath.Join(dir, "panel-password.txt"), []byte(password)); e != nil {
		return e
	}
	if e := atomicWrite(filepath.Join(dir, "auth.sha256"), []byte(hex.EncodeToString(sum[:]))); e != nil {
		return e
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return e
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Aqara Local Panel"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(ip), net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(dir, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})); e != nil {
		return e
	}
	return atomicWrite(filepath.Join(dir, "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func main() {
	dir := flag.String("data", "/data/aqara-panel", "private data directory")
	listen := flag.String("listen", ":80", "HTTP(S) listen address")
	useHTTPS := flag.Bool("https", false, "serve HTTPS using local certificate; use -listen :443")
	initIP := flag.String("init", "", "generate local identity for this IP and exit")
	netWatch := flag.String("network-watchdog", "", "internal rollback worker token")
	flag.Parse()
	if *netWatch != "" {
		if e := networkWatchdog(*dir, *netWatch); e != nil {
			log.Fatal(e)
		}
		return
	}
	if *initIP != "" {
		if e := provision(*dir, *initIP); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Identity created; password saved in panel-password.txt")
		return
	}
	a := &App{dir: *dir, cfg: Config{Port: 1883, Prefix: "aqara/m2", ClientID: "aqara-m2-bridge"}, status: Status{Message: "Мост выключен"}}
	if e := a.loadAuth(); e != nil {
		log.Fatal("Missing or invalid panel identity")
	}
	var b []byte
	var e error
	if b, e = os.ReadFile(filepath.Join(*dir, "config.json")); e == nil {
		if e = json.Unmarshal(b, &a.cfg); e != nil {
			log.Fatal("Invalid config")
		}
		if e = validate(a.cfg); e != nil {
			log.Fatal("Invalid saved settings")
		}
	} else if !os.IsNotExist(e) {
		log.Fatal("Cannot read config")
	}
	a.devices, e = newDeviceManager(*dir)
	if e != nil {
		log.Fatal("Invalid device preferences")
	}
	a.devices.changed = func() {
		a.mu.Lock()
		h := a.ha
		a.mu.Unlock()
		if h != nil {
			h.reannounce()
		}
	}
	a.devices.start()
	go a.runBridge()
	go func() {
		for range time.NewTicker(20 * time.Second).C {
			a.mu.Lock()
			retry := a.cfg.Enabled && (a.remote == nil || !a.remote.IsConnected() || a.local == nil || !a.local.IsConnected())
			a.mu.Unlock()
			if retry {
				a.runBridge()
			}
		}
	}()
	s := &http.Server{Addr: *listen, Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Printf("Aqara Local Panel listening on %s", *listen)
	if *useHTTPS {
		log.Fatal(s.ListenAndServeTLS(filepath.Join(*dir, "server.crt"), filepath.Join(*dir, "server.key")))
	}
	log.Fatal(s.ListenAndServe())
}

// Report the installed boot hook, not merely the presence of a script.
func (a *App) autostartStatus() string {
	if _, err := os.Stat(filepath.Join(a.dir, "autostart.disabled")); err == nil {
		return "disabled"
	}
	if _, err := os.Stat(filepath.Join(a.dir, "autostart.sh")); err != nil {
		return "not_configured"
	}
	boot, err := os.ReadFile("/etc/init.d/rcS")
	if err != nil || !strings.Contains(string(boot), "/data/aqara-panel/autostart.sh") {
		return "not_configured"
	}
	return "enabled"
}
