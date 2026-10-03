package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type NetworkConfig struct {
	Mode    string   `json:"mode"`
	IP      string   `json:"ip"`
	Mask    string   `json:"mask"`
	Gateway string   `json:"gateway"`
	DNS     []string `json:"dns"`
}
type NetworkSnapshot struct {
	Config   NetworkConfig
	Resolver string
	DHCPArgs []string
}
type NetworkChange struct {
	Token    string        `json:"token"`
	Deadline time.Time     `json:"deadline"`
	Target   NetworkConfig `json:"target"`
	Applied  bool          `json:"applied"`
}
type networkDisk struct {
	Change NetworkChange
	Before NetworkSnapshot
}

func command(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}
func dhcpProcess() (int, []string) {
	paths, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if len(args) < 3 || filepath.Base(args[0]) != "udhcpc" {
			continue
		}
		for i := 1; i+1 < len(args); i++ {
			if args[i] == "-i" && args[i+1] == "eth0" {
				pid, _ := strconv.Atoi(filepath.Base(filepath.Dir(p)))
				return pid, args[1:]
			}
		}
	}
	return 0, nil
}
func gateway() string {
	b, _ := os.ReadFile("/proc/net/route")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 3 && f[0] == "eth0" && f[1] == "00000000" {
			h, e := hex.DecodeString(f[2])
			if e == nil && len(h) == 4 {
				return net.IPv4(h[3], h[2], h[1], h[0]).String()
			}
		}
	}
	return ""
}
func networkSnapshot() (NetworkSnapshot, error) {
	var s NetworkSnapshot
	iface, e := net.InterfaceByName("eth0")
	if e != nil {
		return s, e
	}
	addresses, e := iface.Addrs()
	if e != nil {
		return s, e
	}
	for _, addr := range addresses {
		ip, n, e := net.ParseCIDR(addr.String())
		if e == nil && ip.To4() != nil {
			s.Config.IP = ip.String()
			s.Config.Mask = net.IP(n.Mask).String()
			break
		}
	}
	if s.Config.IP == "" {
		return s, errors.New("Ethernet IPv4 не назначен")
	}
	s.Config.Mode = "static"
	pid, args := dhcpProcess()
	if pid > 0 {
		s.Config.Mode = "dhcp"
		s.DHCPArgs = args
	}
	s.Config.Gateway = gateway()
	b, e := os.ReadFile("/etc/resolv.conf")
	if e != nil {
		return s, e
	}
	s.Resolver = string(b)
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "nameserver" {
			s.Config.DNS = append(s.Config.DNS, f[1])
		}
	}
	return s, nil
}
func validateNetwork(c NetworkConfig) error {
	if c.Mode != "dhcp" && c.Mode != "static" {
		return errors.New("Режим: dhcp или static")
	}
	if c.Mode == "dhcp" {
		return nil
	}
	ip := net.ParseIP(c.IP).To4()
	maskIP := net.ParseIP(c.Mask).To4()
	if ip == nil || maskIP == nil || !ip.IsGlobalUnicast() {
		return errors.New("Укажите корректные IPv4 и маску")
	}
	ones, bits := net.IPMask(maskIP).Size()
	if bits != 32 || ones < 1 || ones > 30 {
		return errors.New("Нужна непрерывная маска от /1 до /30")
	}
	n := &net.IPNet{IP: ip.Mask(net.IPMask(maskIP)), Mask: net.IPMask(maskIP)}
	broadcast := append(net.IP(nil), n.IP...)
	for i := range broadcast {
		broadcast[i] |= ^maskIP[i]
	}
	if ip.Equal(n.IP) || ip.Equal(broadcast) {
		return errors.New("Адрес сети или broadcast нельзя назначить хабу")
	}
	if c.Gateway != "" {
		g := net.ParseIP(c.Gateway).To4()
		if g == nil || !n.Contains(g) || g.Equal(ip) || g.Equal(n.IP) || g.Equal(broadcast) {
			return errors.New("Шлюз должен быть отдельным адресом в той же подсети")
		}
	}
	if len(c.DNS) > 3 {
		return errors.New("Не более трёх DNS-серверов")
	}
	for _, d := range c.DNS {
		if net.ParseIP(d).To4() == nil {
			return errors.New("DNS должен быть IPv4-адресом")
		}
	}
	return nil
}
func stopDHCP() error {
	pid, _ := dhcpProcess()
	if pid == 0 {
		return nil
	}
	return command("/bin/kill", "-TERM", strconv.Itoa(pid))
}
func startDHCP(args []string) error {
	if len(args) == 0 {
		args = []string{"-i", "eth0", "-s", "/etc/udhcp/simple.script", "-t", "10"}
	}
	c := exec.Command("/bin/udhcpc", args...)
	c.Stdin = nil
	c.Stdout = nil
	c.Stderr = nil
	if e := c.Start(); e != nil {
		return e
	}
	go c.Wait()
	return nil
}
func applyStatic(c NetworkConfig, resolver string) error {
	if e := command("/bin/ifconfig", "eth0", c.IP, "netmask", c.Mask); e != nil {
		return errors.New("Не удалось назначить IP")
	}
	for i := 0; i < 4; i++ {
		if command("/bin/route", "del", "default", "dev", "eth0") != nil {
			break
		}
	}
	if c.Gateway != "" {
		if e := command("/bin/route", "add", "default", "gw", c.Gateway, "dev", "eth0"); e != nil {
			return errors.New("Не удалось назначить шлюз")
		}
	}
	return os.WriteFile("/etc/resolv.conf", []byte(resolver), 0644)
}
func restoreNetwork(s NetworkSnapshot) error {
	_ = stopDHCP()
	if e := applyStatic(s.Config, s.Resolver); e != nil {
		return e
	}
	if s.Config.Mode == "dhcp" {
		return startDHCP(s.DHCPArgs)
	}
	return nil
}
func readNetworkDisk(p string) (networkDisk, error) {
	var d networkDisk
	b, e := os.ReadFile(p)
	if e == nil {
		e = json.Unmarshal(b, &d)
	}
	return d, e
}
func networkWatchdog(dir, token string) error {
	if len(token) != 16 {
		return errors.New("invalid rollback token")
	}
	if _, e := hex.DecodeString(token); e != nil {
		return e
	}
	p := filepath.Join(dir, "network-rollback-"+token+".json")
	d, e := readNetworkDisk(p)
	if e != nil {
		return e
	}
	if wait := time.Until(d.Change.Deadline); wait > 0 {
		time.Sleep(wait)
	}
	claimed := filepath.Join(dir, "network-rollback-active-"+token+".json")
	if e = os.Rename(p, claimed); e != nil {
		if os.IsNotExist(e) {
			return nil
		}
		return e
	}
	e = restoreNetwork(d.Before)
	if e == nil {
		_ = os.Remove(claimed)
		_ = os.Remove(filepath.Join(dir, "network-pending.json"))
		_ = atomicWrite(filepath.Join(dir, "network-last-result.txt"), []byte("Автоматический откат выполнен"))
	}
	return e
}
func (a *App) networkGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method", 405)
		return
	}
	s, e := networkSnapshot()
	if e != nil {
		http.Error(w, "Не удалось прочитать Ethernet", 500)
		return
	}
	iface, _ := net.InterfaceByName("eth0")
	mac := ""
	if iface != nil {
		mac = iface.HardwareAddr.String()
	}
	out := map[string]any{"interface": "eth0", "mac": mac, "config": s.Config, "persistence": "Настройки сети действуют до перезагрузки; автозапуск не настроен."}
	if d, e := readNetworkDisk(filepath.Join(a.dir, "network-pending.json")); e == nil {
		out["pending"] = d.Change
	}
	writeJSON(w, out)
}
func (a *App) networkApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method", 405)
		return
	}
	var c NetworkConfig
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		http.Error(w, "Некорректные настройки", 400)
		return
	}
	if e := validateNetwork(c); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	a.netMu.Lock()
	defer a.netMu.Unlock()
	pending := filepath.Join(a.dir, "network-pending.json")
	if _, e := os.Stat(pending); e == nil {
		http.Error(w, "Сначала подтвердите или дождитесь отката предыдущего изменения", 409)
		return
	}
	before, e := networkSnapshot()
	if e != nil {
		http.Error(w, "Не удалось сохранить исходные настройки", 500)
		return
	}
	change := NetworkChange{Token: randomID(), Deadline: time.Now().Add(90 * time.Second), Target: c}
	disk := networkDisk{Change: change, Before: before}
	b, _ := json.Marshal(disk)
	if e = atomicWrite(pending, b); e != nil {
		http.Error(w, "Не удалось подготовить откат", 500)
		return
	}
	executable, e := os.Executable()
	if e != nil {
		os.Remove(pending)
		http.Error(w, "Не удалось подготовить откат", 500)
		return
	}
	rollbackPath := filepath.Join(a.dir, "network-rollback-"+change.Token+".json")
	if e = atomicWrite(rollbackPath, b); e != nil {
		os.Remove(pending)
		http.Error(w, "Не удалось сохранить откат", 500)
		return
	}
	watchdog := exec.Command(executable, "-data", a.dir, "-network-watchdog", change.Token)
	if e = watchdog.Start(); e != nil {
		os.Remove(rollbackPath)
		os.Remove(pending)
		http.Error(w, "Не удалось запустить защиту отката", 500)
		return
	}
	go watchdog.Wait()
	go func() {
		time.Sleep(time.Second)
		e := stopDHCP()
		if e == nil {
			if c.Mode == "dhcp" {
				e = startDHCP(before.DHCPArgs)
			} else {
				var resolver strings.Builder
				for _, ip := range c.DNS {
					fmt.Fprintf(&resolver, "nameserver %s\n", ip)
				}
				e = applyStatic(c, resolver.String())
			}
		}
		if e != nil {
			_ = os.Remove(rollbackPath)
			_ = restoreNetwork(before)
			_ = os.Remove(pending)
			_ = atomicWrite(filepath.Join(a.dir, "network-last-result.txt"), []byte("Изменение не выполнено; запущено восстановление"))
			return
		}
		if _, e := os.Stat(rollbackPath); e != nil {
			return
		}
		disk.Change.Applied = true
		b, _ := json.Marshal(disk)
		_ = atomicWrite(pending, b)
	}()
	writeJSON(w, map[string]any{"ok": true, "pending": change, "message": "Изменение начнётся через секунду. Подтвердите доступ через панель до истечения 90 секунд; иначе настройки вернутся."})
}
func (a *App) networkConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method", 405)
		return
	}
	var v struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&v) != nil {
		http.Error(w, "Некорректный запрос", 400)
		return
	}
	a.netMu.Lock()
	defer a.netMu.Unlock()
	p := filepath.Join(a.dir, "network-pending.json")
	d, e := readNetworkDisk(p)
	if e != nil || !d.Change.Applied || time.Now().After(d.Change.Deadline) || v.Token != d.Change.Token {
		http.Error(w, "Нет применённого изменения для подтверждения", 409)
		return
	}
	if e = os.Remove(filepath.Join(a.dir, "network-rollback-"+d.Change.Token+".json")); e != nil {
		http.Error(w, "Откат уже начался; подтверждение невозможно", 409)
		return
	}
	if e = os.Rename(p, filepath.Join(a.dir, "network-confirmed.json")); e != nil {
		http.Error(w, "Подтверждение не выполнено", 409)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": "Сеть подтверждена. Параметры действуют до перезагрузки хаба."})
}
