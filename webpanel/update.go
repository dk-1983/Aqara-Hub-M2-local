package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const updateLimit = 24 << 20

var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type releaseManifest struct {
	Format      int    `json:"format"`
	Version     string `json:"version"`
	Platform    string `json:"platform"`
	Model       string `json:"model"`
	Firmware    string `json:"factory_firmware"`
	Credentials bool   `json:"contains_credentials"`
	Rootfs      bool   `json:"contains_rootfs"`
}
type pendingUpdate struct {
	Token     string `json:"token"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	PanelSHA  string `json:"panel_sha256"`
	ScriptSHA string `json:"script_sha256"`
}

// Never unpack arbitrary paths, links, devices, scripts or configuration files.
// Only the executable and supervisor are retained; other allowed files are hashed.
func unpackUpdate(src io.Reader, dir, expected string) (pendingUpdate, error) {
	var result pendingUpdate
	if !digestPattern.MatchString(expected) {
		return result, errors.New("Требуется SHA256 архива из файла .tar.sha256")
	}
	overall := sha256.New()
	limited := &io.LimitedReader{R: src, N: updateLimit + 1}
	stream := io.TeeReader(limited, overall)
	reader := tar.NewReader(stream)
	hashes := map[string]string{}
	var manifest, checks []byte
	allowed := map[string]bool{"panel": true, "autostart.sh": true, "install.sh": true, "INSTALLER.md": true, "LICENSE": true, "THIRD_PARTY.md": true, "manifest.json": true, "SHA256SUMS": true,
		"licenses/go.txt": true, "licenses/go-x-net.txt": true, "licenses/go-x-sync.txt": true, "licenses/gorilla-websocket.txt": true, "licenses/paho.txt": true}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, err
		}
		name := strings.TrimPrefix(header.Name, "4vrs-m2/")
		if header.Name != "4vrs-m2/"+name || !allowed[name] || hashes[name] != "" || header.Typeflag != tar.TypeReg || header.Size < 0 {
			return result, errors.New("Недопустимый файл или повтор в архиве")
		}
		max := int64(256 << 10)
		if name == "panel" {
			max = 20 << 20
		}
		if header.Size > max {
			return result, errors.New("Файл в архиве слишком большой")
		}
		hash := sha256.New()
		var buffer bytes.Buffer
		var dest io.Writer = io.Discard
		var file *os.File
		if name == "panel" || name == "autostart.sh" {
			file, err = os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
			if err != nil {
				return result, err
			}
			dest = file
		} else if name == "manifest.json" || name == "SHA256SUMS" {
			dest = &buffer
		}
		_, err = io.Copy(io.MultiWriter(hash, dest), reader)
		if file != nil {
			if e := file.Sync(); err == nil {
				err = e
			}
			if e := file.Close(); err == nil {
				err = e
			}
		}
		if err != nil {
			return result, err
		}
		hashes[name] = hex.EncodeToString(hash.Sum(nil))
		if name == "manifest.json" {
			manifest = buffer.Bytes()
		}
		if name == "SHA256SUMS" {
			checks = buffer.Bytes()
		}
	}
	// Include padding/trailing bytes in the externally supplied archive digest.
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return result, err
	}
	if limited.N <= 0 {
		return result, errors.New("Архив превышает 24 МиБ")
	}
	if hex.EncodeToString(overall.Sum(nil)) != expected {
		return result, errors.New("SHA256 архива не совпадает")
	}
	for _, name := range []string{"panel", "autostart.sh", "manifest.json", "SHA256SUMS"} {
		if hashes[name] == "" {
			return result, errors.New("Неполный пакет")
		}
	}
	covered := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(checks)), "\n") {
		parts := strings.Split(strings.TrimSuffix(line, "\r"), "  ")
		if len(parts) != 2 || !digestPattern.MatchString(parts[0]) || parts[1] == "SHA256SUMS" || covered[parts[1]] || hashes[parts[1]] != parts[0] {
			return result, errors.New("Некорректный список контрольных сумм")
		}
		covered[parts[1]] = true
	}
	if len(covered) != len(hashes)-1 {
		return result, errors.New("Не все файлы защищены контрольными суммами")
	}
	var m releaseManifest
	if json.Unmarshal(manifest, &m) != nil || m.Format != 1 || !releaseVersion.MatchString(m.Version) || m.Platform != "linux/mipsle/softfloat" || m.Model != "lumi.gateway.agl001" || m.Firmware != "4.1.6_0018.0650" || m.Credentials || m.Rootfs {
		return result, errors.New("Несовместимый пакет приложения")
	}
	f, err := os.Open(filepath.Join(dir, "panel"))
	if err != nil {
		return result, err
	}
	header := make([]byte, 20)
	_, err = io.ReadFull(f, header)
	f.Close()
	if err != nil || !bytes.Equal(header[:6], []byte{127, 'E', 'L', 'F', 1, 1}) || header[18] != 8 || header[19] != 0 {
		return result, errors.New("Нужен ELF Linux/MIPS little-endian")
	}
	script, err := os.ReadFile(filepath.Join(dir, "autostart.sh"))
	if err != nil || !bytes.HasPrefix(script, []byte("#!/bin/sh\n")) || bytes.Contains(script, []byte{'\r'}) || !bytes.Contains(script, []byte(".web-update/transaction")) {
		return result, errors.New("Некорректный скрипт автозапуска")
	}
	result = pendingUpdate{Token: randomID(), Version: m.Version, SHA256: expected, PanelSHA: hashes["panel"], ScriptSHA: hashes["autostart.sh"]}
	return result, nil
}

func updateCompatible(dir string) error {
	if filepath.Clean(dir) != "/data/aqara-panel" {
		return errors.New("Обновление доступно только на хабе")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	model, err := exec.CommandContext(ctx, "/bin/getprop", "persist.sys.model").Output()
	if err != nil || strings.TrimSpace(string(model)) != "lumi.gateway.agl001" {
		return errors.New("Неизвестная модель хаба")
	}
	prop, err := os.ReadFile("/etc/build.prop")
	if err != nil || !bytes.Contains(prop, []byte("ro.sys.fw_ver=4.1.6\n")) || !bytes.Contains(prop, []byte("ro.sys.build_num=0018\n")) {
		return errors.New("Непроверенная заводская версия")
	}
	boot, err := os.ReadFile("/etc/init.d/rcS")
	if err != nil || !bytes.Contains(boot, []byte("/data/aqara-panel/autostart.sh")) {
		return errors.New("Не установлен хук автозапуска")
	}
	for _, name := range []string{"autostart.disabled", "network-pending.json", "install-incomplete"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return errors.New("Есть отключение автозапуска или незавершённая операция")
		}
	}
	return nil
}

var checkUpdateTarget = updateCompatible

func fileSHA(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), e
}
func (a *App) updateRoutes(m *http.ServeMux) {
	m.HandleFunc("/maintenance", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method", 405)
			return
		}
		b, _ := assets.ReadFile("maintenance.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	m.HandleFunc("/api/update/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method", 405)
			return
		}
		a.updateMu.Lock()
		defer a.updateMu.Unlock()
		v := map[string]any{"version": addonVersion}
		if free, err := updateFree(a.dir); err == nil {
			v["free_bytes"] = free
		}
		if e := checkUpdateTarget(a.dir); e != nil {
			v["unavailable"] = e.Error()
		}
		var pending pendingUpdate
		if b, e := os.ReadFile(filepath.Join(a.dir, ".web-update", "pending.json")); e == nil && json.Unmarshal(b, &pending) == nil {
			v["pending"] = pending
		}
		var outcome map[string]any
		if b, e := os.ReadFile(filepath.Join(a.dir, "update-result.json")); e == nil && json.Unmarshal(b, &outcome) == nil {
			v["result"] = outcome
		}
		if _, e := os.Stat(filepath.Join(a.dir, ".web-update", "transaction")); e == nil {
			v["applying"] = true
		}
		writeJSON(w, v)
	})
	m.HandleFunc("/api/update/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method", 405)
			return
		}
		a.updateMu.Lock()
		defer a.updateMu.Unlock()
		if e := checkUpdateTarget(a.dir); e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		stage := filepath.Join(a.dir, ".web-update")
		if e := os.Mkdir(stage, 0700); e != nil {
			http.Error(w, "Уже есть пакет или незавершённое обновление", 409)
			return
		}
		ok := false
		defer func() {
			if !ok {
				os.RemoveAll(stage)
			}
		}()
		// Check free space before streaming, without keeping a second archive copy.
		if r.ContentLength <= 0 || r.ContentLength > updateLimit {
			http.Error(w, "Недопустимый размер архива", 400)
			return
		}
		free, e := updateFree(a.dir)
		if e != nil || free < uint64(r.ContentLength)+(2<<20) {
			http.Error(w, "Недостаточно места: нужен размер архива плюс 2 МиБ", 507)
			return
		}
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_ = controller.SetWriteDeadline(time.Now().Add(6 * time.Minute))
		pending, e := unpackUpdate(http.MaxBytesReader(w, r.Body, updateLimit), stage, strings.ToLower(r.Header.Get("X-Archive-SHA256")))
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		b, _ := json.Marshal(pending)
		if e = atomicWrite(filepath.Join(stage, "pending.json"), b); e != nil {
			http.Error(w, "Ошибка сохранения", 500)
			return
		}
		ok = true
		writeJSON(w, pending)
	})
	m.HandleFunc("/api/update/cancel", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method", 405)
			return
		}
		a.updateMu.Lock()
		defer a.updateMu.Unlock()
		stage := filepath.Join(a.dir, ".web-update")
		if _, e := os.Stat(filepath.Join(stage, "transaction")); !os.IsNotExist(e) {
			http.Error(w, "Обновление уже применяется", 409)
			return
		}
		if e := os.RemoveAll(stage); e != nil {
			http.Error(w, "Не удалось убрать пакет", 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	m.HandleFunc("/api/update/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method", 405)
			return
		}
		a.updateMu.Lock()
		defer a.updateMu.Unlock()
		if e := checkUpdateTarget(a.dir); e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		stage := filepath.Join(a.dir, ".web-update")
		var input struct {
			Token string `json:"token"`
		}
		var p pendingUpdate
		b, e := os.ReadFile(filepath.Join(stage, "pending.json"))
		if e != nil || json.Unmarshal(b, &p) != nil || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil || input.Token == "" || input.Token != p.Token {
			http.Error(w, "Нет подтверждённого пакета", 400)
			return
		}
		for name, expected := range map[string]string{"panel": p.PanelSHA, "autostart.sh": p.ScriptSHA} {
			actual, e := fileSHA(filepath.Join(stage, name))
			if e != nil || actual != expected {
				http.Error(w, "Файлы пакета изменились", 400)
				return
			}
		}
		worker, _ := assets.ReadFile("update-worker.sh")
		if e = atomicWrite(filepath.Join(stage, "worker.sh"), worker); e != nil {
			http.Error(w, "Не удалось подготовить обновление", 500)
			return
		}
		lock, e := os.OpenFile(filepath.Join(stage, "transaction"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			http.Error(w, "Обновление уже запущено", 409)
			return
		}
		lock.Close()
		c := exec.Command("/bin/sh", filepath.Join(stage, "worker.sh"))
		c.Env = append(os.Environ(), "GOMEMLIMIT=12MiB", "GOGC=50")
		if e = c.Start(); e != nil {
			os.Remove(filepath.Join(stage, "transaction"))
			http.Error(w, "Не удалось запустить обновление", 500)
			return
		}
		go c.Wait()
		writeJSON(w, map[string]string{"message": fmt.Sprintf("Устанавливается версия %s. Панель временно отключится.", p.Version)})
	})
}
