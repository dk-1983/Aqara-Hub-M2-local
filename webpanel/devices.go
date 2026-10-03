package main

import (
	"encoding/json"
	"errors"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const addonVersion = "0.4.1"

type devicePrefs struct {
	Name          string `json:"name"`
	MotionTimeout int    `json:"motion_timeout"`
}
type deviceCommand struct {
	ID       int64     `json:"id"`
	DID      string    `json:"did"`
	Resource string    `json:"resource"`
	Value    int       `json:"value"`
	Status   string    `json:"status"`
	Message  string    `json:"message"`
	Created  time.Time `json:"created"`
}
type deviceRemoval struct {
	ID        int64     `json:"id"`
	DID       string    `json:"did"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Created   time.Time `json:"created"`
	eventSeen bool
}

type pairState struct {
	Until      time.Time      `json:"until"`
	Status     string         `json:"status"`
	Found      []sensorDevice `json:"found"`
	baseline   map[string]bool
	trackUntil time.Time
}
type deviceManager struct {
	mu         sync.Mutex
	dir        string
	client     mqtt.Client
	prefs      map[string]devicePrefs
	devices    map[string]sensorDevice
	states     map[string]map[string]string
	seen       map[string]time.Time
	kinds      map[string]string
	parameters map[string]map[string]int
	removals   map[string]*deviceRemoval
	commands   map[int64]*deviceCommand
	pairing    pairState
	seq        int64
	send       func([]byte) error
	changed    func()
}

// Hardware resources are added only after verification against this hub's protocol.
var p1Resources = map[string]string{"detection_interval": "8.0.2115", "sensitivity": "14.1.85", "indicator": "4.21.85"}

func newDeviceManager(dir string) (*deviceManager, error) {
	d := &deviceManager{dir: dir, prefs: map[string]devicePrefs{}, devices: map[string]sensorDevice{},
		states: map[string]map[string]string{}, seen: map[string]time.Time{}, kinds: map[string]string{}, parameters: map[string]map[string]int{},
		removals: map[string]*deviceRemoval{}, commands: map[int64]*deviceCommand{}, seq: time.Now().UnixMilli() & 0x3fffffff}
	b, err := os.ReadFile(filepath.Join(dir, "devices.json"))
	if err == nil {
		if err = json.Unmarshal(b, &d.prefs); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if d.prefs == nil {
		d.prefs = map[string]devicePrefs{}
	}
	d.refreshInventory()
	return d, nil
}
func (d *deviceManager) preference(did string) devicePrefs {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.prefs[did]
	if p.MotionTimeout == 0 {
		p.MotionTimeout = 60
	}
	return p
}
func readDevices() ([]sensorDevice, error) {
	b, err := os.ReadFile(deviceInfoPath)
	if err != nil {
		return nil, err
	}
	if len(b) > 1024*1024 {
		return nil, errors.New("inventory too large")
	}
	var data struct {
		Devices []sensorDevice `json:"devInfo"`
	}
	if err = json.Unmarshal(b, &data); err != nil {
		return nil, err
	}
	if data.Devices == nil || len(data.Devices) > 256 {
		return nil, errors.New("invalid inventory")
	}
	out := []sensorDevice{}
	for _, dev := range data.Devices {
		if validDID.MatchString(dev.DID) {
			out = append(out, dev)
		}
	}
	return out, nil
}
func (d *deviceManager) refreshInventory() {
	devices, err := readDevices()
	if err != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	next := map[string]sensorDevice{}
	for _, dev := range devices {
		next[dev.DID] = dev
		if d.pairing.baseline != nil && time.Now().Before(d.pairing.trackUntil) && !d.pairing.baseline[dev.DID] {
			d.pairing.Found = append(d.pairing.Found, dev)
			d.pairing.baseline[dev.DID] = true
		}
	}
	d.devices = next
	for did, removal := range d.removals {
		if _, exists := next[did]; !exists && removal.eventSeen && (removal.Status == "pending" || removal.Status == "accepted" || removal.Status == "unconfirmed") {
			removal.Status = "confirmed"
			removal.Message = "Удаление подтверждено хабом; устройство отсутствует в его базе. MQTT Discovery очищается автоматически."
		}
	}
}
func (d *deviceManager) start() {
	opts := mqtt.NewClientOptions().AddBroker(localBrokerURL).SetClientID("4vrs-device-manager").
		SetAutoReconnect(true).SetConnectRetry(true).SetConnectRetryInterval(10 * time.Second).
		SetConnectTimeout(5 * time.Second).SetWriteTimeout(5 * time.Second).SetKeepAlive(30 * time.Second)
	opts.SetOnConnectHandler(func(cl mqtt.Client) {
		cl.Subscribe("zigbee/send", 0, func(_ mqtt.Client, m mqtt.Message) {
			if !m.Retained() && len(m.Payload()) <= 65536 {
				d.process(m.Payload())
			}
		})
	})
	d.client = mqtt.NewClient(opts)
	d.send = func(b []byte) error {
		if !d.client.IsConnectionOpen() {
			return errors.New("Нет соединения с MQTT хаба")
		}
		t := d.client.Publish("zigbee/recv", 0, false, b)
		if !t.WaitTimeout(3 * time.Second) {
			return errors.New("Истекло время отправки")
		}
		return t.Error()
	}
	d.client.Connect()
	go func() {
		for range time.NewTicker(5 * time.Second).C {
			d.refreshInventory()
			d.expire()
		}
	}()
}
func (d *deviceManager) expire() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.commands {
		if (c.Status == "pending" || c.Status == "accepted") && time.Since(c.Created) > 90*time.Second {
			if c.DID == "lumi.0" {
				d.pairing.Status = "unconfirmed"
			}
			c.Status = "unconfirmed"
			c.Message = "Нет подтверждения значения. Разбудите датчик коротким нажатием и повторите."
		}
	}
	for _, r := range d.removals {
		if (r.Status == "pending" || r.Status == "accepted") && time.Since(r.Created) > 90*time.Second {
			r.Status = "unconfirmed"
			r.Message = "Удаление не подтверждено за 90 секунд. Проверьте список устройств; автоматического повтора нет."
		}
	}
	if d.pairing.Status == "open" && time.Now().After(d.pairing.Until) {
		d.pairing.Status = "expired"
	}
}
func (d *deviceManager) issue(did, resource string, value int) (deviceCommand, error) {
	d.mu.Lock()
	if len(d.commands) >= 64 {
		var oldest int64
		for id := range d.commands {
			if oldest == 0 || id < oldest {
				oldest = id
			}
		}
		delete(d.commands, oldest)
	}
	d.seq++
	id := d.seq
	c := &deviceCommand{ID: id, DID: did, Resource: resource, Value: value, Status: "pending",
		Message: "Команда отправляется; ожидаем ответ хаба", Created: time.Now()}
	d.commands[id] = c
	d.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"cmd": "write", "id": id, "did": did, "params": []map[string]any{{"res_name": resource, "value": value}}})
	var err error
	if d.send == nil {
		err = errors.New("Локальный MQTT не запущен")
	} else {
		err = d.send(b)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		c.Status = "failed"
		c.Message = "Команда не отправлена: " + err.Error()
	}
	return *c, err
}
func (d *deviceManager) process(b []byte) {
	var m struct {
		Cmd     string          `json:"cmd"`
		DID     string          `json:"did"`
		ID      int64           `json:"id"`
		Error   *int            `json:"error_code"`
		Params  json.RawMessage `json:"params"`
		Results json.RawMessage `json:"results"`
	}
	if json.Unmarshal(b, &m) != nil {
		return
	}
	if len(m.Params) == 0 {
		m.Params = m.Results
	}
	if len(m.Params) == 0 {
		m.Params = json.RawMessage("[]")
	}
	type event struct {
		DID    string      `json:"did"`
		Params []lumiParam `json:"res_list"`
	}
	events := []event{}
	if m.Cmd == "heartbeat" {
		if json.Unmarshal(m.Params, &events) != nil {
			return
		}
	} else {
		var p []lumiParam
		if json.Unmarshal(m.Params, &p) != nil {
			return
		}
		events = append(events, event{m.DID, p})
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if m.DID == "lumi.0" {
		for _, r := range d.removals {
			if m.Cmd == "write_rsp" && m.ID == r.ID && (r.Status == "pending" || r.Status == "accepted") {
				if m.Error != nil && *m.Error != 0 {
					r.Status = "failed"
					r.Message = fmt.Sprintf("Ошибка хаба: %d", *m.Error)
					continue
				}
				for _, ev := range events {
					for _, p := range ev.Params {
						if p.Resource != "8.0.2082" {
							continue
						}
						if p.Error != 0 {
							r.Status = "failed"
							r.Message = fmt.Sprintf("Ошибка удаления: %d", p.Error)
							continue
						}
						var target string
						if json.Unmarshal(p.Value, &target) == nil && target == r.DID {
							r.Status = "accepted"
							r.Message = "Хаб принял команду. Ожидаем событие удаления и обновление базы."
						}
					}
				}
			}
		}
		if m.Cmd == "report" && (m.Error == nil || *m.Error == 0) {
			for _, ev := range events {
				for _, p := range ev.Params {
					if p.Resource != "8.0.2338" || p.Error != 0 {
						continue
					}
					var value string
					if json.Unmarshal(p.Value, &value) != nil {
						continue
					}
					var event struct {
						Type int    `json:"type"`
						DID  string `json:"did"`
					}
					if json.Unmarshal([]byte(value), &event) != nil || event.Type != 2 {
						continue
					}
					if r := d.removals[event.DID]; r != nil && r.Status != "failed" && r.Status != "confirmed" {
						r.eventSeen = true
					}
				}
			}
		}
	}
	for _, ev := range events {
		if dev, ok := d.devices[ev.DID]; ok && (m.Cmd == "report" || m.Cmd == "heartbeat") {
			d.seen[ev.DID] = time.Now()
			d.kinds[ev.DID] = m.Cmd
			if d.states[ev.DID] == nil {
				d.states[ev.DID] = map[string]string{}
			}
			for k, v := range decodeSensor(dev.Model, m.Cmd, ev.Params) {
				d.states[ev.DID][k] = v
			}
		}
		for _, p := range ev.Params {
			n, ok := number(p.Value)
			// Failed responses must never be shown as new parameter values.
			if p.Error != 0 {
				continue
			}
			if ok && (m.Error == nil || *m.Error == 0) && (m.Cmd == "report" || m.Cmd == "read_rsp" || m.Cmd == "heartbeat" || m.Cmd == "write_ack") {
				for name, res := range p1Resources {
					if p.Resource == res && d.devices[ev.DID].Model == "lumi.motion.ac02" {
						if d.parameters[ev.DID] == nil {
							d.parameters[ev.DID] = map[string]int{}
						}
						d.parameters[ev.DID][name] = int(n)
					}
				}
			}
			if ev.DID == "lumi.0" && p.Resource == "8.0.2109" && ok && (m.Cmd == "report" || m.Cmd == "write_rsp" || m.Cmd == "write_ack") && (m.Error == nil || *m.Error == 0) {
				if n == 0 {
					d.pairing.Status = "closed"
					d.pairing.Until = time.Time{}
				}
			}
			for _, c := range d.commands {
				if c.DID != ev.DID || c.Resource != p.Resource || (c.Status != "pending" && c.Status != "accepted") {
					continue
				}
				matchResponse := m.ID == c.ID && (m.Cmd == "write_rsp" || m.Cmd == "write_ack")
				matchReport := m.Cmd == "report" && ok && int(n) == c.Value
				if !matchResponse && !matchReport {
					continue
				}
				if m.Error != nil && *m.Error != 0 {
					c.Status = "failed"
					c.Message = fmt.Sprintf("Хаб вернул ошибку %d", *m.Error)
					continue
				}
				if matchReport || ((m.Cmd == "write_ack" || c.DID == "lumi.0" && m.Cmd == "write_rsp") && ok && n == float64(c.Value)) {
					c.Status = "confirmed"
					c.Message = "Датчик подтвердил значение"
					if c.DID == "lumi.0" {
						c.Message = "Хаб подтвердил команду сопряжения"
					}
					if c.DID == "lumi.0" && c.Resource == "8.0.2109" && c.Value > 0 {
						d.pairing.Status = "open"
						d.pairing.Until = time.Now().Add(time.Duration(c.Value) * time.Second)
					}
				} else {
					c.Status = "accepted"
					c.Message = "Хаб принял команду; ожидаем подтверждение датчика"
				}
			}
		}
	}
	// Handle explicit failures even when no value or params are present.
	for _, c := range d.commands {
		if c.ID != m.ID || c.DID != m.DID || (m.Cmd != "write_rsp" && m.Cmd != "write_ack") {
			continue
		}
		if m.Error != nil && *m.Error != 0 {
			c.Status = "failed"
			c.Message = fmt.Sprintf("Ошибка хаба: %d", *m.Error)
		}
		for _, ev := range events {
			for _, p := range ev.Params {
				if p.Resource == c.Resource && p.Error != 0 {
					c.Status = "failed"
					c.Message = fmt.Sprintf("Ошибка параметра: %d", p.Error)
				}
			}
		}
	}
}
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != "POST" {
		http.Error(w, "Method", 405)
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	var extra any
	if dec.Decode(v) != nil || dec.Decode(&extra) != io.EOF {
		http.Error(w, "Некорректные данные", 400)
		return false
	}
	return true
}
func (a *App) devicesRoutes(m *http.ServeMux) {
	m.HandleFunc("/api/devices/remove", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			DID     string `json:"did"`
			Confirm string `json:"confirm"`
		}
		if !decodeBody(w, r, &v) {
			return
		}
		if !validDID.MatchString(v.DID) || v.Confirm != v.DID {
			http.Error(w, "Требуется подтверждение выбранного устройства", 400)
			return
		}
		d := a.devices
		if d == nil {
			http.Error(w, "Менеджер недоступен", 503)
			return
		}
		d.refreshInventory()
		d.expire()
		d.mu.Lock()
		dev, exists := d.devices[v.DID]
		if !exists {
			d.mu.Unlock()
			http.Error(w, "Устройство уже отсутствует в базе хаба", 404)
			return
		}
		if previous := d.removals[v.DID]; previous != nil && (previous.Status == "pending" || previous.Status == "accepted") {
			d.mu.Unlock()
			http.Error(w, "Удаление уже выполняется", 409)
			return
		}
		if len(d.removals) >= 64 {
			var oldest string
			for id, item := range d.removals {
				if item.Status != "pending" && item.Status != "accepted" && (oldest == "" || item.ID < d.removals[oldest].ID) {
					oldest = id
				}
			}
			if oldest == "" {
				d.mu.Unlock()
				http.Error(w, "Слишком много незавершённых команд", 409)
				return
			}
			delete(d.removals, oldest)
		}
		name := d.prefs[v.DID].Name
		if name == "" {
			name = dev.name()
		}
		d.seq++
		removal := &deviceRemoval{ID: d.seq, DID: v.DID, Name: name, Status: "pending", Message: "Отправляем команду удаления в хаб", Created: time.Now()}
		d.removals[v.DID] = removal
		d.mu.Unlock()
		payload, _ := json.Marshal(map[string]any{"cmd": "write", "did": "lumi.0", "id": removal.ID, "params": []map[string]any{{"res_name": "8.0.2082", "value": v.DID}}})
		var err error
		if d.send == nil {
			err = errors.New("Локальный MQTT не запущен")
		} else {
			err = d.send(payload)
		}
		d.mu.Lock()
		if err != nil {
			removal.Status = "failed"
			removal.Message = "Команда не отправлена: " + err.Error()
		}
		result := *removal
		d.mu.Unlock()
		if err != nil {
			http.Error(w, result.Message, 502)
			return
		}
		writeJSON(w, result)
	})
	m.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method", 405)
			return
		}
		d := a.devices
		if d == nil {
			http.Error(w, "Менеджер устройств недоступен", 503)
			return
		}
		d.refreshInventory()
		d.expire()
		d.mu.Lock()
		defer d.mu.Unlock()
		list := []map[string]any{}
		for id, dev := range d.devices {
			p := d.prefs[id]
			if p.MotionTimeout == 0 {
				p.MotionTimeout = 60
			}
			name := p.Name
			if name == "" {
				name = dev.name()
			}
			motion := dev.Model == "lumi.motion.ac02" || dev.Model == "lumi.sensor_motion.aq2"
			list = append(list, map[string]any{"did": id, "model": dev.Model, "name": name, "preferences": p,
				"motion": motion, "supported": len(entitiesFor(dev.Model)) > 0, "last_seen": d.seen[id], "last_event": d.kinds[id],
				"states": d.states[id], "parameters": d.parameters[id], "p1_parameters": p1Resources, "p1_controls": dev.Model == "lumi.motion.ac02" && len(p1Resources) > 0})
		}
		sort.Slice(list, func(i, j int) bool { return list[i]["did"].(string) < list[j]["did"].(string) })
		cmds := []deviceCommand{}
		for _, c := range d.commands {
			cmds = append(cmds, *c)
		}
		sort.Slice(cmds, func(i, j int) bool { return cmds[i].ID > cmds[j].ID })
		if len(cmds) > 10 {
			cmds = cmds[:10]
		}
		removals := []deviceRemoval{}
		for _, removal := range d.removals {
			removals = append(removals, *removal)
		}
		sort.Slice(removals, func(i, j int) bool { return removals[i].ID > removals[j].ID })
		connected := d.client != nil && d.client.IsConnectionOpen()
		writeJSON(w, map[string]any{"devices": list, "commands": cmds, "removals": removals, "pairing": d.pairing, "local_connected": connected, "server_time": time.Now()})
	})
	m.HandleFunc("/api/devices/preferences", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			DID string `json:"did"`
			devicePrefs
		}
		if !decodeBody(w, r, &v) {
			return
		}
		d := a.devices
		if d == nil {
			http.Error(w, "Менеджер недоступен", 503)
			return
		}
		v.Name = strings.TrimSpace(v.Name)
		if len(v.Name) > 120 || strings.ContainsAny(v.Name, "\x00\r\n") || v.MotionTimeout < 1 || v.MotionTimeout > 86400 {
			http.Error(w, "Имя до 120 байт, время сброса от 1 до 86400 секунд", 400)
			return
		}
		d.mu.Lock()
		if _, ok := d.devices[v.DID]; !ok {
			d.mu.Unlock()
			http.Error(w, "Устройство не найдено", 404)
			return
		}
		next := map[string]devicePrefs{}
		for id, p := range d.prefs {
			next[id] = p
		}
		next[v.DID] = v.devicePrefs
		b, _ := json.MarshalIndent(next, "", "  ")
		err := atomicWrite(filepath.Join(d.dir, "devices.json"), b)
		if err == nil {
			d.prefs = next
		}
		d.mu.Unlock()
		if err != nil {
			http.Error(w, "Не удалось сохранить", 500)
			return
		}
		if d.changed != nil {
			d.changed()
		}
		writeJSON(w, map[string]any{"ok": true, "message": "Сохранено. Описание устройства в MQTT обновлено; имя, заданное вручную в HA, имеет приоритет."})
	})
	m.HandleFunc("/api/devices/pair", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Seconds int `json:"seconds"`
		}
		if !decodeBody(w, r, &v) {
			return
		}
		if v.Seconds != 0 && v.Seconds != 60 {
			http.Error(w, "Допустимо 0 или 60 секунд", 400)
			return
		}
		d := a.devices
		if d == nil {
			http.Error(w, "Менеджер недоступен", 503)
			return
		}
		d.refreshInventory()
		d.mu.Lock()
		if v.Seconds > 0 {
			if d.pairing.Status == "opening" || d.pairing.Status == "open" {
				d.mu.Unlock()
				http.Error(w, "Сопряжение уже открывается или открыто", 409)
				return
			}
			d.pairing = pairState{Status: "opening", trackUntil: time.Now().Add(90 * time.Second), Found: []sensorDevice{}, baseline: map[string]bool{}}
			for id := range d.devices {
				d.pairing.baseline[id] = true
			}
		}
		d.mu.Unlock()
		c, err := d.issue("lumi.0", "8.0.2109", v.Seconds)
		if err != nil {
			d.mu.Lock()
			d.pairing.Status = "failed"
			d.mu.Unlock()
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, c)
	})
	m.HandleFunc("/api/devices/parameter", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			DID       string `json:"did"`
			Parameter string `json:"parameter"`
			Value     int    `json:"value"`
		}
		if !decodeBody(w, r, &v) {
			return
		}
		d := a.devices
		if d == nil {
			http.Error(w, "Менеджер недоступен", 503)
			return
		}
		d.mu.Lock()
		dev, ok := d.devices[v.DID]
		d.mu.Unlock()
		res, known := p1Resources[v.Parameter]
		if !ok || dev.Model != "lumi.motion.ac02" || !known {
			http.Error(w, "Параметр не поддерживается для этой модели", 400)
			return
		}
		valid := v.Parameter == "detection_interval" && (v.Value == 10 || v.Value == 30 || v.Value == 60 || v.Value == 120 || v.Value == 180) ||
			v.Parameter == "sensitivity" && v.Value >= 1 && v.Value <= 3 ||
			v.Parameter == "indicator" && (v.Value == 0 || v.Value == 1)
		if !valid {
			http.Error(w, "Недопустимое значение", 400)
			return
		}
		c, err := d.issue(v.DID, res, v.Value)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, c)
	})
}
