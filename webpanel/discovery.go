package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Only explicitly supported models are decoded. Resource numbers are model-specific.
type sensorDevice struct {
	DID   string `json:"did"`
	Model string `json:"model"`
}
type haEntity struct{ Key, Domain, Class, Unit, Name string }

var deviceInfoPath = "/data/zigbee/device.info"
var validDID = regexp.MustCompile(`^lumi\.[0-9a-f]{10,16}$`)

func entitiesFor(model string) []haEntity {
	battery := haEntity{"battery", "sensor", "battery", "%", "Battery"}
	switch model {
	case "lumi.motion.ac02", "lumi.sensor_motion.aq2":
		return []haEntity{{"motion", "binary_sensor", "motion", "", "Motion"}, {"illuminance", "sensor", "illuminance", "lx", "Illuminance"}, battery}
	case "lumi.sensor_wleak.aq1", "lumi.flood.agl02":
		return []haEntity{{"moisture", "binary_sensor", "moisture", "", "Water leak"}, battery}
	}
	return nil
}
func (d sensorDevice) id() string { return "4vrs_" + d.DID[5:] }
func (d sensorDevice) name() string {
	name := map[string]string{"lumi.motion.ac02": "Aqara P1", "lumi.sensor_motion.aq2": "Aqara Motion", "lumi.sensor_wleak.aq1": "Aqara Water Leak", "lumi.flood.agl02": "Aqara Water Leak T1"}[d.Model]
	if name == "" {
		name = d.Model
	}
	return name + " " + d.DID[len(d.DID)-6:]
}
func discoveryPayload(prefix string, d sensorDevice, e haEntity) map[string]any {
	v := map[string]any{
		"name": e.Name, "unique_id": d.id() + "_" + e.Key,
		"state_topic":       prefix + "/devices/" + d.DID + "/" + e.Key,
		"device_class":      e.Class,
		"availability":      []map[string]string{{"topic": prefix + "/bridge/availability"}, {"topic": prefix + "/bridge/local"}},
		"availability_mode": "all",
		"device":            map[string]any{"identifiers": []string{d.id()}, "name": d.name(), "manufacturer": "Aqara", "model": d.Model},
		"origin":            map[string]string{"name": "4VRS M2 Local", "sw_version": addonVersion},
	}
	if e.Domain == "binary_sensor" {
		v["payload_on"] = "ON"
		v["payload_off"] = "OFF"
	} else {
		v["unit_of_measurement"] = e.Unit
		v["state_class"] = "measurement"
	}
	if e.Key == "battery" {
		v["entity_category"] = "diagnostic"
	}
	if e.Key == "motion" {
		v["off_delay"] = 60
	}
	return v
}
func discoveryTopic(d sensorDevice, e haEntity) string {
	return "homeassistant/" + e.Domain + "/" + d.id() + "/" + e.Key + "/config"
}

// Ethernet identity remains stable across IP, MQTT prefix and client ID changes.
func hubIdentifier() string {
	iface, err := net.InterfaceByName("eth0")
	if err != nil || len(iface.HardwareAddr) != 6 {
		return ""
	}
	return "4vrs_m2_" + strings.ReplaceAll(iface.HardwareAddr.String(), ":", "")
}
func hubDiscoveryPayload(prefix, id string) map[string]any {
	return map[string]any{
		"name": "Zigbee connection", "unique_id": id + "_zigbee_connection",
		"device_class": "connectivity", "entity_category": "diagnostic",
		"state_topic": prefix + "/bridge/local", "payload_on": "online", "payload_off": "offline",
		"availability_topic": prefix + "/bridge/availability",
		"device":             map[string]any{"identifiers": []string{id}, "name": "Aqara M2", "manufacturer": "Aqara", "model": "Hub M2 (lumi.gateway.agl001)"},
		"origin":             map[string]string{"name": "4VRS M2 Local", "sw_version": addonVersion},
	}
}
func (h *haBridge) announceHub() {
	if h.hubID == "" {
		return
	}
	b, _ := json.Marshal(hubDiscoveryPayload(h.cfg.Prefix, h.hubID))
	h.publish("homeassistant/binary_sensor/"+h.hubID+"/zigbee_connection/config", b, true)
}

type haBridge struct {
	hubID      string
	mu         sync.Mutex
	cfg        Config
	client     mqtt.Client
	devices    map[string]sensorDevice
	states     map[string]string
	stopped    bool
	stop       chan struct{}
	preference func(string) devicePrefs
}

func newHABridge(c Config) *haBridge {
	h := &haBridge{hubID: hubIdentifier(), cfg: c, devices: map[string]sensorDevice{}, states: map[string]string{}, stop: make(chan struct{})}
	h.loadInventory()
	return h
}
func (h *haBridge) publish(topic string, value any, retained bool) {
	if h.client != nil && h.client.IsConnectionOpen() {
		h.client.Publish(topic, 1, retained, value)
	}
}
func (h *haBridge) announce(d sensorDevice) {
	for _, e := range entitiesFor(d.Model) {
		v := discoveryPayload(h.cfg.Prefix, d, e)
		if h.hubID != "" {
			v["device"].(map[string]any)["via_device"] = h.hubID
		}
		if h.preference != nil {
			p := h.preference(d.DID)
			if p.Name != "" {
				v["device"].(map[string]any)["name"] = p.Name
			}
			if e.Key == "motion" && p.MotionTimeout > 0 {
				v["off_delay"] = p.MotionTimeout
			}
		}
		b, _ := json.Marshal(v)
		h.publish(discoveryTopic(d, e), b, true)
	}
}
func (h *haBridge) loadInventory() {
	b, err := os.ReadFile(deviceInfoPath)
	if err != nil || len(b) > 1024*1024 {
		return
	}
	var data struct {
		Devices []sensorDevice `json:"devInfo"`
	}
	if json.Unmarshal(b, &data) != nil || data.Devices == nil || len(data.Devices) > 256 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return
	}
	next := map[string]sensorDevice{}
	for _, d := range data.Devices {
		if validDID.MatchString(d.DID) && len(entitiesFor(d.Model)) > 0 {
			next[d.DID] = d
		}
	}
	for id, d := range h.devices {
		if n, ok := next[id]; !ok || n.Model != d.Model {
			for _, e := range entitiesFor(d.Model) {
				h.publish(discoveryTopic(d, e), "", true)
				topic := h.cfg.Prefix + "/devices/" + d.DID + "/" + e.Key
				h.publish(topic, "", true)
				delete(h.states, topic)
			}
		}
	}
	for id, d := range next {
		if h.devices[id] != d {
			h.announce(d)
		}
	}
	h.devices = next
}
func (h *haBridge) connected(cl mqtt.Client) {
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return
	}
	h.client = cl
	// Local MQTT may not yet be subscribed; never announce readiness prematurely.
	h.publish(h.cfg.Prefix+"/bridge/availability", "online", true)
	h.announceHub()
	for _, d := range h.devices {
		h.announce(d)
	}
	for topic, value := range h.states {
		h.publish(topic, value, true)
	}
	h.mu.Unlock()
	cl.Subscribe("homeassistant/status", 0, func(_ mqtt.Client, m mqtt.Message) {
		if string(m.Payload()) == "online" {
			go h.reannounce()
		}
	})
}
func (h *haBridge) reannounce() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return
	}
	h.announceHub()
	for _, d := range h.devices {
		h.announce(d)
	}
	for topic, value := range h.states {
		h.publish(topic, value, true)
	}
}
func (h *haBridge) localReady(ready bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return
	}
	value := "offline"
	if ready {
		value = "online"
	}
	topic := h.cfg.Prefix + "/bridge/local"
	h.states[topic] = value
	h.publish(topic, value, true)
}
func (h *haBridge) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return
	}
	h.stopped = true
	close(h.stop)
	// Explicit offline for clean disconnects; LWT covers connection loss.
	if h.client != nil && h.client.IsConnectionOpen() {
		t := h.client.Publish(h.cfg.Prefix+"/bridge/availability", 1, true, "offline")
		t.WaitTimeout(2 * time.Second)
	}
}
func (h *haBridge) watch() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			h.loadInventory()
		}
	}
}

type lumiParam struct {
	Resource string          `json:"res_name"`
	Value    json.RawMessage `json:"value"`
	Error    int             `json:"error_code"`
}
type lumiMessage struct {
	Cmd    string          `json:"cmd"`
	DID    string          `json:"did"`
	Params json.RawMessage `json:"params"`
}

func number(raw json.RawMessage) (float64, bool) {
	var n float64
	if json.Unmarshal(raw, &n) == nil && string(raw) != "null" {
		return n, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		n, err := strconv.ParseFloat(s, 64)
		return n, err == nil
	}
	return 0, false
}
func decodeSensor(model, cmd string, params []lumiParam) map[string]string {
	out := map[string]string{}
	supported := entitiesFor(model)
	if len(supported) == 0 {
		return out
	}
	lux := -1.0
	for _, p := range params {
		if p.Error != 0 {
			continue
		}
		n, ok := number(p.Value)
		if !ok {
			continue
		}
		if p.Resource == "8.0.2001" && n >= 0 && n <= 100 {
			out["battery"] = strconv.FormatFloat(n, 'f', -1, 64)
		}
		if cmd != "report" {
			continue
		} // Heartbeat zero lux/motion is not a new measurement.
		if p.Resource == "3.1.85" && (n == 0 || n == 1) {
			key := "motion"
			if model == "lumi.sensor_wleak.aq1" || model == "lumi.flood.agl02" {
				key = "moisture"
			}
			value := "OFF"
			if n == 1 {
				value = "ON"
			}
			out[key] = value
		}
		if model == "lumi.motion.ac02" || model == "lumi.sensor_motion.aq2" {
			if p.Resource == "0.4.85" && n >= 0 {
				out["illuminance"] = strconv.FormatFloat(n, 'f', -1, 64)
			}
			if p.Resource == "0.3.85" && n >= 0 {
				lux = n
			}
		}
	}
	if _, ok := out["illuminance"]; !ok && lux >= 0 {
		out["illuminance"] = fmt.Sprint(lux)
	}
	return out
}
func (h *haBridge) process(payload []byte) {
	var m lumiMessage
	if json.Unmarshal(payload, &m) != nil {
		return
	}
	type report struct {
		did    string
		params []lumiParam
	}
	var reports []report
	switch m.Cmd {
	case "report":
		var p []lumiParam
		if json.Unmarshal(m.Params, &p) != nil {
			return
		}
		reports = append(reports, report{m.DID, p})
	case "heartbeat":
		var items []struct {
			DID    string      `json:"did"`
			Params []lumiParam `json:"res_list"`
		}
		if json.Unmarshal(m.Params, &items) != nil {
			return
		}
		for _, item := range items {
			reports = append(reports, report{item.DID, item.Params})
		}
	default:
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return
	}
	for _, r := range reports {
		d, ok := h.devices[r.did]
		if !ok {
			continue
		}
		for key, value := range decodeSensor(d.Model, m.Cmd, r.params) {
			topic := h.cfg.Prefix + "/devices/" + d.DID + "/" + key
			retain := key != "motion"
			if retain {
				h.states[topic] = value
			}
			h.publish(topic, value, retain)
		}
	}
}
