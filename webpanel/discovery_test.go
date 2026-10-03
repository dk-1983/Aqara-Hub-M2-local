package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscovery127Sensors(t *testing.T) {
	old := deviceInfoPath
	deviceInfoPath = filepath.Join(t.TempDir(), "device.info")
	defer func() { deviceInfoPath = old }()
	devices := make([]sensorDevice, 127)
	for i := range devices {
		devices[i] = sensorDevice{DID: fmt.Sprintf("lumi.%016x", i+1), Model: "lumi.motion.ac02"}
	}
	data, _ := json.Marshal(map[string]any{"devInfo": devices})
	if err := os.WriteFile(deviceInfoPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	h := newHABridge(Config{Prefix: "aqara/test"})
	defer h.close()
	if len(h.devices) != 127 {
		t.Fatal("inventory truncated", len(h.devices))
	}
	ids := map[string]bool{}
	for _, d := range devices {
		for _, e := range entitiesFor(d.Model) {
			v := discoveryPayload("aqara/test", d, e)
			id := v["unique_id"].(string)
			if ids[id] {
				t.Fatal("duplicate identity", id)
			}
			ids[id] = true
		}
		h.process([]byte(fmt.Sprintf(`{"cmd":"report","did":%q,"params":[{"res_name":"3.1.85","value":1},{"res_name":"0.4.85","value":40},{"res_name":"8.0.2001","value":89}]}`, d.DID)))
	}
	if len(ids) != 381 || len(h.states) != 254 {
		t.Fatal(len(ids), len(h.states))
	}
	t.Logf("127 devices, %d unique entities, %d cached values; inventory JSON %d bytes (not a radio or RAM stress test)", len(ids), len(h.states), len(data))
}

func params(raw string) []lumiParam { var p []lumiParam; json.Unmarshal([]byte(raw), &p); return p }
func TestSensorSemantics(t *testing.T) {
	p := params(`[{"res_name":"3.1.85","value":1},{"res_name":"0.3.85","value":40},{"res_name":"0.4.85","value":41},{"res_name":"8.0.2001","value":89}]`)
	motion := decodeSensor("lumi.motion.ac02", "report", p)
	if motion["motion"] != "ON" || motion["illuminance"] != "41" || motion["battery"] != "89" {
		t.Fatal(motion)
	}
	leak := decodeSensor("lumi.sensor_wleak.aq1", "report", p)
	if leak["moisture"] != "ON" || leak["motion"] != "" || leak["illuminance"] != "" {
		t.Fatal(leak)
	}
	dry := decodeSensor("lumi.sensor_wleak.aq1", "report", params(`[{"res_name":"3.1.85","value":0}]`))
	if dry["moisture"] != "OFF" {
		t.Fatal(dry)
	}
	if len(decodeSensor("unknown", "report", p)) != 0 {
		t.Fatal("unknown device decoded")
	}
	heartbeat := decodeSensor("lumi.motion.ac02", "heartbeat", p)
	if len(heartbeat) != 1 || heartbeat["battery"] != "89" {
		t.Fatal(heartbeat)
	}
	invalid := decodeSensor("lumi.motion.ac02", "report", params(`[{"res_name":"3.1.85","value":2},{"res_name":"8.0.2001","value":101},{"res_name":"0.4.85","value":20,"error_code":1}]`))
	if len(invalid) != 0 {
		t.Fatal(invalid)
	}
}
func TestDiscoveryAndMultiHeartbeat(t *testing.T) {
	old := deviceInfoPath
	deviceInfoPath = filepath.Join(t.TempDir(), "device.info")
	defer func() { deviceInfoPath = old }()
	os.WriteFile(deviceInfoPath, []byte(`{"devInfo":[{"did":"lumi.54ef441000bf1a3e","model":"lumi.motion.ac02"},{"did":"lumi.158d000af040a0","model":"lumi.sensor_wleak.aq1"},{"did":"bad/+/id","model":"lumi.motion.ac02"}]}`), 0600)
	h := newHABridge(Config{Prefix: "aqara/test"})
	defer h.close()
	if len(h.devices) != 2 {
		t.Fatal(h.devices)
	}
	h.process([]byte(`{"cmd":"heartbeat","params":[{"did":"lumi.54ef441000bf1a3e","res_list":[{"res_name":"8.0.2001","value":90},{"res_name":"0.3.85","value":0}]},{"did":"lumi.158d000af040a0","res_list":[{"res_name":"8.0.2001","value":70}]}]}`))
	if len(h.states) != 2 || h.states["aqara/test/devices/lumi.158d000af040a0/battery"] != "70" {
		t.Fatal(h.states)
	}
	h.process([]byte(`{"cmd":"report","did":"lumi.54ef441000bf1a3e","params":[{"res_name":"3.1.85","value":1},{"res_name":"0.3.85","value":40}]}`))
	if len(h.states) != 3 {
		t.Fatal("motion must not be cached for replay", h.states)
	}
	d := h.devices["lumi.54ef441000bf1a3e"]
	v := discoveryPayload("aqara/test", d, entitiesFor(d.Model)[0])
	if v["off_delay"] != 60 || v["availability_mode"] != "all" {
		t.Fatal(v)
	}
	v2 := discoveryPayload("other/prefix", d, entitiesFor(d.Model)[0])
	if v["unique_id"] != v2["unique_id"] {
		t.Fatal("unstable identity")
	}
	os.WriteFile(deviceInfoPath, []byte(`{"devInfo":[]}`), 0600)
	h.loadInventory()
	if len(h.devices) != 0 || len(h.states) != 0 {
		t.Fatal("removed sensor retained", h.states)
	}
}

func TestHubDiscovery(t *testing.T) {
	id := "4vrs_m2_001122334455"
	v := hubDiscoveryPayload("aqara/test", id)
	if v["state_topic"] != "aqara/test/bridge/local" || v["availability_topic"] != "aqara/test/bridge/availability" || v["payload_off"] != "offline" {
		t.Fatal(v)
	}
	if v["device"].(map[string]any)["identifiers"].([]string)[0] != id {
		t.Fatal(v)
	}
	if v["unique_id"] != hubDiscoveryPayload("changed/prefix", id)["unique_id"] {
		t.Fatal("hub identity changed with prefix")
	}
}
