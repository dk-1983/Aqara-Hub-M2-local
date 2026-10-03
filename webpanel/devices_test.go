package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func managerForTest(t *testing.T) (*App, *deviceManager) {
	t.Helper()
	old := deviceInfoPath
	deviceInfoPath = filepath.Join(t.TempDir(), "device.info")
	t.Cleanup(func() { deviceInfoPath = old })
	os.WriteFile(deviceInfoPath, []byte(`{"devInfo":[{"did":"lumi.54ef441000bf1a3e","model":"lumi.motion.ac02"},{"did":"lumi.158d000af040a0","model":"lumi.sensor_wleak.aq1"}]}`), 0600)
	a := testApp(t)
	d, e := newDeviceManager(a.dir)
	if e != nil {
		t.Fatal(e)
	}
	a.devices = d
	d.send = func([]byte) error { return nil }
	return a, d
}
func TestDeviceCommandsAwaitActualAck(t *testing.T) {
	_, d := managerForTest(t)
	c, e := d.issue("lumi.54ef441000bf1a3e", "8.0.2115", 10)
	if e != nil {
		t.Fatal(e)
	}
	rsp := map[string]any{"cmd": "write_rsp", "id": c.ID, "did": c.DID, "results": []map[string]any{{"res_name": c.Resource, "value": 10, "error_code": 0}}}
	b, _ := json.Marshal(rsp)
	d.process(b)
	if d.commands[c.ID].Status != "accepted" {
		t.Fatal(d.commands[c.ID])
	}
	if _, ok := d.parameters[c.DID]["detection_interval"]; ok {
		t.Fatal("write_rsp treated as sensor state")
	}
	rsp["cmd"] = "write_ack"
	rsp["params"] = rsp["results"]
	delete(rsp, "results")
	rsp["id"] = c.ID + 1
	b, _ = json.Marshal(rsp)
	d.process(b)
	if d.commands[c.ID].Status != "accepted" {
		t.Fatal("unrelated ack confirmed command")
	}
	rsp["id"] = c.ID
	b, _ = json.Marshal(rsp)
	d.process(b)
	if d.commands[c.ID].Status != "confirmed" || d.parameters[c.DID]["detection_interval"] != 10 {
		t.Fatal(d.commands[c.ID])
	}
	c, _ = d.issue(c.DID, c.Resource, 30)
	d.process([]byte(`{"cmd":"report","did":"lumi.158d000af040a0","params":[{"res_name":"8.0.2115","value":30}]}`))
	if d.commands[c.ID].Status != "pending" {
		t.Fatal("wrong device confirmed command")
	}
	d.commands[c.ID].Created = time.Now().Add(-2 * time.Minute)
	d.expire()
	if d.commands[c.ID].Status != "unconfirmed" {
		t.Fatal("timeout")
	}
}
func TestDevicePreferencesAndGuards(t *testing.T) {
	a, d := managerForTest(t)
	w := req(a, "POST", "/api/devices/preferences", `{"did":"lumi.54ef441000bf1a3e","name":"Hall P1","motion_timeout":75}`, true, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	fresh, e := newDeviceManager(a.dir)
	if e != nil || fresh.preference("lumi.54ef441000bf1a3e").MotionTimeout != 75 {
		t.Fatal("persistence", e)
	}
	for _, body := range []string{`{"did":"lumi.158d000af040a0","parameter":"sensitivity","value":3}`, `{"did":"lumi.54ef441000bf1a3e","parameter":"identify","value":1}`, `{"did":"lumi.54ef441000bf1a3e","parameter":"detection_interval","value":20}`} {
		if w := req(a, "POST", "/api/devices/parameter", body, true, true); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if len(d.commands) != 0 {
		t.Fatal("invalid requests sent commands")
	}
	if w := req(a, "POST", "/api/devices/pair", `{"seconds":60}`, true, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := req(a, "POST", "/api/devices/pair", `{"seconds":60}`, false, true); w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestPairingConfirmationAndFailure(t *testing.T) {
	a, d := managerForTest(t)
	w := req(a, "POST", "/api/devices/pair", `{"seconds":60}`, true, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var c deviceCommand
	json.Unmarshal(w.Body.Bytes(), &c)
	rsp := map[string]any{"cmd": "write_rsp", "did": "lumi.0", "id": c.ID, "results": []map[string]any{{"res_name": "8.0.2109", "value": 60, "error_code": 0}}}
	b, _ := json.Marshal(rsp)
	d.process(b)
	if d.pairing.Status != "open" || d.pairing.Until.Before(time.Now()) {
		t.Fatal(d.pairing)
	}
	if w := req(a, "POST", "/api/devices/pair", `{"seconds":60}`, true, true); w.Code != 409 {
		t.Fatal("duplicate opening accepted")
	}
	w = req(a, "POST", "/api/devices/pair", `{"seconds":0}`, true, true)
	json.Unmarshal(w.Body.Bytes(), &c)
	rsp["id"] = c.ID
	rsp["results"] = []map[string]any{{"res_name": "8.0.2109", "value": 0, "error_code": 0}}
	b, _ = json.Marshal(rsp)
	d.process(b)
	if d.pairing.Status != "closed" {
		t.Fatal("cancel not confirmed", d.pairing)
	}
	d.send = func([]byte) error { return errors.New("offline") }
	if w := req(a, "POST", "/api/devices/pair", `{"seconds":60}`, true, true); w.Code != 502 {
		t.Fatal(w.Code)
	}
	if d.pairing.Status == "open" {
		t.Fatal("false success")
	}
}

func TestP1Intervals(t *testing.T) {
	for _, value := range []int{10, 30, 60, 120, 180} {
		a, d := managerForTest(t)
		body, _ := json.Marshal(map[string]any{"did": "lumi.54ef441000bf1a3e", "parameter": "detection_interval", "value": value})
		w := req(a, "POST", "/api/devices/parameter", string(body), true, true)
		if w.Code != 200 {
			t.Fatal(value, w.Code, w.Body.String())
		}
		for _, c := range d.commands {
			if c.Resource != "8.0.2115" || c.Value != value {
				t.Fatal(c)
			}
		}
	}
}

func TestRemovalRequiresConfirmationAndCompletion(t *testing.T) {
	a, d := managerForTest(t)
	did := "lumi.158d000af040a0"
	body := `{"did":"` + did + `","confirm":"` + did + `"}`
	sent := 0
	d.send = func(b []byte) error {
		sent++
		var command struct {
			Cmd    string `json:"cmd"`
			DID    string `json:"did"`
			Params []struct {
				Resource string `json:"res_name"`
				Value    string `json:"value"`
			} `json:"params"`
		}
		if json.Unmarshal(b, &command) != nil || command.Cmd != "write" || command.DID != "lumi.0" || len(command.Params) != 1 || command.Params[0].Resource != "8.0.2082" || command.Params[0].Value != did {
			t.Fatal(string(b))
		}
		return nil
	}
	for _, tc := range []struct {
		body       string
		auth, csrf bool
		status     int
	}{
		{body, false, true, 401}, {body, true, false, 403}, {`{"did":"` + did + `"}`, true, true, 400},
		{`{"did":"lumi.0","confirm":"lumi.0"}`, true, true, 400},
		{`{"did":"lumi.1234567890","confirm":"lumi.1234567890"}`, true, true, 404},
	} {
		if w := req(a, "POST", "/api/devices/remove", tc.body, tc.auth, tc.csrf); w.Code != tc.status {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if sent != 0 {
		t.Fatal("unsafe request published")
	}
	w := req(a, "POST", "/api/devices/remove", body, true, true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	r := d.removals[did]
	if w = req(a, "POST", "/api/devices/remove", body, true, true); w.Code != 409 || sent != 1 {
		t.Fatal("duplicate deletion")
	}
	b, _ := json.Marshal(map[string]any{"cmd": "write_rsp", "did": "lumi.0", "id": r.ID, "results": []map[string]any{{"res_name": "8.0.2082", "value": did, "error_code": 0}}})
	d.process(b)
	if r.Status != "accepted" {
		t.Fatal(r)
	}
	report := func(target string) {
		value, _ := json.Marshal(map[string]any{"type": 2, "did": target})
		b, _ := json.Marshal(map[string]any{"cmd": "report", "did": "lumi.0", "params": []map[string]any{{"res_name": "8.0.2338", "value": string(value)}}})
		d.process(b)
	}
	report("lumi.1234567890")
	if r.eventSeen {
		t.Fatal("wrong device matched")
	}
	report(did)
	d.refreshInventory()
	if r.Status == "confirmed" {
		t.Fatal("device still present")
	}
	os.WriteFile(deviceInfoPath, []byte(`{"devInfo":[{"did":"lumi.54ef441000bf1a3e","model":"lumi.motion.ac02"}]}`), 0600)
	d.refreshInventory()
	if r.Status != "confirmed" {
		t.Fatal(r)
	}
	if w = req(a, "POST", "/api/devices/remove", body, true, true); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestRemovalInventoryAloneIsNotSuccess(t *testing.T) {
	a, d := managerForTest(t)
	did := "lumi.158d000af040a0"
	req(a, "POST", "/api/devices/remove", `{"did":"`+did+`","confirm":"`+did+`"}`, true, true)
	r := d.removals[did]
	os.WriteFile(deviceInfoPath, []byte(`{"devInfo":[]}`), 0600)
	d.refreshInventory()
	if r.Status == "confirmed" {
		t.Fatal("absence alone")
	}
	r.Created = time.Now().Add(-2 * time.Minute)
	d.expire()
	if r.Status != "unconfirmed" || d.pairing.Status != "" {
		t.Fatal(r, d.pairing)
	}
	value, _ := json.Marshal(map[string]any{"type": 2, "did": did})
	b, _ := json.Marshal(map[string]any{"cmd": "report", "did": "lumi.0", "params": []map[string]any{{"res_name": "8.0.2338", "value": string(value)}}})
	d.process(b)
	d.refreshInventory()
	if r.Status != "confirmed" {
		t.Fatal("late confirmation", r)
	}
}
func TestRemovalFailures(t *testing.T) {
	a, d := managerForTest(t)
	did := "lumi.158d000af040a0"
	body := `{"did":"` + did + `","confirm":"` + did + `"}`
	d.send = func([]byte) error { return errors.New("offline") }
	if w := req(a, "POST", "/api/devices/remove", body, true, true); w.Code != 502 {
		t.Fatal(w.Code)
	}
	if d.removals[did].Status != "failed" {
		t.Fatal("offline")
	}
	d.send = func([]byte) error { return nil }
	req(a, "POST", "/api/devices/remove", body, true, true)
	r := d.removals[did]
	b, _ := json.Marshal(map[string]any{"cmd": "write_rsp", "did": "lumi.0", "id": r.ID, "results": []map[string]any{{"res_name": "8.0.2082", "value": did, "error_code": 7}}})
	d.process(b)
	if r.Status != "failed" {
		t.Fatal(r)
	}
}
