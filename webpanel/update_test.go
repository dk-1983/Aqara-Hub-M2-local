package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func updateArchive(t *testing.T, mutate func(map[string][]byte), extra *tar.Header) ([]byte, string) {
	t.Helper()
	header := make([]byte, 64)
	copy(header, []byte{127, 'E', 'L', 'F', 1, 1})
	header[18] = 8
	manifest, _ := json.Marshal(releaseManifest{Format: 1, Version: "0.4.0", Platform: "linux/mipsle/softfloat", Model: "lumi.gateway.agl001", Firmware: "4.1.6_0018.0650"})
	files := map[string][]byte{"panel": header, "autostart.sh": []byte("#!/bin/sh\n# .web-update/transaction\n"), "manifest.json": manifest}
	if mutate != nil {
		mutate(files)
	}
	checks := ""
	for name, b := range files {
		checks += fmt.Sprintf("%x  %s\n", sha256.Sum256(b), name)
	}
	files["SHA256SUMS"] = []byte(checks)
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for name, b := range files {
		if e := tw.WriteHeader(&tar.Header{Name: "4vrs-m2/" + name, Size: int64(len(b)), Mode: 0600, Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		tw.Write(b)
	}
	if extra != nil {
		if e := tw.WriteHeader(extra); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(out.Bytes())
	return out.Bytes(), hex.EncodeToString(sum[:])
}
func TestUpdatePackage(t *testing.T) {
	b, digest := updateArchive(t, nil, nil)
	dir := t.TempDir()
	p, e := unpackUpdate(bytes.NewReader(b), dir, digest)
	if e != nil || p.Version != "0.4.0" || p.Token == "" {
		t.Fatal(p, e)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatal("Only executable and supervisor should be retained")
	}
	cases := []struct {
		name   string
		mutate func(map[string][]byte)
		extra  *tar.Header
	}{
		{"wrong architecture", func(f map[string][]byte) { f["panel"][18] = 62 }, nil},
		{"wrong model", func(f map[string][]byte) {
			f["manifest.json"] = bytes.ReplaceAll(f["manifest.json"], []byte("lumi.gateway.agl001"), []byte("other"))
		}, nil},
		{"credentials", func(f map[string][]byte) { f["auth.sha256"] = []byte("secret") }, nil},
		{"traversal", nil, &tar.Header{Name: "4vrs-m2/../../config.json", Typeflag: tar.TypeReg}},
		{"symlink", nil, &tar.Header{Name: "4vrs-m2/LICENSE", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		{"duplicate", nil, &tar.Header{Name: "4vrs-m2/panel", Typeflag: tar.TypeReg}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			b, d := updateArchive(t, test.mutate, test.extra)
			if _, e := unpackUpdate(bytes.NewReader(b), t.TempDir(), d); e == nil {
				t.Fatal("accepted unsafe package")
			}
		})
	}
	if _, e := unpackUpdate(bytes.NewReader(b), t.TempDir(), strings.Repeat("0", 64)); e == nil {
		t.Fatal("wrong digest accepted")
	}
	corrupted := append([]byte{}, b...)
	corrupted[520] ^= 1
	if _, e := unpackUpdate(bytes.NewReader(corrupted), t.TempDir(), digest); e == nil {
		t.Fatal("corrupt package accepted")
	}
}
func TestUpdateEndpointsProtected(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/api/update/upload", "/api/update/apply", "/api/update/cancel"} {
		if w := req(a, "POST", path, "{}", false, true); w.Code != 401 {
			t.Fatal(path, w.Code)
		}
		if w := req(a, "POST", path, "{}", true, false); w.Code != 403 {
			t.Fatal(path, w.Code)
		}
	}
	os.Mkdir(filepath.Join(a.dir, ".web-update"), 0700)
	os.WriteFile(filepath.Join(a.dir, ".web-update", "transaction"), nil, 0600)
	if w := req(a, "POST", "/api/update/cancel", "{}", true, true); w.Code != 409 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", "http://hub/api/update/cancel", strings.NewReader("{}"))
	r.SetBasicAuth("admin", "panel-secret")
	r.Header.Set("X-Aqara-Panel", "1")
	r.Header.Set("Origin", "https://unrelated.test")
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("Cross-origin update action accepted")
	}
}
