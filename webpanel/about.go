package main

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func systemInfo() map[string]any {
	info := map[string]any{"addon": map[string]string{"name": "4VRS Add-ons", "version": addonVersion, "authors": "Дмитрий / 4VRS", "project": "Aqara-Hub-M2-local", "license": "MIT", "relationship": "Независимый проект; не официальная прошивка Aqara."}, "platform": runtime.GOOS + "/" + runtime.GOARCH}
	allow := map[string]bool{"ro.sys.name": true, "ro.sys.model": true, "ro.sys.product": true, "ro.sys.manufacturer": true, "ro.sys.vendor": true, "ro.sys.fw_ver": true, "ro.sys.build_num": true, "ro.sys.hw_ver": true}
	factory := map[string]string{}
	if b, e := os.ReadFile("/etc/build.prop"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && allow[k] {
				factory[k] = v
			}
		}
	}
	info["factory"] = factory
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if b, e := exec.CommandContext(ctx, "/bin/getprop", "persist.sys.model").Output(); e == nil {
		info["effective_model"] = strings.TrimSpace(string(b))
	}
	if b, e := os.ReadFile("/etc/version"); e == nil && len(b) < 8192 {
		info["sdk"] = strings.TrimSpace(string(b))
	}
	if b, e := os.ReadFile("/proc/sys/kernel/osrelease"); e == nil {
		info["kernel"] = strings.TrimSpace(string(b))
	}
	if b, e := os.ReadFile("/proc/cpuinfo"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok && (strings.TrimSpace(k) == "system type" || strings.TrimSpace(k) == "cpu model") {
				info[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return info
}
