package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
)

type authRecord struct {
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}

func (a *App) loadAuth() error {
	b, e := os.ReadFile(filepath.Join(a.dir, "auth.sha256"))
	if e != nil {
		return e
	}
	var rec authRecord
	if json.Unmarshal(b, &rec) == nil && rec.Iterations == 100000 {
		salt, e := hex.DecodeString(rec.Salt)
		if e != nil || len(salt) != 16 {
			return errors.New("invalid salt")
		}
		hash, e := hex.DecodeString(rec.Hash)
		if e != nil || len(hash) != 32 {
			return errors.New("invalid hash")
		}
		a.authSalt = salt
		a.authRounds = rec.Iterations
		copy(a.auth[:], hash)
		return nil
	}
	hash, e := hex.DecodeString(string(b))
	if e != nil || len(hash) != 32 {
		return errors.New("invalid initial identity")
	}
	copy(a.auth[:], hash)
	return nil
}
func (a *App) passwordOKLocked(p string) bool {
	if len(p) > 512 {
		return false
	}
	sum := sha256.Sum256([]byte(p))
	if a.authCached && subtle.ConstantTimeCompare(sum[:], a.authCache[:]) == 1 {
		return true
	}
	candidate := sum[:]
	if a.authRounds > 0 {
		var e error
		candidate, e = pbkdf2.Key(sha256.New, p, a.authSalt, a.authRounds, 32)
		if e != nil {
			return false
		}
	}
	if subtle.ConstantTimeCompare(candidate, a.auth[:]) != 1 {
		return false
	}
	a.authCache = sum
	a.authCached = true
	return true
}
func (a *App) passwordOK(p string) bool {
	a.authMu.Lock()
	defer a.authMu.Unlock()
	return a.passwordOKLocked(p)
}
func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method", 405)
		return
	}
	var v struct {
		Current string `json:"current"`
		New     string `json:"new"`
		Repeat  string `json:"repeat"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		http.Error(w, "Некорректный запрос", 400)
		return
	}
	if len([]rune(v.New)) < 12 || len(v.New) > 256 || v.New != v.Repeat {
		http.Error(w, "Нужно не менее 12 символов; новый пароль и повтор должны совпадать", 400)
		return
	}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if !a.passwordOKLocked(v.Current) {
		http.Error(w, "Текущий пароль неверен", 400)
		return
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		http.Error(w, "Не удалось создать соль", 500)
		return
	}
	hash, e := pbkdf2.Key(sha256.New, v.New, salt, 100000, 32)
	if e != nil {
		http.Error(w, "Ошибка пароля", 500)
		return
	}
	b, _ := json.Marshal(authRecord{hex.EncodeToString(salt), hex.EncodeToString(hash), 100000})
	if e = atomicWrite(filepath.Join(a.dir, "auth.sha256"), b); e != nil {
		http.Error(w, "Пароль не изменён: ошибка записи", 500)
		return
	}
	a.authSalt = salt
	a.authRounds = 100000
	copy(a.auth[:], hash)
	a.authCached = false
	writeJSON(w, map[string]any{"ok": true, "message": "Пароль панели изменён. Войдите заново с новым паролем. Системный пароль root не изменялся."})
}
