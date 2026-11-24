package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testIterations keeps the tests fast; the file format records the count.
const testIterations = 10

func testAuth(t *testing.T) (*Auth, *time.Time) {
	t.Helper()
	salt := []byte("0123456789abcdef")
	hash, err := derive("correct horse", salt, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := SetPassword(path, "admin", "placeholder"); err != nil {
		t.Fatal(err)
	}
	credentials, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuth(credentials, path)
	if err != nil {
		t.Fatal(err)
	}
	a.salt, a.hash, a.credentials.Iterations = salt, hash, testIterations
	now := time.Unix(1000, 0)
	a.now = func() time.Time { return now }
	return a, &now
}

func TestPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "auth.json")
	if err := SetPassword(path, "admin", "short"); err == nil {
		t.Fatal("a short password was accepted")
	}
	if err := SetPassword(path, "admin", "long enough"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, err = %v", info.Mode(), err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "long enough") {
		t.Fatal("the password is stored in clear")
	}
	credentials, err := LoadCredentials(path)
	if err != nil || credentials.Iterations != hashIterations {
		t.Fatalf("%+v %v", credentials, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("a file readable by others was accepted")
	}
}

func TestLoginAndSessionLife(t *testing.T) {
	a, now := testAuth(t)
	if _, err := a.Login("admin", "wrong", "1.1.1.1"); !errors.Is(err, errBadLogin) {
		t.Fatalf("err = %v", err)
	}
	if _, err := a.Login("nobody", "correct horse", "1.1.1.1"); !errors.Is(err, errBadLogin) {
		t.Fatalf("err = %v", err)
	}
	token, err := a.Login("admin", "correct horse", "1.1.1.1")
	if err != nil || !a.Valid(token) {
		t.Fatalf("token %q err %v", token, err)
	}
	if a.Valid("forged") || a.Valid("") {
		t.Fatal("a forged token was accepted")
	}
	*now = now.Add(sessionIdle - time.Minute)
	if !a.Valid(token) {
		t.Fatal("expired while in use")
	}
	*now = now.Add(sessionIdle - time.Minute) // use extended it
	if !a.Valid(token) {
		t.Fatal("use did not extend the session")
	}
	*now = now.Add(sessionIdle + time.Minute)
	if a.Valid(token) {
		t.Fatal("an idle session survived")
	}
	token, _ = a.Login("admin", "correct horse", "1.1.1.1")
	a.Logout(token)
	if a.Valid(token) {
		t.Fatal("a logged out session survived")
	}
}

func TestRepeatedFailuresLockAnAddressOut(t *testing.T) {
	a, now := testAuth(t)
	for i := 0; i < failureLimit; i++ {
		if _, err := a.Login("admin", "wrong", "1.1.1.1"); !errors.Is(err, errBadLogin) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := a.Login("admin", "correct horse", "1.1.1.1"); !errors.Is(err, errLocked) {
		t.Fatalf("err = %v", err)
	}
	if _, err := a.Login("admin", "correct horse", "2.2.2.2"); err != nil {
		t.Fatalf("another address was locked out: %v", err)
	}
	*now = now.Add(failureLockout + time.Second)
	if _, err := a.Login("admin", "correct horse", "1.1.1.1"); err != nil {
		t.Fatalf("still locked: %v", err)
	}
}

func TestConcurrentPasswordChecksAreRefused(t *testing.T) {
	a, _ := testAuth(t)
	a.hashing <- struct{}{}
	defer func() { <-a.hashing }()
	if _, err := a.Login("admin", "correct horse", "1.1.1.1"); !errors.Is(err, errBusy) {
		t.Fatalf("err = %v", err)
	}
}

func TestSessionLimit(t *testing.T) {
	a, now := testAuth(t)
	first, _ := a.Login("admin", "correct horse", "1.1.1.1")
	for i := 0; i < sessionLimit+5; i++ {
		*now = now.Add(time.Second)
		if _, err := a.Login("admin", "correct horse", "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.sessions) > sessionLimit {
		t.Fatalf("%d sessions", len(a.sessions))
	}
	if a.sessions[sha256.Sum256([]byte(first))] != (time.Time{}) {
		t.Fatal("the oldest session was kept")
	}
}

func wrapped(a *Auth) http.Handler {
	return a.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("inner " + r.URL.Path))
	}))
}

func request(h http.Handler, method, path, body, cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "9.9.9.9:1234"
	r.Host = "panel:9480"
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestEverythingExceptLoginNeedsASession(t *testing.T) {
	a, _ := testAuth(t)
	h := wrapped(a)
	if w := request(h, "GET", "/", "", "", ""); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login.html" {
		t.Fatalf("/ = %d %v", w.Code, w.Header())
	}
	for _, path := range []string{"/api/status", "/api/nat", "/api/series?range=60&key=x"} {
		if w := request(h, "GET", path, "", "", ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d", path, w.Code)
		}
	}
	for _, path := range []string{"/login.html", "/login.js", "/style.css"} {
		if w := request(h, "GET", path, "", "", ""); w.Code != http.StatusOK {
			t.Errorf("%s = %d", path, w.Code)
		}
	}
	if w := request(h, "GET", "/index.html", "", "", ""); w.Code != http.StatusSeeOther {
		t.Errorf("/index.html = %d", w.Code)
	}
}

func TestLoginFlow(t *testing.T) {
	a, _ := testAuth(t)
	h := wrapped(a)
	if w := request(h, "POST", "/api/login", `{"user":"admin","password":"nope"}`, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", w.Code)
	}
	w := request(h, "POST", "/api/login", `{"user":"admin","password":"correct horse"}`, "", "https://panel:9480")
	if w.Code != http.StatusNoContent {
		t.Fatalf("login = %d %s", w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie = %+v", cookie)
	}
	if w := request(h, "GET", "/api/status", "", cookie.Value, ""); w.Code != http.StatusOK || w.Body.String() != "inner /api/status" {
		t.Fatalf("status = %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/api/logout", "", cookie.Value, ""); w.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", w.Code)
	}
	if w := request(h, "GET", "/api/status", "", cookie.Value, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("after logout = %d", w.Code)
	}
}

func TestPasswordChange(t *testing.T) {
	a, _ := testAuth(t)
	h := wrapped(a)
	login := func(password string) string {
		w := request(h, "POST", "/api/login", `{"user":"admin","password":"`+password+`"}`, "", "")
		if w.Code != http.StatusNoContent {
			return ""
		}
		return w.Result().Cookies()[0].Value
	}
	mine, other := login("correct horse"), login("correct horse")
	if mine == "" || other == "" {
		t.Fatal("login failed")
	}
	if w := request(h, "POST", "/api/password", `{"current":"correct horse","password":"new one here"}`, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("without a session = %d", w.Code)
	}
	if w := request(h, "POST", "/api/password", `{"current":"wrong","password":"new one here"}`, mine, ""); w.Code != http.StatusForbidden {
		t.Fatalf("wrong current = %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/api/password", `{"current":"correct horse","password":"short"}`, mine, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("short = %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/api/password", `{"current":"correct horse","password":"new one here"}`, mine, ""); w.Code != http.StatusNoContent {
		t.Fatalf("change = %d %s", w.Code, w.Body)
	}
	if !a.Valid(mine) || a.Valid(other) {
		t.Fatal("the changing session must stay and the others end")
	}
	if login("correct horse") != "" || login("new one here") == "" {
		t.Fatal("the new password is not the one in use")
	}
	stored, err := LoadCredentials(a.path)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewAuth(stored, a.path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := fresh.check("admin", "new one here"); err != nil || !ok {
		t.Fatalf("the file does not hold the new password: %v %v", ok, err)
	}
}

func TestWrongCurrentPasswordCountsAsAFailure(t *testing.T) {
	a, _ := testAuth(t)
	token, err := a.Login("admin", "correct horse", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < failureLimit; i++ {
		if err := a.ChangePassword(token, "guess", "new one here", "1.2.3.4"); !errors.Is(err, errBadLogin) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := a.ChangePassword(token, "correct horse", "new one here", "1.2.3.4"); !errors.Is(err, errLocked) {
		t.Fatalf("after %d wrong guesses: %v", failureLimit, err)
	}
}

func TestCrossOriginWritesAreRefused(t *testing.T) {
	a, _ := testAuth(t)
	h := wrapped(a)
	token, _ := a.Login("admin", "correct horse", "1.1.1.1")
	if w := request(h, "POST", "/api/change", "", token, "https://evil.example"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin = %d", w.Code)
	}
	if w := request(h, "POST", "/api/login", `{}`, "", "https://evil.example"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login = %d", w.Code)
	}
	if w := request(h, "POST", "/api/change", "", token, "https://panel:9480"); w.Code != http.StatusOK {
		t.Fatalf("same origin = %d", w.Code)
	}
	if w := request(h, "GET", "/api/status", "", token, ""); w.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("headers = %v", w.Header())
	}
}

func TestCertificateIsCreatedOnceAndUsable(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := ensureCertificate(cert, key, "192.0.2.7:9480"); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(cert)
	if err := ensureCertificate(cert, key, "192.0.2.7:9480"); err != nil {
		t.Fatal(err)
	}
	if second, _ := os.ReadFile(cert); string(first) != string(second) {
		t.Fatal("the certificate was replaced")
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(key); info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", info.Mode())
	}
	block, _ := pem.Decode(first)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifyHostname("192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	os.Remove(key)
	if err := ensureCertificate(cert, key, "192.0.2.7:9480"); err == nil {
		t.Fatal("a certificate without its key was accepted")
	}
}

func TestWildcardListenCoversLocalAddresses(t *testing.T) {
	ips, _ := certificateNames("0.0.0.0:9480")
	if len(ips) < 2 || !containsIP(ips, net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("ips = %v", ips)
	}
}

func containsIP(ips []net.IP, wanted net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(wanted) {
			return true
		}
	}
	return false
}
