package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie   = "vpp_monitor_session"
	sessionIdle     = 12 * time.Hour
	sessionLimit    = 256
	hashIterations  = 600000
	minPassword     = 8
	failureLimit    = 5
	failureWindow   = 15 * time.Minute
	failureLockout  = time.Minute
	failureAddrs    = 1024
	maxLoginRequest = 4096
)

// Credentials is the file that holds the one administrator's password hash.
type Credentials struct {
	User       string `json:"user"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Hash       string `json:"hash"`
}

func derive(password string, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
}

// SetPassword writes the credentials file atomically, readable only by its owner.
func SetPassword(path, user, password string) error {
	credentials, err := newCredentials(user, password)
	if err != nil {
		return err
	}
	return writeCredentials(path, credentials)
}

func newCredentials(user, password string) (*Credentials, error) {
	if user == "" {
		return nil, errors.New("the user name is empty")
	}
	if len(password) < minPassword {
		return nil, fmt.Errorf("the password must be at least %d characters", minPassword)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hash, err := derive(password, salt, hashIterations)
	if err != nil {
		return nil, err
	}
	return &Credentials{
		User: user, Iterations: hashIterations,
		Salt: base64.StdEncoding.EncodeToString(salt), Hash: base64.StdEncoding.EncodeToString(hash),
	}, nil
}

func writeCredentials(path string, credentials *Credentials) error {
	data, err := json.Marshal(credentials)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".auth-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path) // CreateTemp already made it 0600
}

// LoadCredentials refuses a file others can read, since it can be attacked offline.
func LoadCredentials(path string) (*Credentials, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var credentials Credentials
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if credentials.User == "" || credentials.Iterations <= 0 || credentials.Salt == "" || credentials.Hash == "" {
		return nil, fmt.Errorf("%s is incomplete", path)
	}
	return &credentials, nil
}

type failureRecord struct {
	count int
	first time.Time
	until time.Time
}

// Auth decides who may use the panel. Sessions live in memory: restarting logs everyone out.
type Auth struct {
	path    string // the credentials file, rewritten when the password changes in the panel
	now     func() time.Time
	hashing chan struct{} // one password check at a time, they are slow on purpose

	mu          sync.Mutex
	credentials Credentials
	salt, hash  []byte
	sessions    map[[sha256.Size]byte]time.Time
	failures    map[string]*failureRecord
}

func NewAuth(credentials *Credentials, path string) (*Auth, error) {
	salt, err := base64.StdEncoding.DecodeString(credentials.Salt)
	if err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	hash, err := base64.StdEncoding.DecodeString(credentials.Hash)
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	return &Auth{
		path: path, credentials: *credentials, salt: salt, hash: hash, now: time.Now,
		hashing:  make(chan struct{}, 1),
		sessions: make(map[[sha256.Size]byte]time.Time),
		failures: make(map[string]*failureRecord),
	}, nil
}

var (
	errBadLogin = errors.New("wrong user or password")
	errLocked   = errors.New("too many failed attempts")
	errBusy     = errors.New("busy checking another login")
)

// Login returns a new session token for correct credentials.
func (a *Auth) Login(user, password, address string) (string, error) {
	if a.lockedOut(address) {
		return "", errLocked
	}
	select {
	case a.hashing <- struct{}{}:
		defer func() { <-a.hashing }()
	default:
		return "", errBusy
	}
	// The hash runs for an unknown user too, so timing does not reveal which names exist.
	ok, err := a.check(user, password)
	if err != nil {
		return "", err
	}
	if !ok {
		a.recordFailure(address)
		return "", errBadLogin
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.failures, address)
	a.pruneSessions()
	encoded := base64.RawURLEncoding.EncodeToString(token)
	a.sessions[sha256.Sum256([]byte(encoded))] = a.now().Add(sessionIdle)
	return encoded, nil
}

// check compares a user and password with the stored ones. The caller holds a.hashing.
func (a *Auth) check(user, password string) (bool, error) {
	a.mu.Lock()
	stored, salt, hash := a.credentials, a.salt, a.hash
	a.mu.Unlock()
	derived, err := derive(password, salt, stored.Iterations)
	if err != nil {
		return false, err
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(stored.User)) == 1
	hashOK := subtle.ConstantTimeCompare(derived, hash) == 1
	return userOK && hashOK, nil
}

// User is the administrator's name.
func (a *Auth) User() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.credentials.User
}

var errShortPassword = fmt.Errorf("新密码至少 %d 个字符", minPassword)

// ChangePassword replaces the password after checking the current one, writes the
// credentials file and ends every session except the one that made the change.
func (a *Auth) ChangePassword(token, current, next, address string) error {
	if len(next) < minPassword {
		return errShortPassword
	}
	if a.lockedOut(address) {
		return errLocked
	}
	select {
	case a.hashing <- struct{}{}:
		defer func() { <-a.hashing }()
	default:
		return errBusy
	}
	user := a.User()
	ok, err := a.check(user, current)
	if err != nil {
		return err
	}
	if !ok {
		a.recordFailure(address)
		return errBadLogin
	}
	credentials, err := newCredentials(user, next)
	if err != nil {
		return err
	}
	salt, _ := base64.StdEncoding.DecodeString(credentials.Salt)
	hash, _ := base64.StdEncoding.DecodeString(credentials.Hash)
	if err := writeCredentials(a.path, credentials); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.credentials, a.salt, a.hash = *credentials, salt, hash
	delete(a.failures, address)
	keep := sha256.Sum256([]byte(token))
	for key := range a.sessions {
		if key != keep {
			delete(a.sessions, key)
		}
	}
	return nil
}

func (a *Auth) lockedOut(address string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	record := a.failures[address]
	return record != nil && a.now().Before(record.until)
}

func (a *Auth) recordFailure(address string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	record := a.failures[address]
	if record == nil || now.Sub(record.first) > failureWindow {
		if len(a.failures) >= failureAddrs {
			a.failures = make(map[string]*failureRecord)
		}
		record = &failureRecord{first: now}
		a.failures[address] = record
	}
	record.count++
	if record.count >= failureLimit {
		record.until = now.Add(failureLockout)
		record.count, record.first = 0, now
	}
}

// pruneSessions makes room for a new session, dropping the one closest to expiry if needed.
func (a *Auth) pruneSessions() {
	now := a.now()
	for key, expires := range a.sessions {
		if now.After(expires) {
			delete(a.sessions, key)
		}
	}
	if len(a.sessions) < sessionLimit {
		return
	}
	var oldest [sha256.Size]byte
	var soonest time.Time
	for key, expires := range a.sessions {
		if soonest.IsZero() || expires.Before(soonest) {
			oldest, soonest = key, expires
		}
	}
	delete(a.sessions, oldest)
}

// Valid checks a session token and extends the session.
func (a *Auth) Valid(token string) bool {
	if token == "" {
		return false
	}
	key := sha256.Sum256([]byte(token))
	a.mu.Lock()
	defer a.mu.Unlock()
	expires, ok := a.sessions[key]
	now := a.now()
	if !ok || now.After(expires) {
		delete(a.sessions, key)
		return false
	}
	a.sessions[key] = now.Add(sessionIdle)
	return true
}

// Logout ends a session.
func (a *Auth) Logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, sha256.Sum256([]byte(token)))
}

func remoteAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sameOrigin rejects requests a page on another site made the browser send. The Origin
// header is sent with such requests and scripts cannot change it.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Browsers send it on every unsafe cross-site request; other clients are not at risk.
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host == r.Host
}

func publicPath(path string) bool {
	switch path {
	case "/login.html", "/login.js", "/style.css", "/api/login":
		return true
	}
	return false
}

func (a *Auth) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginRequest)).Decode(&request); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	address := remoteAddress(r)
	token, err := a.Login(request.User, request.Password, address)
	switch {
	case err == nil:
		log.Printf("audit: login by %s from %s", a.User(), address)
		a.setCookie(w, token, int(sessionIdle/time.Second))
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, errLocked), errors.Is(err, errBusy):
		log.Printf("audit: login refused from %s: %v", address, err)
		w.Header().Set("Retry-After", "60")
		http.Error(w, err.Error(), http.StatusTooManyRequests)
	case errors.Is(err, errBadLogin):
		log.Printf("audit: failed login from %s", address)
		http.Error(w, err.Error(), http.StatusUnauthorized)
	default:
		log.Printf("login error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (a *Auth) handlePassword(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginRequest)).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	address := remoteAddress(r)
	err := a.ChangePassword(token, request.Current, request.Password, address)
	switch {
	case err == nil:
		log.Printf("audit: password changed by %s from %s", a.User(), address)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, errShortPassword):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, errLocked), errors.Is(err, errBusy):
		log.Printf("audit: password change refused from %s: %v", address, err)
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "尝试次数过多，请稍后再试")
	case errors.Is(err, errBadLogin):
		// Not 401: the page would take that as a lost session and go to the login.
		log.Printf("audit: password change with a wrong current password from %s", address)
		writeError(w, http.StatusForbidden, "当前密码错误")
	default:
		log.Printf("password change error: %v", err)
		writeError(w, http.StatusInternalServerError, "保存失败："+err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Wrap puts next behind the login, and adds the headers every response needs.
func (a *Auth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Frame-Options", "DENY")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			log.Printf("audit: cross-origin %s %s from %s refused", r.Method, r.URL.Path, remoteAddress(r))
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/api/login":
			a.handleLogin(w, r)
			return
		case "/api/logout":
			if r.Method != http.MethodPost {
				http.Error(w, "POST only", http.StatusMethodNotAllowed)
				return
			}
			if cookie, err := r.Cookie(sessionCookie); err == nil {
				a.Logout(cookie.Value)
			}
			log.Printf("audit: logout from %s", remoteAddress(r))
			a.setCookie(w, "", -1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if publicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(sessionCookie)
		if err == nil && a.Valid(cookie.Value) {
			if r.URL.Path == "/api/password" {
				a.handlePassword(w, r, cookie.Value)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
	})
}
