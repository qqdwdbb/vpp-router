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
	if user == "" {
		return errors.New("the user name is empty")
	}
	if len(password) < minPassword {
		return fmt.Errorf("the password must be at least %d characters", minPassword)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash, err := derive(password, salt, hashIterations)
	if err != nil {
		return err
	}
	data, err := json.Marshal(Credentials{
		User: user, Iterations: hashIterations,
		Salt: base64.StdEncoding.EncodeToString(salt), Hash: base64.StdEncoding.EncodeToString(hash),
	})
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
	credentials Credentials
	salt, hash  []byte
	now         func() time.Time
	hashing     chan struct{} // one password check at a time, they are slow on purpose

	mu       sync.Mutex
	sessions map[[sha256.Size]byte]time.Time
	failures map[string]*failureRecord
}

func NewAuth(credentials *Credentials) (*Auth, error) {
	salt, err := base64.StdEncoding.DecodeString(credentials.Salt)
	if err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	hash, err := base64.StdEncoding.DecodeString(credentials.Hash)
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	return &Auth{
		credentials: *credentials, salt: salt, hash: hash, now: time.Now,
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
	derived, err := derive(password, a.salt, a.credentials.Iterations)
	if err != nil {
		return "", err
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(a.credentials.User)) == 1
	hashOK := subtle.ConstantTimeCompare(derived, a.hash) == 1
	if !userOK || !hashOK {
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
		log.Printf("audit: login by %s from %s", a.credentials.User, address)
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
