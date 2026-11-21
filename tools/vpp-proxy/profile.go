package main

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Profile is the upstream as the panel's wizard has it: a protocol, a server and how to
// authenticate, with TLS and transport where the protocol takes them. It is turned into one
// sing-box outbound, or for WireGuard an endpoint, tagged "proxy".
type Profile struct {
	Name     string `json:"name"` // what the node is called, shown only
	Type     string `json:"type"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`   // Shadowsocks
	UUID     string `json:"uuid,omitempty"`     // VMess, VLESS, TUIC
	Security string `json:"security,omitempty"` // VMess
	AlterID  int    `json:"alter_id,omitempty"` // VMess
	Flow     string `json:"flow,omitempty"`     // VLESS

	Congestion string `json:"congestion,omitempty"` // TUIC
	Obfs       string `json:"obfs,omitempty"`       // Hysteria2 salamander password
	UpMbps     int    `json:"up_mbps,omitempty"`    // Hysteria2
	DownMbps   int    `json:"down_mbps,omitempty"`  // Hysteria2

	TLS       TLS       `json:"tls"`
	Transport Transport `json:"transport"`

	// WireGuard.
	Address      []string `json:"address,omitempty"`
	PrivateKey   string   `json:"private_key,omitempty"`
	PeerKey      string   `json:"peer_public_key,omitempty"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
	MTU          int      `json:"mtu,omitempty"`

	// Ignored lists what an import had that the wizard cannot hold.
	Ignored []string `json:"ignored,omitempty"`
}

type TLS struct {
	Enabled     bool     `json:"enabled"`
	ServerName  string   `json:"server_name,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"` // uTLS
	Reality     bool     `json:"reality,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"`
	ShortID     string   `json:"short_id,omitempty"`
}

type Transport struct {
	Type        string `json:"type,omitempty"` // ws, grpc, http, httpupgrade; empty is plain TCP
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"` // grpc
}

const proxyTag = "proxy"

var protocols = map[string]string{
	"socks": "SOCKS5", "http": "HTTP", "shadowsocks": "Shadowsocks", "vmess": "VMess", "vless": "VLESS",
	"trojan": "Trojan", "hysteria2": "Hysteria2", "tuic": "TUIC", "anytls": "AnyTLS", "wireguard": "WireGuard",
}

// What each protocol requires of TLS: on, off, or optional.
var tlsUse = map[string]string{
	"socks": "off", "http": "optional", "shadowsocks": "off", "vmess": "optional", "vless": "optional",
	"trojan": "on", "hysteria2": "on", "tuic": "on", "anytls": "on", "wireguard": "off",
}

var withTransport = map[string]bool{"vmess": true, "vless": true, "trojan": true}

var shadowsocksMethods = []string{
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "none",
}

var fingerprints = []string{"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}

var uuidText = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// secrets are the fields a view leaves out and an empty form keeps.
var secrets = []string{"password", "uuid", "private_key", "pre_shared_key", "obfs"}

func (p *Profile) secret(name string) *string {
	switch name {
	case "password":
		return &p.Password
	case "uuid":
		return &p.UUID
	case "private_key":
		return &p.PrivateKey
	case "pre_shared_key":
		return &p.PreSharedKey
	case "obfs":
		return &p.Obfs
	}
	return nil
}

// Masked is the profile without its secrets, and which of them it has.
func (p Profile) Masked() (Profile, []string) {
	var set []string
	for _, name := range secrets {
		if field := p.secret(name); *field != "" {
			set = append(set, name)
			*field = ""
		}
	}
	return p, set
}

// KeepSecrets fills secrets a form left empty from the saved profile of the same upstream.
func (p *Profile) KeepSecrets(saved *Profile) {
	if saved == nil || saved.Type != p.Type || saved.Server != p.Server || saved.Port != p.Port {
		return
	}
	for _, name := range secrets {
		if field := p.secret(name); *field == "" {
			*field = *saved.secret(name)
		}
	}
}

func (p *Profile) normalize() {
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	p.Server = strings.Trim(strings.TrimSpace(p.Server), "[]")
	p.Name = strings.TrimSpace(p.Name)
	switch tlsUse[p.Type] {
	case "on":
		p.TLS.Enabled = true
	case "off":
		p.TLS = TLS{}
	}
	if !withTransport[p.Type] {
		p.Transport = Transport{}
	}
	if p.Type == "vmess" && p.Security == "" {
		p.Security = "auto"
	}
	if p.Type == "tuic" && p.Congestion == "" {
		p.Congestion = "bbr"
	}
}

// Validate checks what sing-box would otherwise refuse less clearly.
func (p *Profile) Validate() error {
	p.normalize()
	if protocols[p.Type] == "" {
		return fmt.Errorf("不支持的协议 %q", p.Type)
	}
	if p.Type == "wireguard" {
		return p.validateWireGuard()
	}
	if p.Server == "" || strings.ContainsAny(p.Server, " \t/") {
		return errors.New("服务器地址不能为空，也不能有空格或斜杠")
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("端口要在 1 到 65535 之间")
	}
	switch p.Type {
	case "socks", "http":
		if p.Password != "" && p.Username == "" {
			return errors.New("有密码时必须有用户名")
		}
	case "shadowsocks":
		if !slices.Contains(shadowsocksMethods, p.Method) {
			return fmt.Errorf("不支持的加密方式 %q", p.Method)
		}
		if p.Password == "" && p.Method != "none" {
			return errors.New("Shadowsocks 要有密码")
		}
	case "vmess", "vless":
		if !uuidText.MatchString(p.UUID) {
			return errors.New("UUID 格式不对")
		}
	case "tuic":
		if !uuidText.MatchString(p.UUID) {
			return errors.New("UUID 格式不对")
		}
		if p.Password == "" {
			return errors.New("TUIC 要有密码")
		}
	case "trojan", "hysteria2", "anytls":
		if p.Password == "" {
			return fmt.Errorf("%s 要有密码", protocols[p.Type])
		}
	}
	if p.TLS.Reality {
		if p.Type != "vless" {
			return errors.New("Reality 只用于 VLESS")
		}
		if p.TLS.PublicKey == "" {
			return errors.New("Reality 要有公钥")
		}
		if p.TLS.Fingerprint == "" {
			p.TLS.Fingerprint = "chrome" // sing-box needs uTLS for Reality
		}
	}
	if p.TLS.Fingerprint != "" && !slices.Contains(fingerprints, p.TLS.Fingerprint) {
		return fmt.Errorf("不认识的 uTLS 指纹 %q", p.TLS.Fingerprint)
	}
	switch p.Transport.Type {
	case "", "ws", "http", "httpupgrade":
	case "grpc":
		if p.Transport.ServiceName == "" {
			return errors.New("gRPC 要有 service name")
		}
	default:
		return fmt.Errorf("不支持的传输 %q", p.Transport.Type)
	}
	return nil
}

func (p *Profile) validateWireGuard() error {
	if p.Server == "" || p.Port < 1 || p.Port > 65535 {
		return errors.New("要填对端的地址和端口")
	}
	if len(p.Address) == 0 {
		return errors.New("要填本机在隧道里的地址，比如 10.0.0.2/32")
	}
	for _, text := range p.Address {
		if _, err := netip.ParsePrefix(strings.TrimSpace(text)); err != nil {
			return fmt.Errorf("本机地址 %q 要写成 地址/掩码长度", text)
		}
	}
	for _, key := range []struct{ name, value string }{{"私钥", p.PrivateKey}, {"对端公钥", p.PeerKey}} {
		if !wireguardKey(key.value) {
			return fmt.Errorf("%s不是 WireGuard 的密钥", key.name)
		}
	}
	if p.PreSharedKey != "" && !wireguardKey(p.PreSharedKey) {
		return errors.New("预共享密钥不是 WireGuard 的密钥")
	}
	if len(p.AllowedIPs) == 0 {
		p.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	for _, text := range p.AllowedIPs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(text)); err != nil {
			return fmt.Errorf("AllowedIPs %q 要写成网段", text)
		}
	}
	if p.MTU != 0 && (p.MTU < 1280 || p.MTU > 9000) {
		return errors.New("MTU 要在 1280 到 9000 之间")
	}
	return nil
}

func wireguardKey(text string) bool {
	return len(text) == 44 && strings.HasSuffix(text, "=")
}

// Upstream is the sing-box fragment for upstream.json.
func (p *Profile) Upstream() (map[string]any, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Type == "wireguard" {
		peer := map[string]any{"address": p.Server, "port": p.Port, "public_key": p.PeerKey, "allowed_ips": p.AllowedIPs}
		if p.PreSharedKey != "" {
			peer["pre_shared_key"] = p.PreSharedKey
		}
		endpoint := map[string]any{"type": "wireguard", "tag": proxyTag, "address": p.Address, "private_key": p.PrivateKey,
			"peers": []any{peer}}
		if p.MTU != 0 {
			endpoint["mtu"] = p.MTU
		}
		return map[string]any{"endpoints": []any{endpoint}}, nil
	}
	out := map[string]any{"type": p.Type, "tag": proxyTag, "server": p.Server, "server_port": p.Port}
	set := func(key string, value any) {
		switch v := value.(type) {
		case string:
			if v == "" {
				return
			}
		case int:
			if v == 0 {
				return
			}
		}
		out[key] = value
	}
	switch p.Type {
	case "socks":
		out["version"] = "5"
		set("username", p.Username)
		set("password", p.Password)
	case "http":
		set("username", p.Username)
		set("password", p.Password)
	case "shadowsocks":
		out["method"] = p.Method
		out["password"] = p.Password
	case "vmess":
		out["uuid"] = p.UUID
		out["security"] = p.Security
		set("alter_id", p.AlterID)
	case "vless":
		out["uuid"] = p.UUID
		set("flow", p.Flow)
	case "trojan", "anytls":
		out["password"] = p.Password
	case "hysteria2":
		out["password"] = p.Password
		set("up_mbps", p.UpMbps)
		set("down_mbps", p.DownMbps)
		if p.Obfs != "" {
			out["obfs"] = map[string]any{"type": "salamander", "password": p.Obfs}
		}
	case "tuic":
		out["uuid"] = p.UUID
		out["password"] = p.Password
		out["congestion_control"] = p.Congestion
	}
	if p.TLS.Enabled {
		tls := map[string]any{"enabled": true}
		if p.TLS.ServerName != "" {
			tls["server_name"] = p.TLS.ServerName
		}
		if p.TLS.Insecure {
			tls["insecure"] = true
		}
		if len(p.TLS.ALPN) > 0 {
			tls["alpn"] = p.TLS.ALPN
		}
		if p.TLS.Fingerprint != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": p.TLS.Fingerprint}
		}
		if p.TLS.Reality {
			reality := map[string]any{"enabled": true, "public_key": p.TLS.PublicKey}
			if p.TLS.ShortID != "" {
				reality["short_id"] = p.TLS.ShortID
			}
			tls["reality"] = reality
		}
		out["tls"] = tls
	}
	if t := p.Transport; t.Type != "" {
		transport := map[string]any{"type": t.Type}
		switch t.Type {
		case "ws":
			if t.Path != "" {
				transport["path"] = t.Path
			}
			if t.Host != "" {
				transport["headers"] = map[string]any{"Host": t.Host}
			}
		case "http":
			if t.Path != "" {
				transport["path"] = t.Path
			}
			if t.Host != "" {
				transport["host"] = []any{t.Host}
			}
		case "httpupgrade":
			if t.Path != "" {
				transport["path"] = t.Path
			}
			if t.Host != "" {
				transport["host"] = t.Host
			}
		case "grpc":
			transport["service_name"] = t.ServiceName
		}
		out["transport"] = transport
	}
	return map[string]any{"outbounds": []any{out}}, nil
}
