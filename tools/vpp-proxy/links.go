package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseLinks reads share links, one per line; lines that are not links are skipped, and links
// that cannot be read are reported in the node's Ignored.
func ParseLinks(text string) ([]Profile, error) {
	var nodes []Profile
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "://") {
			continue
		}
		node, err := ParseLink(line)
		if err != nil {
			scheme, _, _ := strings.Cut(line, "://")
			node = Profile{Name: scheme + " 链接", Ignored: []string{err.Error()}}
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil, errors.New("没有找到分享链接")
	}
	return nodes, nil
}

// decodeBase64 accepts the standard and URL alphabets, padded or not.
func decodeBase64(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err := encoding.DecodeString(text); err == nil {
			return data, nil
		}
	}
	return nil, errors.New("不是 base64")
}

func ParseLink(link string) (Profile, error) {
	scheme, _, _ := strings.Cut(link, "://")
	switch strings.ToLower(scheme) {
	case "vmess":
		return parseVMess(link)
	case "ss":
		return parseShadowsocks(link)
	}
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, fmt.Errorf("链接格式不对：%v", err)
	}
	p := Profile{Name: u.Fragment, Server: u.Hostname()}
	if p.Port, err = strconv.Atoi(u.Port()); err != nil {
		return p, errors.New("链接里没有端口")
	}
	q := u.Query()
	user := u.User.Username()
	password, _ := u.User.Password()
	tlsFromQuery := func() {
		p.TLS.ServerName = first(q.Get("sni"), q.Get("peer"))
		p.TLS.Insecure = truthy(first(q.Get("allowInsecure"), q.Get("insecure"), q.Get("allow_insecure")))
		if alpn := q.Get("alpn"); alpn != "" {
			p.TLS.ALPN = strings.Split(alpn, ",")
		}
		p.TLS.Fingerprint = q.Get("fp")
	}
	transportFromQuery := func() {
		switch kind := q.Get("type"); kind {
		case "", "tcp", "raw":
		case "ws", "grpc", "http", "httpupgrade":
			p.Transport = Transport{Type: kind, Path: q.Get("path"), Host: q.Get("host"), ServiceName: q.Get("serviceName")}
		case "h2":
			p.Transport = Transport{Type: "http", Path: q.Get("path"), Host: q.Get("host")}
		default:
			p.Ignored = append(p.Ignored, "传输 "+kind)
		}
	}
	switch strings.ToLower(scheme) {
	case "socks", "socks5", "socks5h":
		p.Type = "socks"
		// Some clients put base64 of user:password where the user name goes.
		if password == "" && user != "" {
			if data, err := decodeBase64(user); err == nil && strings.Contains(string(data), ":") {
				user, password, _ = strings.Cut(string(data), ":")
			}
		}
		p.Username, p.Password = user, password
	case "http", "https":
		p.Type = "http"
		p.Username, p.Password = user, password
		p.TLS.Enabled = scheme == "https"
		if p.TLS.Enabled {
			tlsFromQuery()
		}
	case "vless":
		p.Type, p.UUID, p.Flow = "vless", user, q.Get("flow")
		switch q.Get("security") {
		case "tls":
			p.TLS.Enabled = true
			tlsFromQuery()
		case "reality":
			p.TLS.Enabled, p.TLS.Reality = true, true
			tlsFromQuery()
			p.TLS.PublicKey, p.TLS.ShortID = q.Get("pbk"), q.Get("sid")
		}
		transportFromQuery()
	case "trojan":
		p.Type, p.Password = "trojan", user
		p.TLS.Enabled = true
		tlsFromQuery()
		transportFromQuery()
	case "hysteria2", "hy2":
		p.Type, p.Password = "hysteria2", user
		if password != "" {
			p.Password = user + ":" + password
		}
		p.TLS.Enabled = true
		tlsFromQuery()
		if q.Get("obfs") == "salamander" {
			p.Obfs = q.Get("obfs-password")
		}
	case "tuic":
		p.Type, p.UUID, p.Password = "tuic", user, password
		p.Congestion = q.Get("congestion_control")
		p.TLS.Enabled = true
		tlsFromQuery()
	case "anytls":
		p.Type, p.Password = "anytls", user
		p.TLS.Enabled = true
		tlsFromQuery()
	default:
		return p, fmt.Errorf("不支持 %s 链接", scheme)
	}
	return p, nil
}

// parseShadowsocks reads SIP002 (ss://userinfo@host:port#name, userinfo plain or base64) and the
// older ss://base64(method:password@host:port)#name.
func parseShadowsocks(link string) (Profile, error) {
	rest, fragment, _ := strings.Cut(link[strings.Index(link, "://")+3:], "#")
	name, _ := url.PathUnescape(fragment)
	p := Profile{Type: "shadowsocks", Name: name}
	if !strings.Contains(rest, "@") {
		data, err := decodeBase64(strings.SplitN(rest, "?", 2)[0])
		if err != nil {
			return p, errors.New("ss 链接无法解码")
		}
		rest = string(data)
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return p, errors.New("ss 链接里没有服务器")
	}
	userinfo, address := rest[:at], rest[at+1:]
	address, query, _ := strings.Cut(address, "?")
	address = strings.TrimSuffix(address, "/")
	if decoded, err := url.PathUnescape(userinfo); err == nil {
		userinfo = decoded
	}
	if !strings.Contains(userinfo, ":") {
		data, err := decodeBase64(userinfo)
		if err != nil {
			return p, errors.New("ss 链接的加密方式和密码无法解码")
		}
		userinfo = string(data)
	}
	p.Method, p.Password, _ = strings.Cut(userinfo, ":")
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return p, errors.New("ss 链接的地址不对")
	}
	p.Server = host
	if p.Port, err = strconv.Atoi(port); err != nil {
		return p, errors.New("ss 链接的端口不对")
	}
	if values, _ := url.ParseQuery(query); values.Get("plugin") != "" {
		p.Ignored = append(p.Ignored, "插件 "+values.Get("plugin"))
	}
	return p, nil
}

// parseVMess reads the base64 JSON that v2rayN made common.
func parseVMess(link string) (Profile, error) {
	data, err := decodeBase64(link[len("vmess://"):])
	if err != nil {
		return Profile{}, errors.New("vmess 链接无法解码")
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		return Profile{}, errors.New("vmess 链接里不是 JSON")
	}
	text := func(key string) string {
		switch value := v[key].(type) {
		case string:
			return value
		case float64:
			return strconv.Itoa(int(value))
		}
		return ""
	}
	p := Profile{Type: "vmess", Name: text("ps"), Server: text("add"), UUID: text("id"), Security: first(text("scy"), "auto")}
	p.Port, _ = strconv.Atoi(text("port"))
	p.AlterID, _ = strconv.Atoi(text("aid"))
	switch net := text("net"); net {
	case "", "tcp":
		if text("type") == "http" {
			p.Ignored = append(p.Ignored, "TCP 的 HTTP 伪装")
		}
	case "ws", "grpc", "httpupgrade":
		p.Transport = Transport{Type: net, Path: text("path"), Host: text("host")}
		if net == "grpc" {
			p.Transport = Transport{Type: "grpc", ServiceName: text("path")}
		}
	case "h2", "http":
		p.Transport = Transport{Type: "http", Path: text("path"), Host: text("host")}
	default:
		p.Ignored = append(p.Ignored, "传输 "+net)
	}
	if text("tls") == "tls" {
		p.TLS = TLS{Enabled: true, ServerName: text("sni"), Fingerprint: text("fp")}
		if alpn := text("alpn"); alpn != "" {
			p.TLS.ALPN = strings.Split(alpn, ",")
		}
	}
	return p, nil
}

func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func truthy(text string) bool { return text == "1" || strings.EqualFold(text, "true") }

// ParseSubscription reads what a subscription URL returned: a sing-box configuration, base64 of
// share links, or share links as plain text.
func ParseSubscription(body string) ([]Profile, error) {
	body = strings.TrimSpace(strings.TrimPrefix(body, "\ufeff"))
	if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		return ParseSingBox(body)
	}
	if !strings.Contains(body, "://") {
		if data, err := decodeBase64(strings.Join(strings.Fields(body), "")); err == nil {
			body = string(data)
		}
	}
	return ParseLinks(body)
}
