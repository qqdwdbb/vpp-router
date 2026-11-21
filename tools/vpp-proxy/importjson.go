package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Types that route or group rather than reach a server; an import leaves them out.
var notNodes = map[string]bool{"direct": true, "block": true, "dns": true, "selector": true, "urltest": true}

// ParseSingBox reads the nodes of a sing-box configuration: a whole client configuration, a
// fragment with outbounds and endpoints, a list, or one outbound.
func ParseSingBox(text string) ([]Profile, error) {
	var data any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return nil, fmt.Errorf("不是合法的 JSON：%v", err)
	}
	var items []any
	switch v := data.(type) {
	case map[string]any:
		if _, ok := v["type"]; ok {
			items = []any{v}
		} else {
			items = append(asList(v["outbounds"]), asList(v["endpoints"])...)
		}
	case []any:
		items = v
	}
	var nodes []Profile
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		kind, _ := object["type"].(string)
		if notNodes[kind] {
			continue
		}
		node, err := fromOutbound(object)
		if err != nil {
			tag, _ := object["tag"].(string)
			node = Profile{Name: tag, Type: kind, Ignored: []string{err.Error()}}
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil, errors.New("里面没有可以用的节点")
	}
	return nodes, nil
}

func asList(value any) []any {
	list, _ := value.([]any)
	return list
}

// reader takes fields out of a JSON object and remembers which were not taken.
type reader struct {
	object map[string]any
	used   map[string]bool
}

func (r *reader) str(key string) string {
	r.used[key] = true
	value, _ := r.object[key].(string)
	return value
}

func (r *reader) num(key string) int {
	r.used[key] = true
	value, _ := r.object[key].(float64)
	return int(value)
}

func (r *reader) boolean(key string) bool {
	r.used[key] = true
	value, _ := r.object[key].(bool)
	return value
}

func (r *reader) strs(key string) []string {
	r.used[key] = true
	switch value := r.object[key].(type) {
	case string:
		return []string{value}
	case []any:
		var out []string
		for _, item := range value {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}

func (r *reader) child(key string) *reader {
	r.used[key] = true
	object, _ := r.object[key].(map[string]any)
	if object == nil {
		object = map[string]any{}
	}
	return &reader{object: object, used: map[string]bool{}}
}

func (r *reader) unused(prefix string) []string {
	var out []string
	for key := range r.object {
		if !r.used[key] {
			out = append(out, prefix+key)
		}
	}
	sort.Strings(out)
	return out
}

func fromOutbound(object map[string]any) (Profile, error) {
	r := &reader{object: object, used: map[string]bool{}}
	p := Profile{Type: r.str("type"), Name: r.str("tag")}
	if protocols[p.Type] == "" {
		return p, fmt.Errorf("向导不支持 %s 类型", p.Type)
	}
	var ignored []string
	if p.Type == "wireguard" {
		p.Address = r.strs("address")
		p.PrivateKey = r.str("private_key")
		p.MTU = r.num("mtu")
		r.used["peers"] = true
		peers := asList(object["peers"])
		if len(peers) == 0 {
			return p, errors.New("WireGuard 没有对端")
		}
		if len(peers) > 1 {
			ignored = append(ignored, fmt.Sprintf("除第一个以外的 %d 个对端", len(peers)-1))
		}
		peerObject, _ := peers[0].(map[string]any)
		peer := &reader{object: peerObject, used: map[string]bool{}}
		p.Server, p.Port = peer.str("address"), peer.num("port")
		p.PeerKey, p.PreSharedKey = peer.str("public_key"), peer.str("pre_shared_key")
		p.AllowedIPs = peer.strs("allowed_ips")
		ignored = append(ignored, peer.unused("peers.")...)
		p.Ignored = append(ignored, r.unused("")...)
		return p, nil
	}
	p.Server, p.Port = r.str("server"), r.num("server_port")
	p.Username, p.Password = r.str("username"), r.str("password")
	p.Method, p.UUID = r.str("method"), r.str("uuid")
	p.Security, p.AlterID, p.Flow = r.str("security"), r.num("alter_id"), r.str("flow")
	p.Congestion = r.str("congestion_control")
	p.UpMbps, p.DownMbps = r.num("up_mbps"), r.num("down_mbps")
	r.used["version"] = true
	if _, ok := object["obfs"]; ok {
		obfs := r.child("obfs")
		if kind := obfs.str("type"); kind != "salamander" {
			ignored = append(ignored, "obfs 类型 "+kind)
		}
		p.Obfs = obfs.str("password")
	}
	if _, ok := object["tls"]; ok {
		tls := r.child("tls")
		p.TLS.Enabled = tls.boolean("enabled")
		p.TLS.ServerName, p.TLS.Insecure, p.TLS.ALPN = tls.str("server_name"), tls.boolean("insecure"), tls.strs("alpn")
		if _, ok := tls.object["utls"]; ok {
			utls := tls.child("utls")
			if utls.boolean("enabled") {
				p.TLS.Fingerprint = utls.str("fingerprint")
			}
			ignored = append(ignored, utls.unused("tls.utls.")...)
		}
		if _, ok := tls.object["reality"]; ok {
			reality := tls.child("reality")
			p.TLS.Reality = reality.boolean("enabled")
			p.TLS.PublicKey, p.TLS.ShortID = reality.str("public_key"), reality.str("short_id")
			ignored = append(ignored, reality.unused("tls.reality.")...)
		}
		ignored = append(ignored, tls.unused("tls.")...)
	}
	if _, ok := object["transport"]; ok {
		t := r.child("transport")
		p.Transport.Type = t.str("type")
		p.Transport.Path = t.str("path")
		p.Transport.ServiceName = t.str("service_name")
		switch p.Transport.Type {
		case "ws":
			headers := t.child("headers")
			p.Transport.Host = headers.str("Host")
			ignored = append(ignored, headers.unused("transport.headers.")...)
		case "http":
			if hosts := t.strs("host"); len(hosts) > 0 {
				p.Transport.Host = hosts[0]
			}
		case "httpupgrade":
			p.Transport.Host = t.str("host")
		}
		ignored = append(ignored, t.unused("transport.")...)
	}
	p.Ignored = append(ignored, r.unused("")...)
	if len(p.Ignored) == 0 {
		p.Ignored = nil
	}
	return p, nil
}

// describe is how a node is listed: its name, protocol and server.
func describe(p Profile) string {
	return strings.TrimSpace(fmt.Sprintf("%s %s %s:%d", p.Name, protocols[p.Type], p.Server, p.Port))
}
