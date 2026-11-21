package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/vlib"
)

// VPN clients are read only while the page is open, and at most this often. WireGuard comes
// from `wg show` (patches/vpp/0002) and IPsec from strongSwan's stroke interface.
const (
	vpnMinInterval = 5 * time.Second
	vpnOnlineAfter = 3 * time.Minute // WireGuard renews a live session every two minutes
	vpnCommandTime = 5 * time.Second
)

// WireGuardPeer is one configured client. Parsing takes named fields only, so a line holding
// anything else, such as a private key, cannot reach the page.
type WireGuardPeer struct {
	Interface  string   `json:"interface"`
	PublicKey  string   `json:"public_key"`
	Name       string   `json:"name"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	// HandshakeSeconds is -1 for a peer that never completed a handshake.
	HandshakeSeconds int64 `json:"handshake_seconds"`
	Online           bool  `json:"online"`
	// Upstream marks a peer this router tunnels out through, which is not a client of it.
	Upstream bool   `json:"upstream"`
	RxBytes  uint64 `json:"rx_bytes"`
	TxBytes  uint64 `json:"tx_bytes"`
	// Limited means VPP has no `wg show`, so handshakes and traffic are unknown, not zero.
	Limited bool `json:"limited"`
}

// IPsecClient is an established IKE session.
type IPsecClient struct {
	Connection         string   `json:"connection"`
	Identity           string   `json:"identity"`
	EAPIdentity        string   `json:"eap_identity"`
	Remote             string   `json:"remote"`
	VirtualIPs         []string `json:"virtual_ips"`
	EstablishedSeconds int64    `json:"established_seconds"`
	HasCounters        bool     `json:"has_counters"`
	BytesIn            uint64   `json:"bytes_in"`
	BytesOut           uint64   `json:"bytes_out"`
}

// VPNReport is what the VPN page shows.
type VPNReport struct {
	Time           int64           `json:"time"`
	WireGuardError string          `json:"wireguard_error"`
	WireGuard      []WireGuardPeer `json:"wireguard"`
	IPsecError     string          `json:"ipsec_error"`
	IPsec          []IPsecClient   `json:"ipsec"`
}

// vpnSource fetches the raw status text.
type vpnSource interface {
	wireGuardStatus() (string, error)
	ipsecStatus() (string, error)
}

// VPNService caches readings, so any number of viewers cause one read per interval.
type VPNService struct {
	source vpnSource
	names  map[string]string
	now    func() time.Time
	// namesFile is read again with each reading, as the admin service updates it.
	namesFile string

	mu       sync.Mutex
	cached   *VPNReport
	cachedAt time.Time
}

func NewVPNService(source vpnSource, names map[string]string) *VPNService {
	return &VPNService{source: source, names: names, now: time.Now}
}

// LoadVPNNames reads an optional JSON object mapping WireGuard public keys to client names.
// The file need not exist yet: the admin service creates it when a peer is first named.
func LoadVPNNames(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names map[string]string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return names, nil
}

// Invalidate makes the next report read VPP again, after a peer was added or removed.
func (s *VPNService) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = nil
}

// Report returns a reading no older than vpnMinInterval.
func (s *VPNService) Report() *VPNReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.cached != nil && now.Sub(s.cachedAt) < vpnMinInterval {
		return s.cached
	}
	report := &VPNReport{Time: now.Unix(), WireGuard: []WireGuardPeer{}, IPsec: []IPsecClient{}}
	if text, err := s.source.wireGuardStatus(); err != nil {
		report.WireGuardError = err.Error()
	} else if peers, err := parseWireGuard(text); err != nil {
		report.WireGuardError = err.Error()
	} else {
		if s.namesFile != "" {
			if names, err := LoadVPNNames(s.namesFile); err != nil {
				log.Printf("vpn names: %v", err)
			} else {
				s.names = names
			}
		}
		for i := range peers {
			peers[i].Name = s.names[peers[i].PublicKey]
		}
		sortWireGuard(peers)
		report.WireGuard = peers
	}
	if text, err := s.source.ipsecStatus(); err != nil {
		report.IPsecError = err.Error()
	} else {
		report.IPsec = parseIPsec(text)
	}
	s.cached, s.cachedAt = report, now
	return report
}

// sortWireGuard puts upstream tunnels first, then the most recently seen, and peers never
// seen last.
func sortWireGuard(peers []WireGuardPeer) {
	sort.SliceStable(peers, func(i, j int) bool {
		if peers[i].Upstream != peers[j].Upstream {
			return peers[i].Upstream
		}
		a, b := peers[i].HandshakeSeconds, peers[j].HandshakeSeconds
		if (a < 0) != (b < 0) {
			return b < 0
		}
		return a < b
	})
}

var durationUnits = map[string]int64{
	"second": 1, "seconds": 1, "minute": 60, "minutes": 60, "h": 3600, "hour": 3600, "hours": 3600, "day": 86400, "days": 86400,
}

// parseAgo reads "1 minute, 44 seconds", "12 minutes" or VPP's "1 day, 2 h, 3 minutes, 4 seconds".
func parseAgo(text string) (int64, bool) {
	var total int64
	found := false
	for _, part := range strings.Split(text, ",") {
		fields := strings.Fields(part)
		if len(fields) != 2 {
			return 0, false
		}
		count, err := strconv.ParseInt(fields[0], 10, 64)
		unit, ok := durationUnits[fields[1]]
		if err != nil || !ok {
			return 0, false
		}
		total += count * unit
		found = true
	}
	return total, found
}

var transferUnits = map[string]float64{"B": 1, "KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}

func parseSize(number, unit string) uint64 {
	value, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0
	}
	return uint64(value * transferUnits[unit])
}

var transferLine = regexp.MustCompile(`^transfer: ([0-9.]+) ([A-Z]+) received, ([0-9.]+) ([A-Z]+) sent$`)

// parseWireGuard reads `wg show`. An error means VPP cannot produce it.
func parseWireGuard(text string) ([]WireGuardPeer, error) {
	if strings.Contains(text, "unknown input") {
		return nil, errors.New("这个 VPP 没有 wg show 命令（需要仓库里的 0002 补丁）")
	}
	if plainPeerStart.MatchString(text) {
		return parsePlainPeers(text), nil
	}
	peers := []WireGuardPeer{}
	var iface string
	var peer *WireGuardPeer
	inAllowed := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "interface: "):
			iface, peer, inAllowed = strings.TrimPrefix(line, "interface: "), nil, false
		case strings.HasPrefix(line, "peer: "):
			peers = append(peers, WireGuardPeer{Interface: iface, PublicKey: strings.TrimPrefix(line, "peer: "), AllowedIPs: []string{}, HandshakeSeconds: -1})
			peer, inAllowed = &peers[len(peers)-1], false
		case peer == nil:
			continue
		case strings.HasPrefix(line, "endpoint: "):
			peer.Endpoint, inAllowed = strings.TrimPrefix(line, "endpoint: "), false
		case line == "allowed ips:":
			inAllowed = true
		case strings.HasPrefix(line, "latest handshake: "):
			inAllowed = false
			if ago, ok := parseAgo(strings.TrimSuffix(strings.TrimPrefix(line, "latest handshake: "), " ago")); ok {
				peer.HandshakeSeconds = ago
				peer.Online = time.Duration(ago)*time.Second < vpnOnlineAfter
			}
		case strings.HasPrefix(line, "transfer: "):
			inAllowed = false
			if match := transferLine.FindStringSubmatch(line); match != nil {
				peer.RxBytes, peer.TxBytes = parseSize(match[1], match[2]), parseSize(match[3], match[4])
			}
		case inAllowed && allowedPrefix.MatchString(line):
			peer.AllowedIPs = append(peer.AllowedIPs, line)
			peer.Upstream = peer.Upstream || line == "0.0.0.0/0" || line == "::/0"
		default:
			inAllowed = false
		}
	}
	return peers, nil
}

var (
	plainPeerStart = regexp.MustCompile(`(?m)^\s*\[\d+\] endpoint:`)
	plainPeerLine  = regexp.MustCompile(`^\[\d+\] endpoint:\[\S*?->(\S*?)\] (\S+)`)
	plainKeyLine   = regexp.MustCompile(`^(?:public )?key:\s*(\S+)`)
)

// parsePlainPeers reads `show wireguard peer`, which stock VPP has. It has no handshake time
// or traffic counters.
func parsePlainPeers(text string) []WireGuardPeer {
	peers := []WireGuardPeer{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if match := plainPeerLine.FindStringSubmatch(line); match != nil {
			peers = append(peers, WireGuardPeer{Interface: match[2], Endpoint: match[1], AllowedIPs: []string{}, HandshakeSeconds: -1, Limited: true})
			continue
		}
		if len(peers) == 0 {
			continue
		}
		peer := &peers[len(peers)-1]
		if match := plainKeyLine.FindStringSubmatch(line); match != nil {
			peer.PublicKey = match[1]
		} else if rest, ok := strings.CutPrefix(line, "allowed-ips:"); ok {
			for _, prefix := range strings.Fields(rest) {
				if allowedPrefix.MatchString(prefix) {
					peer.AllowedIPs = append(peer.AllowedIPs, prefix)
					peer.Upstream = peer.Upstream || prefix == "0.0.0.0/0" || prefix == "::/0"
				}
			}
		}
	}
	return peers
}

var allowedPrefix = regexp.MustCompile(`^[0-9a-fA-F:.]+/\d+$`)

var (
	ikeLine    = regexp.MustCompile(`^(\S+?)\[(\d+)\]: ESTABLISHED (.+?) ago, (.+?)\[(.*?)\]\.\.\.(.+?)\[(.*)\]$`)
	eapLine    = regexp.MustCompile(`^(\S+?)\[(\d+)\]: Remote EAP identity: (.*)$`)
	bytesPart  = regexp.MustCompile(`(\d+) bytes_i.*?(\d+) bytes_o`)
	tunnelLine = regexp.MustCompile(`^(\S+?)\{\d+\}:\s+(.+) === (.+)$`)
	childLine  = regexp.MustCompile(`^(\S+?)\{\d+\}:\s+(.*)$`)
)

// parseIPsec reads `ipsec statusall`, where each IKE session is followed by its children.
func parseIPsec(text string) []IPsecClient {
	clients := []IPsecClient{}
	section := false
	byIKE := map[string]int{}
	lastOf := map[string]int{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Security Associations") {
			section = true
			continue
		}
		if !section {
			continue
		}
		if match := ikeLine.FindStringSubmatch(line); match != nil {
			client := IPsecClient{Connection: match[1], Remote: match[6], Identity: match[7], VirtualIPs: []string{}, EstablishedSeconds: -1}
			if seconds, ok := parseAgo(match[3]); ok {
				client.EstablishedSeconds = seconds
			}
			clients = append(clients, client)
			byIKE[match[1]+"["+match[2]+"]"] = len(clients) - 1
			lastOf[match[1]] = len(clients) - 1
			continue
		}
		if match := eapLine.FindStringSubmatch(line); match != nil {
			if index, ok := byIKE[match[1]+"["+match[2]+"]"]; ok {
				clients[index].EAPIdentity = match[3]
			}
			continue
		}
		if match := tunnelLine.FindStringSubmatch(line); match != nil {
			if index, ok := lastOf[match[1]]; ok {
				clients[index].VirtualIPs = append(clients[index].VirtualIPs, strings.Fields(match[3])...)
			}
			continue
		}
		if match := childLine.FindStringSubmatch(line); match != nil {
			index, ok := lastOf[match[1]]
			if !ok {
				continue
			}
			if counters := bytesPart.FindStringSubmatch(match[2]); counters != nil {
				in, _ := strconv.ParseUint(counters[1], 10, 64)
				out, _ := strconv.ParseUint(counters[2], 10, 64)
				clients[index].HasCounters = true
				clients[index].BytesIn += in
				clients[index].BytesOut += out
			}
		}
	}
	return clients
}

// systemVPN reads the real sources.
type systemVPN struct {
	apiSocket, strokeBinary, strongswanConf string
}

func (s *systemVPN) wireGuardStatus() (string, error) {
	conn, err := govpp.Connect(s.apiSocket)
	if err != nil {
		return "", fmt.Errorf("连接 VPP API 失败：%w", err)
	}
	defer conn.Disconnect()
	channel, err := conn.NewAPIChannel()
	if err != nil {
		return "", err
	}
	defer channel.Close()
	channel.SetReplyTimeout(3 * time.Second)
	reply := &vlib.CliInbandReply{}
	if err := channel.SendRequest(&vlib.CliInband{Cmd: "wg show"}).ReceiveReply(reply); err != nil {
		if !cliUnsupported(err) {
			return "", err
		}
		// Without patches/vpp/0002 there is no `wg show`; every VPP has this one.
		plain := &vlib.CliInbandReply{}
		if err := channel.SendRequest(&vlib.CliInband{Cmd: "show wireguard peer"}).ReceiveReply(plain); err != nil {
			return "unknown input", nil
		}
		return plain.Reply, nil
	}
	return reply.Reply, nil
}

func (s *systemVPN) ipsecStatus() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), vpnCommandTime)
	defer cancel()
	command := exec.CommandContext(ctx, s.strokeBinary, "statusall")
	if s.strongswanConf != "" {
		command.Env = append(os.Environ(), "STRONGSWAN_CONF="+s.strongswanConf)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("这台主机没有安装 strongSwan")
		}
		text := strings.TrimSpace(string(output))
		if len(text) > 200 {
			text = text[:200]
		}
		return "", fmt.Errorf("读取 strongSwan 状态失败：%v %s", err, text)
	}
	return string(output), nil
}

// cliUnsupported says whether a CLI request failed because VPP has no such command: the API
// reports that as a bare -1 and drops the "unknown input" text.
func cliUnsupported(err error) bool {
	var failure api.VPPApiError
	return errors.As(err, &failure) && int32(failure) == -1
}

var strokeSocket = regexp.MustCompile(`^unix:///[A-Za-z0-9_./-]+$`)

// writeStrokeConfig points the stroke client at a charon whose socket is not the default
// one, such as one running in its own mount namespace, and returns the file to use.
func writeStrokeConfig(socket string) (string, error) {
	if !strokeSocket.MatchString(socket) {
		return "", fmt.Errorf("-ipsec-socket must look like unix:///run/charon.ctl")
	}
	file, err := os.CreateTemp("", "vpp-monitor-strongswan-*.conf")
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := fmt.Fprintf(file, "charon {\n plugins {\n  stroke {\n   socket = %s\n  }\n }\n}\n", socket); err != nil {
		return "", err
	}
	return file.Name(), nil
}
