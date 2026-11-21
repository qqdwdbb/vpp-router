package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type realSystem struct {
	opts Options

	mu          sync.Mutex
	versionText string
}

func (s *realSystem) check(dir string) error {
	output, err := exec.Command(s.opts.Binary, "check", "--disable-color", "-C", dir).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text == "" {
			text = err.Error()
		}
		return errors.New(text)
	}
	return nil
}

func (s *realSystem) version() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.versionText == "" {
		if output, err := exec.Command(s.opts.Binary, "version").Output(); err == nil {
			s.versionText = strings.TrimPrefix(strings.SplitN(string(output), "\n", 2)[0], "sing-box version ")
		}
	}
	return s.versionText
}

func (s *realSystem) unit(action string) error {
	output, err := exec.Command("systemctl", action, s.opts.Unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s：%v %s", action, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s *realSystem) active() bool {
	return exec.Command("systemctl", "is-active", "--quiet", s.opts.Unit).Run() == nil
}

func (s *realSystem) fetch(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return fetchLimited(ctx, url, 4<<20)
}

// probe runs a throwaway sing-box with one loopback SOCKS inbound in front of the upstream and
// makes one request through it.
func (s *realSystem) probe(upstream map[string]any, url string) (int, time.Duration, error) {
	port, err := freePort()
	if err != nil {
		return 0, 0, err
	}
	config := map[string]any{
		"log":      map[string]any{"level": "error"},
		"dns":      map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "system"}}},
		"inbounds": []any{map[string]any{"type": "socks", "tag": "probe", "listen": "127.0.0.1", "listen_port": port}},
		"route":    map[string]any{"final": proxyTag, "default_domain_resolver": "system"},
	}
	for _, key := range []string{"outbounds", "endpoints"} {
		if list := asList(upstream[key]); len(list) > 0 {
			config[key] = list
		}
	}
	dir, err := os.MkdirTemp(s.opts.StateDir, "probe-")
	if err != nil {
		return 0, 0, err
	}
	defer os.RemoveAll(dir)
	data, _ := json.Marshal(config)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return 0, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, s.opts.Binary, "run", "--disable-color", "-c", path, "-D", dir)
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return 0, 0, err
	}
	defer func() {
		command.Process.Kill()
		command.Wait()
	}()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for started := time.Now(); ; time.Sleep(100 * time.Millisecond) {
		if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		if time.Since(started) > 5*time.Second {
			return 0, 0, fmt.Errorf("测试用的 sing-box 没有启动：%s", strings.TrimSpace(stderr.String()))
		}
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
				return dialSOCKS5(ctx, address, target)
			},
			TLSClientConfig:   &tls.Config{},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	started := time.Now()
	response, err := client.Get(url)
	elapsed := time.Since(started)
	if err != nil {
		message := err.Error()
		if text := strings.TrimSpace(stderr.String()); text != "" {
			message += "；sing-box：" + lastLine(text)
		}
		return 0, elapsed, errors.New(message)
	}
	io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))
	response.Body.Close()
	return response.StatusCode, elapsed, nil
}

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return lines[len(lines)-1]
}

// dialSOCKS5 connects to target through a SOCKS5 server without authentication, passing host
// names on for the server to resolve.
func dialSOCKS5(ctx context.Context, server, target string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	fail := func(err error) (net.Conn, error) { conn.Close(); return nil, err }
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	reader := bufio.NewReader(conn)
	reply := make([]byte, 2)
	if _, err := io.ReadFull(reader, reply); err != nil || reply[0] != 5 || reply[1] != 0 {
		return fail(errors.New("SOCKS5 握手失败"))
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		request = append(append(request, 1), ip.To4()...)
	} else if ip != nil {
		request = append(append(request, 4), ip.To16()...)
	} else {
		request = append(append(request, 3, byte(len(host))), host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(reader, head); err != nil {
		return fail(err)
	}
	if head[1] != 0 {
		return fail(fmt.Errorf("经上游连接 %s 失败（SOCKS5 应答 %d）", target, head[1]))
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		length, err := reader.ReadByte()
		if err != nil {
			return fail(err)
		}
		skip = int(length)
	}
	if _, err := io.ReadFull(reader, make([]byte, skip+2)); err != nil {
		return fail(err)
	}
	conn.SetDeadline(time.Time{})
	if reader.Buffered() > 0 {
		return fail(errors.New("SOCKS5 应答之后有多余的数据"))
	}
	return conn, nil
}
