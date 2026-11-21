package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const certificateLife = 10 * 365 * 24 * time.Hour

// certificateNames lists what the certificate should be valid for: the listen address and,
// for a wildcard, every address of this host, along with the host name.
func certificateNames(listen string) (ips []net.IP, names []string) {
	seen := make(map[string]bool)
	add := func(ip net.IP) {
		if ip != nil && !seen[ip.String()] {
			seen[ip.String()] = true
			ips = append(ips, ip)
		}
	}
	add(net.IPv4(127, 0, 0, 1))
	add(net.IPv6loopback)
	host, _, err := net.SplitHostPort(listen)
	listenIP := net.ParseIP(host)
	if err == nil && (host == "" || (listenIP != nil && listenIP.IsUnspecified())) {
		if addresses, err := net.InterfaceAddrs(); err == nil {
			for _, address := range addresses {
				if network, ok := address.(*net.IPNet); ok {
					add(network.IP)
				}
			}
		}
	} else if listenIP != nil {
		add(listenIP)
	} else if host != "" {
		names = append(names, host)
	}
	names = append(names, "localhost")
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		names = append(names, hostname)
	}
	return ips, names
}

// ensureCertificate creates a self-signed certificate on first use and keeps it afterwards,
// so a browser's stored exception stays valid.
func ensureCertificate(certPath, keyPath, listen string) error {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil {
		return nil
	}
	if certErr == nil || keyErr == nil {
		return fmt.Errorf("one of %s and %s exists without the other", certPath, keyPath)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	ips, names := certificateNames(listen)
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vpp-monitor"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certificateLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
