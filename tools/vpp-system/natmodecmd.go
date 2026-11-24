package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// natModeUsage names the subcommand; the installer looks for it in the binary to know that a
// vpp-system can rewrite files offline, as an older one would start the service instead.
const natModeUsage = "usage: vpp-system nat-mode -mode ei|ed [-check] [-vpp-config F] [-cli-file F] [-wireguard-store F] [-backup-dir D]"

// runNATMode rewrites the NAT44 commands of the CLI file and the files it runs with exec for one
// plugin, as a switch from the system page does, without the startup file and without VPP: the
// installer calls it after writing the startup file and the CLI file for the plugin chosen, so
// the files those exec, which it keeps, follow. Commands already in that plugin's form stay.
// With -check it only says whether that can be done. It refuses as the system page does, and
// then changes nothing.
func runNATMode(args []string) error {
	fs := flag.NewFlagSet("vpp-system nat-mode", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(fs.Output(), natModeUsage); fs.PrintDefaults() }
	opts := Options{}
	mode := fs.String("mode", "", "the plugin the files are for: ei (NAT44-EI) or ed (NAT44-ED)")
	check := fs.Bool("check", false, "only check that the files can be rewritten")
	backupDir := fs.String("backup-dir", "", "where each file is copied before it is rewritten. Empty for no copies")
	fs.StringVar(&opts.StartConf, "vpp-config", "/etc/vpp/router.conf", "VPP's startup file, to find the CLI file in")
	fs.StringVar(&opts.CLIFile, "cli-file", "", "the CLI file VPP runs at startup; found in -vpp-config when empty")
	fs.StringVar(&opts.WireGuardStore, "wireguard-store", "/etc/vpp/wireguard/wireguard.json", "vpp-wireguard's configurations, whose commands are checked. Empty to ignore")
	if err := fs.Parse(args); err != nil {
		return err
	}
	to := natMode(*mode)
	if to != natEI && to != natED {
		return fmt.Errorf("-mode 只能是 ei 或 ed\n%s", natModeUsage)
	}
	if opts.CLIFile == "" {
		data, err := os.ReadFile(opts.StartConf)
		if err != nil {
			return fmt.Errorf("找 CLI 文件：%w；或者用 -cli-file 指定", err)
		}
		if opts.CLIFile = cliFileFromConfig(string(data)); opts.CLIFile == "" {
			return fmt.Errorf("%s 里没有 startup-config 或 exec；用 -cli-file 指定", opts.StartConf)
		}
	}
	s := &Service{opts: opts}
	file, err := s.loadCLI()
	if err != nil {
		return err
	}
	files, err := s.natModeFiles(file, to)
	if err != nil {
		return err
	}
	var paths []string
	for path, text := range files {
		if old, err := os.ReadFile(path); err != nil || string(old) != text {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	if *check {
		for _, path := range paths {
			fmt.Printf("会改写 %s\n", path)
		}
		return nil
	}
	if *backupDir != "" {
		if err := os.MkdirAll(*backupDir, 0o700); err != nil {
			return err
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// The whole path in the name, so two files with one base name keep their own copies.
			name := strings.ReplaceAll(strings.TrimPrefix(filepath.Clean(path), "/"), "/", "_") + ".nat-mode.bak"
			if err := writeFileAtomic(filepath.Join(*backupDir, name), data, 0o600); err != nil {
				return err
			}
		}
	}
	for _, path := range paths {
		if err := writeFileAtomic(path, []byte(files[path]), fileMode(path)); err != nil {
			return err
		}
		fmt.Printf("改写了 %s\n", path)
	}
	return nil
}
