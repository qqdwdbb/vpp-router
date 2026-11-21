package main

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// VPP's startup file is sections of words, "name { ... }", nested, with "#" comments to the end
// of the line. Only the cpu section and the dpdk dev blocks' num-rx-queues are changed; every
// other byte of the file stays as it is.

type token struct {
	text       string
	start, end int // byte offsets in the file
}

func tokenize(text string) []token {
	var tokens []token
	i := 0
	for i < len(text) {
		c := text[i]
		switch {
		case c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '{' || c == '}':
			tokens = append(tokens, token{string(c), i, i + 1})
			i++
		default:
			start := i
			for i < len(text) && !strings.ContainsRune(" \t\r\n{}#", rune(text[i])) {
				i++
			}
			tokens = append(tokens, token{text[start:i], start, i})
		}
	}
	return tokens
}

// item is a word, or a section when it has a body.
type item struct {
	word       token
	body       []item
	open, shut int  // offsets of "{" and of the end of "}"
	section    bool // has a body
}

func parseItems(tokens []token, pos int, nested bool) ([]item, int, error) {
	var items []item
	for pos < len(tokens) {
		t := tokens[pos]
		switch t.text {
		case "}":
			if !nested {
				return nil, 0, fmt.Errorf("多余的 } （第 %d 字节）", t.start)
			}
			return items, pos, nil
		case "{":
			return nil, 0, fmt.Errorf("{ 前面没有名字（第 %d 字节）", t.start)
		}
		it := item{word: t}
		pos++
		if pos < len(tokens) && tokens[pos].text == "{" {
			body, next, err := parseItems(tokens, pos+1, true)
			if err != nil {
				return nil, 0, err
			}
			if next >= len(tokens) {
				return nil, 0, fmt.Errorf("%s 的 { 没有对应的 }", t.text)
			}
			it.section, it.body, it.open, it.shut = true, body, tokens[pos].start, tokens[next].end
			pos = next + 1
		}
		items = append(items, it)
	}
	if nested {
		return nil, 0, errors.New("文件结尾缺少 }")
	}
	return items, pos, nil
}

// startConf is a parsed startup file.
type startConf struct {
	text  string
	items []item
}

func parseStartConf(text string) (*startConf, error) {
	items, _, err := parseItems(tokenize(text), 0, false)
	if err != nil {
		return nil, err
	}
	return &startConf{text: text, items: items}, nil
}

func (c *startConf) section(name string) *item {
	for i := range c.items {
		if c.items[i].section && c.items[i].word.text == name {
			return &c.items[i]
		}
	}
	return nil
}

// cpuConf is the cpu section: what this program manages, and the rest kept as words.
type cpuConf struct {
	MainCore *int   `json:"main_core"`
	Workers  []int  `json:"workers"`
	Policy   string `json:"scheduler_policy"`
	Priority *int   `json:"scheduler_priority"`
	// AutoWorkers is "workers N": that many workers placed by VPP rather than listed.
	AutoWorkers int `json:"auto_workers"`
	// Other is what the section has besides, kept when it is written back.
	Other []string `json:"other"`
}

var cpuValueKeys = []string{"main-core", "corelist-workers", "coremask-workers", "workers", "scheduler-policy", "scheduler-priority",
	"skip-cores", "thread-prefix"}

func (c *startConf) cpu() (*cpuConf, error) {
	conf := &cpuConf{}
	s := c.section("cpu")
	if s == nil {
		return conf, nil
	}
	words := []string{}
	for _, it := range s.body {
		if it.section {
			return nil, fmt.Errorf("cpu 里的 %s { } 不认识", it.word.text)
		}
		words = append(words, it.word.text)
	}
	for i := 0; i < len(words); i++ {
		key := words[i]
		if !slices.Contains(cpuValueKeys, key) && !strings.HasPrefix(key, "corelist-") {
			conf.Other = append(conf.Other, key)
			continue
		}
		if i+1 >= len(words) {
			return nil, fmt.Errorf("cpu 里的 %s 没有值", key)
		}
		value := words[i+1]
		i++
		switch key {
		case "main-core":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("main-core %q", value)
			}
			conf.MainCore = &n
		case "corelist-workers":
			list, err := parseCoreList(value)
			if err != nil {
				return nil, fmt.Errorf("corelist-workers %q: %w", value, err)
			}
			conf.Workers = list
		case "coremask-workers":
			list, err := parseCoreMask(value)
			if err != nil {
				return nil, fmt.Errorf("coremask-workers %q: %w", value, err)
			}
			conf.Workers = list
		case "workers":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("workers %q", value)
			}
			conf.AutoWorkers = n
		case "scheduler-policy":
			conf.Policy = value
		case "scheduler-priority":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("scheduler-priority %q", value)
			}
			conf.Priority = &n
		default:
			conf.Other = append(conf.Other, key, value)
		}
	}
	return conf, nil
}

// cpuText is the cpu section for these settings, on one line.
func cpuText(conf *cpuConf) string {
	parts := []string{"cpu {"}
	if conf.MainCore != nil {
		parts = append(parts, "main-core", strconv.Itoa(*conf.MainCore))
	}
	if len(conf.Workers) > 0 {
		parts = append(parts, "corelist-workers", formatCoreList(conf.Workers))
	}
	if conf.Policy != "" {
		parts = append(parts, "scheduler-policy", conf.Policy)
	}
	if conf.Priority != nil {
		parts = append(parts, "scheduler-priority", strconv.Itoa(*conf.Priority))
	}
	parts = append(parts, conf.Other...)
	return strings.Join(append(parts, "}"), " ")
}

func parseCoreList(text string) ([]int, error) {
	var list []int
	for _, part := range strings.Split(text, ",") {
		first, last, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(first)
		if err != nil || a < 0 {
			return nil, errors.New("不是核心列表")
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(last); err != nil || b < a {
				return nil, errors.New("不是核心列表")
			}
		}
		for n := a; n <= b; n++ {
			if !slices.Contains(list, n) {
				list = append(list, n)
			}
		}
	}
	slices.Sort(list)
	return list, nil
}

func parseCoreMask(text string) ([]int, error) {
	mask, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(text), "0x"), 16, 64)
	if err != nil {
		return nil, errors.New("不是十六进制掩码")
	}
	var list []int
	for n := 0; n < 64; n++ {
		if mask&(1<<n) != 0 {
			list = append(list, n)
		}
	}
	return list, nil
}

func formatCoreList(list []int) string {
	sorted := slices.Clone(list)
	slices.Sort(sorted)
	var parts []string
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}
		if j == i {
			parts = append(parts, strconv.Itoa(sorted[i]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", sorted[i], sorted[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// dpdkDev is a "dev ADDRESS" entry in the dpdk section.
type dpdkDev struct {
	Address string // as written; "default" for dev default
	Name    string
	Queues  int // num-rx-queues, 0 when not given
	item    *item
	queues  *token // the value of num-rx-queues
	nameTok *token // the value of name
	devWord token  // the word dev
}

func (c *startConf) dpdkDevs() []dpdkDev {
	s := c.section("dpdk")
	if s == nil {
		return nil
	}
	var devs []dpdkDev
	for i := 0; i < len(s.body); i++ {
		if s.body[i].section || s.body[i].word.text != "dev" || i+1 >= len(s.body) {
			continue
		}
		it := &s.body[i+1]
		dev := dpdkDev{Address: it.word.text, item: it, devWord: s.body[i].word}
		for j := 0; j+1 < len(it.body); j++ {
			switch it.body[j].word.text {
			case "name":
				dev.nameTok = &it.body[j+1].word
				dev.Name = dev.nameTok.text
			case "num-rx-queues":
				dev.queues = &it.body[j+1].word
				dev.Queues, _ = strconv.Atoi(dev.queues.text)
			}
		}
		devs = append(devs, dev)
		i++
	}
	return devs
}

// edit is a replacement of the bytes start:end.
type edit struct {
	start, end int
	text       string
}

func applyEdits(text string, edits []edit) string {
	slices.SortFunc(edits, func(a, b edit) int { return b.start - a.start })
	for _, e := range edits {
		text = text[:e.start] + e.text + text[e.end:]
	}
	return text
}

// withThreads is the file with the cpu section replaced and these dpdk devices' queue counts.
func (c *startConf) withThreads(conf *cpuConf, queues map[string]int) (string, error) {
	var edits []edit
	if s := c.section("cpu"); s != nil {
		edits = append(edits, edit{s.word.start, s.shut, cpuText(conf)})
	} else {
		prefix := ""
		if c.text != "" && !strings.HasSuffix(c.text, "\n") {
			prefix = "\n"
		}
		edits = append(edits, edit{len(c.text), len(c.text), prefix + cpuText(conf) + "\n"})
	}
	devs := c.dpdkDevs()
	for address, n := range queues {
		i := slices.IndexFunc(devs, func(d dpdkDev) bool { return sameAddress(d.Address, address) })
		if i < 0 {
			return "", fmt.Errorf("dpdk 里没有 dev %s", address)
		}
		dev := devs[i]
		value := strconv.Itoa(n)
		switch {
		case dev.queues != nil:
			edits = append(edits, edit{dev.queues.start, dev.queues.end, value})
		case dev.item.section:
			edits = append(edits, edit{dev.item.open + 1, dev.item.open + 1, " num-rx-queues " + value})
		default:
			edits = append(edits, edit{dev.item.word.end, dev.item.word.end, " { num-rx-queues " + value + " }"})
		}
	}
	return applyEdits(c.text, edits), nil
}

// pciAddress parses "0000:01:00.0" or "01:00.0", the function in hex and in VPP's "00" form alike.
func pciAddress(text string) (string, bool) {
	parts := strings.Split(text, ":")
	if len(parts) == 2 {
		parts = append([]string{"0"}, parts...)
	}
	if len(parts) != 3 {
		return "", false
	}
	device, function, ok := strings.Cut(parts[2], ".")
	if !ok {
		return "", false
	}
	var n [4]uint64
	for i, s := range []string{parts[0], parts[1], device, function} {
		v, err := strconv.ParseUint(s, 16, 32)
		if err != nil {
			return "", false
		}
		n[i] = v
	}
	return fmt.Sprintf("%04x:%02x:%02x.%x", n[0], n[1], n[2], n[3]), true
}

func sameAddress(a, b string) bool {
	x, ok1 := pciAddress(a)
	y, ok2 := pciAddress(b)
	return ok1 && ok2 && x == y
}
