#!/usr/bin/env python3
"""VPP 路由器 LAN 上的 dnsmasq：/etc/vpp/dnsmasq.conf 和静态分配 /etc/vpp/dhcp-hosts。

LAN 只用这一个 dnsmasq 实例（vpp-router-dnsmasq.service）。系统原有的 dnsmasq.service
由安装脚本停用，它的配置中能沿用的部分导入到这里。

  scan            读取系统 dnsmasq 的配置，列出能导入和不导入的内容，不修改任何文件
  import          导入：静态分配进 dhcp-hosts，其余配置追加到 dnsmasq.conf，
                  LAN 网段内的现有租约复制到新的租约文件（只在它还不存在时）
  set             就地更新 dnsmasq.conf 里由安装脚本和面板管理的几行，其余行原样保留
  range           打印 dnsmasq.conf 里的 IPv4 地址池：起始 结束 掩码（没有时为 -） 租期
  restore-legacy  还原 2026-11 以前的安装对系统 dnsmasq 配置做的修改

dnsmasq.conf 里由这里管理的是：interface、bind-interfaces、bind-dynamic、except-interface、
listen-address、dhcp-authoritative、IPv4 的 dhcp-range、不带标签的 router 和 dns-server
选项、dhcp-leasefile、dhcp-hostsfile，指定 --script 时还有 dhcp-script 和 script-on-renewal
（面板用它记录客户端，识别同一台设备）。别的行（包括导入的和手工加的）都不改动。
"""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

DEBIAN_CONFIG_DIR = '/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new'
DEFAULT_LEASES = '/var/lib/misc/dnsmasq.leases'
HEADER = ('# VPP 路由器 LAN 的 dnsmasq。安装脚本和面板只修改监听、地址池、网关、DNS、租约文件和\n'
          '# 静态分配文件这几项，其余内容可以自由增改；静态分配写在 dhcp-hostsfile 指向的文件里。\n')
MAC = re.compile(r'^(?:[0-9a-fA-F*]{2}[:-]){5}[0-9a-fA-F*]{2}$')
LEASE = re.compile(r'^(?:\d+[smhdw]?|infinite)$')
# What the installer wrote on top before the file was changed in place, which says it is all generated.
OLD_HEADER = re.compile(r'^# 由 vpp-router-install\.sh 生成；只在 \S+ 上提供 DHCP 和 DNS$')

# 由 VPP 的拓扑和本工具决定，不从系统配置导入
SKIP = {
    'interface': '监听接口由 VPP 的拓扑决定',
    'listen-address': '监听地址由 VPP 的拓扑决定',
    'except-interface': '监听接口由 VPP 的拓扑决定',
    'no-dhcp-interface': '监听接口由 VPP 的拓扑决定',
    'bind-interfaces': '监听方式由本工具设置',
    'bind-dynamic': '监听方式由本工具设置',
    'port': 'DNS 端口由本工具设置',
    'dhcp-authoritative': '由本工具设置',
    'dhcp-leasefile': '租约文件由本工具设置，现有租约另行复制',
    'dhcp-lease-file': '租约文件由本工具设置，现有租约另行复制',
    'dhcp-hostsfile': '其中的静态分配已导入',
    'dhcp-hostsdir': '其中的静态分配已导入',
    'dhcp-script': '由面板设置',
    'enable-ra': 'LAN 的 RA 由 VPP 发出',
    'pid-file': '由 systemd 服务管理',
    'user': '由 systemd 服务管理',
    'group': '由 systemd 服务管理',
    'keep-in-foreground': '由 systemd 服务管理',
}


class Entry:
    def __init__(self, path, line, key, value):
        self.path, self.line, self.key, self.value = path, line, key, value

    def text(self):
        return f'{self.key}={self.value}' if self.value else self.key


# ---------- 找出系统 dnsmasq 实际读取的配置 ----------

def service_state():
    def query(*args):
        try:
            return subprocess.run(['systemctl', *args, 'dnsmasq.service'], capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ''
    return {'active': query('is-active') == 'active', 'enabled': query('is-enabled') == 'enabled',
            'pid': query('show', '-p', 'MainPID', '--value')}


def split_cmdline(args):
    """从 dnsmasq 命令行取出 -C/--conf-file 和 -7/--conf-dir。"""
    conf, dirs = None, []
    i = 0
    while i < len(args):
        arg, key, value = args[i], None, None
        if arg.startswith('--'):
            key, sep, value = arg[2:].partition('=')
            if not sep and key in ('conf-file', 'conf-dir') and i + 1 < len(args):
                i, value = i + 1, args[i + 1]
        elif arg[:2] in ('-C', '-7'):
            key = 'conf-file' if arg[:2] == '-C' else 'conf-dir'
            value = arg[2:] or None
            if value is None and i + 1 < len(args):
                i, value = i + 1, args[i + 1]
        if key == 'conf-file':
            conf = value
        elif key == 'conf-dir':
            dirs.append(value)
        i += 1
    return conf, dirs


def discover(args):
    if args.system_conf:
        return args.system_conf, list(args.system_conf_dir or [])
    state = service_state()
    try:
        raw = Path(f'/proc/{int(state["pid"])}/cmdline').read_bytes()
        cmdline = [a.decode() for a in raw.split(b'\0') if a]
    except (OSError, ValueError):
        cmdline = []
    if cmdline:
        conf, dirs = split_cmdline(cmdline[1:])
        return conf or '/etc/dnsmasq.conf', dirs
    # 没有运行时按 Debian 启动脚本的默认值推断
    dirs = []
    default = Path('/etc/default/dnsmasq')
    if default.exists() or Path('/etc/init.d/dnsmasq').exists():
        value = DEBIAN_CONFIG_DIR
        if default.exists():
            for line in default.read_text(errors='replace').splitlines():
                if line.strip().startswith('CONFIG_DIR='):
                    value = line.split('=', 1)[1].strip().strip('"\'')
        if value:
            dirs.append(value)
    return '/etc/dnsmasq.conf', dirs


def dir_files(spec):
    directory, *suffixes = spec.split(',')
    include = [s[1:] for s in suffixes if s.startswith('*')]
    exclude = [s for s in suffixes if s and not s.startswith('*')]
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    files = []
    for name in names:
        if name.endswith('~') or name.startswith('.') or (name.startswith('#') and name.endswith('#')):
            continue
        if include and not any(name.endswith(s) for s in include):
            continue
        if not include and any(name.endswith(s) for s in exclude):
            continue
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            files.append(path)
    return files


def read_entries(main, dirs, skip=()):
    """按 dnsmasq 的规则展开 conf-file 和 conf-dir，返回 (文件列表, 条目)。skip 里的文件不读。"""
    files, entries, seen = [], [], {os.path.realpath(p) for p in skip}

    def visit(path):
        real = os.path.realpath(path)
        if real in seen or not os.path.isfile(path):
            return
        seen.add(real)
        files.append(path)
        for n, raw in enumerate(Path(path).read_text(errors='replace').splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            key, _, value = line.partition('=')
            key, value = key.strip(), value.strip()
            if key == 'conf-file':
                visit(value)
            elif key == 'conf-dir':
                for f in dir_files(value):
                    visit(f)
            else:
                entries.append(Entry(path, n, key, value))

    visit(main)
    for spec in dirs:
        for f in dir_files(spec):
            visit(f)
    return files, entries


# ---------- 解析 ----------

def ip4(text):
    try:
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def strip_tags(value):
    fields = [f.strip() for f in value.split(',')]
    tags = []
    while fields and re.match(r'^(tag|set|id):', fields[0]):
        tags.append(fields.pop(0))
    return tags, fields


def parse_range(value):
    """IPv4 的 dhcp-range：返回 {tags, start, end, mask, lease}；不是 IPv4 地址池时返回 None。"""
    tags, fields = strip_tags(value)
    if len(fields) < 2 or not ip4(fields[0]):
        return None
    start = fields[0]
    rest = fields[1:]
    end = rest.pop(0) if rest and ip4(rest[0]) else None
    if end is None:
        return None
    mask = lease = None
    for f in rest:
        if mask is None and ip4(f):
            mask = f
        elif LEASE.match(f):
            lease = f
    return {'tags': tags, 'start': start, 'end': end, 'mask': mask, 'lease': lease}


def option_kind(value):
    """不带标签的 router/dns-server 选项返回 'router'/'dns'，其余返回 None。"""
    tags, fields = strip_tags(value)
    if tags or not fields:
        return None
    opt = fields[0]
    if opt in ('3', 'option:router'):
        return 'router'
    if opt in ('6', 'option:dns-server'):
        return 'dns'
    return None


def host_macs(line):
    _, fields = strip_tags(line)
    return {f.lower().replace('-', ':') for f in fields if MAC.match(f)}


def host_ip(line):
    _, fields = strip_tags(line)
    for f in fields:
        a = ip4(f)
        if a:
            return a
    return None


# ---------- 导入 ----------

def plan_import(entries, lan):
    """把系统配置的条目分成：静态分配、地址池、追加的配置行、跳过的条目，以及租约文件位置。"""
    network = ipaddress.IPv4Interface(lan).network
    result = {'hosts': [], 'range': None, 'lines': [], 'skipped': [], 'leases': DEFAULT_LEASES}

    def skip(e, reason):
        result['skipped'].append({'file': e.path, 'line': e.line, 'text': e.text(), 'reason': reason})

    def add_host(e, value, where=None):
        address = host_ip(value)
        if address and address not in network:
            result['skipped'].append({'file': where or e.path, 'line': e.line, 'text': f'dhcp-host={value}',
                                      'reason': f'{address} 不在 LAN 网段 {network} 内'})
        else:
            result['hosts'].append(value)

    for e in entries:
        if e.key == 'dhcp-host':
            add_host(e, e.value)
        elif e.key in ('dhcp-hostsfile', 'dhcp-hostsdir'):
            paths = [e.value] if e.key == 'dhcp-hostsfile' else dir_files(e.value)
            for path in paths:
                try:
                    lines = Path(path).read_text(errors='replace').splitlines()
                except OSError:
                    skip(e, f'读不到 {path}')
                    continue
                for line in lines:
                    if line.strip() and not line.strip().startswith('#'):
                        add_host(e, line.strip(), path)
        elif e.key in ('dhcp-leasefile', 'dhcp-lease-file'):
            result['leases'] = e.value
            skip(e, SKIP[e.key])
        elif e.key == 'dhcp-range':
            r = parse_range(e.value)
            if r and not r['tags'] and ip4(r['start']) in network and ip4(r['end']) in network and not result['range']:
                result['range'] = r
                skip(e, '作为地址池的默认值')
            else:
                skip(e, f'不是 LAN 网段 {network} 内的 IPv4 地址池')
        elif e.key in ('dhcp-option', 'dhcp-option-force') and option_kind(e.value):
            skip(e, '网关和 DNS 由 VPP 的拓扑决定')
        elif e.key in SKIP:
            skip(e, SKIP[e.key])
        else:
            result['lines'].append(e.text())
    return result


def scan(args):
    main_conf, dirs = discover(args)
    files, entries = read_entries(main_conf, dirs, skip=[args.conf])
    result = plan_import(entries, args.lan)
    result['leases_in_lan'] = len(lease_lines(result['leases'], args.lan))
    result.update(main=main_conf, dirs=dirs, files=files, service=service_state())
    if args.json:
        print(json.dumps(result, ensure_ascii=False))
        return 0
    if args.range_only:
        r = result['range']
        if r:
            print(r['start'], r['end'], r['mask'] or '-', r['lease'] or '1h')
        return 0
    if result['hosts']:
        print(f'导入 {len(result["hosts"])} 条静态分配')
    if result['range']:
        r = result['range']
        print(f'地址池 {r["start"]} – {r["end"]}（租期 {r["lease"] or "1h"}）作为默认值')
    if result['leases_in_lan']:
        print(f'复制 {result["leases_in_lan"]} 条 LAN 网段内的现有租约')
    for line in result['lines']:
        print(f'导入 {line}')
    for s in result['skipped']:
        print(f'不导入 {s["text"]}（{s["file"]}:{s["line"]}）：{s["reason"]}')
    return 0


def lease_lines(path, lan):
    network = ipaddress.IPv4Interface(lan).network
    try:
        lines = Path(path).read_text(errors='replace').splitlines()
    except OSError:
        return []
    kept = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and ip4(fields[2]) and ip4(fields[2]) in network:
            kept.append(line)
    return kept


def write_atomic(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '.')
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.chmod(tmp, path.stat().st_mode & 0o7777 if path.exists() else mode)
    os.replace(tmp, path)


def dnsmasq_test(conf):
    binary = shutil.which('dnsmasq')
    if not binary:
        return None
    try:
        r = subprocess.run([binary, '--test', '-C', str(conf)], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return str(e)
    return None if r.returncode == 0 else (r.stderr or r.stdout).strip()


def do_import(args):
    main_conf, dirs = discover(args)
    _, entries = read_entries(main_conf, dirs, skip=[args.conf, args.hosts])
    result = plan_import(entries, args.lan)
    conf, hosts = Path(args.conf), Path(args.hosts)
    if not conf.exists():
        raise ValueError(f'{conf} 还不存在，先用 set 生成')
    # 静态分配：同一个 MAC 或同一行已经有了就不再加
    existing = hosts.read_text().splitlines() if hosts.exists() else []
    seen = {m for line in existing for m in host_macs(line)}
    added_hosts = []
    for line in result['hosts']:
        macs = host_macs(line)
        if line in existing or (macs and macs & seen):
            continue
        added_hosts.append(line)
        seen |= macs
    if added_hosts:
        write_atomic(hosts, '\n'.join(existing + added_hosts) + '\n')
    # 其余配置：已经有同样的行就不再加
    text = conf.read_text()
    present = {line.strip() for line in text.splitlines()}
    lines = [line for line in result['lines'] if line not in present]
    if any(line.startswith('cache-size=') for line in lines):
        # 用原来的缓存大小，不留两行
        text = '\n'.join(l for l in text.splitlines() if not l.strip().startswith('cache-size=')) + '\n'
    if lines:
        stamp = f'{datetime.datetime.now():%Y-%m-%d %H:%M}'
        block = f'\n# {stamp} 从系统 dnsmasq（{main_conf}）导入\n' + '\n'.join(lines) + '\n'
        candidate = text.rstrip('\n') + '\n' + block
        write_atomic(conf, candidate)
        error = dnsmasq_test(conf)
        if error:
            # 导入的行让 dnsmasq 起不来时改成注释，地址池等管理的配置照常生效
            block = (f'\n# {stamp} 从系统 dnsmasq（{main_conf}）导入，未通过 dnsmasq --test，已注释：{error}\n'
                     + '\n'.join('#' + line for line in lines) + '\n')
            write_atomic(conf, text.rstrip('\n') + '\n' + block)
            print(f'警告：导入的配置未通过 dnsmasq --test，已改成注释：{error}')
    # 现有租约：新租约文件还没有时才复制，避免覆盖这个实例自己的租约
    leases = Path(args.leases)
    copied = 0
    if not leases.exists():
        kept = lease_lines(result['leases'], args.lan)
        if kept:
            write_atomic(leases, '\n'.join(kept) + '\n')
            copied = len(kept)
    print(f'导入了 {len(added_hosts)} 条静态分配、{len(lines)} 行配置、{copied} 条租约')
    return 0


# ---------- 管理的行 ----------

def identity(key, value, script=False):
    if script and key in ('dhcp-script', 'script-on-renewal'):
        return key
    if key in ('interface', 'bind-interfaces', 'bind-dynamic', 'except-interface', 'listen-address',
               'dhcp-authoritative', 'dhcp-hostsfile'):
        return key
    if key in ('dhcp-leasefile', 'dhcp-lease-file'):
        return 'dhcp-leasefile'
    if key == 'dhcp-range' and parse_range(value):
        return 'dhcp-range'
    if key in ('dhcp-option', 'dhcp-option-force'):
        kind = option_kind(value)
        return f'option-{kind}' if kind else None
    return None


def managed_lines(args):
    start, end, mask, lease = args.range.split(',')
    for a in (start, end, mask, args.listen, args.router):
        if not ip4(a):
            raise ValueError(f'{a} 不是 IPv4 地址')
    if not LEASE.match(lease):
        raise ValueError(f'租期 {lease} 无效，写成 12h、30m 或 infinite')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+', args.interface):
        raise ValueError(f'接口名 {args.interface} 无效')
    return [f'interface={args.interface}', 'bind-interfaces', 'except-interface=lo',
            f'listen-address={args.listen}', 'dhcp-authoritative',
            f'dhcp-range={start},{end},{mask},{lease}',
            f'dhcp-option=option:router,{args.router}',
            f'dhcp-option=option:dns-server,{args.dns or args.listen}',
            f'dhcp-leasefile={args.leasefile}', f'dhcp-hostsfile={args.hostsfile}'] + script_lines(args.script)


def script_lines(script):
    """dhcp-script, and script-on-renewal where this dnsmasq has it (2.86 and later), so that
    the script hears of a client at every renewal and not only when it first comes."""
    if not script:
        return []
    lines = [f'dhcp-script={script}']
    binary = shutil.which('dnsmasq')
    if binary:
        try:
            help_text = subprocess.run([binary, '--help'], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            help_text = ''
        if 'script-on-renewal' in help_text:
            lines.append('script-on-renewal')
    return lines


def update(text, managed, script=False):
    """去掉管理的行，在第一处原位置（没有时在开头的注释之后）放上新的；其他行不动。
    旧版本整个生成时写在开头的注释换成现在的说明。"""
    out, at = [], None
    lines = text.splitlines()
    if lines and OLD_HEADER.match(lines[0].strip()):
        lines = HEADER.rstrip('\n').split('\n') + lines[1:]
    for raw in lines:
        line = raw.strip()
        key, _, value = line.partition('=')
        if line and not line.startswith('#') and identity(key.strip(), value.strip(), script):
            if at is None:
                at = len(out)
            continue
        out.append(raw)
    if at is None:
        at = 0
        while at < len(out) and (not out[at].strip() or out[at].lstrip().startswith('#')):
            at += 1
    return '\n'.join(out[:at] + managed + out[at:]) + '\n'


def do_set(args):
    conf = Path(args.conf)
    managed = managed_lines(args)
    if conf.exists():
        text = update(conf.read_text(), managed, bool(args.script))
    else:
        text = HEADER + '\n'.join(managed) + '\ncache-size=1000\n'
    write_atomic(conf, text)
    hosts = Path(args.hostsfile)
    if not hosts.exists():
        write_atomic(hosts, '# 静态分配，一行一条，格式同 dhcp-host（不写 dhcp-host=），比如\n'
                            '# 02:00:00:00:10:01,10.61.30.20,nas\n')
    error = dnsmasq_test(conf)
    if error:
        raise ValueError(f'{conf} 未通过 dnsmasq --test：{error}')
    return 0


def do_range(args):
    try:
        lines = Path(args.conf).read_text().splitlines()
    except OSError:
        return 0
    for raw in lines:
        key, _, value = raw.strip().partition('=')
        if key.strip() == 'dhcp-range':
            r = parse_range(value.strip())
            if r:
                print(r['start'], r['end'], r['mask'] or '-', r['lease'] or '1h')
                return 0
    return 0


# ---------- 旧安装 ----------

def restore_legacy(args):
    orig = Path(args.state) / 'dnsmasq-orig'
    if not (orig / 'manifest.json').exists():
        print('没有 dnsmasq 原始配置备份，无需恢复')
        return 0
    manifest = json.loads((orig / 'manifest.json').read_text())
    for p in manifest['backed_up']:
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(orig / 'files' / p.lstrip('/'), p)
    for p in manifest['created']:
        if os.path.exists(p):
            os.remove(p)
    done = orig.with_name(f'dnsmasq-orig.restored-{datetime.datetime.now():%Y%m%d-%H%M%S}')
    orig.rename(done)
    print(f'已恢复系统 dnsmasq 的原始配置（{len(manifest["backed_up"])} 个文件），备份移到 {done}')
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('scan', 'import'):
        s = sub.add_parser(name)
        s.add_argument('--lan', required=True, help='VPP LAN 网关地址/前缀')
        s.add_argument('--conf', default='/etc/vpp/dnsmasq.conf')
        s.add_argument('--system-conf', help='系统 dnsmasq 的主配置；不指定时从运行中的进程读取')
        s.add_argument('--system-conf-dir', action='append', help='系统 dnsmasq 的 conf-dir（可重复）')
        if name == 'scan':
            s.add_argument('--json', action='store_true')
            s.add_argument('--range-only', action='store_true', help='只打印可用作默认值的地址池，格式同 range')
        else:
            s.add_argument('--hosts', default='/etc/vpp/dhcp-hosts')
            s.add_argument('--leases', default='/var/lib/vpp-router/dnsmasq.leases')
    s = sub.add_parser('set')
    s.add_argument('--conf', default='/etc/vpp/dnsmasq.conf')
    s.add_argument('--interface', default='vpp-host')
    s.add_argument('--listen', required=True)
    s.add_argument('--range', required=True, help='起始,结束,掩码,租期')
    s.add_argument('--router', required=True)
    s.add_argument('--dns', help='发给客户端的 DNS，默认是监听地址')
    s.add_argument('--leasefile', default='/var/lib/vpp-router/dnsmasq.leases')
    s.add_argument('--hostsfile', default='/etc/vpp/dhcp-hosts')
    s.add_argument('--script', help='dhcp-script：面板的 vpp-interfaces，记录客户端')
    s = sub.add_parser('range')
    s.add_argument('--conf', default='/etc/vpp/dnsmasq.conf')
    s = sub.add_parser('restore-legacy')
    s.add_argument('--state', default='/var/lib/vpp-router')
    args = p.parse_args()
    return {'scan': scan, 'import': do_import, 'set': do_set, 'range': do_range,
            'restore-legacy': restore_legacy}[args.command](args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'dnsmasq：{exc}', file=sys.stderr)
        sys.exit(1)
