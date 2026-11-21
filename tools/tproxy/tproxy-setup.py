#!/usr/bin/env python3
"""One-time Linux policy setup after VPP creates its dedicated TAP."""
import json
import subprocess
import time


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args) + ': ' + result.stderr.strip())
    return result.stdout


def main():
    for unused in range(25):
        if subprocess.run(['ip', 'link', 'show', 'dev', 'vpp-tproxy'], capture_output=True).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('VPP TAP vpp-tproxy is absent')
    run('ip', 'link', 'set', 'dev', 'vpp-tproxy', 'up')
    run('sysctl', '-qw', 'net.ipv4.conf.vpp-tproxy.rp_filter=2',
        'net.ipv6.conf.vpp-tproxy.accept_ra=0', 'net.ipv6.conf.vpp-tproxy.autoconf=0')
    # Refuse to overwrite unrelated rules at our reserved priorities.
    existing_rules = {}
    for family in ('-4', '-6'):
        rules = json.loads(run('ip', '-j', family, 'rule', 'show'))
        existing_rules[family] = rules
        for priority, mark, table in ((12080, 0x2080, 2080), (12081, 0x2081, 2081)):
            for rule in (rule for rule in rules if rule.get('priority') == priority):
                if (str(rule.get('table')) != str(table) or
                        str(rule.get('fwmark')) not in (str(mark), hex(mark)) or
                        str(rule.get('fwmask', '0xffff')) not in ('65535', '0xffff')):
                    raise RuntimeError('Conflicting ' + family + ' policy priority ' + str(priority))
    run('nft', '-c', '-f', '/etc/vpp/tproxy.nft')
    run('ip', '-4', 'route', 'replace', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '2080')
    run('ip', '-4', 'route', 'replace', '10.61.30.0/24', 'via', '10.63.50.1', 'dev', 'vpp-tproxy', 'table', '2081')
    run('ip', '-6', 'route', 'replace', 'local', '::/0', 'dev', 'lo', 'table', '2080')
    run('ip', '-6', 'route', 'replace', 'default', 'via', 'fd76:7070:2080::1', 'dev', 'vpp-tproxy', 'table', '2081')
    for family, rules in existing_rules.items():
        for priority, mark, table in ((12080, '0x2080/0xffff', '2080'), (12081, '0x2081/0xffff', '2081')):
            if not any(rule.get('priority') == priority for rule in rules):
                run('ip', family, 'rule', 'add', 'priority', str(priority), 'fwmark', mark, 'lookup', table)
    run('nft', '-f', '/etc/vpp/tproxy.nft')
    print('VPP TAP TPROXY rules and reply routes ready')


if __name__ == '__main__':
    main()
