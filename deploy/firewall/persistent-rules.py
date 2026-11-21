#!/usr/bin/env python3
"""Render the persistent VPP includes while preserving the Linux base policy."""
import re

BEGIN = '# BEGIN VROUTER VPP includes'
END = '# END VROUTER VPP includes'

# VPP FIB/NAT owns these destinations and IPsec/sg IPv4 sources. Linux inet
# mangle must still mark TPROXY (proxylist/proxylist6, vrouter_lease) and host-path bits.
VPP_SOURCE_PREFIXES = ('10.62.20.0/24', '10.62.40.0/24')
VPP_SOURCE_PATTERN = '|'.join(re.escape(prefix) for prefix in VPP_SOURCE_PREFIXES)
VPP_OWNED_MARK = re.compile(
    r'(?i)^\s*(?:'
    r'ip6?\s+daddr\s+@(?:uk|altroute|vpn|vpn6)\b|'
    rf'ip\s+saddr\s+(?:(?:{VPP_SOURCE_PATTERN})|\{{[^}}]*(?:{VPP_SOURCE_PATTERN})[^}}]*\}})|'
    r'ip6\s+saddr\s+fd42:1111:2222:70::/64\b'
    r').*\bmark set\b'
)


def drop_vpp_owned_marks(text):
    return '\n'.join(line for line in text.splitlines() if not VPP_OWNED_MARK.search(line))


def main_ruleset(text):
    text = re.sub(re.escape(BEGIN)+r'.*?'+re.escape(END)+r'\n?', '', text, flags=re.S)
    # The Linux WAN device is owned by DPDK in VPP mode. A flowtable cannot
    # bind that absent netdevice; ordinary Linux forwarding remains available.
    while match := re.search(r'\bflowtable\s+(\w+)\s*\{', text):
        depth, end = 1, match.end()
        while depth and end < len(text):
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        if depth:
            raise ValueError('Unbalanced flowtable')
        name = match[1]
        text = text[:match.start()]+text[end:]
        text = '\n'.join(line for line in text.splitlines()
                         if not re.search(r'\bflow add @'+re.escape(name)+r'\b', line))+'\n'
    # Preserve Linux boot behavior as well as the active VPP management bridge.
    def interfaces(match):
        value = match[1]
        if '"lan"' in value and '"br-mgmt"' not in value:
            value = value.replace('"lan"', '"lan", "br-mgmt"')
        return match[0].replace(match[1], value)
    text = re.sub(r'\b[io]ifname\s+(\{[^}]*\})', interfaces, text)
    text = re.sub(r'\b([io]ifname)\s+"lan"', r'\1 { "lan", "br-mgmt" }', text)
    text = drop_vpp_owned_marks(text)
    return text.rstrip()+'\n\n'+BEGIN+'\ninclude "/etc/nftables.d/vrouter-vpp.nft"\n'+END+'\n'


def includes():
    return ''.join('include "/etc/vpp/'+name+'"\n' for name in
                   ('wg-proxy.nft', 'host-path.nft', 'dns-route-gate.nft'))
