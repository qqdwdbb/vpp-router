import importlib.util
import json
import ipaddress
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

FIREWALL_DIR = Path(__file__).parents[2] / "deploy/firewall"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fw_mod = load_module("vrouter_firewall", FIREWALL_DIR / "vrouter-firewall.py")
DEFAULT_CONFIG = fw_mod.DEFAULT_CONFIG
generate_vpp_acls = fw_mod.generate_vpp_acls
load_config = fw_mod.load_config
parse_args = fw_mod.parse_args



class TestVROUTERFirewallUnit(unittest.TestCase):

    def test_lan_ipv6_accepts_only_configured_ula_and_delegated_prefixes(self):
        cfg = {"vpp": {**DEFAULT_CONFIG["vpp"], "lan_ipv6": ["fd42:1111:2222:10::/64", "2001:db8:1234::/64"]}}
        rules = generate_vpp_acls(cfg)["lan_in"]
        self.assertIn("permit+reflect src 2001:db8:1234::/64 dst ::/0", rules)
        self.assertIn("permit+reflect src fd42:1111:2222:10::/64 dst ::/0", rules)
        self.assertNotIn("permit+reflect src ::/0 dst ::/0", rules)
        self.assertTrue(rules.endswith("deny src ::/0 dst ::/0"))

    def test_lan_service_precedes_gateway_deny_and_does_not_open_wan(self):
        cfg = {"vpp": {**DEFAULT_CONFIG["vpp"], "lan_tcp_services": [1080]}}
        rules = generate_vpp_acls(cfg)
        permit = "permit src 10.61.20.0/24 dst 10.61.20.1/32 proto 6 dport 1080"
        self.assertLess(rules['lan_in'].index(permit), rules['lan_in'].index("deny src 0.0.0.0/0 dst 10.61.20.1/32"))
        self.assertNotIn('dport 1080', rules['wan_in'])
        self.assertNotIn('dport 1080', generate_vpp_acls(DEFAULT_CONFIG)['lan_in'])
        with self.assertRaises(ValueError):
            generate_vpp_acls({'vpp': {'lan_tcp_services': [0]}})

    def test_blocked_lan_tcp_destination_precedes_forwarding(self):
        cfg = {"vpp": {**DEFAULT_CONFIG["vpp"],
                        "blocked_lan_tcp_destinations": ["8.8.8.8"]}}
        rules = generate_vpp_acls(cfg)["lan_in"]
        dns = "permit src 10.61.20.0/24 dst 8.8.8.8/32 proto 6 dport 53"
        blocked = "deny src 10.61.20.0/24 dst 8.8.8.8/32 proto 6"
        forwarding = "permit+reflect src 10.61.20.0/24 dst 0.0.0.0/0"
        self.assertIn(dns, rules)
        self.assertIn(blocked, rules)
        self.assertLess(rules.index(dns), rules.index(blocked))
        self.assertLess(rules.index(blocked), rules.index(forwarding))

    def test_gost_wan_tcp_exception_is_exact_and_opt_in(self):
        cfg = {'vpp': {**DEFAULT_CONFIG['vpp'], 'wan_host_tcp_ports': [42002]}}
        rules = generate_vpp_acls(cfg)
        self.assertIn('permit src 0.0.0.0/0 dst 10.61.10.2/32 proto 6 dport 42002', rules['wan_in'])
        self.assertNotIn('dport 42002', generate_vpp_acls(DEFAULT_CONFIG)['wan_in'])
        with self.assertRaises(ValueError):
            generate_vpp_acls({'vpp': {'wan_host_tcp_ports': [True]}})

    def test_gost_wan_tcp_sources_restrict_the_port(self):
        cfg = {'vpp': {**DEFAULT_CONFIG['vpp'],
                       'wan_host_tcp_ports': [42002],
                       'wan_host_tcp_sources': {'42002': ['198.18.16.0/20']}}}
        rules = generate_vpp_acls(cfg)['wan_in']
        allowed = 'permit src 198.18.16.0/20 dst 10.61.10.2/32 proto 6 dport 42002'
        denied = 'deny src 0.0.0.0/0 dst 10.61.10.2/32 proto 6 dport 42002'
        generic = 'permit src 0.0.0.0/0 dst 10.61.10.2/32 proto 6 dport 42002'
        self.assertIn(allowed, rules)
        self.assertIn(denied, rules)
        self.assertNotIn(generic, rules)
        self.assertLess(rules.index(allowed), rules.index(denied))

    def test_gost_wan_tcp_sources_require_ipv4_networks(self):
        with self.assertRaises(ValueError):
            generate_vpp_acls({'vpp': {**DEFAULT_CONFIG['vpp'],
                                       'wan_host_tcp_ports': [42002],
                                       'wan_host_tcp_sources': {'42002': ['2001:db8::/32']}}})

    def test_default_config_loading(self):
        cfg = load_config(None)
        self.assertIn("vpp", cfg)
        self.assertIn("nftables", cfg)
        self.assertEqual(cfg["vpp"]["lan_bvi"], "loop200")
        self.assertEqual(cfg["vpp"]["wan_interface"], "nic1")
        self.assertEqual(cfg["vpp"]["vpp_gw4"], "10.61.20.1")
        self.assertEqual(cfg["vpp"]["vpp_gw6"], "fd42:1111:2222:10::1")
        self.assertEqual(cfg["nftables"]["table_name"], "vrouter_firewall")

    def test_custom_config_loading(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({
                "vpp": {
                    "wan_interface": "nic0",
                    "wireguard_ports": [49915, 49916],
                    "vpp_gw4": "10.64.30.1"
                },
                "nftables": {
                    "table_name": "custom_fw"
                }
            }, f)
            cfg_path = f.name

        try:
            cfg = load_config(cfg_path)
            self.assertEqual(cfg["vpp"]["wan_interface"], "nic0")
            self.assertEqual(cfg["vpp"]["wireguard_ports"], [49915, 49916])
            self.assertEqual(cfg["vpp"]["vpp_gw4"], "10.64.30.1")
            self.assertEqual(cfg["nftables"]["table_name"], "custom_fw")
            # Default values should remain intact if not overridden
            self.assertEqual(cfg["vpp"]["lan_bvi"], "loop200")
        finally:
            Path(cfg_path).unlink()

    def test_generate_vpp_acls_structure(self):
        cfg = DEFAULT_CONFIG.copy()
        acls = generate_vpp_acls(cfg)
        self.assertIn("wan_in", acls)
        self.assertIn("wan_out", acls)
        self.assertIn("lan_in", acls)
        self.assertIsInstance(acls["wan_in"], str)
        self.assertIsInstance(acls["wan_out"], str)
        self.assertIsInstance(acls["lan_in"], str)

    def test_wan_in_anti_spoofing_rules(self):
        acls = generate_vpp_acls(DEFAULT_CONFIG)
        wan_in = acls["wan_in"]
        # Must drop RFC1918 private ranges entering WAN
        self.assertIn("deny src 10.0.0.0/8 dst 0.0.0.0/0", wan_in)
        self.assertIn("deny src 172.16.0.0/12 dst 0.0.0.0/0", wan_in)
        self.assertIn("deny src 192.168.0.0/16 dst 0.0.0.0/0", wan_in)
        # Must drop loopback and multicast
        self.assertIn("deny src 127.0.0.0/8 dst 0.0.0.0/0", wan_in)
        self.assertIn("deny src 224.0.0.0/4 dst 0.0.0.0/0", wan_in)
        # Must drop ULA and link-local on public WAN
        self.assertIn("deny src fc00::/7 dst ::/0", wan_in)
        self.assertIn("deny src fe80::/10 dst ::/0", wan_in)

    def test_wan_in_permitted_services(self):
        acls = generate_vpp_acls(DEFAULT_CONFIG)
        wan_in = acls["wan_in"]
        # IKEv2 ports
        self.assertIn("permit src 0.0.0.0/0 dst 0.0.0.0/0 proto 17 sport 0-65535 dport 500", wan_in)
        self.assertIn("permit src 0.0.0.0/0 dst 0.0.0.0/0 proto 17 sport 0-65535 dport 4500", wan_in)
        self.assertIn("permit src ::/0 dst ::/0 proto 17 sport 0-65535 dport 500", wan_in)
        self.assertIn("permit src ::/0 dst ::/0 proto 17 sport 0-65535 dport 4500", wan_in)
        # WireGuard (wg0 42008, sg 42007)
        self.assertIn("permit src 0.0.0.0/0 dst 0.0.0.0/0 proto 17 sport 0-65535 dport 42008", wan_in)
        self.assertIn("permit src ::/0 dst ::/0 proto 17 sport 0-65535 dport 42008", wan_in)
        self.assertIn("permit src 0.0.0.0/0 dst 0.0.0.0/0 proto 17 sport 0-65535 dport 42007", wan_in)
        self.assertIn("permit src ::/0 dst ::/0 proto 17 sport 0-65535 dport 42007", wan_in)
        # DHCPv6 client responses from upstream
        self.assertIn("permit src ::/0 dst ::/0 proto 17 sport 547 dport 546", wan_in)
        # ICMP and ICMPv6
        self.assertIn("permit src 0.0.0.0/0 dst 0.0.0.0/0 proto 1", wan_in)
        self.assertIn("permit src ::/0 dst ::/0 proto 58", wan_in)
        # Final default drop
        self.assertTrue(wan_in.endswith("deny src ::/0 dst ::/0"))

    def test_wan_out_anti_leak_rules(self):
        acls = generate_vpp_acls(DEFAULT_CONFIG)
        wan_out = acls["wan_out"]
        # Must prevent cleartext private IP leak
        self.assertIn("deny src 10.0.0.0/8 dst 0.0.0.0/0", wan_out)
        self.assertIn("deny src 172.16.0.0/12 dst 0.0.0.0/0", wan_out)
        self.assertIn("deny src 192.168.0.0/16 dst 0.0.0.0/0", wan_out)
        self.assertIn("deny src fc00::/7 dst ::/0", wan_out)
        # Permit legitimate outbound
        self.assertIn("permit+reflect src 0.0.0.0/0 dst 0.0.0.0/0", wan_out)
        self.assertIn("permit+reflect src ::/0 dst ::/0", wan_out)

    def test_lan_in_anti_spoofing_and_gateway_protection(self):
        acls = generate_vpp_acls(DEFAULT_CONFIG)
        lan_in = acls["lan_in"]
        # Allow DHCP discover/request from 0.0.0.0/32
        self.assertIn("permit src 0.0.0.0/32 dst 255.255.255.255/32 proto 17 sport 68 dport 67", lan_in)
        # Allow ping to gateway
        self.assertIn("permit src 10.61.20.0/24 dst 10.61.20.1/32 proto 1", lan_in)
        self.assertIn("permit src fd42:1111:2222:10::/64 dst fd42:1111:2222:10::1/128 proto 58", lan_in)
        # Deny other direct traffic to gateway IP
        self.assertIn("deny src 0.0.0.0/0 dst 10.61.20.1/32", lan_in)
        self.assertIn("deny src ::/0 dst fd42:1111:2222:10::1/128", lan_in)
        # Permit legitimate outbound forwarding
        self.assertIn("permit+reflect src 10.61.20.0/24 dst 0.0.0.0/0", lan_in)
        self.assertIn("permit+reflect src fd42:1111:2222:10::/64 dst ::/0", lan_in)
        # Drop all spoofed sources
        self.assertTrue(lan_in.endswith("deny src ::/0 dst ::/0"))

    def first_action(self, chain, src, dst, proto, sport=12345, dport=443, config=None):
        """Evaluate a new flow against ordered generated ACLs (no cached session)."""
        for rule in generate_vpp_acls(config or DEFAULT_CONFIG)[chain].split(", "):
            fields = rule.split()
            source = ipaddress.ip_network(fields[fields.index("src") + 1])
            target = ipaddress.ip_network(fields[fields.index("dst") + 1])
            if ipaddress.ip_address(src) not in source or ipaddress.ip_address(dst) not in target:
                continue
            if "proto" in fields and int(fields[fields.index("proto") + 1]) != proto:
                continue
            matches = True
            for label, port in (("sport", sport), ("dport", dport)):
                if label in fields:
                    bounds = fields[fields.index(label) + 1].split("-")
                    if not int(bounds[0]) <= port <= int(bounds[-1]):
                        matches = False
            if matches:
                return fields[0]
        self.fail("No matching ACL rule")

    def test_upstream_link_local_control_precedes_spoof_drop(self):
        for destination in ("ff02::1", "fe80::2", "2001:db8::2"):
            self.assertEqual(self.first_action("wan_in", "fe80::1", destination, 58), "permit")
        self.assertEqual(self.first_action("wan_in", "fe80::1", "fe80::2", 17,
                                          sport=547, dport=546), "permit")
        self.assertEqual(self.first_action("wan_in", "fe80::1", "2001:db8::2", 6), "deny")

    def test_unsolicited_global_ipv6_tcp_udp_denied(self):
        for proto in (6, 17):
            self.assertEqual(self.first_action("wan_in", "2001:db8:1::1", "2001:db8:2::100",
                                              proto, dport=44444), "deny")
        self.assertEqual(self.first_action("wan_in", "2001:db8:1::1", "2001:db8:2::2",
                                          17, dport=4500), "permit")

    def test_private_wan_allows_only_configured_source(self):
        self.assertEqual(self.first_action("wan_out", "10.61.10.2", "1.1.1.1", 6), "permit+reflect")
        for source in ("10.61.10.3", "10.61.20.100", "10.62.20.100"):
            self.assertEqual(self.first_action("wan_out", source, "1.1.1.1", 6), "deny")
        self.assertEqual(self.first_action("wan_in", "10.61.10.1", "10.61.10.2", 1), "permit")
        self.assertEqual(self.first_action("wan_in", "10.61.10.1", "10.61.10.2", 6), "deny")
        cfg = {"vpp": {"wan_ipv4": "172.16.1.2", "wan_gateway4": "172.16.1.1"}}
        self.assertEqual(self.first_action("wan_out", "172.16.1.2", "1.1.1.1", 17, config=cfg),
                         "permit+reflect")
        self.assertEqual(self.first_action("wan_out", "10.61.10.2", "1.1.1.1", 6, config=cfg), "deny")

    def test_lan_acl_attaches_to_ingress_ports_not_bvi(self):
        cfg = {"vpp": {"lan_interfaces": ["tap2001", "tap2002"]}}
        calls = []
        def cli(sock, command, ctl):
            calls.append(command)
            return "ACL index:3" if command.startswith("set acl-plugin acl") else ""
        with patch.object(fw_mod, "vpp_cli", side_effect=cli):
            fw_mod.apply_vpp_firewall(cfg)
        self.assertIn("set acl-plugin interface tap2001 input acl 3", calls)
        self.assertIn("set acl-plugin interface tap2002 input acl 3", calls)
        self.assertFalse(any("interface loop200" in command for command in calls))

    def test_lan_ports_required_before_acl_mutations(self):
        for ports in ([], ["loop200"], ["nic1"], "tap2001"):
            with self.subTest(ports=ports), patch.object(fw_mod, "vpp_cli") as cli:
                with self.assertRaises(ValueError):
                    fw_mod.apply_vpp_firewall({"vpp": {"lan_interfaces": ports}})
                cli.assert_not_called()

    def test_nftables_file_syntax_and_structure(self):
        nft_file = Path(__file__).parents[2] / "deploy/firewall/vrouter-firewall.nft"
        self.assertTrue(nft_file.exists(), f"nft file missing: {nft_file}")
        content = nft_file.read_text()

        # Check table declaration
        self.assertIn("table inet vrouter_firewall {", content)
        # Check sets matching /etc/nftables.conf and management
        expected_sets = [
            "trusted_mgmt", "trusted_mgmt6", "blacklist", "black6",
            "altroute", "vpn", "vpn6", "uk", "local", "carrier6",
            "proxylist", "proxylist6"
        ]
        for s in expected_sets:
            self.assertIn(f"set {s} {{", content, f"Missing set: {s}")

        # Check chains
        self.assertIn("chain input {", content)
        self.assertIn("chain forward {", content)
        self.assertIn("chain prerouting_nat {", content)
        self.assertIn("chain prerouting_mangle {", content)

        # Check policies
        self.assertIn("type filter hook input priority filter; policy drop;", content)
        self.assertIn("type filter hook forward priority filter; policy drop;", content)
        self.assertIn('iifname "br-mgmt" oifname "br-mgmt" icmp type destination-unreachable counter accept', content)
        self.assertIn('iifname "br-mgmt" oifname "br-mgmt" icmpv6 type { destination-unreachable, packet-too-big } counter accept', content)

        # Check threat defense rules
        self.assertIn("ip saddr @blacklist counter drop", content)
        self.assertIn("ip6 saddr @black6 counter drop", content)

        # Check policy steering and bypass returns
        self.assertIn("ip daddr @local return", content)
        self.assertIn("ip6 daddr @carrier6 return", content)
        self.assertNotIn("ip daddr @uk meta mark set", content)
        self.assertNotIn("ip daddr @altroute meta mark set", content)
        self.assertNotIn("ip daddr @vpn meta mark set", content)
        self.assertNotIn("ip6 daddr @vpn6 meta mark set", content)
        self.assertIn("ip daddr @proxylist meta l4proto { tcp, udp } counter tproxy", content)
        self.assertIn("ip6 daddr @proxylist6 meta l4proto { tcp, udp } counter tproxy", content)

        # Check DNS redirection
        self.assertIn("th dport 53 counter redirect to :1053", content)
        # Check proxy port protection
        self.assertIn("th dport { 1080, 2080 } counter drop", content)
        # Check SSH protection
        self.assertIn("tcp dport 22 ip saddr @trusted_mgmt accept", content)


    def test_firewall_systemd_unit(self):
        import configparser
        service_file = Path(__file__).parents[2] / "deploy/startup/vrouter-firewall.service"
        self.assertTrue(service_file.exists(), f"Service file missing: {service_file}")
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        cp.read_string(service_file.read_text())

        # Check Unit section dependencies
        self.assertEqual(cp.get("Unit", "After"), "vrouter-network-prep.service")
        self.assertEqual(cp.get("Unit", "Requires"), "vrouter-network-prep.service")
        self.assertEqual(cp.get("Unit", "PartOf"), "vrouter-vpp.service")
        self.assertIn("vrouter-dns-route-gate.service", cp.get("Unit", "Before"))
        self.assertIn("vrouter-strongswan.service", cp.get("Unit", "Before"))

        # Check Service section
        self.assertEqual(cp.get("Service", "Type"), "oneshot")
        self.assertEqual(cp.get("Service", "RemainAfterExit"), "yes")
        self.assertIn("--apply", cp.get("Service", "ExecStart"))
        self.assertIn("--flush", cp.get("Service", "ExecStop"))


if __name__ == "__main__":
    unittest.main()

