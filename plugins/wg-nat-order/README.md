# VPP 26.06 NAT44/WireGuard output ordering

WireGuard's `wg4-output-tun` consumes the output feature chain when encrypting.
If it precedes `nat44-ei-in2out-output`, the plaintext packet is never translated.
This plugin adds an unused ordering anchor: NAT output and
`tcp-mss-clamping-ip4-out` must precede WireGuard. Enable the bundled
`mss_clamp_plugin.so` as well, and set wg1 IPv4 MSS to MTU minus 40.
It does not implement or enable a packet-processing feature of its own.

Build against the exact installed VPP version (vpp-dev and libvppinfra-dev):

```sh
cc -shared -fPIC -O2 \
  -o wg_nat_order_plugin.so wg_nat_order.c
```

Install the shared object into VPP's plugin directory and explicitly enable
`wg_nat_order_plugin.so` in startup.conf. VPP must restart to register ordering.
Do not enable `wg-nat-order-anchor` on an interface. NAT44 output features are
enabled on WAN and wg1; WAN uses tenant VRF 0 and wg1 uses the isolated EI
context VRF 101, configured by nat_ei_context_plugin.so. WireGuard importers and startup config
must preserve this mode. Rebuild/revalidate this plugin when upgrading VPP;
remove it when upstream ordering handles NAT before WireGuard directly.
