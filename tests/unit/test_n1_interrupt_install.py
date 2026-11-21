"""Check that the installer exposes adaptive receive for the N1 PMD."""
from pathlib import Path
import subprocess


SOURCE = (Path(__file__).parents[2] / "deploy/install/vpp-router-install.sh").read_text()


def function(name):
    start = SOURCE.index(name + "() {")
    return SOURCE[start:SOURCE.index("\n}", start) + 2]


def test_n1_offers_interrupt_mode_without_changing_pci_driver():
    script = r'''
set -eu
has_kind() { for kind in "$@"; do [ "$kind" = plat ] && return 0; done; return 1; }
info() { :; }; note() { :; }; warn() { :; }
ask() { printf -v "$1" 2; }
PLAT_RX_INTERRUPTS=1 UIO=uio_pci_generic IOMMU=0 SERVICE=vpp-router
''' + function("ask_rx_mode") + r'''
ask_rx_mode
test "$RX_MODE" = interrupt
test "$UIO" = uio_pci_generic
'''
    subprocess.run(["bash", "-c", script], check=True)


def test_controller_enables_adaptive_for_platform_interface():
    script = r'''
set -eu
NICS=('wan - eth0 plat port0')
VPPCTL=vppctl
vppctl() {
  if [ "$1" = set ]; then printf '%s\n' "$*"; else
    printf '    port0 queue 0 (adaptive)\n'
  fi
}
log() { printf '%s\n' "$*"; }
''' + function("set_interrupt") + r'''
set_interrupt
'''
    result = subprocess.run(["bash", "-c", script], check=True, capture_output=True, text=True)
    assert "port0 使用 adaptive 收包" in result.stdout


def test_controller_retries_until_interface_is_ready(tmp_path):
    script = r'''
set -eu
NICS=('wan - eth0 plat port0')
VPPCTL=vppctl
vppctl() {
  if [ "$1" = set ]; then
    echo x >> "$COUNT_FILE"
  elif [ "$(wc -l < "$COUNT_FILE")" -lt 3 ]; then
    printf '    port0 queue 0 (polling)\n'
  else
    printf '    port0 queue 0 (adaptive)\n'
  fi
}
sleep() { :; }
log() { printf '%s\n' "$*"; }
''' + function("set_interrupt") + '\nset_interrupt\n'
    import os
    result = subprocess.run(["bash", "-c", script], check=True, capture_output=True,
                            text=True, env={**os.environ, "COUNT_FILE": str(tmp_path / "calls")})
    assert "port0 使用 adaptive 收包" in result.stdout
    assert (tmp_path / "calls").read_text().count("x") == 3
