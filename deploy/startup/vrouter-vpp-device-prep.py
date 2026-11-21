#!/usr/bin/env python3
"""Cold-initialize the VROUTER RTL8125 before a stopped VPP reclaims its UIO device."""
from pathlib import Path
import argparse
import subprocess
import time

PCI = Path('/sys/bus/pci/devices/0000:01:00.0')


def run(*command):
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)


def bind(pci, driver):
    (pci/'driver/unbind').write_text(pci.name)
    (pci/'driver_override').write_text(driver)
    (pci.parents[1]/'drivers_probe').write_text(pci.name)
    if (pci/'driver').resolve().name != driver:
        raise RuntimeError('PCI driver binding failed')


def prepare(pci=PCI, kernel_driver='r8125'):
    if (pci/'vendor').read_text().strip() != '0x10ec' or (pci/'device').read_text().strip() != '0x8125':
        raise RuntimeError('Unexpected WAN PCI device')
    if (pci/'driver').resolve().name != 'uio_pci_generic':
        raise RuntimeError('WAN must already be assigned to the stopped VPP deployment')
    if kernel_driver not in ('r8125', 'r8169'):
        raise ValueError('Unsupported RTL8125 kernel driver')
    run('modprobe', kernel_driver)
    bind(pci, kernel_driver)
    try:
        # The validated experimental PMD does not reliably recover RX after a
        # warm process restart. Let the kernel driver initialize the hardware
        # before handing it back. Do not recreate IP addresses, VLANs or routes.
        devices = list((pci/'net').iterdir())
        if len(devices) != 1:
            raise RuntimeError('Expected one physical WAN netdevice')
        run('ip', 'link', 'set', devices[0].name, 'up')
        time.sleep(3)
    finally:
        bind(pci, 'uio_pci_generic')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', default='vpp-router.service')
    parser.add_argument('--pci', action='append')
    parser.add_argument('--kernel-driver', choices=['r8125','r8169'], default='r8125')
    args = parser.parse_args()
    pid = subprocess.check_output(['systemctl', 'show', args.unit, '-p', 'MainPID', '--value'], text=True).strip()
    if pid != '0':
        raise RuntimeError('Refusing to rebind a running VPP device')
    for address in args.pci or [PCI.name]:
        if not __import__('re').fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]', address):
            raise ValueError('Invalid PCI address')
        prepare(Path('/sys/bus/pci/devices')/address, args.kernel_driver)
