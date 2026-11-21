#!/usr/bin/env python3
"""Readiness probe for VROUTER VPP service.

Polls the VPP CLI/socket until 'show version' returns cleanly or timeout expires.
Used in systemd ExecStartPost to ensure dependent units start only after VPP is ready.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import time


def check_ready(socket_path, vppctl_path='/usr/local/bin/vppctl', timeout=25):
    sock = Path(socket_path)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if sock.exists():
            try:
                p = subprocess.run([str(vppctl_path), '-s', str(sock), 'show version'],
                                   capture_output=True, text=True, timeout=3)
                if p.returncode == 0 and 'vpp v' in p.stdout.lower():
                    return True
            except (subprocess.TimeoutExpired, OSError):
                pass
        time.sleep(0.1)
    return False


def main():
    parser = argparse.ArgumentParser(description='VROUTER VPP readiness probe')
    parser.add_argument('--socket', default='/run/vpp/cli.sock', help='VPP CLI socket path')
    parser.add_argument('--vppctl', default='/usr/local/bin/vppctl', help='vppctl path')
    parser.add_argument('--timeout', type=int, default=25, help='Timeout in seconds')
    args = parser.parse_args()

    if check_ready(args.socket, args.vppctl, args.timeout):
        sys.exit(0)
    else:
        print(f"ERROR: VPP at {args.socket} failed to become ready within {args.timeout}s", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
