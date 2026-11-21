#!/usr/bin/env python3
"""Readiness probe for VROUTER strongSwan (kernel-vpp) service.

Ensures that strongSwan has started, kernel-vpp plugin is loaded,
the VPP Binary API client connection is established, and required
connection profile(s) are present.
Used in systemd ExecStartPost for vrouter-strongswan.service.
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time


def check_ready(socket_path, unit=None, pid=None, stroke_path='/usr/lib/ipsec/stroke',
                vppctl_path='/usr/local/bin/vppctl', conn_name=None, timeout=25):
    if pid is not None and pid <= 0:
        return False
    sock = Path(socket_path)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        # Determine target PID if unit or pid specified
        target_pid = pid
        if unit and not target_pid:
            p = subprocess.run(['systemctl', 'show', unit, '--property=MainPID', '--value'],
                               capture_output=True, text=True, timeout=3)
            val = p.stdout.strip()
            if val.isdigit() and int(val) > 0:
                target_pid = int(val)

        if unit and not target_pid:
            time.sleep(0.1)
            continue

        stroke_cmd = [str(stroke_path), 'statusall']
        if target_pid:
            stroke_cmd = ['nsenter', '-t', str(target_pid), '-m', '-n'] + stroke_cmd

        try:
            status = subprocess.run(stroke_cmd, capture_output=True, text=True, timeout=5)
            clients = subprocess.run([str(vppctl_path), '-s', str(sock), 'show api clients'],
                                     capture_output=True, text=True, timeout=5)

            if status.returncode == 0 and clients.returncode == 0:
                has_plugin = bool(re.search(r'loaded plugins:.*\bkernel-vpp\b', status.stdout))
                has_api = 'strongswan' in clients.stdout
                has_conn = True
                if conn_name:
                    has_conn = bool(re.search(r'(?m)^\s*' + re.escape(conn_name) + r':', status.stdout))

                if has_plugin and has_api and has_conn:
                    return True
        except (subprocess.TimeoutExpired, OSError):
            pass

        time.sleep(0.1)
    return False


def main():
    parser = argparse.ArgumentParser(description='VROUTER strongSwan readiness probe')
    parser.add_argument('--socket', default='/run/vpp/cli.sock', help='VPP CLI socket path')
    parser.add_argument('--unit', default=None, help='systemd unit name to query MainPID')
    parser.add_argument('--pid', type=int, default=None, help='strongSwan MainPID directly')
    parser.add_argument('--stroke', default='/usr/lib/ipsec/stroke', help='Path to stroke binary')
    parser.add_argument('--vppctl', default='/usr/local/bin/vppctl', help='vppctl path')
    parser.add_argument('--conn', default=None, help='Expected connection name in status')
    parser.add_argument('--timeout', type=int, default=25, help='Timeout in seconds')
    args = parser.parse_args()

    if check_ready(args.socket, args.unit, args.pid, args.stroke, args.vppctl, args.conn, args.timeout):
        sys.exit(0)
    else:
        print(f"ERROR: strongSwan failed to become ready within {args.timeout}s", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
