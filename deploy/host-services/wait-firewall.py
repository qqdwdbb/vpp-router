#!/usr/bin/env python3
"""Wait until the current VPP instance has its firewall configuration applied."""
import json
import subprocess
import time

for attempt in range(120):
    try:
        data = subprocess.check_output(['curl', '-fsS', '--max-time', '2', '--unix-socket',
                                        '/run/vpp-firewall/firewall.sock', 'http://localhost/firewall'],
                                       stderr=subprocess.DEVNULL, timeout=3)
        state = json.loads(data)
        if state.get('applied') and not state.get('apply_error'):
            break
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    time.sleep(.5)
else:
    raise SystemExit('VPP firewall did not become ready')
