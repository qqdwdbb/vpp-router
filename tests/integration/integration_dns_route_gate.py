import json
from pathlib import Path
import runpy
import socket
import struct
import tempfile
import threading
import time

m = runpy.run_path('/usr/local/sbin/vpp-dns-route-gate')
s = m['load_sync']('/usr/local/sbin/vpp-nft-route-sync')
query = struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + b'\x04gate\x07invalid\0' + struct.pack('!HH', 1, 1)
answer = struct.pack('!6H', 123, 0x8180, 1, 1, 0, 0) + query[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton('198.51.100.77')
with tempfile.TemporaryDirectory(prefix='gate-live-') as directory:
    root = Path(directory)
    config = s.load_config('/etc/vpp/nftset-route-sync.json')
    config['state_file'] = str(root / 'state.json')
    (root / 'config.json').write_text(json.dumps(config))
    (root / 'rules.conf').write_text('nftset=/gate.invalid/4#inet#mangle#altroute\n')
    entered, release = threading.Event(), threading.Event()
    class DelayedBackend(s.Backend):
        def prefixes(self, mapping):
            # Isolate this ledger from production set members.
            return set()

        def apply(self, lines):
            if any('ip route add 198.51.100.77/32' in l for l in lines):
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('test ACK timeout')
            return super().apply(lines)
    controller = m['Controller'](s, root / 'config.json', lambda: [root / 'rules.conf'], root / 'leases.json', DelayedBackend)
    route = s.Route(0, '198.51.100.77/32', '10.62.30.1', 'wg1')
    backend = s.Backend(config)
    assert route.key not in backend.lookup([route]), 'test address already in use'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.bind(('127.0.0.1', 0))
            def serve():
                for _ in range(2):
                    _, peer = upstream.recvfrom(4096)
                    upstream.sendto(answer, peer)
            producer = threading.Thread(target=serve, daemon=True)
            producer.start()
            gate = m['Gate'](controller, upstream.getsockname())
            output = []
            worker = threading.Thread(target=lambda: output.append(gate.exchange(query)))
            worker.start()
            assert entered.wait(4)
            time.sleep(0.25)
            assert not output, 'DNS response escaped before route applied'
            release.set()
            worker.join(5)
            assert len(output) == 1 and m['decode'](output[0])[1] & 15 == 0
            assert s.matches(route, backend.lookup([route]))
            print('PASS real VPP: response held during delayed add; verified route before success')
            backend.apply([route.command('del')])
            controller.verified.clear()
            controller.backend_factory = lambda config: FailingBackend(config)
            class FailingBackend(s.Backend):
                def apply(self, lines):
                    return super().apply([line.replace(' wg1', ' missing-benchmark-interface') for line in lines])
            rejected = gate.exchange(query)
            assert m['decode'](rejected)[1] & 15 == 2
            print('PASS real VPP: route command failure yields SERVFAIL, no answer addresses')
            producer.join(2)
    finally:
        # Only the test prefix; no production routes are touched.
        release.set()
        if route.key in backend.lookup([route]):
            backend.apply([route.command('del')])
