"""Additional CLI/API/HA checks for the isolated NAT ownership fixture."""
import re
import struct
import sys
import time


def run_checks(cli, ns, check, sock, workers, mode):
    sys.path.insert(0, '/usr/local/lib/vpp-vrouter/python')
    from vpp_papi import VPPApiClient
    build = '/opt/vpp-nic1-test/vpp-build/CMakeFiles'
    client = VPPApiClient(apifiles=[build + '/vlibmemory/memclnt.api.json',
                                  build + '/plugins/nat/nat44-ei/nat44_ei.api.json'],
                          server_address=sock.replace('cli.sock', 'api.sock'), read_timeout=3)
    client.connect('thread-control-test')
    mask = 0 if workers == '0' else 1 if workers == '1' else 3

    def api_basics():
        listing = cli('show nat44 ei workers')
        details = client.api.nat44_ei_worker_dump()
        if not mask:
            assert not details
            assert client.api.nat44_ei_set_workers(worker_mask=1).retval != 0
        else:
            assert f'{mask.bit_count()} workers' in listing, listing
            assert len(details) == mask.bit_count(), details
            assert client.api.nat44_ei_set_workers(worker_mask=mask).retval == 0
        assert client.api.nat44_ei_set_workers(worker_mask=0).retval != 0
        return {'cli': listing.strip(), 'api_worker_count': len(details)}

    def worker_guard():
        if mask != 3:
            return 'worker change requires two workers; zero/one-worker API behavior checked separately'
        before = cli('show nat44 ei workers')
        assert client.api.nat44_ei_set_workers(worker_mask=1).retval == -147
        # Capture the explicit CLI error without the fixture's success-only helper.
        import subprocess
        text = subprocess.check_output(['vppctl', '-s', sock, 'set nat44 ei workers 0'], text=True)
        assert 'Worker set is in use' in text, text
        assert cli('show nat44 ei workers') == before
        assert client.api.nat44_ei_set_workers(worker_mask=3).retval == 0
        cli('clear nat44 ei sessions')
        mapping = 'nat44 ei add static mapping udp local 10.254.243.2 49000 external 10.254.244.1 49150'
        cli(mapping)
        assert client.api.nat44_ei_set_workers(worker_mask=1).retval == -147
        cli(mapping + ' del')
        assert client.api.nat44_ei_set_workers(worker_mask=1).retval == -147
        cli('nat44 ei plugin disable')
        assert client.api.nat44_ei_set_workers(worker_mask=1).retval == 0
        assert len(client.api.nat44_ei_worker_dump()) == 1
        assert client.api.nat44_ei_set_workers(worker_mask=3).retval == 0
        cli('nat44 ei plugin enable sessions 1024 users 128 user-sessions 512')
        cli('nat44 ei add address 10.254.244.1')
        if mode == 'output':
            cli('set interface nat44 ei out tap2 output-feature')
            cli('nat44 ei output-chain tap2')
        else:
            cli('set interface nat44 ei in tap1 out tap2')
        return 'active/empty enabled state rejected; disabled state changed and restored'

    check('CLI/API single-worker display and idempotence', api_basics)
    check('CLI/API worker change guards', worker_guard)

    def ha_lifecycle():
        cli('clear nat44 ei sessions')
        cli('nat44 ei add identity mapping 10.254.244.1 udp 49010')
        cli('nat44 ei ha listener 10.254.244.1:49010')
        sequence = 100

        def send(event, target, packets=7, ack=True):
            nonlocal sequence
            sequence += 1
            # NAT HA v1: UDP, one event, session 10.254.243.3:44000.
            record = struct.pack('!BBH4s4sHH4s4sHHIIQ', event, 1, 0,
                                 bytes([10,254,243,3]), bytes([10,254,244,1]),
                                 44000, 55000, bytes([10,254,244,2]), bytes(4),
                                 49000, 0, 0, packets, packets * 100)
            data = struct.pack('!BBHII', 1, 0, 1, sequence, target) + record
            program = '''import socket,sys,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1)
s.sendto(bytes.fromhex(sys.argv[1]),('10.254.244.1',49010))
try:
 d,_=s.recvfrom(2048)
 assert sys.argv[2]=='yes',d.hex()
 version,flags,count,seq,thread=struct.unpack('!BBHII',d[:12])
 assert version==1 and flags&1 and count==0 and seq==int(sys.argv[3]) and thread==int(sys.argv[4]),d.hex()
except socket.timeout:
 assert sys.argv[2]=='no','Missing HA ACK'
'''
            ns(1, 'python3', '-c', program, data.hex(), 'yes' if ack else 'no', str(sequence), str(target))
            time.sleep(.05)

        def session():
            text = cli('show nat44 ei sessions detail')
            sections = re.split(r'-------- thread (\d+)[^\n]*\n', text)
            return {int(sections[i]): sections[i+1] for i in range(1, len(sections), 2)}

        try:
            # Main-thread-owned HA state must reach main even if RX is worker 1.
            send(1, 0)
            assert 'port 44000 fib 0' in session()[0]
            send(3, 0, packets=777)
            assert 'total pkts 777' in session()[0]
            if mask:
                send(3, 1, packets=888)
                assert 'total pkts 777' in session()[0]
                send(2, 1)
                assert 'port 44000 fib 0' in session()[0]
            send(3, 65536, ack=False)
            assert 'port 44000 fib 0' in session()[0]
            send(2, 0)
            assert 'port 44000 fib 0' not in cli('show nat44 ei sessions detail')
            for owner in range(1, mask.bit_count() + 1):
                send(1, owner)
                assert 'port 44000 fib 0' in session()[owner]
                send(3, owner, packets=999)
                assert 'total pkts 999' in session()[owner]
                send(2, owner)
                assert 'port 44000 fib 0' not in cli('show nat44 ei sessions detail')
            return 'HA ADD/REFRESH/DEL on every owner; foreign owner ignored; invalid thread rejected'
        finally:
            cli('nat44 ei ha listener 0.0.0.0:0')
            cli('nat44 ei add identity mapping 10.254.244.1 udp 49010 del')

    try:
        check('HA single-worker ownership and invalid thread', ha_lifecycle)
    finally:
        client.disconnect()
