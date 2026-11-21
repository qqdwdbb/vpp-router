#!/usr/bin/env python3
"""Stop issuing Fake-IP answers, retaining the frontend for cached connections."""
import json
from pathlib import Path
import subprocess


def main():
    path = Path('/etc/vpp/dns-route-domains.json')
    document = json.loads(path.read_text())
    changed = False
    for route in document['routes']:
        if (route['name'] in ('proxylist', 'proxylist6')
                and route.get('dns_upstream') == ['127.0.0.1', 5354]):
            del route['dns_upstream']
            changed = True
    if changed:
        temporary = path.with_suffix('.fakeip-retire')
        with temporary.open('x') as out:
            temporary.chmod(path.stat().st_mode & 0o777)
            out.write(json.dumps(document, indent=2) + '\n')
        temporary.replace(path)
        subprocess.run(['systemctl', 'restart', 'vrouter-dns-route-gate.service'], check=True)
    print('Real DNS restored for PLIST exits; Fake-IP frontend and cache retained for existing clients.')


if __name__ == '__main__':
    main()
