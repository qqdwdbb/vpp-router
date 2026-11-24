import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location('host_links', ROOT/'deploy/host-services/host-links.py')
links = importlib.util.module_from_spec(spec)
spec.loader.exec_module(links)


class HostLinksTests(unittest.TestCase):
    def apply(self, routes):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)/'links.json'
            config.write_text(json.dumps(dict(routes=routes)))
            with patch('sys.argv', ['host-links.py', '--config', str(config)]):
                links.main()

    def test_ipv6_return_route_uses_configured_metric(self):
        route = dict(prefix='fd42::/64', via='fd43::1', interface='vpp-host', metric=100)
        with patch.object(links, 'run') as run:
            self.apply([route])
        run.assert_called_once_with('ip', '-6', 'route', 'replace', 'fd42::/64',
                                    'via', 'fd43::1', 'dev', 'vpp-host', 'metric', 100)

    def test_unspecified_metric_preserves_existing_command(self):
        for prefix, gateway, family in [('fd42::/64', 'fd43::1', '-6'),
                                        ('10.0.0.0/24', '192.0.2.1', '-4')]:
            with self.subTest(family=family), patch.object(links, 'run') as run:
                self.apply([dict(prefix=prefix, via=gateway, interface='vpp-host')])
                run.assert_called_once_with('ip', family, 'route', 'replace', prefix,
                                            'via', gateway, 'dev', 'vpp-host')

    def test_invalid_metric_rejected_before_route_install(self):
        for metric in (-1, 2**32, True, 1.5, '100', None):
            with self.subTest(metric=metric), patch.object(links, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'invalid route metric'):
                    self.apply([dict(prefix='fd42::/64', via='fd43::1',
                                     interface='vpp-host', metric=metric)])
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
