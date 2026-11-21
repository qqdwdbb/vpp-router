import importlib.util
import hashlib
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[2]/'deploy'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer=load('vrouter_installer',ROOT/'install/install.py')
runtime=load('vrouter_runtime_installed',ROOT/'cutover/runtime.py')
activation=load('vrouter_activation',ROOT/'install/activate.py')


class InstallTests(unittest.TestCase):
    def test_baseline_rejects_stale_plugins_and_pmd(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle=Path(directory)
            plugins=bundle/'plugins';plugins.mkdir()
            pmd=bundle/'pmd.so';pmd.write_bytes(b'accepted-pmd')
            vnet=bundle/'ipsec-ip6-udp/lib/libvnet.so.26.06.0';vnet.parent.mkdir(parents=True)
            files={
                'usr/local/lib/vpp-vrouter/plugins/acl_plugin.so': plugins/'acl_plugin.so',
                'usr/local/lib/vpp-vrouter/plugins/dpdk_plugin.so': plugins/'dpdk_plugin.so',
                'usr/local/lib/vpp-vrouter/plugins/nat44_ei_plugin.so': plugins/'nat44_ei_plugin.so',
                'usr/local/lib/vpp-vrouter/plugins/nat_ei_context_plugin.so': plugins/'nat_ei_context_plugin.so',
                'usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1': pmd,
                'usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu/libvnet.so.26.06.0': vnet,
            }
            for path in files.values():
                path.write_bytes(b'accepted-'+path.name.encode())
            accepted={name: hashlib.sha256(path.read_bytes()).hexdigest() for name,path in files.items()}
            with patch.object(installer,'BASELINE',{'files':accepted}), \
                    patch.object(installer,'BASE',bundle), \
                    patch.object(installer,'rtl8125_pmd',return_value=pmd):
                installer.validate_baseline(bundle)
                for path in files.values():
                    with self.subTest(path=path):
                        original=path.read_bytes()
                        path.write_bytes(b'old-version')
                        with self.assertRaisesRegex(ValueError,'accepted baseline'):
                            installer.validate_baseline(bundle)
                        path.write_bytes(original)

    def test_relocation_prefers_specific_config_and_plugin_paths(self):
        mappings={'/old/release':'/var/lib/vpp-vrouter',
                  '/old/release/config':'/etc/vpp',
                  '/old/release/plugins':'/usr/local/lib/vpp-vrouter/plugins'}
        self.assertEqual(installer.rewrite('/old/release/config/secret /old/release/plugins/nat.so /old/release/state',mappings),
                         '/etc/vpp/secret /usr/local/lib/vpp-vrouter/plugins/nat.so /var/lib/vpp-vrouter/state')

    def test_configuration_and_writable_state_are_separate(self):
        with patch.dict(os.environ,{'VROUTER_CONFIG_DIRECTORY':'/etc/vpp'}):
            self.assertEqual(runtime.config_path(Path('/var/lib/vpp-vrouter'),'startup.conf'),Path('/etc/vpp/startup.conf'))
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(runtime.config_path(Path('/trial'),'startup.conf'),Path('/trial/config/startup.conf'))

    def test_cli_wrapper_preserves_arguments_and_private_library_path(self):
        wrapper=installer.wrapper('vppctl')
        self.assertIn('exec /usr/local/lib/vpp-vrouter/bin/vppctl "$@"',wrapper)
        self.assertNotIn('/opt/',wrapper)
        self.assertNotIn('sudo',wrapper)

    def test_environment_has_no_trial_dependencies(self):
        values=installer.runtime_environment()
        self.assertEqual(values['VROUTER_CONFIG_DIRECTORY'],'/etc/vpp')
        self.assertEqual(values['VPP_API_DIR'],'/usr/local/share/vpp-vrouter/api')
        self.assertEqual(values['DPDK_PLUGIN_PATH'],
                         '/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1')
        self.assertEqual(values['LD_LIBRARY_PATH'],
                         '/usr/local/lib/aarch64-linux-gnu:/usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu')
        self.assertFalse(any('/opt/' in value for value in values.values()))
        self.assertEqual(values['R8169_DMA_NONCOHERENT'], '1')
        self.assertEqual(values['PYTHONPYCACHEPREFIX'], '/var/cache/vpp-vrouter/python')

    def test_rtl8125_relocation_requires_dma_patched_pmd(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            source=base/'dma-pmd/librte_net_r8169.so.26.1'
            source.parent.mkdir()
            with patch.object(installer, 'BASE', base):
                with self.assertRaises(FileNotFoundError):
                    installer.rtl8125_pmd()
                source.write_bytes(b'ordinary PMD')
                with self.assertRaisesRegex(ValueError, 'non-coherent DMA'):
                    installer.rtl8125_pmd()
                source.write_bytes(b'patched PMD\0R8169_DMA_NONCOHERENT\0')
                self.assertEqual(installer.rtl8125_pmd(), source)

    def test_health_rejects_successful_cli_with_zero_wan_replies(self):
        def command(*args):
            return 'Statistics: 2 sent, 0 received, 100% packet loss' if args[-1].startswith('ping ') else ''
        with patch.object(activation,'run',side_effect=command):
            with self.assertRaisesRegex(RuntimeError,'WAN gateway'):
                activation.health([])

    def test_service_keeps_daemon_specific_environment(self):
        text=('[Service]\nEnvironment=STRONGSWAN_CONF=/etc/vpp/strongswan.conf\n'
              'Environment=PATH=/old/bin\n'
              'ExecStart=/usr/lib/ipsec/starter --conf /etc/vpp/ipsec.conf\n')
        unit=installer.service_unit(text,{},'vrouter-strongswan.service')
        self.assertIn('Environment=STRONGSWAN_CONF=/etc/vpp/strongswan.conf',unit)
        self.assertNotIn('Environment=PATH=',unit)
        self.assertIn('EnvironmentFile=/etc/vpp/runtime.env',unit)
        self.assertIn('--conf /etc/vpp/ipsec.conf', unit)
        self.assertNotIn('/var/lib/vpp-vrouter/generated/ipsec.conf', unit)

    def test_namespace_creation_uses_host_mount_namespace(self):
        unit=installer.service_unit('[Service]\nExecStart=ip netns add test\n',{},'vrouter-namespace.service')
        self.assertNotIn('InaccessiblePaths=',unit)
        self.assertNotIn('PrivateMounts=',unit)

    def test_broken_dpdk_relative_soname_link_fails_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'librte_bus_pci.so').symlink_to('dpdk/pmds-26.1/librte_bus_pci.so')
            with self.assertRaisesRegex(ValueError,'Broken or external'):
                installer.validate_links(root)
            target=root/'dpdk/pmds-26.1/librte_bus_pci.so'
            target.parent.mkdir(parents=True);target.write_bytes(b'driver')
            installer.validate_links(root)

    def test_vpp_service_does_not_need_dpdk_compatibility_mount(self):
        text=installer.service_unit('[Service]\n',{},'vrouter-vpp.service')
        self.assertNotIn('BindReadOnlyPaths=',text)
        self.assertNotIn('BindReadOnlyPaths=',installer.service_unit('[Service]\n',{},'vrouter-namespace.service'))

    def activation_record(self, directory, phase):
        state=Path(directory)
        (state/'installation.json').write_text(json.dumps(
            dict(phase=phase, units=[], rollback_unit='test-rollback', recovery_bundle='/missing/pre-fhs')))
        return state

    def test_rollback_uses_current_version_without_opening_legacy_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            state=self.activation_record(directory, 'switching')
            with patch.object(activation, 'STATE', state), patch.object(activation, 'run') as run:
                activation.activate('rollback')
            run.assert_called_once_with('python3', activation.HERE/'recovery.py', 'restore', timeout=300)

    def test_linux_recovery_does_not_rearm_pre_migration_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state=self.activation_record(directory, 'confirmed')
            before=(state/'installation.json').read_bytes()
            with patch.object(activation, 'STATE', state), patch.object(activation, 'run') as run:
                activation.activate('linux')
            run.assert_called_once_with('python3', activation.HERE/'recovery.py', 'linux', timeout=240)
            self.assertEqual((state/'installation.json').read_bytes(), before)

    def test_failed_snapshot_does_not_cancel_pending_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            state=self.activation_record(directory, 'awaiting-confirmation')
            with patch.object(activation, 'STATE', state), patch.object(activation, 'health'), \
                    patch.object(activation, 'run', side_effect=RuntimeError('snapshot failed')) as run:
                with self.assertRaisesRegex(RuntimeError, 'snapshot failed'):
                    activation.activate('confirm')
            run.assert_called_once_with('python3', activation.HERE/'recovery.py', 'snapshot', timeout=300)
