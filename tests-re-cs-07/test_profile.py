"""RE-CS-07 configuration/export checks without downloading build sources."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('recs07_builder', ROOT / 'Scripts/re-cs-07-nss/build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ProfileTests(unittest.TestCase):
    def test_fixed_sources_and_emmc_memory_profile(self):
        lock, config = build.validate_inputs()
        self.assertEqual(lock['base']['commit'], 'f0a60eee2fe051741c643ea6118718aae1ef17fb')
        self.assertEqual(lock['identity']['version'], '25.12.5-nss-recs07.2')
        self.assertEqual(config['CONFIG_TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-cs-07'], 'y')
        self.assertEqual(config['CONFIG_IPQ_MEM_PROFILE_1024'], 'y')
        self.assertEqual(config['CONFIG_NSS_MEM_PROFILE_MEDIUM'], 'y')
        self.assertEqual(config['CONFIG_IPQ_MEM_PROFILE_256'], 'n')
        self.assertEqual(config['CONFIG_PACKAGE_block-mount'], 'y')
        self.assertEqual(config['CONFIG_PACKAGE_dnsmasq-full'], 'y')
        for name in ('kmod-inet-diag', 'kmod-tun', 'kmod-wireguard', 'wireguard-tools', 'luci-proto-wireguard'):
            self.assertEqual(config['CONFIG_PACKAGE_' + name], 'y')
        self.assertFalse(any('memory-zero' in patch['file'] for patch in lock['patches']))

    def test_profile_rejects_wrong_device_radio_and_low_memory(self):
        source = build.PROFILE_PATH.read_text()
        cases = [source.replace('DEVICE_jdcloud_re-cs-07', 'DEVICE_zn_m2'),
                 source.replace('# CONFIG_PACKAGE_kmod-ath11k is not set', 'CONFIG_PACKAGE_kmod-ath11k=y'),
                 source.replace('CONFIG_NSS_MEM_PROFILE_MEDIUM=y', '# CONFIG_NSS_MEM_PROFILE_MEDIUM is not set')]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'profile'
            for text in cases:
                path.write_text(text)
                with self.subTest(text=text[:80]), mock.patch.object(build, 'PROFILE_PATH', path), self.assertRaises(ValueError):
                    build.validate_inputs()

    def test_changed_patch_hash_rejected(self):
        lock, _ = build.validate_inputs()
        lock['patches'][0]['sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lock'
            path.write_text(json.dumps(lock))
            with mock.patch.object(build, 'LOCK_PATH', path), self.assertRaisesRegex(ValueError, 'hash mismatch'):
                build.validate_inputs()

    def test_only_reviewed_fstab_overlay_is_allowed(self):
        lock, _ = build.validate_inputs()
        for edit in ('extra', 'target', 'hash'):
            candidate = json.loads(json.dumps(lock))
            if edit == 'extra':
                candidate['files'].append(candidate['files'][0])
            elif edit == 'target':
                candidate['files'][0]['destination'] = 'etc/config/network'
            else:
                candidate['files'][0]['sha256'] = '0' * 64
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'lock'
                path.write_text(json.dumps(candidate))
                with self.subTest(edit=edit), mock.patch.object(build, 'LOCK_PATH', path), self.assertRaises(ValueError):
                    build.validate_inputs()

    def test_configuration_parser_refuses_duplicate_and_executable_values(self):
        for text in ('CONFIG_X=y\nCONFIG_X=n\n', 'CONFIG_X=$(id)', 'source x', 'CONFIG_X=y; id'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                build.read_config(text)

    def test_generation_preserves_identity_and_required_variants(self):
        lock, _ = build.validate_inputs()
        text = build.generate_config(lock, Path('/tmp/toolchain'))
        config = build.read_config(text)
        self.assertEqual(config['CONFIG_VERSION_NUMBER'], json.dumps(lock['identity']['version']))
        self.assertEqual(config['CONFIG_KERNEL_IPQ_MEM_PROFILE'], '1024')
        text += 'CONFIG_PACKAGE_kmod-qca-nss-drv=y\nCONFIG_PACKAGE_kmod-qca-nss-ecm=y\n'
        text += ''.join('CONFIG_PACKAGE_dnsmasq_full_' + feature + '=y\n' for feature in ('dhcp', 'dhcpv6', 'dnssec', 'nftset', 'conntrack'))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.config'
            path.write_text(text)
            build.verify_config(path.parent)
            path.write_text(text.replace('CONFIG_PACKAGE_block-mount=y', '# CONFIG_PACKAGE_block-mount is not set'))
            with self.assertRaisesRegex(ValueError, 'changed/dropped'):
                build.verify_config(path.parent)

    def test_source_export_contains_recs07_sources_without_private_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.zip'
            build.source_zip(path)
            with zipfile.ZipFile(path) as archive:
                self.assertIsNone(archive.testzip())
                names = archive.namelist()
                for name in ('Config/RE-CS-07-NSS.config', 'Config/RE-CS-07-NSS/files/etc/config/fstab',
                             '.github/workflows/RE-CS-07-NSS.yml', 'Scripts/re-cs-07-nss/build.py',
                             'tests-re-cs-07/test_profile.py', 'docs/RE-CS-07-NSS.md'):
                    self.assertIn(name, names)
                self.assertFalse(any('.git/' in name or '_work/' in name or '__pycache__' in name or name.endswith('.key') for name in names))
                self.assertIn('tests/test_zn_m2_profile.py', names)
                self.assertIn('Config/ZN-M2-NSS.config', names)
                self.assertIn('Scripts/zn-m2-nss/build.py', names)


class WorkflowTests(unittest.TestCase):
    def test_manual_workflow_uses_pinned_actions_and_standard_runner(self):
        path = ROOT / '.github/workflows/RE-CS-07-NSS.yml'
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(workflow['name'], 'RE-CS-07-NSS')
        self.assertEqual(set(workflow['on']), {'workflow_dispatch'})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        inputs = workflow['on']['workflow_dispatch']['inputs']
        self.assertEqual(inputs['jobs']['default'], '4')
        self.assertEqual(inputs['jobs']['options'], ['2', '4'])
        self.assertEqual(inputs['mode']['options'], ['config', 'build'])
        self.assertEqual(workflow['concurrency']['cancel-in-progress'], 'false')
        job = workflow['jobs']['build']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], '360')
        for step in job['steps']:
            if 'uses' in step:
                self.assertRegex(step['uses'], r'^actions/[a-z-]+@[0-9a-f]{40}$')
                if step['uses'].startswith('actions/checkout@'):
                    self.assertEqual(step['with']['persist-credentials'], 'false')
                if step['uses'].startswith('actions/cache@'):
                    self.assertEqual(step['with']['path'], '_work/downloads')
        for forbidden in ('secrets.', 'gh release', 'staging_dir', 'push:', 'pull_request:', 'self-hosted'):
            self.assertNotIn(forbidden, path.read_text())
        self.assertIn('python3 -m unittest discover -s tests-re-cs-07 -v', path.read_text())


if __name__ == '__main__':
    unittest.main()
