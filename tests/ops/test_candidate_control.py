"""Candidate guards: real filesystem/NTFS, pure fixture Docker metadata."""
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('candidate_control', ROOT / 'scripts/candidate-control.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class CandidateControlTests(unittest.TestCase):
    def setUp(self):
        scratch = Path("C:/Users/user/AppData/Local/hermes/profiles/openai-login/cache/scratch").resolve(strict=True)
        self.temp = tempfile.TemporaryDirectory(prefix="osee-r1-guards-", dir=scratch)
        self.base = Path(self.temp.name)
        self.source, self.target = self.base / 'source', self.base / 'candidate'
        self.source.mkdir()
        paths = ['go.mod', 'go.sum'] + [f'internal/fixture_{n:03d}.go' for n in range(112)]
        self.audited = []
        for name in paths:
            p = self.source / name
            p.parent.mkdir(parents=True, exist_ok=True)
            data = f'fixture-content-{name}\n'.encode()
            p.write_bytes(data)
            self.audited.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        (self.source / '.env').write_text('unit-fixture-not-to-copy', encoding='utf-8')

    def tearDown(self):
        self.temp.cleanup()

    def permitted(self, function, *args):
        try:
            return function(*args)
        except control.ScopeError:
            self.fail("Required permitted candidate behavior is unavailable")

    def public_cache_fixture(self):
        cache = self.target / '.local/public-modules'
        cache.mkdir(parents=True)
        metadata = {'scope_id': 'b' * 32, 'candidate_root': self.target.as_posix(),
                    'cache_root': cache.as_posix(), 'dependency_step': 'R1-T02',
                    'goproxy': 'https://proxy.golang.org', 'gosumdb': 'sum.golang.org',
                    'private_mounts': False, 'verified': True}
        marker = self.target / '.local/public-modules.json'
        marker.write_text(json.dumps(metadata), encoding='utf-8')
        return cache, marker, metadata

    def exercise_go_command(self, race, pattern=None, all_checks=False):
        from types import SimpleNamespace
        manifest, _ = self.owned_fixture()
        manifest['private_root'] = str(self.base)
        manifest['images'] = {'sdk':'sha256' + 'd'*64}
        mounts = [{'Type':'bind','Destination':'/src/'+part,'RW':False} for part in ['cmd','internal','db','go.mod','go.sum']]
        mounts.append({'Type':'bind','Destination':'/modules','RW':False})
        commands = []
        def transport(_, args, **kwargs):
            commands.append(args)
            return SimpleNamespace(stdout='c'*64 if args[:2]==['container','create'] else '')
        with patch.object(control, '_load_manifest', return_value=manifest), patch.object(control, 'verify_owned', return_value={'Mounts':mounts}), patch.object(control, 'verify_private_acl'), patch.object(control, '_module_cache', return_value=self.base), patch.object(control, '_save_metadata'), patch.object(control.DockerClient, 'call', transport), patch.object(control, '_execute_sdk', return_value={'exit_code':0,'full_marker':True}):
            control.run_go('./...', pattern, race, all_checks)
        return next(args[-1] for args in commands if args[:2]==['container','create'])

    def test_go_race_has_bounded_four_minute_case_deadline(self):
        command = self.exercise_go_command(True)
        self.assertIn('-race', command)
        self.assertIn('-timeout=240s', command)
        self.assertNotIn('-timeout=0', command)

    def test_go_nonrace_retains_bounded_two_minute_case_deadline(self):
        command = self.exercise_go_command(False, pattern='one_bounded_case')
        self.assertNotIn('-race', command)
        self.assertIn('-timeout=120s', command)

    def test_go_full_nonrace_has_bounded_three_minute_case_deadline(self):
        command = self.exercise_go_command(False)
        self.assertIn('-timeout=180s', command)
        self.assertNotIn('-timeout=0', command)

    def test_go_all_preserves_full_normal_and_race_phase_deadlines(self):
        command = self.exercise_go_command(False, all_checks=True)
        self.assertIn('go test -json ./... -count=1 -timeout=180s', command)
        self.assertIn('go test -race -json ./... -count=1 -timeout=240s', command)
        self.assertNotIn('-timeout=0', command)

    def test_go_serializes_shared_private_fixture_packages(self):
        modes = [(False, None, False), (True, None, False),
                 (False, 'one_bounded_case', False), (False, None, True)]
        for race, pattern, all_checks in modes:
            with self.subTest(race=race, pattern=pattern, all_checks=all_checks):
                command = self.exercise_go_command(race, pattern, all_checks)
                tests = [phase.strip() for phase in command.split(';')
                         if phase.strip().startswith('go test ')]
                self.assertEqual(len(tests), 2 if all_checks else 1)
                for test in tests:
                    self.assertIn('-p=1', test.split())
                    self.assertIn('-count=1', test.split())
                    self.assertNotIn('-short', test.split())
                if race:
                    self.assertIn('-race', tests[0].split())

    def test_sdk_uses_scoped_owned_public_cache(self):
        cache, marker, metadata = self.public_cache_fixture()
        with patch.object(control, 'ROOT', self.target):
            result = self.permitted(control._module_cache, {'scope_id': 'b' * 32})
        self.assertEqual(result, cache)
        self.assertEqual(json.loads(marker.read_text()), metadata)

    def test_sdk_refuses_unverified_foreign_or_escaping_public_cache(self):
        cache, marker, metadata = self.public_cache_fixture()
        cases = [('scope_id', 'a' * 32), ('candidate_root', self.source.as_posix()),
                 ('cache_root', self.source.as_posix()), ('dependency_step', 'unapproved'),
                 ('goproxy', 'https://unapproved.invalid'), ('gosumdb', 'off'),
                 ('private_mounts', True), ('private_mounts', 0), ('verified', False), ('verified', 1)]
        with patch.object(control, 'ROOT', self.target):
            for key, value in cases:
                with self.subTest(key=key, value=value):
                    marker.write_text(json.dumps(dict(metadata, **{key: value})), encoding='utf-8')
                    with self.assertRaises(control.ScopeError):
                        control._module_cache({'scope_id': 'b' * 32})
            marker.unlink()
            with self.assertRaises(control.ScopeError):
                control._module_cache({'scope_id': 'b' * 32})
            marker.write_text(json.dumps(metadata), encoding='utf-8')
            cache.rmdir()
            other = self.base / 'foreign-cache'
            other.mkdir()
            made = subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(cache), str(other)],
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(made.returncode, 0, 'Could not exercise public-cache NTFS junction refusal')
            try:
                with self.assertRaises(control.ScopeError):
                    control._module_cache({'scope_id': 'b' * 32})
            finally:
                cache.rmdir()

    def test_sdk_public_cache_invalid_json_fails_closed(self):
        cache, marker, metadata = self.public_cache_fixture()
        with patch.object(control, 'ROOT', self.target):
            for document in ['[]', 'null', '17', '"text"', '{bad-json']:
                with self.subTest(document=document):
                    marker.write_text(document, encoding='utf-8')
                    try:
                        control._module_cache({'scope_id': 'b' * 32})
                    except control.ScopeError:
                        continue
                    except Exception:
                        self.fail('Malformed public metadata must produce a scoped refusal, not an uncaught exception')
                    self.fail('Malformed public-cache metadata accepted')

    def test_sdk_retains_legacy_public_cache_readonly_selection(self):
        cache = self.source / '.local/gopath/pkg/mod'
        cache.mkdir(parents=True)
        self.target.mkdir()
        (self.target / '.local').mkdir()
        with patch.object(control, 'ROOT', self.target), patch.object(control, '_owner',
                return_value={'source_root': self.source.as_posix()}):
            result = self.permitted(control._module_cache, {'scope_id': 'b' * 32})
        self.assertEqual(result, cache)
        self.assertEqual(list(cache.iterdir()), [])

    def test_exact_audited_source_copy(self):
        result = self.permitted(control.copy_audited_sources, self.source, self.target, self.audited)
        self.assertEqual(result['source_hashes'], self.audited)
        self.assertEqual(result['copied_count'], 114)
        self.assertFalse((self.target / '.env').exists())
        for row in self.audited:
            self.assertEqual(hashlib.sha256((self.target / row['path']).read_bytes()).hexdigest(), row['sha256'])

    def test_source_drift_refused_before_copy(self):
        (self.source / self.audited[-1]['path']).write_text('changed', encoding='utf-8')
        with self.assertRaises(control.ScopeError):
            control.copy_audited_sources(self.source, self.target, self.audited)
        self.assertFalse(self.target.exists())

    def test_symlink_escape_refused(self):
        other, link = self.base / 'other', self.source / 'internal/junction'
        other.mkdir()
        (other / 'escape.go').write_text('outside', encoding='utf-8')
        made = subprocess.run(['cmd.exe', '/c', 'mklink', '/J', str(link), str(other)], capture_output=True, text=True, timeout=10)
        self.assertEqual(made.returncode, 0, 'Could not exercise actual NTFS junction boundary')
        row = {'path': 'internal/junction/escape.go', 'bytes': 7, 'sha256': hashlib.sha256(b'outside').hexdigest()}
        try:
            with self.assertRaises(control.ScopeError):
                control.copy_audited_sources(self.source, self.target, [row])
            self.assertFalse(self.target.exists())
        finally:
            link.rmdir()

    def test_unsafe_and_duplicate_paths_refused(self):
        for rows in [[dict(self.audited[0], path='../go.mod')], [self.audited[0], self.audited[0]], [dict(self.audited[0], path='AGENTS.md')]]:
            with self.subTest(paths=[r['path'] for r in rows]):
                with self.assertRaises(control.ScopeError):
                    control.copy_audited_sources(self.source, self.target, rows)
                self.assertFalse(self.target.exists())

    def test_namespace_collision_refused(self):
        self.target.mkdir()
        retained = self.target / 'unrelated.txt'
        retained.write_text('retain', encoding='utf-8')
        with self.assertRaises(control.ScopeError):
            control.copy_audited_sources(self.source, self.target, self.audited)
        self.assertEqual(retained.read_text(encoding='utf-8'), 'retain')

    def owned_fixture(self):
        scope = 'b' * 32
        network_id, database_id, volume_name = 'c' * 64, 'a' * 64, 'osee-r1-bbbbbbbbbbbb-pg'
        network_name = 'osee-r1-bbbbbbbbbbbb'
        labels = {'osee.testops.candidate': scope, 'osee.testops.role': 'db'}
        manifest = {'scope_id': scope, 'network': {'id': network_id, 'name': network_name}, 'volume': {'name': volume_name},
                    'resources': {'db': {'id': database_id, 'name': network_name + '-db', 'image_id': 'sha256:' + 'd' * 64}}}
        responses = {
            ('container', database_id): {'Id': database_id, 'Name': '/' + network_name + '-db', 'Image': 'sha256:' + 'd' * 64,
                'Config': {'Labels': labels}, 'NetworkSettings': {'Networks': {network_name: {'NetworkID': network_id}}},
                'HostConfig': {'PortBindings': {}}, 'Mounts': [{'Type': 'volume', 'Name': volume_name, 'Destination': '/var/lib/postgresql/data'}]},
            ('network', network_id): {'Id': network_id, 'Name': network_name, 'Internal': True, 'Labels': {'osee.testops.candidate': scope}},
            ('volume', volume_name): {'Name': volume_name, 'Labels': {'osee.testops.candidate': scope}},
        }
        return manifest, responses

    def test_exact_owned_resource_accepted(self):
        manifest, responses = self.owned_fixture()
        with patch.object(control.DockerClient, 'inspect', side_effect=lambda kind, identifier: responses[(kind, identifier)]):
            result = self.permitted(control.verify_owned, manifest, 'db')
        self.assertEqual(result['Id'], manifest['resources']['db']['id'])

    def test_foreign_id_or_label_refused(self):
        manifest, responses = self.owned_fixture()
        db = responses[('container', manifest['resources']['db']['id'])]
        for field in ['id', 'label', 'image']:
            fresh = json.loads(json.dumps(responses[('container', manifest['resources']['db']['id'])]))
            if field == 'id': fresh['Id'] = 'e' * 64
            elif field == 'image': fresh['Image'] = 'sha256:' + 'e' * 64
            else: fresh['Config']['Labels']['osee.testops.candidate'] = 'foreign'
            with self.subTest(field=field):
                with patch.object(control.DockerClient, 'inspect', side_effect=lambda kind, identifier: fresh if kind == 'container' else responses[(kind, identifier)]):
                    with self.assertRaises(control.ScopeError): control.verify_owned(manifest, 'db')

    def test_original_network_refused(self):
        manifest, responses = self.owned_fixture()
        responses[('container', manifest['resources']['db']['id'])]['NetworkSettings']['Networks']['osee-testops-foundation'] = {'NetworkID': 'e' * 64}
        with patch.object(control.DockerClient, 'inspect', side_effect=lambda kind, identifier: responses[(kind, identifier)]):
            with self.assertRaises(control.ScopeError): control.verify_owned(manifest, 'db')

    def test_private_key_acl_required(self):
        private = self.base / 'private'
        result = self.permitted(control.ensure_private_directory, private)
        self.assertTrue(result['acl_verified'])
        key = private / 'test-key.bin'
        key.write_bytes(b'unit-test-file')
        self.assertTrue(control.verify_private_acl(key)['acl_verified'])
        changed = subprocess.run(['icacls.exe', str(key), '/grant', '*S-1-1-0:R'], capture_output=True, text=True, timeout=10)
        self.assertEqual(changed.returncode, 0, 'Could not exercise actual NTFS disclosure ACL')
        with self.assertRaises(control.ScopeError): control.verify_private_acl(key)

    def test_private_environment_is_strict_and_multiline(self):
        (self.base / '.local').mkdir()
        with patch.object(control, 'ROOT', self.base):
            private = control._prepare_private_files()
        app = {line.split('=', 1)[0]: line.split('=', 1)[1] for line in (private / 'app.env').read_text().splitlines() if '=' in line}
        sdk = {line.split('=', 1)[0]: line.split('=', 1)[1] for line in (private / 'sdk.env').read_text().splitlines() if '=' in line}
        self.assertEqual(set(app), {'APP_ENV', 'DATABASE_IDENTITY', 'PRODUCTION_DATABASE_IDENTITY', 'OUTBOUND_MODE', 'SIMULATOR', 'RECIPIENT_MODE', 'AUTH_ORIGIN', 'LISTEN_ADDRESS', 'DEMO_ENABLED', 'DATABASE_URL'})
        self.assertEqual(set(sdk), {'GOFLAGS', 'GOTOOLCHAIN', 'GOPROXY', 'GOSUMDB', 'GOMODCACHE', 'GOCACHE', 'OSEE_TEST_DATABASE_URL'})
        self.assertEqual(app['OUTBOUND_MODE'], 'off')
        self.assertEqual(app['DEMO_ENABLED'], 'false')
        self.assertEqual(app['AUTH_ORIGIN'], 'http://127.0.0.1:8091')
        self.assertEqual(len((private / 'staff-master.key').read_bytes()), 32)
        for name in ['app.env', 'sdk.env', 'postgres-password', 'staff-master.key']:
            self.assertTrue(control.verify_private_acl(private / name)['acl_verified'])

    def frozen_fixture(self):
        (self.base / '.local').mkdir()
        control.copy_audited_sources(self.source, self.base / '.local/frozen-baseline', self.audited)
        evidence = self.base / 'docs/campaign/evidence/r1'
        evidence.mkdir(parents=True)
        imported = {'scope_id': 'b' * 32, 'copied_count': 114, 'source_hashes': self.audited}
        manifest = evidence / 't01-source-import.json'
        manifest.write_text(json.dumps(imported), encoding='utf-8')
        owner = {'scope_id': 'b' * 32, 'candidate_root': self.base.as_posix(), 'source_root': self.source.as_posix()}
        approval = dict(owner, decision='Continue from the frozen candidate; leave the parent untouched',
                        origin='owner-clarify', allow_parent_drift=True, import_parent_changes=False,
                        baseline_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
        (self.base / '.local/frozen-continuation.json').write_text(json.dumps(approval), encoding='utf-8')
        return owner

    def test_frozen_continuation_preserves_changed_parent(self):
        owner = self.frozen_fixture()
        parent = self.source / self.audited[-1]['path']
        parent.write_bytes(b'competing-parent-change')
        with patch.object(control, 'ROOT', self.base):
            actual = self.permitted(control._verify_frozen_baseline, owner)
        self.assertTrue(actual['snapshot_verified'])
        self.assertEqual(actual['paths_verified'], 114)
        self.assertEqual(parent.read_bytes(), b'competing-parent-change')

    def test_frozen_continuation_requires_matching_scope_and_manifest(self):
        owner = self.frozen_fixture()
        path = self.base / '.local/frozen-continuation.json'
        approved = json.loads(path.read_text())
        for field, wrong in [('scope_id', 'f' * 32), ('baseline_manifest_sha256', '0' * 64),
                             ('import_parent_changes', True), ('allow_parent_drift', False)]:
            with self.subTest(field=field):
                path.write_text(json.dumps(dict(approved, **{field: wrong})))
                with patch.object(control, 'ROOT', self.base):
                    with self.assertRaises(control.ScopeError):
                        control._verify_frozen_baseline(owner)

    def test_frozen_baseline_change_refused_without_parent_repair(self):
        owner = self.frozen_fixture()
        parent = self.source / self.audited[-1]['path']
        parent.write_bytes(b'preserve-parent')
        baseline = self.base / '.local/frozen-baseline' / self.audited[-1]['path']
        baseline.write_bytes(b'corrupt-snapshot')
        with patch.object(control, 'ROOT', self.base):
            with self.assertRaises(control.ScopeError):
                control._verify_frozen_baseline(owner)
        self.assertEqual(parent.read_bytes(), b'preserve-parent')

    def test_inventory_cli_has_no_provisioning_side_effect(self):
        before = {str(p): p.stat().st_size for p in (ROOT / '.local').rglob('*') if p.is_file()}
        result = subprocess.run(['python', str(ROOT / 'scripts/candidate-control.py'), 'inventory'], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.strip(), 'Inventory did not return actual JSON metadata')
        metadata = json.loads(result.stdout)
        self.assertEqual(metadata['source_import_count'], 114)
        self.assertTrue(metadata.get('snapshot_verified'))
        self.assertIsInstance(metadata['source_drift'], list)
        after = {str(p): p.stat().st_size for p in (ROOT / '.local').rglob('*') if p.is_file()}
        self.assertEqual(after, before)

    def test_provision_dry_run_does_not_create_resources(self):
        before = (ROOT / '.local/resources.json').read_bytes() if (ROOT / '.local/resources.json').exists() else None
        result = subprocess.run(['python', str(ROOT / 'scripts/candidate-control.py'), 'provision', '--dry-run'], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.strip(), 'No guarded provisioning plan returned')
        metadata = json.loads(result.stdout)
        self.assertFalse(metadata['applied'])
        self.assertTrue(metadata['internal_network'])
        self.assertEqual(metadata['database_host_ports'], [])
        after = (ROOT / '.local/resources.json').read_bytes() if (ROOT / '.local/resources.json').exists() else None
        self.assertEqual(after, before)

    def test_created_owned_container_network_verified_before_start(self):
        manifest, responses = self.owned_fixture()
        actual = responses[('container', manifest['resources']['db']['id'])]
        actual['State'] = {'Status': 'created', 'Running': False}
        actual['HostConfig']['NetworkMode'] = manifest['network']['name']
        actual['NetworkSettings']['Networks'][manifest['network']['name']]['NetworkID'] = ''
        with patch.object(control.DockerClient, 'inspect', side_effect=lambda kind, identifier: responses[(kind, identifier)]):
            result = self.permitted(control.verify_owned, manifest, 'db')
            self.assertEqual(result['State']['Status'], 'created')
        actual['HostConfig']['NetworkMode'] = 'osee-testops-foundation'
        with patch.object(control.DockerClient, 'inspect', side_effect=lambda kind, identifier: responses[(kind, identifier)]):
            with self.assertRaises(control.ScopeError): control.verify_owned(manifest, 'db')

    def test_unexpected_private_mount_refused(self):
        manifest, responses = self.owned_fixture()
        responses[('container', manifest['resources']['db']['id'])]['Mounts'].append(
            {'Type': 'bind', 'Source': 'D:/osee-testops-lite/.local', 'Destination': '/original-private', 'RW': False})
        with patch.object(control.DockerClient, 'inspect', side_effect=lambda kind, identifier: responses[(kind, identifier)]):
            with self.assertRaises(control.ScopeError): control.verify_owned(manifest, 'db')

    def test_build_context_excludes_runtime_and_preserves_required_config(self):
        root = self.base / 'build-source'
        (root / 'internal/config').mkdir(parents=True)
        (root / 'cmd/web').mkdir(parents=True)
        (root / 'db/migrations').mkdir(parents=True)
        (root / 'deploy').mkdir()
        (root / '.local/private').mkdir(parents=True)
        for relative in ['go.mod', 'go.sum', 'internal/config/config.go', 'cmd/web/main.go',
                         'db/migrations/embed.go', 'deploy/Dockerfile', '.dockerignore']:
            (root / relative).write_text('public-build-fixture', encoding='utf-8')
        (root / '.env').write_text('never-build-this', encoding='utf-8')
        (root / '.local/private/key').write_text('never-build-this', encoding='utf-8')
        (root / 'AGENTS.md').write_text('never-build-this', encoding='utf-8')
        target = self.base / 'context'
        with patch.object(control, 'ROOT', root):
            result = self.permitted(control.prepare_build_context, target)
        self.assertIn('internal/config/config.go', [row['path'] for row in result['source_hashes']])
        self.assertFalse((target / '.local').exists())
        self.assertFalse((target / '.env').exists())
        self.assertFalse((target / 'AGENTS.md').exists())
        self.assertEqual((root / '.env').read_text(), 'never-build-this')
        with patch.object(control, 'ROOT', root):
            with self.assertRaises(control.ScopeError):
                control.prepare_build_context(target)

    def test_ops_observes_owned_resources_without_changing_manifest(self):
        before = (ROOT / '.local/resources.json').read_bytes()
        result = subprocess.run(['python', str(ROOT / 'scripts/candidate-control.py'), 'ops'],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        metadata = json.loads(result.stdout)
        self.assertEqual(metadata['scope_id'], 'a63fdfed593f404584fb2212183ca987')
        self.assertEqual(metadata['database_host_ports'], [])
        self.assertTrue(metadata['internal_network'])
        self.assertEqual(before, (ROOT / '.local/resources.json').read_bytes())

    def test_candidate_up_rejects_invalid_profile_without_side_effects(self):
        before = (ROOT / '.local/resources.json').read_bytes()
        for profile in ['production', 'local']:
            result = subprocess.run(['python', str(ROOT / 'scripts/candidate-control.py'), 'up',
                                     '--profile', profile], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, (ROOT / '.local/resources.json').read_bytes())

    def test_candidate_down_refuses_foreign_profile_without_side_effects(self):
        before = (ROOT / '.local/resources.json').read_bytes()
        result = subprocess.run(['python', str(ROOT / 'scripts/candidate-control.py'), 'down',
                                 '--profile', 'local'], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, (ROOT / '.local/resources.json').read_bytes())

    def test_sdk_nonzero_exit_retains_evidence_and_cleanup(self):
        directory = ROOT / 'docs/campaign/evidence/r1'
        before = set(directory.glob('go-*.json'))
        result = subprocess.run(['python', str(ROOT / 'scripts/candidate-control.py'), 'go',
                                 '--package', './internal/__missing_contract__'],
                                capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, 1)
        created = set(directory.glob('go-*.json')) - before
        self.assertEqual(len(created), 1, 'Failed SDK execution lost its actual evidence')
        report = json.loads(next(iter(created)).read_text())
        self.assertNotEqual(report['exit_code'], 0)
        self.assertTrue(report['exact_sdk_removed'])
        self.assertNotIn('go', json.loads((ROOT / '.local/resources.json').read_text())['resources'])

    def test_build_cli_produces_exact_owned_nonroot_image(self):
        result = subprocess.run(['python', str(ROOT / 'scripts/candidate-control.py'), 'build'],
                                capture_output=True, text=True, timeout=560)
        self.assertEqual(result.returncode, 0, 'Candidate image build is unavailable or failed')
        report = json.loads(result.stdout)
        self.assertRegex(report['image_id'], r'^sha256:[a-f0-9]{64}$')
        self.assertTrue(report['public_context_verified'])
        inspected = subprocess.run(['docker', '--context', 'default', 'image', 'inspect', report['image_id'],
                                    '--format', '{{.Config.User}} {{index .Config.Labels "osee.testops.candidate"}}'],
                                   capture_output=True, text=True, timeout=20)
        self.assertEqual(inspected.returncode, 0)
        self.assertEqual(inspected.stdout.strip(), '65532:65532 a63fdfed593f404584fb2212183ca987')

    def test_fixture_compose_roundtrip_is_owned_loopback_and_cleaned(self):
        from urllib.request import build_opener,ProxyHandler,Request,HTTPCookieProcessor
        from urllib.error import HTTPError
        from http.cookiejar import CookieJar
        client=build_opener(ProxyHandler({}),HTTPCookieProcessor(CookieJar()))
        try:
            result=subprocess.run(['python',str(ROOT/'scripts/candidate-control.py'),'up','--profile','fixture'],
                                  capture_output=True,text=True,timeout=330)
            self.assertEqual(result.returncode,0,'Owned gateway fixture startup failed')
            report=json.loads(result.stdout)
            self.assertEqual(report['origin'],'http://127.0.0.1:8091')
            self.assertEqual(report['database_identity'],'osee_testops_test')
            self.assertTrue(report['readiness_checked'])
            with client.open(report['origin']+'/health/ready',timeout=5) as response: self.assertEqual(response.status,200)
            for path in ['/','/assets/app.css','/auth/login']:
                with client.open(report['origin']+path,timeout=5) as response:
                    self.assertEqual(response.status,200)
                    self.assertFalse(response.headers.get('Location'))
                    if path=='/auth/login':
                        self.assertEqual(response.headers.get('Referrer-Policy'),'same-origin')
                        self.assertTrue('HttpOnly' in (response.headers.get('Set-Cookie') or ''),'Login state cookie attributes missing')
            refusals=[
                (Request(report['origin']+'/auth/me',headers={'X-Forwarded-For':'127.0.0.1','X-OSEE-Role':'owner'}),401),
                (Request(report['origin']+'/auth/logout',data=b'csrf=invalid',headers={'Origin':'https://attacker.invalid','Content-Type':'application/x-www-form-urlencoded'}),401),
                (Request(report['origin']+'/auth/login',data=b'csrf=invalid&token=invalid',headers={'Origin':'https://attacker.invalid','Content-Type':'application/x-www-form-urlencoded'}),403),
                (Request(report['origin']+'/auth/login',data=b'csrf=invalid&token=invalid',headers={'Origin':report['origin'],'Content-Type':'application/x-www-form-urlencoded'}),403)]
            for request,expected in refusals:
                with self.subTest(path=request.full_url,expected=expected):
                    try:
                        with client.open(request,timeout=5): self.fail('Unauthorized/invalid-origin request was accepted')
                    except HTTPError as denied:
                        try: self.assertEqual(denied.code,expected)
                        finally: denied.close()
            manifest=control._load_manifest()
            self.assertEqual(set(manifest['resources']),{'db','web','worker','gateway'})
            self.assertNotIn('migrate',manifest['resources'])
            private_name='osee-r1-a63fdfed593f'
            for role in ['db','web','worker']:
                actual=control.verify_owned(manifest,role)
                self.assertEqual(set(actual['NetworkSettings']['Networks']),{private_name})
                self.assertFalse(actual['HostConfig'].get('PortBindings'))
            gateway=control.verify_owned(manifest,'gateway')
            ports={key:value for key,value in gateway['NetworkSettings']['Ports'].items() if value}
            self.assertEqual(ports,{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'8091'}]})
            self.assertEqual(set(gateway['NetworkSettings']['Networks']),{private_name,private_name+'-frontend'})
            self.assertEqual(gateway['Config']['User'],'65532:65532')
            self.assertFalse(any(mount['Type'] != 'tmpfs' for mount in gateway['Mounts']))
            self.assertEqual(set(gateway['HostConfig']['Tmpfs']),{'/tmp','/config','/data'})
            memory=control.DockerClient().call(['container','exec',gateway['Id'],'stat','-f','-c','%T','/tmp','/config','/data']).stdout
            self.assertEqual(memory.splitlines(),['tmpfs','tmpfs','tmpfs'])
            frontend=control._verify_frontend(manifest)
            self.assertEqual(set(frontend['Containers']),{gateway['Id']})
            self.assertTrue(control.DockerClient().inspect('network',manifest['network']['id'])['Internal'])
            admin=subprocess.run(control.DOCKER+['container','exec',gateway['Id'],'wget','-q','-T','2','-O','-','http://127.0.0.1:2019/config/'],capture_output=True,text=True,timeout=10)
            self.assertNotEqual(admin.returncode,0,'Caddy admin API unexpectedly reachable')
            version=control.DockerClient().call(['container','exec',gateway['Id'],'caddy','version']).stdout
            self.assertTrue(version.startswith('v2.11.7 '),'Pinned runtime version mismatch')
        finally:
            removed=subprocess.run(['python',str(ROOT/'scripts/candidate-control.py'),'down','--profile','fixture'],
                                   capture_output=True,text=True,timeout=75)
            self.assertEqual(removed.returncode,0,'Exact-owned fixture cleanup failed')
        manifest=control._load_manifest()
        self.assertEqual(set(manifest['resources']),{'db'})
        self.assertEqual(control._verify_frontend(manifest)['Containers'],{})

    def service_fixture(self):
        manifest, responses = self.owned_fixture()
        database = responses[('container', manifest['resources']['db']['id'])]
        name = manifest['network']['name'] + '-web'
        manifest['private_root'] = self.base.as_posix()
        manifest['resources']['web'] = dict(manifest['resources']['db'], name=name, profile='fixture')
        actual = json.loads(json.dumps(database))
        actual['Name'] = '/' + name
        actual['Config'].update({'User':'65532:65532','Env':['CANDIDATE_PROFILE=fixture','APP_ENV=development',
              'OUTBOUND_MODE=off','DEMO_ENABLED=false','AUTH_ORIGIN=http://127.0.0.1:8091',
              'DATABASE_IDENTITY=osee_testops_test']})
        actual['Config']['Labels'].update({'osee.testops.role':'web','osee.testops.profile':'fixture'})
        actual['HostConfig'].update({'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],
              'CapAdd':None,'SecurityOpt':['no-new-privileges:true'],
              'PortBindings':{}})
        actual['Mounts'] = [{'Type':'bind','Source':self.base.as_posix()+'/staff-master.key',
                            'Destination':'/run/secrets/staff-master.key','RW':False}]
        responses[('container', manifest['resources']['web']['id'])] = actual
        return manifest, responses

    def test_web_service_refuses_exposure_privilege_and_foreign_mounts(self):
        manifest, responses = self.service_fixture()
        key = ('container', manifest['resources']['web']['id'])
        baseline = json.loads(json.dumps(responses[key]))
        changes = ['port','private_mount','writable_root','privileged','cap_add','profile','outbound']
        for change in changes:
            actual = json.loads(json.dumps(baseline))
            if change == 'port': actual['HostConfig']['PortBindings'] = {'8080/tcp':[{'HostIp':'0.0.0.0','HostPort':'8091'}]}
            elif change == 'private_mount': actual['Mounts'].append({'Type':'bind','Source':'/var/run/docker.sock','Destination':'/socket','RW':False})
            elif change == 'writable_root': actual['HostConfig']['ReadonlyRootfs'] = False
            elif change == 'privileged': actual['HostConfig']['Privileged'] = True
            elif change == 'cap_add': actual['HostConfig']['CapAdd'] = ['SYS_ADMIN']
            elif change == 'profile': actual['Config']['Labels']['osee.testops.profile'] = 'local'
            else: actual['Config']['Env'].append('OUTBOUND_MODE=live')
            responses[key] = actual
            with self.subTest(change=change):
                with patch.object(control.DockerClient,'inspect',side_effect=lambda kind,identifier:responses[(kind,identifier)]):
                    with self.assertRaises(control.ScopeError):
                        control.verify_owned(manifest,'web')
        responses[key] = baseline
        with patch.object(control.DockerClient,'inspect',side_effect=lambda kind,identifier:responses[(kind,identifier)]):
            self.assertEqual(control.verify_owned(manifest,'web')['Config']['User'],'65532:65532')

    def gateway_fixture(self):
        manifest, responses = self.owned_fixture()
        manifest['candidate_root'] = self.base.as_posix()
        manifest['frontend_network'] = {'name':manifest['network']['name']+'-frontend','id':'f'*64}
        manifest['images'] = {'caddy':'sha256:'+'d'*64}
        identifier = 'e'*64
        manifest['resources']['gateway'] = {'id':identifier,'name':manifest['network']['name']+'-gateway',
                                          'image_id':manifest['images']['caddy'],'profile':'fixture'}
        (self.base/'.local').mkdir()
        approved = {'scope_id':manifest['scope_id'],'candidate_root':self.base.as_posix(),
                    'decision':'Approve the isolated Caddy ingress fix','origin':'owner-chat','approved':True,
                    'publication':'127.0.0.1:8091','frontend_members':['gateway'],
                    'live_providers_approved':False,'global_engine_or_firewall_changes':False,'other_projects_approved':False}
        (self.base/'.local/ingress-approved.json').write_text(json.dumps(approved))
        responses[('network','f'*64)] = {'Id':'f'*64,'Name':manifest['frontend_network']['name'],
             'Internal':False,'Driver':'bridge','Labels':{'osee.testops.candidate':manifest['scope_id'],'osee.testops.role':'frontend'},
             'Options':{'com.docker.network.bridge.host_binding_ipv4':'127.0.0.1'},'Containers':{identifier:{}}}
        responses[('container',identifier)] = {'Id':identifier,'Name':'/'+manifest['resources']['gateway']['name'],
             'Image':manifest['images']['caddy'],'State':{'Status':'running','Running':True},
             'Config':{'Labels':{'osee.testops.candidate':manifest['scope_id'],'osee.testops.role':'gateway','osee.testops.profile':'fixture'},
                       'User':'65532:65532','Env':['PATH=/usr/bin'],'Entrypoint':['caddy','reverse-proxy','--from','http://:8080','--to','http://web:8080']},
             'NetworkSettings':{'Networks':{manifest['network']['name']:{'NetworkID':manifest['network']['id']},
                                            manifest['frontend_network']['name']:{'NetworkID':'f'*64}},
                               'Ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'8091'}]}},
             'HostConfig':{'NetworkMode':manifest['network']['name'],'PortBindings':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'8091'}]},
                           'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges:true'],
                           'Tmpfs':{x:'rw,nosuid,noexec,size=16m' for x in ['/tmp','/config','/data']}},
             'Mounts':[{'Type':'tmpfs','Destination':x,'RW':True} for x in ['/tmp','/config','/data']]}
        return manifest,responses

    def test_gateway_allows_only_approved_frontend_and_no_private_material(self):
        manifest,responses = self.gateway_fixture()
        with patch.object(control,'ROOT',self.base), patch.object(control.DockerClient,'inspect',side_effect=lambda k,i:responses[(k,i)]):
            actual = self.permitted(control.verify_owned,manifest,'gateway')
            self.assertEqual(actual['NetworkSettings']['Ports']['8080/tcp'],[{'HostIp':'127.0.0.1','HostPort':'8091'}])
        baseline=json.loads(json.dumps(responses[('container','e'*64)]))
        for change in ['public_port','credential','bind','external_upstream','foreign_network','capability','wrong_image']:
            actual=json.loads(json.dumps(baseline))
            if change=='public_port': actual['HostConfig']['PortBindings']['8080/tcp'][0]['HostIp']='0.0.0.0'
            elif change=='credential': actual['Config']['Env'].append('DATABASE_URL=unit-fixture-not-a-secret')
            elif change=='bind': actual['Mounts'].append({'Type':'bind','Source':'/var/run/docker.sock','Destination':'/socket','RW':False})
            elif change=='external_upstream': actual['Config']['Entrypoint'][-1]='http://example.com'
            elif change=='foreign_network': actual['NetworkSettings']['Networks']['osee-testops-foundation']={'NetworkID':'1'*64}
            elif change=='capability': actual['HostConfig']['CapAdd']=['SYS_ADMIN']
            else: actual['Image']='sha256:'+'1'*64
            responses[('container','e'*64)]=actual
            with self.subTest(change=change), patch.object(control,'ROOT',self.base), patch.object(control.DockerClient,'inspect',side_effect=lambda k,i:responses[(k,i)]):
                with self.assertRaises(control.ScopeError): control.verify_owned(manifest,'gateway')
        responses[('container','e'*64)]=baseline
        approval=self.base/'.local/ingress-approved.json'
        approval.unlink()
        with patch.object(control,'ROOT',self.base), patch.object(control.DockerClient,'inspect',side_effect=lambda k,i:responses[(k,i)]):
            with self.assertRaises(control.ScopeError): control.verify_owned(manifest,'gateway')

    def test_compiled_compose_publishes_only_the_secret_free_gateway(self):
        before=(ROOT/'.local/resources.json').read_bytes()
        manifest=control._load_manifest()
        manifest['images']['caddy']='sha256:'+'d'*64
        manifest['frontend_network']={'name':'osee-r1-a63fdfed593f-frontend','id':'f'*64}
        args,env=control._compose_command(manifest,'fixture',ROOT/'.local/private/fixture.env')
        result=subprocess.run(args+['config','--format','json'],env=env,capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,0)
        config=json.loads(result.stdout)
        self.assertEqual(set(config['services']),{'web','worker','gateway'})
        self.assertEqual(set(config['networks']),{'candidate','frontend'})
        self.assertEqual(set(config['services']['gateway']['networks']),{'candidate','frontend'})
        self.assertEqual(set(config['services']['web']['networks']),{'candidate'})
        self.assertEqual(set(config['services']['worker']['networks']),{'candidate'})
        self.assertFalse(config['services']['gateway'].get('environment'))
        self.assertFalse(config['services']['gateway'].get('volumes'))
        self.assertFalse(config['services']['web'].get('ports'))
        self.assertFalse(config['services']['worker'].get('ports'))
        ports=config['services']['gateway']['ports']
        self.assertEqual([(p['host_ip'],str(p['published']),p['target']) for p in ports],[('127.0.0.1','8091',8080)])
        self.assertEqual((ROOT/'.local/resources.json').read_bytes(),before)

    def test_gateway_rejects_frontend_drift_and_unapproved_permissions(self):
        manifest,responses=self.gateway_fixture()
        baseline=json.loads(json.dumps(responses[('network','f'*64)]))
        for change in ['scope','id','driver','internal','binding','membership']:
            front=json.loads(json.dumps(baseline))
            if change=='scope': front['Labels']['osee.testops.candidate']='1'*32
            elif change=='id': front['Id']='1'*64
            elif change=='driver': front['Driver']='host'
            elif change=='internal': front['Internal']=True
            elif change=='binding': front['Options']['com.docker.network.bridge.host_binding_ipv4']='0.0.0.0'
            else: front['Containers']['1'*64]={}
            responses[('network','f'*64)]=front
            with self.subTest(change=change), patch.object(control,'ROOT',self.base), patch.object(control.DockerClient,'inspect',side_effect=lambda k,i:responses[(k,i)]):
                with self.assertRaises(control.ScopeError): control.verify_owned(manifest,'gateway')
        responses[('network','f'*64)]=baseline
        path=self.base/'.local/ingress-approved.json'
        original=json.loads(path.read_text())
        for field,wrong in [('scope_id','1'*32),('approved',False),('frontend_members',['web','gateway']),('live_providers_approved',True)]:
            path.write_text(json.dumps(dict(original,**{field:wrong})))
            with self.subTest(field=field), patch.object(control,'ROOT',self.base), patch.object(control.DockerClient,'inspect',side_effect=lambda k,i:responses[(k,i)]):
                with self.assertRaises(control.ScopeError): control.verify_owned(manifest,'gateway')

    def test_ingress_permission_flags_require_literal_booleans(self):
        manifest,_=self.gateway_fixture()
        path=self.base/'.local/ingress-approved.json'
        original=json.loads(path.read_text())
        for field,wrong in [('approved',1),('live_providers_approved',0),('global_engine_or_firewall_changes',0),('other_projects_approved',0)]:
            path.write_text(json.dumps(dict(original,**{field:wrong})))
            with self.subTest(field=field), patch.object(control,'ROOT',self.base):
                with self.assertRaises(control.ScopeError): control._ingress_gate(manifest)

    def test_created_gateway_uses_verified_tmpfs_configuration_before_start(self):
        manifest,responses=self.gateway_fixture()
        actual=responses[('container','e'*64)]
        actual['State']={'Status':'created','Running':False}
        actual['Mounts']=[]
        for endpoint in actual['NetworkSettings']['Networks'].values(): endpoint['NetworkID']=''
        responses[('network','f'*64)]['Containers']={}
        with patch.object(control,'ROOT',self.base), patch.object(control.DockerClient,'inspect',side_effect=lambda k,i:responses[(k,i)]):
            result=self.permitted(control.verify_owned,manifest,'gateway')
            self.assertEqual(result['State']['Status'],'created')
            for change in ['missing','oversized','executable','bind']:
                saved=json.loads(json.dumps(actual))
                if change=='missing': actual['HostConfig']['Tmpfs'].pop('/data')
                elif change=='oversized': actual['HostConfig']['Tmpfs']['/data']='rw,nosuid,noexec,size=1g'
                elif change=='executable': actual['HostConfig']['Tmpfs']['/data']='rw,nosuid,exec,size=16m'
                else: actual['Mounts']=[{'Type':'bind','Source':'/private','Destination':'/config','RW':False}]
                with self.subTest(change=change), self.assertRaises(control.ScopeError): control.verify_owned(manifest,'gateway')
                actual.clear(); actual.update(saved)

    def test_owned_gateway_image_executes_without_runtime_capabilities(self):
        manifest=control._load_manifest()
        control._ensure_caddy_image(manifest)
        docker=control.DockerClient()
        role='gateway-probe'
        name=manifest['network']['name']+'-'+role
        control._namespace_absent(docker,name)
        args=['container','create','--pull=never','--name',name,'--label',control.SCOPE_LABEL+'='+manifest['scope_id'],
              '--label',control.ROLE_LABEL+'='+role,'--network',manifest['network']['name'],
              '--read-only','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges:true']
        for directory in ['/tmp','/config','/data']: args+=['--tmpfs',directory+':rw,nosuid,noexec,size=16m']
        args+=['--entrypoint','sh',manifest['images']['caddy'],'-ec','test -z "$(getcap /usr/bin/caddy)"; exec /usr/bin/caddy version']
        identifier=docker.call(args).stdout.strip()
        manifest['resources'][role]={'id':identifier,'name':name,'image_id':manifest['images']['caddy']}
        control._save_metadata(control.MANIFEST,manifest)
        try:
            control.verify_owned(manifest,role)
            result=subprocess.run(control.DOCKER+['container','start','-a',identifier],capture_output=True,text=True,timeout=30)
            actual=control.verify_owned(manifest,role)
            self.assertEqual(actual['State']['ExitCode'],0,'Pinned gateway requires forbidden runtime file capabilities')
            self.assertEqual(result.returncode,0)
            self.assertTrue(result.stdout.startswith('v2.11.7 '),'Real pinned Caddy execution was not proved')
            image=docker.inspect('image',manifest['images']['caddy'])
            self.assertEqual(image['Config']['User'],'65532:65532')
            self.assertEqual(image['Config']['Labels'][control.SCOPE_LABEL],manifest['scope_id'])
        finally:
            control.verify_owned(manifest,role)
            docker.call(['container','rm','-f',identifier])
            del manifest['resources'][role]
            control._save_metadata(control.MANIFEST,manifest)
            self.assertNotIn(identifier,docker.call(['container','ls','-a','--no-trunc','--format','{{.ID}}']).stdout.splitlines())

    def test_readiness_uses_registered_database_auth_schema_endpoint(self):
        from unittest.mock import Mock
        from contextlib import nullcontext
        manifest={}
        actual={'State':{'Running':True},'NetworkSettings':{'Ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'8091'}]}}}
        response=Mock(status=200)
        response.read.return_value=b'{"database":"ready"}'
        def opened(url,**kwargs):
            self.assertEqual(url,'http://127.0.0.1:8091/health/ready','Readiness used an unregistered route')
            self.assertEqual(kwargs['timeout'],3)
            return nullcontext(response)
        opener=Mock()
        opener.open.side_effect=opened
        with patch.object(control,'verify_owned',return_value=actual), patch('urllib.request.build_opener',return_value=opener):
            control._wait_candidate_ready(manifest)

    def test_nested_tool_error_is_failure(self):
        for result in [{'exit_code': 1}, {'status': 'success', 'result': {'success': False, 'error': 'failed'}}, {'verified': False}, {'error': 'failed'}]:
            with self.subTest(result=result):
                with self.assertRaises(control.ScopeError): control.require_tool_success(result)
        self.assertEqual(self.permitted(control.require_tool_success, {'verified': True}), {'verified': True})


if __name__ == '__main__':
    unittest.main()
