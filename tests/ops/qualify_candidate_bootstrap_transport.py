"""Explicit, owned Docker regression for private tmpfs transport."""
import datetime
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def qualify():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('transport_control', ROOT / 'scripts/candidate-control.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('Owned controller loader unavailable')
    control = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = control
    spec.loader.exec_module(control)
    manifest = control._load_manifest()
    if set(manifest['resources']) != {'db'}:
        raise control.ScopeError('Transport regression requires DB-only candidate')
    database = control.verify_owned(manifest, 'db')
    if not database['State']['Running']:
        raise control.ScopeError('Stopped database preserved')
    bootstrap = control._bootstrap_helpers()
    report = {'task': 'R1-T04', 'test': 'PrivateTmpfsCapabilityTransport',
              'synthetic_non_authority_fixture': True, 'database_mutation': False,
              'private_values_returned': False,
              'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        identifier = bootstrap._create_helper(control, manifest, 'fixture', control._application_environment(manifest, 'fixture'))
        report['helper_id'] = identifier
        docker = control.DockerClient()
        docker.call(['container', 'exec', identifier, '/bin/sh', '-ec',
                     "umask 077; printf '%043d' 0 | tr '0' A > /run/osee-private/setup-capability.txt"])
        tar = subprocess.run(control.DOCKER + ['container', 'exec', identifier, '/bin/tar',
                             '-C', '/run/osee-private', '-cf', '-', '--', 'setup-capability.txt'],
                             capture_output=True, timeout=15)
        report['direct_tar_return_code'] = tar.returncode
        report['direct_tar_archive_bytes'] = len(tar.stdout)
        if tar.returncode:
            raise control.ScopeError('Private tar fixture unavailable')
        with tarfile.open(fileobj=io.BytesIO(tar.stdout), mode='r:') as archive:
            report['direct_tar_headers'] = [{'name': item.name, 'uid': item.uid, 'gid': item.gid,
                                            'mode': oct(item.mode), 'size': item.size,
                                            'regular_file': item.isfile()} for item in archive.getmembers()]
        try:
            capability = bootstrap._read_capability(control, manifest)
        except control.ScopeError as error:
            report['outcome'] = 'FAIL'
            report['failure'] = str(error) if str(error) in {'Private capability copy failed', 'Private capability archive invalid',
                                                           'Private capability encoding invalid'} else 'DETAIL_REDACTED'
        else:
            if capability != b'A' * 43:
                raise control.ScopeError('Private transport altered fixture bytes')
            report['outcome'] = 'PASS'
            report['canonical_fixture_roundtrip'] = True
    finally:
        if 'bootstrap' in manifest['resources']:
            bootstrap._remove_helper(control, manifest)
    current = control._load_manifest()
    identifiers = sorted(control.DockerClient().call(['container', 'ls', '-a', '--no-trunc',
                        '--filter', 'label=' + control.SCOPE_LABEL + '=' + current['scope_id'],
                        '--format', '{{.ID}}']).stdout.splitlines())
    if set(current['resources']) != {'db'} or identifiers != [current['resources']['db']['id']]:
        raise control.ScopeError('Transport regression cleanup unverified')
    report['exact_helper_removed'] = True
    report['scoped_container_ids_after'] = identifiers
    report['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    suffix = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    control._save_metadata(control.EVIDENCE / ('bootstrap-transport-' + suffix + '.json'), report)
    return report


if __name__ == '__main__':
    result = qualify()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['outcome'] == 'PASS' else 1)
