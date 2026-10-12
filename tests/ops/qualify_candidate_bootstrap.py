"""Explicit synthetic host bootstrap qualification; never print private values."""
import base64
import datetime
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]


def qualify():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('host_bootstrap_control', ROOT / 'scripts/candidate-control.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('Owned controller loader unavailable')
    control = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = control
    spec.loader.exec_module(control)
    manifest = control._load_manifest()
    if set(manifest['resources']) != {'db'}:
        raise control.ScopeError('Host qualification requires DB-only candidate')
    database = control.verify_owned(manifest, 'db')
    if not database['State']['Running']:
        raise control.ScopeError('Stopped database preserved')
    private = Path(manifest['private_root'])
    key = private / 'staff-master.key'
    target = private / 'fixture-setup-capability.txt'
    control.verify_private_acl(private)
    control.verify_private_acl(key)
    key_before = key.read_bytes()
    docker = control.DockerClient()
    bootstrap = control._bootstrap_helpers()

    def snapshot():
        control.verify_owned(control._load_manifest(), 'db')
        query = """BEGIN READ ONLY; SET LOCAL statement_timeout='5s';
        SELECT jsonb_build_object(
          'bootstrap', (SELECT jsonb_build_object('digest',encode(token_hash,'hex'),'created_at',created_at,'expires_at',expires_at,
                          'consumed',consumed_at IS NOT NULL,'finalized',finalized_at IS NOT NULL) FROM public.auth_bootstrap),
          'principals',(SELECT count(*) FROM public.auth_principals),
          'sessions',(SELECT count(*) FROM public.auth_sessions),
          'credentials',(SELECT count(*) FROM public.auth_staff_credentials),
          'challenges',(SELECT count(*) FROM public.auth_staff_challenges)); COMMIT;"""
        output = docker.call(['container', 'exec', database['Id'], 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
                             '-U', 'candidate', '-d', 'osee_testops_test', '-At', '-c', query]).stdout
        rows = [line for line in output.splitlines() if line.startswith('{')]
        if len(rows) != 1:
            raise control.ScopeError('Host qualification census invalid')
        state = json.loads(rows[0])
        if any(state[name] != 0 for name in ['principals', 'sessions', 'credentials', 'challenges']):
            raise control.ScopeError('Synthetic host fixture is not empty')
        return state

    def private_bytes():
        control._no_reparse(target)
        control.verify_private_acl(target)
        if not target.is_file() or target.stat().st_size != 43:
            raise control.ScopeError('Host private capability shape invalid')
        content = target.read_bytes()
        decoded = base64.b64decode(content + b'=', altchars=b'-_', validate=True)
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b'=') != content:
            raise control.ScopeError('Host private capability encoding invalid')
        return content

    def verify_roundtrip(result):
        content = private_bytes()
        state = snapshot()['bootstrap']
        if state is None or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), state['digest']):
            raise control.ScopeError('Host file does not match persisted digest')
        start = datetime.datetime.fromisoformat(state['created_at'])
        end = datetime.datetime.fromisoformat(state['expires_at'])
        if (end - start).total_seconds() != 600 or state['consumed'] or state['finalized']:
            raise control.ScopeError('Host bootstrap lifetime/state invalid')
        if result['profile'] != 'fixture' or not result['private_acl_verified'] or not result['exact_helper_removed']:
            raise control.ScopeError('Host controller result incomplete')
        return content

    snapshot()
    report = {'task': 'R1-T04', 'kind': 'ACTUAL_SYNTHETIC_HOST_BOOTSTRAP_QUALIFICATION',
              'scope_id': manifest['scope_id'], 'profile': 'fixture', 'cases': [],
              'private_values_returned': False, 'genuine_owner_enrolled': False,
              'application_deployed': False,
              'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    first = bootstrap.bootstrap(control, 'fixture', reset=True)
    old = verify_roundtrip(first)
    report['cases'].append({'name': 'HostPrivateFileDigestRoundtrip', 'outcome': 'PASS',
                            'helper_id': first['helper_id'], 'expires_at': first['expires_at']})
    unchanged = snapshot()
    try:
        bootstrap.bootstrap(control, 'fixture', reset=False)
    except control.ScopeError:
        if private_bytes() != old or snapshot() != unchanged:
            raise control.ScopeError('Refused host retry changed persisted/private state')
    else:
        raise control.ScopeError('Host silently recovered or rotated existing capability')
    report['cases'].append({'name': 'HostEmptyOnlyRetryRefusesWithoutMutation', 'outcome': 'PASS'})
    second = bootstrap.bootstrap(control, 'fixture', reset=True)
    new = verify_roundtrip(second)
    if hmac.compare_digest(old, new):
        raise control.ScopeError('Explicit empty host reset did not rotate capability')
    report['cases'].append({'name': 'HostExplicitEmptyResetRotatesPrivately', 'outcome': 'PASS',
                            'helper_id': second['helper_id'], 'expires_at': second['expires_at']})
    current = control._load_manifest()
    ids = sorted(docker.call(['container', 'ls', '-a', '--no-trunc', '--filter',
                            'label=' + control.SCOPE_LABEL + '=' + current['scope_id'], '--format', '{{.ID}}']).stdout.splitlines())
    if set(current['resources']) != {'db'} or ids != [database['Id']]:
        raise control.ScopeError('Host helper cleanup unverified')
    if list(private.glob('.bootstrap-*')):
        raise control.ScopeError('Host private temporary file remains')
    control.verify_private_acl(key)
    if not hmac.compare_digest(key_before, key.read_bytes()):
        raise control.ScopeError('Host recovery changed existing master key')
    report['master_key_preserved'] = True
    report['exact_helpers_removed'] = True
    report['scoped_container_ids_after'] = ids
    report['retained_fixture_private_capability'] = {'size_bytes': target.stat().st_size, 'acl_verified': True,
                                                   'digest_matches': True, 'grants_staff_authority': False}
    report['pass'] = sum(case['outcome'] == 'PASS' for case in report['cases'])
    report['fail'] = 0
    report['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    suffix = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    control._save_metadata(control.EVIDENCE / ('bootstrap-host-qualification-' + suffix + '.json'), report)
    return report


if __name__ == '__main__':
    print(json.dumps(qualify(), indent=2))
