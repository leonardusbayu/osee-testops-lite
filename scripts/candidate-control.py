"""Fail-closed copy, NTFS confidentiality and exact Docker ownership guards."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ['docker', '--context', 'default']
SCOPE_LABEL = 'osee.testops.candidate'
ROLE_LABEL = 'osee.testops.role'
MAX_SOURCE_BYTES = 5 * 1024 * 1024


class ScopeError(RuntimeError):
    pass


def require_tool_success(result: dict) -> dict:
    def check(value):
        if isinstance(value, list):
            for child in value:
                check(child)
        elif isinstance(value, dict):
            if value.get('error') or value.get('status') in {'error', 'failed', 'blocked', 'refused'}:
                raise ScopeError('Tool reported failure')
            for key in ['success', 'verified']:
                if key in value and value[key] is not True:
                    raise ScopeError('Tool success was not verified')
            if 'exit_code' in value and (type(value['exit_code']) is not int or value['exit_code'] != 0):
                raise ScopeError('Tool exited unsuccessfully')
            for child in value.values():
                check(child)
    if not isinstance(result, dict) or not result:
        raise ScopeError('Missing tool result')
    check(result)
    if not any(result.get(key) is True for key in ['verified', 'success']) and result.get('exit_code') != 0:
        raise ScopeError('No explicit successful result')
    return result


def _no_reparse(path: Path) -> None:
    for component in [path] + list(path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError as error:
            raise ScopeError('Required path is absent') from error
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ScopeError('Reparse or symbolic-link path refused')


def _source_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or '\\' in value or ':' in value:
        raise ScopeError('Invalid source path')
    relative = PurePosixPath(value)
    if relative.is_absolute() or value != relative.as_posix() or any(part in {'.', '..'} for part in relative.parts):
        raise ScopeError('Unsafe source path')
    if value not in {'go.mod', 'go.sum'} and relative.parts[0] not in {'cmd', 'internal', 'db'}:
        raise ScopeError('Source path outside allowed roots')
    if any(part.casefold() in {'.git', '.local', 'agents.md'} or part.casefold().startswith('.env') for part in relative.parts):
        raise ScopeError('Runtime/private source refused')
    return relative


def copy_audited_sources(source: Path, target: Path, audited: list[dict]) -> dict:
    source, target = Path(source).absolute(), Path(target).absolute()
    _no_reparse(source)
    _no_reparse(target.parent)
    if target.exists() or target.is_symlink():
        raise ScopeError('Candidate namespace already exists')
    if not isinstance(audited, list) or not audited:
        raise ScopeError('Missing audited source')
    checked, seen = [], set()
    for row in audited:
        relative = _source_relative(row.get('path'))
        canonical = relative.as_posix().casefold()
        if canonical in seen:
            raise ScopeError('Duplicate audited path')
        seen.add(canonical)
        count, digest = row.get('bytes'), row.get('sha256')
        if type(count) is not int or not 0 <= count <= MAX_SOURCE_BYTES or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ScopeError('Invalid source inventory row')
        path = source / relative
        _no_reparse(path)
        if not path.is_file():
            raise ScopeError('Source is not a regular file')
        content = path.read_bytes()
        if len(content) != count or hashlib.sha256(content).hexdigest() != digest:
            raise ScopeError('Source changed since approval')
        checked.append((dict(row), content))
    target.mkdir()
    copied = []
    for row, content in checked:
        destination = target / row['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        _no_reparse(destination.parent)
        with destination.open('xb') as stream:
            stream.write(content)
        actual = destination.read_bytes()
        copied.append({'path': row['path'], 'bytes': len(actual), 'sha256': hashlib.sha256(actual).hexdigest()})
    if copied != [row for row, _ in checked]:
        raise ScopeError('Copied source verification mismatch')
    return {'source_hashes': copied, 'copied_count': len(copied)}


class DockerClient:
    def call(self, args: list[str], timeout: int = 25, input_text: str | None = None):
        result = subprocess.run(DOCKER + args, capture_output=True, text=True, input=input_text, timeout=timeout)
        if result.returncode:
            raise ScopeError('Docker step failed: ' + args[0])
        return result

    def inspect(self, kind: str, identifier: str) -> dict:
        if kind not in {'container', 'network', 'volume', 'image'}:
            raise ScopeError('Unsupported Docker inspection')
        result = json.loads(self.call([kind, 'inspect', identifier]).stdout)
        if len(result) != 1:
            raise ScopeError('Docker target is not exact')
        return result[0]


CADDY = 'caddy@sha256:173b26306d711395accaeba8b67afcaad2a085ccb1e6bf26010bfe8c095a5229'
CADDY_ENTRYPOINT = ['caddy', 'reverse-proxy', '--from', 'http://:8080', '--to', 'http://web:8080']
GATEWAY_PORTS = {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8091'}]}


def _ingress_gate(manifest: dict) -> None:
    path = ROOT / '.local/ingress-approved.json'
    _no_reparse(path)
    approved = json.loads(path.read_text())
    expected = {'scope_id': manifest['scope_id'], 'candidate_root': ROOT.as_posix(),
                'decision': 'Approve the isolated Caddy ingress fix', 'origin': 'owner-chat',
                'approved': True, 'publication': '127.0.0.1:8091', 'frontend_members': ['gateway'],
                'live_providers_approved': False, 'global_engine_or_firewall_changes': False,
                'other_projects_approved': False}
    if any(approved.get(key) != value or (type(value) is bool and type(approved.get(key)) is not bool)
           for key, value in expected.items()):
        raise ScopeError('Candidate ingress permission mismatch')
    if manifest.get('candidate_root') != ROOT.as_posix():
        raise ScopeError('Candidate ingress root mismatch')


def _verify_frontend(manifest: dict) -> dict:
    _ingress_gate(manifest)
    frontend = manifest['frontend_network']
    if (frontend['name'] != manifest['network']['name'] + '-frontend'
            or not re.fullmatch(r'[0-9a-f]{64}', frontend['id'])):
        raise ScopeError('Candidate frontend identity mismatch')
    actual = DockerClient().inspect('network', frontend['id'])
    labels = actual.get('Labels') or {}
    if (actual['Id'] != frontend['id'] or actual['Name'] != frontend['name']
            or actual['Internal'] is not False or actual['Driver'] != 'bridge'
            or labels.get(SCOPE_LABEL) != manifest['scope_id'] or labels.get(ROLE_LABEL) != 'frontend'
            or actual.get('Options', {}).get('com.docker.network.bridge.host_binding_ipv4') != '127.0.0.1'):
        raise ScopeError('Candidate frontend readback mismatch')
    gateway = manifest['resources'].get('gateway', {}).get('id')
    if set(actual.get('Containers') or {}) - ({gateway} if gateway else set()):
        raise ScopeError('Only the exact gateway may join the frontend')
    return actual


def _verify_gateway(manifest: dict, actual: dict, resource: dict) -> None:
    config, host = actual['Config'], actual['HostConfig']
    labels = config.get('Labels') or {}
    if (resource.get('profile') not in {'fixture', 'local'}
            or labels.get('osee.testops.profile') != resource['profile']
            or actual['Image'] != manifest['images']['caddy'] or config.get('User') != '65532:65532'
            or config.get('Entrypoint') != CADDY_ENTRYPOINT or config.get('Cmd')
            or host.get('ReadonlyRootfs') is not True or host.get('Privileged') is True
            or host.get('CapAdd') or set(host.get('CapDrop') or []) != {'ALL'}
            or 'no-new-privileges:true' not in (host.get('SecurityOpt') or [])
            or (host.get('PortBindings') or {}) != GATEWAY_PORTS):
        raise ScopeError('Gateway command/privilege/publication mismatch')
    allowed_environment = {'PATH', 'CADDY_VERSION', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'SSL_CERT_FILE', 'SSL_CERT_DIR'}
    if any(item.split('=', 1)[0] not in allowed_environment for item in config.get('Env') or []):
        raise ScopeError('Gateway credentials or unexpected environment refused')
    tmpfs = host.get('Tmpfs') or {}
    paths = {'/tmp', '/config', '/data'}
    if (set(tmpfs) != paths
            or any(set(options.split(',')) != {'rw', 'nosuid', 'noexec', 'size=16m'} for options in tmpfs.values())
            or any(mount['Type'] != 'tmpfs' or mount['Destination'] not in paths for mount in actual['Mounts'])):
        raise ScopeError('Gateway bind/volume/private mounts or unsafe tmpfs refused')


def _ensure_caddy_image(manifest: dict) -> None:
    import uuid
    docker = DockerClient()
    if manifest.get('caddy_reference') not in {None, CADDY}:
        raise ScopeError('Pinned Caddy reference changed')
    if 'caddy_base' not in manifest['images']:
        if 'caddy' not in manifest['images']:
            docker.call(['image', 'pull', '--platform', 'linux/amd64', CADDY], timeout=180)
        base = docker.inspect('image', CADDY)
        if base['Os'] != 'linux' or base['Architecture'] != 'amd64' or CADDY not in base.get('RepoDigests', []):
            raise ScopeError('Pinned Caddy base digest/platform mismatch')
        manifest['images']['caddy_base'] = base['Id']
        manifest['caddy_reference'] = CADDY
        _save_metadata(MANIFEST, manifest)
    if docker.inspect('image', CADDY)['Id'] != manifest['images']['caddy_base']:
        raise ScopeError('Pinned Caddy base identity changed')
    source = ROOT / 'deploy/Dockerfile.gateway'
    _no_reparse(source)
    content = source.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if 'gateway_build' not in manifest:
        target = ROOT / '.local' / ('gateway-context-' + uuid.uuid4().hex)
        _no_reparse(target.parent)
        target.mkdir()
        with (target / 'Dockerfile').open('xb') as stream:
            stream.write(content)
        if (target / 'Dockerfile').read_bytes() != content:
            raise ScopeError('Gateway public context byte mismatch')
        identifier = target / 'image-id'
        result = subprocess.run(DOCKER + ['build', '--network=none', '--pull=false', '--progress=plain',
                                '--label', SCOPE_LABEL+'='+manifest['scope_id'], '--label', ROLE_LABEL+'=gateway-image',
                                '--label', 'osee.testops.gateway.base='+manifest['images']['caddy_base'],
                                '--label', 'osee.testops.gateway.source='+digest, '--iidfile', str(identifier), str(target)],
                                capture_output=True, text=True, timeout=180)
        with (target / 'build.log').open('x') as stream:
            stream.write(result.stdout+result.stderr)
        if result.returncode or not identifier.is_file():
            raise ScopeError('Owned gateway derivative build failed')
        image_id = identifier.read_text().strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
            raise ScopeError('Invalid gateway image identity')
        manifest['images']['caddy'] = image_id
        manifest['gateway_build'] = {'image_id':image_id,'source_sha256':digest,'context_path':target.as_posix()}
        _save_metadata(MANIFEST, manifest)
    build = manifest['gateway_build']
    image = docker.inspect('image', manifest['images']['caddy'])
    labels = image['Config'].get('Labels') or {}
    if (build['source_sha256'] != digest or build['image_id'] != image['Id']
            or image['Config']['User'] != '65532:65532' or labels.get(SCOPE_LABEL) != manifest['scope_id']
            or labels.get(ROLE_LABEL) != 'gateway-image' or labels.get('osee.testops.gateway.source') != digest
            or labels.get('osee.testops.gateway.base') != manifest['images']['caddy_base']):
        raise ScopeError('Owned gateway image/source readback mismatch')


def _ensure_frontend(manifest: dict) -> None:
    if 'frontend_network' in manifest:
        _verify_frontend(manifest)
        return
    _ingress_gate(manifest)
    name = manifest['network']['name'] + '-frontend'
    docker = DockerClient()
    _namespace_absent(docker, name)
    identifier = docker.call(['network', 'create', '--driver', 'bridge', '--label', SCOPE_LABEL + '=' + manifest['scope_id'],
                              '--label', ROLE_LABEL + '=frontend', '--opt',
                              'com.docker.network.bridge.host_binding_ipv4=127.0.0.1', name]).stdout.strip()
    manifest['frontend_network'] = {'name': name, 'id': identifier}
    _save_metadata(MANIFEST, manifest)
    _verify_frontend(_load_manifest())


def _bootstrap_helpers():
    import importlib.util
    path = ROOT / 'scripts/candidate_bootstrap.py'
    _no_reparse(path)
    spec = importlib.util.spec_from_file_location('candidate_bootstrap', path)
    if spec is None or spec.loader is None:
        raise ScopeError('Owned bootstrap module unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bootstrap_candidate(profile: str, reset: bool = False) -> dict:
    import sys
    return _bootstrap_helpers().bootstrap(sys.modules[__name__], profile, reset)


def verify_owned(manifest: dict, role: str) -> dict:
    try:
        scope = manifest['scope_id']
        if not re.fullmatch(r'[0-9a-f]{32}', scope):
            raise ScopeError('Invalid scope identity')
        expected_name = 'osee-r1-' + scope[:12]
        network = manifest['network']
        resource = manifest['resources'][role]
        if network['name'] != expected_name or not re.fullmatch(r'[0-9a-f]{64}', network['id']):
            raise ScopeError('Candidate network identity mismatch')
        if resource['name'] != expected_name + '-' + role or not re.fullmatch(r'[0-9a-f]{64}', resource['id']):
            raise ScopeError('Candidate resource identity mismatch')
        docker = DockerClient()
        actual_network = docker.inspect('network', network['id'])
        if actual_network['Id'] != network['id'] or actual_network['Name'] != network['name'] or not actual_network['Internal'] or (actual_network.get('Labels') or {}).get(SCOPE_LABEL) != scope:
            raise ScopeError('Candidate private network not verified')
        actual = docker.inspect('container', resource['id'])
        labels = actual['Config'].get('Labels') or {}
        if actual['Id'] != resource['id'] or actual['Name'] != '/' + resource['name'] or actual['Image'] != resource['image_id']:
            raise ScopeError('Immutable candidate resource mismatch')
        if labels.get(SCOPE_LABEL) != scope or labels.get(ROLE_LABEL) != role:
            raise ScopeError('Foreign resource label refused')
        attached = actual['NetworkSettings']['Networks']
        networks = {network['name']: network['id']}
        if role == 'gateway':
            frontend = _verify_frontend(manifest)
            networks[frontend['Name']] = frontend['Id']
        if set(attached) != set(networks):
            raise ScopeError('Foreign or additional network refused')
        created = actual.get('State', {}).get('Status') == 'created' and actual.get('State', {}).get('Running') is False
        configured = actual['HostConfig'].get('NetworkMode') in networks
        for name, identifier in networks.items():
            endpoint_id = attached[name].get('NetworkID')
            if endpoint_id != identifier and not (created and configured and endpoint_id == ''):
                raise ScopeError('Candidate endpoint network mismatch')
        if role == 'gateway':
            _verify_gateway(manifest, actual, resource)
        if role == 'bootstrap':
            import types
            _bootstrap_helpers().verify_bootstrap(types.SimpleNamespace(ScopeError=ScopeError), manifest, actual, resource)
        if role == 'db':
            if actual['HostConfig'].get('PortBindings'):
                raise ScopeError('Candidate database host port refused')
            volume = manifest['volume']
            if volume['name'] != expected_name + '-pg':
                raise ScopeError('Candidate volume namespace mismatch')
            actual_volume = docker.inspect('volume', volume['name'])
            if actual_volume['Name'] != volume['name'] or (actual_volume.get('Labels') or {}).get(SCOPE_LABEL) != scope:
                raise ScopeError('Foreign database volume refused')
            mounts = [mount for mount in actual['Mounts'] if mount['Destination'] == '/var/lib/postgresql/data']
            if len(mounts) != 1 or mounts[0]['Type'] != 'volume' or mounts[0]['Name'] != volume['name']:
                raise ScopeError('Database data mount mismatch')
            for mount in actual['Mounts']:
                destination = mount['Destination']
                if destination == '/var/lib/postgresql/data':
                    continue
                if mount['Type'] == 'tmpfs' and destination in {'/tmp', '/var/run/postgresql'}:
                    continue
                expected_private = manifest.get('private_root', '').replace('\\', '/') + '/postgres-password'
                source = mount.get('Source', '').replace('\\', '/')
                for prefix in ['/run/desktop/mnt/host/', '/host_mnt/']:
                    if source.startswith(prefix) and len(source) > len(prefix) + 2:
                        source = source[len(prefix)].upper() + ':/' + source[len(prefix) + 2:]
                if not manifest.get('private_root') or destination != '/run/secrets/postgres-password' or mount['Type'] != 'bind' or mount.get('RW') is not False or source.casefold() != expected_private.casefold():
                    raise ScopeError('Unexpected private/database mount refused')
        if role in {'web','worker'}:
            host = actual['HostConfig']
            profile = resource.get('profile')
            if (profile not in {'fixture','local'} or labels.get('osee.testops.profile') != profile
                    or actual['Config'].get('User') != '65532:65532' or host.get('ReadonlyRootfs') is not True
                    or host.get('Privileged') is True or host.get('CapAdd')
                    or set(host.get('CapDrop') or []) != {'ALL'}
                    or 'no-new-privileges:true' not in (host.get('SecurityOpt') or [])):
                raise ScopeError('Candidate service privileges/profile mismatch')
            expected_ports = {}
            if (host.get('PortBindings') or {}) != expected_ports:
                raise ScopeError('Candidate service publication mismatch')
            env = dict(item.split('=',1) for item in actual['Config'].get('Env',[]) if '=' in item)
            expected = {'CANDIDATE_PROFILE':profile,'APP_ENV':'development','OUTBOUND_MODE':'off',
                        'DEMO_ENABLED':'false','AUTH_ORIGIN':'http://127.0.0.1:8091',
                        'DATABASE_IDENTITY':'osee_testops_test' if profile == 'fixture' else 'osee_testops_dev'}
            if any(env.get(key) != value for key,value in expected.items()):
                raise ScopeError('Candidate service environment mismatch')
            binds = []
            for mount in actual['Mounts']:
                if mount['Type'] == 'tmpfs' and mount['Destination'] == '/tmp':
                    continue
                source = mount.get('Source','').replace('\\','/')
                for prefix in ['/run/desktop/mnt/host/','/host_mnt/']:
                    if source.startswith(prefix) and len(source) > len(prefix)+2:
                        source = source[len(prefix)].upper()+':/'+source[len(prefix)+2:]
                if (role != 'web' or mount['Type'] != 'bind' or mount.get('RW') is not False
                        or mount['Destination'] != '/run/secrets/staff-master.key'
                        or source.casefold() != (manifest['private_root']+'/staff-master.key').casefold()):
                    raise ScopeError('Unexpected service mount refused')
                binds.append(mount)
            if role == 'web' and len(binds) != 1:
                raise ScopeError('Candidate master key mount missing')
        if 'mounts' in resource:
            actual_mounts = [{'type': item['Type'], 'source': item.get('Name') if item['Type'] == 'volume' else item['Source'],
                              'target': item['Destination'], 'readonly': not item['RW']} for item in actual['Mounts']]
            if sorted(actual_mounts, key=lambda item: item['target']) != sorted(resource['mounts'], key=lambda item: item['target']):
                raise ScopeError('Unexpected candidate mounts')
        return actual
    except (KeyError, TypeError, ValueError) as error:
        raise ScopeError('Malformed ownership metadata') from error


def _acl_metadata(path: Path, initialize: bool = False) -> dict:
    _no_reparse(path)
    env = os.environ.copy()
    env['OSEE_ACL_TARGET'] = str(path.absolute())
    script = "$ErrorActionPreference='Stop';$p=$env:OSEE_ACL_TARGET;$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;"
    if initialize:
        script += ("$a=[System.Security.AccessControl.DirectorySecurity]::new();$a.SetOwner($sid);"
                   "$a.SetAccessRuleProtection($true,$false);"
                   "$rule=[System.Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');"
                   "$a.AddAccessRule($rule);Set-Acl -LiteralPath $p -AclObject $a;")
    script += ("$a=Get-Acl -LiteralPath $p;$rules=@($a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])|"
               "ForEach-Object{@{sid=$_.IdentityReference.Value;kind=$_.AccessControlType.ToString();rights=[int]$_.FileSystemRights;"
               "inherit_only=([int]$_.PropagationFlags -band 2)-ne 0}});"
               "@{current_sid=$sid.Value;owner_sid=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value;"
               "protected=$a.AreAccessRulesProtected;rules=$rules}|ConvertTo-Json -Depth 5 -Compress")
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            env=env, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ScopeError('NTFS ACL operation failed')
    return json.loads(result.stdout)


def verify_private_acl(path: Path) -> dict:
    metadata = _acl_metadata(Path(path))
    sid, rules = metadata['current_sid'], metadata['rules']
    if metadata['owner_sid'] != sid or not rules:
        raise ScopeError('Private file owner/access missing')
    if any(rule['sid'] != sid or rule['kind'] != 'Allow' or rule['inherit_only'] for rule in rules):
        raise ScopeError('Non-owner private access refused')
    if not any(rule['rights'] & 0x1F01FF == 0x1F01FF for rule in rules):
        raise ScopeError('Owner full control missing')
    if Path(path).is_dir() and not metadata['protected']:
        raise ScopeError('Private directory inheritance is not protected')
    return {'acl_verified': True, 'path': str(Path(path).absolute()), 'owner_sid': sid, 'rule_count': len(rules)}


def ensure_private_directory(path: Path) -> dict:
    path = Path(path).absolute()
    _no_reparse(path.parent)
    if not path.exists():
        path.mkdir()
        _acl_metadata(path, initialize=True)
    if not path.is_dir():
        raise ScopeError('Private path is not a directory')
    return verify_private_acl(path)


SDK = 'golang:1.27.1-bookworm@sha256:8d48e12ec56735e9358640898b9d9b9fcca110612ed8a5567438c0a1baa24e66'
PG = 'postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'
MANIFEST = ROOT / '.local/resources.json'
EVIDENCE = ROOT / 'docs/campaign/evidence/r1'


def _owner() -> dict:
    _no_reparse(ROOT)
    owner = json.loads((ROOT / '.candidate-owner.json').read_text(encoding='utf-8'))
    if owner['candidate_root'] != ROOT.as_posix() or owner['source_root'] != 'D:/osee-testops-lite' or owner['writer_limit'] != 1 or not owner['no_live_actions']:
        raise ScopeError('Candidate approval/ownership mismatch')
    for relative, field in [('docs/superpowers/specs/2026-10-09-secure-operator-candidate-design.md', 'approved_spec_sha256'),
                            ('docs/superpowers/plans/2026-10-09-secure-operator-candidate.md', 'approved_plan_sha256')]:
        if hashlib.sha256((Path(owner['source_root']) / relative).read_bytes()).hexdigest() != owner[field]:
            raise ScopeError('Approved document changed')
    return owner


def _verify_frozen_baseline(owner: dict) -> dict:
    manifest = ROOT / 'docs/campaign/evidence/r1/t01-source-import.json'
    authorization = ROOT / '.local/frozen-continuation.json'
    baseline = ROOT / '.local/frozen-baseline'
    for path in [manifest, authorization, baseline]:
        _no_reparse(path)
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    approved = json.loads(authorization.read_text(encoding='utf-8'))
    if any(approved.get(field) != owner[field] for field in ['scope_id', 'candidate_root', 'source_root']):
        raise ScopeError('Frozen continuation ownership mismatch')
    if (approved.get('decision') != 'Continue from the frozen candidate; leave the parent untouched'
            or approved.get('origin') != 'owner-clarify' or approved.get('allow_parent_drift') is not True
            or approved.get('import_parent_changes') is not False or approved.get('baseline_manifest_sha256') != digest):
        raise ScopeError('Frozen continuation authorization mismatch')
    imported = json.loads(manifest.read_text(encoding='utf-8'))
    if imported.get('scope_id') != owner['scope_id'] or imported.get('copied_count') != 114 or len(imported['source_hashes']) != 114:
        raise ScopeError('Frozen snapshot identity/count mismatch')
    seen = set()
    for row in imported['source_hashes']:
        relative = _source_relative(row['path'])
        if relative.as_posix().casefold() in seen:
            raise ScopeError('Duplicate frozen source path')
        seen.add(relative.as_posix().casefold())
        path = baseline / relative
        _no_reparse(path)
        content = path.read_bytes()
        if len(content) != row['bytes'] or hashlib.sha256(content).hexdigest() != row['sha256']:
            raise ScopeError('Frozen baseline changed; never repair or refreeze')
    actual_paths = set()
    for path in baseline.rglob('*'):
        _no_reparse(path)
        if path.is_file():
            actual_paths.add(path.relative_to(baseline).as_posix().casefold())
    if actual_paths != seen:
        raise ScopeError('Unexpected frozen source content')
    return {'snapshot_verified': True, 'paths_verified': len(seen), 'baseline_manifest_sha256': digest}


def inventory() -> dict:
    owner = _owner()
    frozen = _verify_frozen_baseline(owner)
    imported = json.loads((EVIDENCE / 't01-source-import.json').read_text(encoding='utf-8'))
    if imported['scope_id'] != owner['scope_id'] or imported['copied_count'] != 114:
        raise ScopeError('Candidate imported baseline mismatch')
    drift, changed = [], []
    for row in imported['source_hashes']:
        original, candidate = Path(owner['source_root']) / row['path'], ROOT / row['path']
        _no_reparse(original)
        _no_reparse(candidate)
        if hashlib.sha256(original.read_bytes()).hexdigest() != row['sha256']:
            drift.append(row['path'])
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != row['sha256']:
            changed.append(row['path'])
    return {'scope_id': owner['scope_id'], 'candidate_root': str(ROOT), 'source_import_count': imported['copied_count'],
            'source_drift': drift, 'candidate_modified_base_paths': changed, 'resources_recorded': MANIFEST.exists(),
            'live_actions': False, 'writer_limit': 1, **frozen}


def _save_metadata(path: Path, content: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.next')
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(content, stream, indent=2)
    temporary.replace(path)


def _load_manifest() -> dict:
    owner = _owner()
    _verify_frozen_baseline(owner)
    if not MANIFEST.is_file():
        raise ScopeError('Candidate resources not provisioned')
    result = json.loads(MANIFEST.read_text(encoding='utf-8'))
    if result.get('scope_id') != owner['scope_id'] or result.get('candidate_root') != ROOT.as_posix():
        raise ScopeError('Resource manifest ownership mismatch')
    return result


def _namespace_absent(docker: DockerClient, name: str) -> None:
    for args in [['container', 'ls', '-a', '--format', '{{.Names}}'], ['network', 'ls', '--format', '{{.Name}}'],
                 ['volume', 'ls', '--format', '{{.Name}}']]:
        existing = docker.call(args).stdout.splitlines()
        if any(value == name or value.startswith(name + '-') for value in existing):
            raise ScopeError('Candidate Docker namespace collision; no adoption or cleanup')


def _private_file(directory: Path, name: str, content: bytes) -> None:
    verify_private_acl(directory)
    target = directory / name
    with target.open('x+b') as stream:
        verify_private_acl(target)
        stream.write(content)
    verify_private_acl(target)


def _prepare_private_files() -> Path:
    import secrets
    from urllib.parse import quote
    private = ROOT / '.local/private'
    ensure_private_directory(private)
    password = secrets.token_urlsafe(32)
    _private_file(private, 'postgres-password', password.encode())
    _private_file(private, 'staff-master.key', secrets.token_bytes(32))
    dev = 'postgresql://candidate:' + quote(password, safe='') + '@osee-testops-db:5432/osee_testops_dev?sslmode=disable'
    test = 'postgresql://candidate:' + quote(password, safe='') + '@osee-testops-db:5432/osee_testops_test?sslmode=disable'
    app = ('APP_ENV=development\nDATABASE_IDENTITY=osee_testops_dev\nPRODUCTION_DATABASE_IDENTITY=production_forbidden\n'
           'OUTBOUND_MODE=off\nSIMULATOR=labelled\nRECIPIENT_MODE=test\nAUTH_ORIGIN=http://127.0.0.1:8091\n'
           'LISTEN_ADDRESS=0.0.0.0:8080\nDEMO_ENABLED=false\nDATABASE_URL=' + dev + '\n')
    sdk = ('GOFLAGS=-buildvcs=false\nGOTOOLCHAIN=local\nGOPROXY=off\nGOSUMDB=off\n'
           'GOMODCACHE=/modules\nGOCACHE=/tmp/candidate-go-cache\nOSEE_TEST_DATABASE_URL=' + test + '\n')
    _private_file(private, 'app.env', app.replace('\\n', '\n').encode())
    _private_file(private, 'sdk.env', sdk.replace('\\n', '\n').encode())
    return private


def provision(dry_run: bool = False) -> dict:
    import uuid
    owner = _owner()
    observed = inventory()
    if observed['snapshot_verified'] is not True:
        raise ScopeError('Frozen candidate snapshot is not verified')
    docker, name = DockerClient(), 'osee-r1-' + owner['scope_id'][:12]
    if MANIFEST.exists():
        manifest = _load_manifest()
        verify_owned(manifest, 'db')
        if manifest['phase'] != 'ready' and not dry_run:
            return _finish_database_provision(manifest, resumed=True)
        return {'applied': False, 'already_provisioned': manifest['phase'] == 'ready', 'scope_id': owner['scope_id'], 'internal_network': True, 'database_host_ports': []}
    _namespace_absent(docker, name)
    images = {'sdk': docker.inspect('image', SDK)['Id'], 'postgres': docker.inspect('image', PG)['Id']}
    plan = {'applied': False, 'scope_id': owner['scope_id'], 'network_name': name, 'internal_network': True,
            'database_host_ports': [], 'pinned_image_ids': images, 'source_import_count': 114}
    if dry_run:
        return plan
    private = _prepare_private_files()
    manifest = {'scope_id': owner['scope_id'], 'candidate_root': ROOT.as_posix(), 'private_root': private.as_posix(),
                'logical_instance_id': str(uuid.uuid4()), 'network': {'name': name}, 'volume': {'name': name + '-pg'},
                'resources': {}, 'images': images, 'phase': 'prepared'}
    _save_metadata(MANIFEST, manifest)
    manifest['network']['id'] = docker.call(['network', 'create', '--internal', '--label', SCOPE_LABEL + '=' + owner['scope_id'], name]).stdout.strip()
    network = docker.inspect('network', manifest['network']['id'])
    if not network['Internal'] or network['Name'] != name or (network.get('Labels') or {}).get(SCOPE_LABEL) != owner['scope_id']:
        raise ScopeError('New network readback failed')
    _save_metadata(MANIFEST, manifest)
    docker.call(['volume', 'create', '--label', SCOPE_LABEL + '=' + owner['scope_id'], manifest['volume']['name']])
    volume = docker.inspect('volume', manifest['volume']['name'])
    if (volume.get('Labels') or {}).get(SCOPE_LABEL) != owner['scope_id']:
        raise ScopeError('New volume readback failed')
    manifest['volume']['created_at'] = volume['CreatedAt']
    _save_metadata(MANIFEST, manifest)
    args = ['container', 'create', '--pull=never', '--name', name + '-db', '--label', SCOPE_LABEL + '=' + owner['scope_id'],
            '--label', ROLE_LABEL + '=db', '--network', name, '--network-alias', 'osee-testops-db', '--read-only',
            '--restart', 'unless-stopped', '--mount', 'type=volume,source=' + manifest['volume']['name'] + ',target=/var/lib/postgresql/data',
            '--mount', 'type=bind,source=' + (private / 'postgres-password').as_posix() + ',target=/run/secrets/postgres-password,readonly',
            '--tmpfs', '/var/run/postgresql:rw,nosuid,size=16m', '--tmpfs', '/tmp:rw,nosuid,size=16m',
            '--env', 'POSTGRES_USER=candidate', '--env', 'POSTGRES_DB=osee_testops_dev',
            '--env', 'POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password',
            '--health-cmd', 'pg_isready -U candidate -d osee_testops_dev', '--health-interval', '3s', '--health-timeout', '2s', '--health-retries', '10', PG]
    identifier = docker.call(args).stdout.strip()
    manifest['resources']['db'] = {'id': identifier, 'name': name + '-db', 'image_id': images['postgres']}
    _save_metadata(MANIFEST, manifest)
    return _finish_database_provision(manifest, resumed=False)


def _finish_database_provision(manifest: dict, resumed: bool) -> dict:
    docker, identifier = DockerClient(), manifest['resources']['db']['id']
    actual = verify_owned(manifest, 'db')
    if actual['State']['Status'] == 'created':
        docker.call(['container', 'start', identifier])
    elif not actual['State']['Running']:
        raise ScopeError('Prepared DB was stopped; preserving manual stop')
    _wait_database(manifest)
    verify_owned(manifest, 'db')
    query = "select count(*) from pg_database where datname='osee_testops_test'"
    exists = int(docker.call(['container', 'exec', identifier, 'psql', '-U', 'candidate', '-d', 'postgres', '-At', '-c', query]).stdout)
    if exists == 0:
        verify_owned(manifest, 'db')
        docker.call(['container', 'exec', identifier, 'createdb', '-U', 'candidate', 'osee_testops_test'])
    result = _database_census(manifest)
    if result['databases'] != ['osee_testops_dev', 'osee_testops_test'] or result['dev_public_tables'] != 0 or result['test_public_tables'] != 0:
        raise ScopeError('Fresh candidate database census failed')
    manifest['phase'] = 'ready'
    _save_metadata(MANIFEST, manifest)
    verify_owned(_load_manifest(), 'db')
    return {'applied': True, 'resumed_exact_owned_resources': resumed, 'scope_id': manifest['scope_id'],
            'network_id': manifest['network']['id'], 'database_id': identifier, 'volume_name': manifest['volume']['name'],
            'internal_network': True, 'database_host_ports': [], 'private_acl_verified': True, 'census': result}


def _wait_database(manifest: dict) -> None:
    import time
    docker, deadline = DockerClient(), time.monotonic() + 40
    while True:
        actual = verify_owned(manifest, 'db')
        if actual['State'].get('Health', {}).get('Status') == 'healthy':
            return
        if not actual['State']['Running'] or time.monotonic() > deadline:
            raise ScopeError('Candidate database readiness deadline/failure')
        time.sleep(0.4)


def _database_census(manifest: dict) -> dict:
    docker, identifier = DockerClient(), manifest['resources']['db']['id']
    verify_owned(manifest, 'db')
    query = "select json_agg(datname order by datname) from pg_database where datname in ('osee_testops_dev','osee_testops_test')"
    names = json.loads(docker.call(['container', 'exec', identifier, 'psql', '-U', 'candidate', '-d', 'postgres', '-At', '-c', query]).stdout)
    result = {'databases': names}
    for kind in ['dev', 'test']:
        query = "select count(*) from information_schema.tables where table_schema='public' and table_type='BASE TABLE'"
        result[kind + '_public_tables'] = int(docker.call(['container', 'exec', identifier, 'psql', '-U', 'candidate', '-d', 'osee_testops_' + kind, '-At', '-c', query]).stdout)
    return result


def _test_events(output: str) -> dict:
    counts, packages, failures, skips = {}, {}, [], []
    section = 'test'
    for line in output.splitlines():
        if line.startswith('CHECK='):
            section = line.split('=', 1)[1]
        if not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        action = event.get('Action')
        if action not in {'pass', 'fail', 'skip'}:
            continue
        target = counts if event.get('Test') else packages
        target.setdefault(section, {'pass': 0, 'fail': 0, 'skip': 0})[action] += 1
        if event.get('Test') and action in {'fail', 'skip'}:
            (failures if action == 'fail' else skips).append({'section': section, 'package': event.get('Package'), 'test': event['Test']})
    return {'counts': counts, 'package_counts': packages, 'failed_tests': failures, 'skipped_tests': skips}


def _module_cache(manifest: dict) -> Path:
    owned, marker = ROOT / '.local/public-modules', ROOT / '.local/public-modules.json'
    _no_reparse(ROOT / '.local')
    if owned.exists() or marker.exists():
        _no_reparse(owned)
        _no_reparse(marker)
        if not owned.is_dir() or not marker.is_file():
            raise ScopeError('Unbound candidate public module cache')
        try:
            metadata = json.loads(marker.read_text(encoding='utf-8'))
        except (ValueError, OSError) as error:
            raise ScopeError('Invalid public-cache metadata') from error
        if not isinstance(metadata, dict):
            raise ScopeError('Public-cache metadata is not an object')
        expected = {'scope_id': manifest['scope_id'], 'candidate_root': ROOT.as_posix(),
                    'cache_root': owned.as_posix(), 'dependency_step': 'R1-T02',
                    'goproxy': 'https://proxy.golang.org', 'gosumdb': 'sum.golang.org'}
        if (any(metadata.get(key) != value for key, value in expected.items())
                or metadata.get('private_mounts') is not False or metadata.get('verified') is not True):
            raise ScopeError('Public module-cache scope or completion mismatch')
        return owned
    legacy = Path(_owner()['source_root']) / '.local/gopath/pkg/mod'
    _no_reparse(legacy)
    if not legacy.is_dir():
        raise ScopeError('Public module cache unavailable')
    return legacy


def run_go(package: str, pattern: str | None, race: bool, all_checks: bool = False) -> dict:
    import shlex
    if not re.fullmatch(r'\./[A-Za-z0-9_./-]+', package) or '..' in package.replace('...', ''):
        raise ScopeError('Unsafe Go package selector')
    manifest, docker = _load_manifest(), DockerClient()
    verify_owned(manifest, 'db')
    private = Path(manifest['private_root'])
    verify_private_acl(private / 'sdk.env')
    module_cache = _module_cache(manifest)
    name = manifest['network']['name'] + '-go'
    existing = docker.call(['container', 'ls', '-a', '--format', '{{.Names}}']).stdout.splitlines()
    if name in existing or 'go' in manifest['resources']:
        raise ScopeError('Candidate SDK collision; no adoption')
    deadline = '240s' if race else ('180s' if package == './...' and pattern is None else '120s')
    test = 'go test ' + ('-race ' if race else '') + '-json ' + shlex.quote(package) + ' -count=1 -timeout=' + deadline + ' -p=1'
    if pattern is not None:
        test += ' -run ' + shlex.quote(pattern)
    script = 'set -eu; printf "CHECK=test\\n"; ' + test
    if all_checks:
        script = ('set -eu; printf "CHECK=normal\\n"; go test -json ./... -count=1 -timeout=180s -p=1; '
                  'printf "CHECK=race\\n"; go test -race -json ./... -count=1 -timeout=240s -p=1; '
                  'printf "CHECK=vet\\n"; go vet ./...; printf "CHECK=build\\n"; go build ./cmd/...; '
                  'printf "CHECK=format\\n"; test -z "$(gofmt -l cmd internal db)"; '
                  'printf "CHECK=modules\\n"; go mod verify; printf "ALL_CANDIDATE_GO_CHECKS_PASSED\\n"')
    args = ['container', 'create', '--pull=never', '--name', name, '--label', SCOPE_LABEL + '=' + manifest['scope_id'],
            '--label', ROLE_LABEL + '=go', '--network', manifest['network']['name'], '--read-only',
            '--tmpfs', '/tmp:rw,exec,nosuid,size=1536m', '--env-file', str(private / 'sdk.env'), '-w', '/src']
    for relative in ['cmd', 'internal', 'db', 'go.mod', 'go.sum']:
        path = ROOT / relative
        _no_reparse(path)
        args += ['--mount', 'type=bind,source=' + path.as_posix() + ',target=/src/' + relative + ',readonly']
    args += ['--mount', 'type=bind,source=' + module_cache.as_posix() + ',target=/modules,readonly', SDK, 'sh', '-ec', script]
    identifier = docker.call(args).stdout.strip()
    manifest['resources']['go'] = {'id': identifier, 'name': name, 'image_id': manifest['images']['sdk']}
    _save_metadata(MANIFEST, manifest)
    actual = verify_owned(manifest, 'go')
    expected_targets = {'/src/' + part for part in ['cmd', 'internal', 'db', 'go.mod', 'go.sum']} | {'/modules'}
    if {mount['Destination'] for mount in actual['Mounts'] if mount['Type'] == 'bind'} != expected_targets or any(mount['RW'] for mount in actual['Mounts'] if mount['Type'] == 'bind'):
        raise ScopeError('SDK source confidentiality/write isolation mismatch')
    result = _execute_sdk(manifest, identifier, all_checks)
    if result['exit_code'] != 0 or (all_checks and not result['full_marker']):
        raise ScopeError('Candidate Go verification failed; see saved redacted evidence')
    return result


def _execute_sdk(manifest: dict, identifier: str, all_checks: bool) -> dict:
    import datetime
    docker, output, exit_code, cleanup = DockerClient(), '', None, False
    try:
        verify_owned(manifest, 'go')
        result = subprocess.run(DOCKER + ['container', 'start', '-a', identifier],
                                capture_output=True, text=True, timeout=420)
        output = result.stdout + result.stderr
        state = verify_owned(manifest, 'go')['State']
        exit_code = state['ExitCode'] if state['Status'] == 'exited' else 1
        if result.returncode != 0 and exit_code == 0:
            exit_code = 1
    except subprocess.TimeoutExpired:
        output = 'Candidate SDK deadline exceeded; not a PASS.'
    finally:
        verify_owned(manifest, 'go')
        docker.call(['container', 'rm', '-f', identifier])
        current = _load_manifest()
        if current['resources'].get('go', {}).get('id') != identifier:
            raise ScopeError('SDK cleanup manifest changed')
        del current['resources']['go']
        _save_metadata(MANIFEST, current)
        remaining = docker.call(['container', 'ls', '-a', '--no-trunc', '--format', '{{.ID}}']).stdout.splitlines()
        cleanup = identifier not in remaining
    password = (Path(manifest['private_root']) / 'postgres-password').read_text(encoding='utf-8')
    output = output.replace(password, '[REDACTED]')
    output = re.sub(r'postgres(?:ql)?://[^\s"\x27]+', '[REDACTED_DSN]', output)
    report = dict(_test_events(output), utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), exit_code=exit_code,
                  scope_id=manifest['scope_id'], full_marker='ALL_CANDIDATE_GO_CHECKS_PASSED' in output,
                  exact_sdk_removed=cleanup, original_network_used=False, source_mounts_readonly=True,
                  module_cache_mount='PUBLIC_MODULE_CACHE_READONLY', all_checks=all_checks)
    suffix = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    log = EVIDENCE / ('go-' + suffix + '.log')
    with log.open('x', encoding='utf-8') as stream:
        stream.write(output)
    metadata = log.with_suffix('.json')
    _save_metadata(metadata, report)
    return dict(report, log=str(log), evidence=str(metadata))


def prepare_build_context(target: Path) -> dict:
    target = Path(target).absolute()
    _no_reparse(ROOT)
    _no_reparse(target.parent)
    if target.exists():
        raise ScopeError('Build context collision; no overwrite')
    files = [ROOT / name for name in ['go.mod', 'go.sum', 'deploy/Dockerfile', '.dockerignore']]
    for part in ['cmd', 'internal', 'db']:
        directory = ROOT / part
        _no_reparse(directory)
        for path in directory.rglob('*'):
            _no_reparse(path)
            if path.is_file():
                relative = path.relative_to(ROOT).as_posix()
                _source_relative(relative)
                if path.suffix not in {'.go', '.sql', '.html', '.css', '.js', '.svg', '.txt', '.md'}:
                    raise ScopeError('Unexpected build-source file type')
                files.append(path)
    checked = []
    for path in sorted(files):
        _no_reparse(path)
        content = path.read_bytes()
        if len(content) > MAX_SOURCE_BYTES:
            raise ScopeError('Build source too large')
        checked.append((path.relative_to(ROOT), content))
    target.mkdir()
    rows = []
    for relative, content in checked:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(content)
        if destination.read_bytes() != content:
            raise ScopeError('Build context byte verification failed')
        rows.append({'path': relative.as_posix(), 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
    return {'source_hashes': rows, 'source_count': len(rows),
            'source_sha256': hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()}


def operations() -> dict:
    import datetime
    manifest = _load_manifest()
    resources = {}
    for role in sorted(manifest['resources']):
        actual = verify_owned(manifest, role)
        resources[role] = {'id': actual['Id'], 'running': actual['State']['Running'],
                           'status': actual['State']['Status'], 'health': actual['State'].get('Health', {}).get('Status'),
                           'started_at': actual['State']['StartedAt'],
                           'health_semantics': ('proxied_application_readiness' if role == 'gateway' else
                                                'process_liveness' if role in {'web','worker'} else 'database_readiness' if role == 'db' else 'not_classified')}
    return {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'scope_id': manifest['scope_id'],
            'resources': resources, 'internal_network': True, 'database_host_ports': [],
            'worker_heartbeat': None, 'checked_backup': None, 'application_observations': 'NOT_IMPLEMENTED_UNTIL_R1_T08'}


def build_candidate() -> dict:
    import uuid
    manifest, docker = _load_manifest(), DockerClient()
    verify_owned(manifest, 'db')
    modules = _module_cache(manifest)
    target = ROOT / '.local' / ('build-context-' + uuid.uuid4().hex)
    source = prepare_build_context(target)
    identifier = target / 'image-id'
    args = ['build', '--network=none', '--progress=plain', '--build-context', 'public_modules=' + modules.as_posix(),
            '--label', SCOPE_LABEL + '=' + manifest['scope_id'], '--label', ROLE_LABEL + '=image',
            '--label', 'osee.testops.source=' + source['source_sha256'], '--iidfile', str(identifier),
            '-f', str(target / 'deploy/Dockerfile'), str(target)]
    result = subprocess.run(DOCKER + args, capture_output=True, text=True, timeout=520)
    with (target / 'build.log').open('x', encoding='utf-8') as stream:
        stream.write(result.stdout + result.stderr)
    if result.returncode != 0 or not identifier.is_file():
        raise ScopeError('Candidate build failed; public-only build log retained')
    image_id = identifier.read_text().strip()
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise ScopeError('Invalid built image identity')
    image = docker.inspect('image', image_id)
    labels = image['Config'].get('Labels') or {}
    if (image['Id'] != image_id or image['Config']['User'] != '65532:65532'
            or labels.get(SCOPE_LABEL) != manifest['scope_id'] or labels.get(ROLE_LABEL) != 'image'
            or labels.get('osee.testops.source') != source['source_sha256']):
        raise ScopeError('Candidate image readback mismatch')
    manifest['images']['candidate'] = image_id
    manifest['build'] = dict(source, context_path=target.as_posix(), image_id=image_id)
    _save_metadata(MANIFEST, manifest)
    if docker.inspect('image', _load_manifest()['images']['candidate'])['Id'] != image_id:
        raise ScopeError('Built image manifest readback failed')
    return {'image_id': image_id, 'source_sha256': source['source_sha256'], 'source_count': source['source_count'],
            'public_context_verified': True, 'context_path': target.as_posix(), 'application_deployed': False}


def _application_environment(manifest: dict, profile: str) -> Path:
    from urllib.parse import urlsplit
    private = Path(manifest['private_root'])
    for name in ['app.env', 'sdk.env', 'staff-master.key']:
        verify_private_acl(private / name)
    app = dict(line.split('=', 1) for line in (private / 'app.env').read_text().splitlines() if '=' in line)
    app['CANDIDATE_PROFILE'] = profile
    app['STAFF_KEY_FILE'] = '/run/secrets/staff-master.key'
    app['CANDIDATE_INSTANCE_ID'] = manifest['logical_instance_id']
    if profile == 'fixture':
        sdk = dict(line.split('=', 1) for line in (private / 'sdk.env').read_text().splitlines() if '=' in line)
        app['DATABASE_URL'] = sdk['OSEE_TEST_DATABASE_URL']
        app['DATABASE_IDENTITY'] = 'osee_testops_test'
    expected = {'APP_ENV':'development','OUTBOUND_MODE':'off','DEMO_ENABLED':'false',
                'AUTH_ORIGIN':'http://127.0.0.1:8091','LISTEN_ADDRESS':'0.0.0.0:8080',
                'DATABASE_IDENTITY':'osee_testops_test' if profile == 'fixture' else 'osee_testops_dev'}
    if any(app.get(key) != value for key, value in expected.items()):
        raise ScopeError('Candidate application environment mismatch')
    url = urlsplit(app['DATABASE_URL'])
    if url.hostname != 'osee-testops-db' or url.port != 5432 or url.path != '/' + expected['DATABASE_IDENTITY']:
        raise ScopeError('Candidate application database mismatch')
    content = ''.join(key + '=' + value + '\n' for key, value in sorted(app.items())).encode()
    path = private / (profile + '.env')
    if path.exists():
        verify_private_acl(path)
        if path.read_bytes() != content:
            raise ScopeError('Private profile configuration changed; no overwrite')
    else:
        _private_file(private, profile + '.env', content)
    return path


def _profile_gate(manifest: dict, profile: str) -> None:
    if profile not in {'fixture', 'local'}:
        raise ScopeError('Unknown candidate profile')
    if profile == 'local':
        gate = ROOT / '.local/local-release-approved.json'
        _no_reparse(gate)
        approved = json.loads(gate.read_text())
        if (approved.get('scope_id') != manifest['scope_id'] or approved.get('qualified') is not True
                or approved.get('image_id') != manifest['images'].get('candidate')
                or approved.get('source_sha256') != manifest.get('build', {}).get('source_sha256')):
            raise ScopeError('Local release qualification is not established')


def _compose_command(manifest: dict, profile: str, env_file: Path) -> tuple:
    _ingress_gate(manifest)
    verify_private_acl(env_file)
    env = os.environ.copy()
    env.update({'OSEE_CANDIDATE_SCOPE':manifest['scope_id'], 'OSEE_CANDIDATE_NETWORK':manifest['network']['name'],
                'OSEE_CANDIDATE_IMAGE':manifest['images']['candidate'], 'OSEE_CANDIDATE_PROFILE':profile,
                'OSEE_CANDIDATE_ENV':env_file.as_posix(), 'OSEE_CANDIDATE_CADDY_IMAGE':manifest['images']['caddy'],
                'OSEE_CANDIDATE_FRONTEND':manifest['network']['name']+'-frontend',
                'OSEE_CANDIDATE_KEY':(Path(manifest['private_root']) / 'staff-master.key').as_posix()})
    args = DOCKER + ['compose', '-p', manifest['network']['name'], '-f', str(ROOT / 'deploy/compose.candidate.yaml'), '--profile', profile]
    result = subprocess.run(args + ['config', '--format', 'json'], env=env, capture_output=True, text=True, timeout=25)
    if result.returncode:
        raise ScopeError('Candidate Compose configuration failed')
    config = json.loads(result.stdout)
    if set(config['services']) != {'web', 'worker', 'gateway'} or set(config['networks']) != {'candidate', 'frontend'}:
        raise ScopeError('Unexpected Compose services/networks')
    for key, name in [('candidate',manifest['network']['name']),('frontend',env['OSEE_CANDIDATE_FRONTEND'])]:
        network = config['networks'][key]
        if network['name'] != name or network.get('external') is not True:
            raise ScopeError('Compose would create/adopt another network')
    private_env = dict(line.split('=',1) for line in env_file.read_text().splitlines() if '=' in line)
    for role, service in config['services'].items():
        gateway = role == 'gateway'
        labels = service['labels']
        expected_networks = {'candidate','frontend'} if gateway else {'candidate'}
        expected_image = manifest['images']['caddy' if gateway else 'candidate']
        entrypoint = CADDY_ENTRYPOINT if gateway else ['/app/'+role]
        if (service['image'] != expected_image or service['container_name'] != manifest['network']['name'] + '-' + role
                or labels.get(SCOPE_LABEL) != manifest['scope_id'] or labels.get(ROLE_LABEL) != role
                or labels.get('osee.testops.profile') != profile or set(service['networks']) != expected_networks
                or service['user'] != '65532:65532' or service.get('read_only') is not True
                or set(service['cap_drop']) != {'ALL'} or service.get('cap_add')
                or 'no-new-privileges:true' not in service['security_opt']
                or service.get('privileged') is True or service['entrypoint'] != entrypoint
                or service.get('command') or service.get('devices') or service.get('pid') or service.get('ipc')):
            raise ScopeError('Compose service isolation mismatch')
        ports = service.get('ports', [])
        if not gateway and ports:
            raise ScopeError('Internal application publication forbidden')
        if gateway and (len(ports) != 1 or ports[0]['host_ip'] != '127.0.0.1'
                        or str(ports[0]['published']) != '8091' or ports[0]['target'] != 8080):
            raise ScopeError('Non-loopback gateway publication refused')
        if (service.get('environment') or {}) != ({} if gateway else private_env):
            raise ScopeError('Compose environment override/credential disclosure refused')
        mounts = service.get('volumes', [])
        if role != 'web' and mounts:
            raise ScopeError('Worker/gateway mounts refused')
        if role == 'web' and (len(mounts) != 1 or mounts[0]['type'] != 'bind' or mounts[0]['read_only'] is not True
                              or mounts[0]['source'].replace('\\','/').casefold() != env['OSEE_CANDIDATE_KEY'].casefold()
                              or mounts[0]['target'] != '/run/secrets/staff-master.key'):
            raise ScopeError('Unexpected candidate web mounts')
    return args, env


def _migrate_candidate(manifest: dict, env_file: Path, profile: str) -> None:
    docker, role = DockerClient(), 'migrate'
    name = manifest['network']['name'] + '-' + role
    _namespace_absent(docker, name)
    verify_owned(manifest, 'db')
    identifier = docker.call(['container', 'create', '--pull=never', '--name', name,
                             '--label', SCOPE_LABEL+'='+manifest['scope_id'], '--label', ROLE_LABEL+'='+role,
                             '--network', manifest['network']['name'], '--read-only', '--user', '65532:65532',
                             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--env-file', str(env_file),
                             '--entrypoint', '/app/migrate', manifest['images']['candidate']]).stdout.strip()
    manifest['resources'][role] = {'id':identifier, 'name':name, 'image_id':manifest['images']['candidate'], 'profile':profile}
    _save_metadata(MANIFEST, manifest)
    try:
        verify_owned(manifest, role)
        result = subprocess.run(DOCKER + ['container','start','-a',identifier], capture_output=True, text=True, timeout=60)
        state = verify_owned(manifest, role)['State']
        if result.returncode or state['Status'] != 'exited' or state['ExitCode'] != 0:
            raise ScopeError('Candidate migration failed')
    finally:
        verify_owned(manifest, role)
        docker.call(['container','rm','-f',identifier])
        del manifest['resources'][role]
        _save_metadata(MANIFEST, manifest)
        if identifier in docker.call(['container','ls','-a','--no-trunc','--format','{{.ID}}']).stdout.splitlines():
            raise ScopeError('Migration cleanup not verified')


def _wait_candidate_ready(manifest: dict) -> None:
    import time
    from urllib.request import build_opener, ProxyHandler
    from urllib.error import URLError
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        for role in ['web', 'worker', 'gateway']:
            if not verify_owned(manifest, role)['State']['Running']:
                raise ScopeError('Candidate service exited during readiness')
        try:
            ports = verify_owned(manifest, 'gateway')['NetworkSettings'].get('Ports') or {}
            if {key:value for key,value in ports.items() if value} != GATEWAY_PORTS:
                raise ScopeError('Configured gateway port was not actually published')
            with build_opener(ProxyHandler({})).open('http://127.0.0.1:8091/health/ready', timeout=3) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError):
            time.sleep(0.4)
    raise ScopeError('Candidate readiness deadline exceeded')


def start_candidate(profile: str) -> dict:
    import socket
    manifest, docker = _load_manifest(), DockerClient()
    _profile_gate(manifest, profile)
    _ingress_gate(manifest)
    verify_owned(manifest, 'db')
    if not manifest['resources']['db'] or not verify_owned(manifest, 'db')['State']['Running']:
        raise ScopeError('Candidate DB was stopped; no implicit recovery')
    image = docker.inspect('image', manifest['images']['candidate'])
    if (image['Config']['Labels'].get(SCOPE_LABEL) != manifest['scope_id']
            or image['Config']['Labels'].get('osee.testops.source') != manifest['build']['source_sha256']):
        raise ScopeError('Candidate image ownership mismatch')
    if any(role in manifest['resources'] for role in ['web','worker','gateway','migrate']):
        raise ScopeError('Existing services/manual stops preserved; no recreation')
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1',8091))
        except OSError as error:
            raise ScopeError('Candidate publication port is occupied') from error
    for role in ['web','worker','gateway']:
        _namespace_absent(docker, manifest['network']['name']+'-'+role)
    env_file = _application_environment(manifest, profile)
    _ensure_caddy_image(manifest)
    args, env = _compose_command(manifest, profile, env_file)
    _ensure_frontend(manifest)
    _migrate_candidate(manifest, env_file, profile)
    result = subprocess.run(args + ['create','--no-build','--pull','never','web','worker','gateway'],
                            env=env, capture_output=True, text=True, timeout=40)
    if result.returncode:
        raise ScopeError('Candidate Compose create failed')
    for role in ['web','worker','gateway']:
        name = manifest['network']['name']+'-'+role
        actual = docker.inspect('container',name)
        manifest['resources'][role] = {'id':actual['Id'],'name':name,'image_id':manifest['images']['caddy' if role == 'gateway' else 'candidate'],'profile':profile}
        _save_metadata(MANIFEST, manifest)
        verify_owned(manifest, role)
    for role in ['worker','web','gateway']:
        verify_owned(manifest, role)
        docker.call(['container','start',manifest['resources'][role]['id']])
        verify_owned(manifest, role)
    _wait_candidate_ready(manifest)
    return {'scope_id':manifest['scope_id'], 'origin':'http://127.0.0.1:8091','profile':profile,
            'database_identity':'osee_testops_test' if profile == 'fixture' else 'osee_testops_dev',
            'readiness_checked':True,'staff_release_accepted':False}


def stop_fixture(profile: str) -> dict:
    if profile != 'fixture':
        raise ScopeError('Only exact fixture teardown authorized')
    manifest, docker = _load_manifest(), DockerClient()
    targets = [role for role in ['gateway','web','worker'] if role in manifest['resources']]
    for role in targets:
        if manifest['resources'][role].get('profile') != 'fixture':
            raise ScopeError('Foreign/non-fixture service teardown refused')
        verify_owned(manifest, role)
    removed = []
    for role in targets:
        identifier = manifest['resources'][role]['id']
        verify_owned(manifest, role)
        docker.call(['container','rm','-f',identifier])
        del manifest['resources'][role]
        _save_metadata(MANIFEST, manifest)
        if identifier in docker.call(['container','ls','-a','--no-trunc','--format','{{.ID}}']).stdout.splitlines():
            raise ScopeError('Fixture removal readback failed')
        removed.append(identifier)
    verify_owned(manifest, 'db')
    return {'removed_exact_ids':removed,'database_retained':True,'profile':'fixture'}


def checkpoint(task: str) -> dict:
    import datetime
    if not re.fullmatch(r'R1-T\d{2}', task):
        raise ScopeError('Invalid checkpoint task')
    manifest = _load_manifest()
    verify_owned(manifest, 'db')
    rows = []
    for part in ['cmd', 'internal', 'db', 'scripts', 'tests', 'deploy']:
        directory = ROOT / part
        if directory.exists():
            for path in sorted(directory.rglob('*')):
                if path.is_file() and '__pycache__' not in path.parts:
                    _no_reparse(path)
                    rows.append({'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    for name in ['go.mod', 'go.sum', '.candidate-owner.json']:
        path = ROOT / name
        rows.append({'path': name, 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    result = {'task': task, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'scope_id': manifest['scope_id'],
              'source_count': len(rows), 'source_hashes': rows, 'original_observation': inventory(), 'acceptance': False}
    target = EVIDENCE / (task + '-checkpoint.json')
    if target.exists():
        raise ScopeError('Checkpoint exists; preserve historical provenance')
    _save_metadata(target, result)
    return {'task': task, 'source_count': len(rows), 'path': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'acceptance': False}


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('inventory')
    commands.add_parser('ops')
    commands.add_parser('build')
    for name in ['up', 'down']:
        profile_parser = commands.add_parser(name)
        profile_parser.add_argument('--profile', required=True)
    bootstrap_parser = commands.add_parser('bootstrap')
    bootstrap_parser.add_argument('--profile', required=True)
    bootstrap_mode = bootstrap_parser.add_mutually_exclusive_group(required=True)
    bootstrap_mode.add_argument('--empty-only', action='store_true')
    bootstrap_mode.add_argument('--reset-empty', action='store_true')
    provision_parser = commands.add_parser('provision')
    provision_parser.add_argument('--dry-run', action='store_true')
    go_parser = commands.add_parser('go')
    go_parser.add_argument('--package', default='./...')
    go_parser.add_argument('--run')
    go_parser.add_argument('--race', action='store_true')
    go_parser.add_argument('--all', action='store_true')
    check_parser = commands.add_parser('checkpoint')
    check_parser.add_argument('--task', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'inventory': result = inventory()
        elif args.command == 'ops': result = operations()
        elif args.command == 'build': result = build_candidate()
        elif args.command == 'up': result = start_candidate(args.profile)
        elif args.command == 'down': result = stop_fixture(args.profile)
        elif args.command == 'bootstrap': result = bootstrap_candidate(args.profile, args.reset_empty)
        elif args.command == 'provision': result = provision(args.dry_run)
        elif args.command == 'go': result = run_go(args.package, args.run, args.race, args.all)
        else: result = checkpoint(args.task)
        print(json.dumps(result, indent=2))
        return 0
    except (ScopeError, subprocess.SubprocessError, OSError, ValueError, KeyError):
        print(json.dumps({'success': False, 'command': args.command, 'error': 'Candidate gate failed; no fallback or foreign-resource repair'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

