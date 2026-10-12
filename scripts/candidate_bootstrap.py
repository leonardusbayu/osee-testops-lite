"""Private candidate CLI boundary; never return authentication material."""
import base64
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import uuid

PRIVATE_TMPFS='rw,nosuid,noexec,size=1m,uid=65532,gid=65532,mode=0700'
CAPABILITY_PATH='/run/osee-private/setup-capability.txt'


def verify_bootstrap(control, manifest, actual, resource):
    host, config = actual['HostConfig'], actual['Config']
    profile=resource.get('profile')
    if (profile not in {'fixture','local'} or actual['Image']!=manifest['images']['candidate']
            or config.get('User')!='65532:65532' or config.get('Entrypoint')!=['/bin/sleep'] or config.get('Cmd')!=['60']
            or config.get('Labels',{}).get('osee.testops.profile')!=profile
            or host.get('ReadonlyRootfs') is not True or host.get('Privileged') is True
            or host.get('CapAdd') or set(host.get('CapDrop') or [])!={'ALL'}
            or set(host.get('SecurityOpt') or []) not in ({'no-new-privileges'},{'no-new-privileges:true'}) or host.get('PortBindings')):
        raise control.ScopeError('Bootstrap privilege/image/command mismatch')
    expected={'CANDIDATE_PROFILE':profile,'APP_ENV':'development','OUTBOUND_MODE':'off','DEMO_ENABLED':'false',
              'AUTH_ORIGIN':'http://127.0.0.1:8091','DATABASE_IDENTITY':'osee_testops_test' if profile=='fixture' else 'osee_testops_dev',
              'STAFF_KEY_FILE':'/run/secrets/staff-master.key','CANDIDATE_INSTANCE_ID':manifest['logical_instance_id']}
    env=dict(item.split('=',1) for item in config.get('Env') or [] if '=' in item)
    allowed=set(expected)|{'PATH','DATABASE_URL','PRODUCTION_DATABASE_IDENTITY','LISTEN_ADDRESS','SIMULATOR','RECIPIENT_MODE'}
    if any(env.get(k)!=v for k,v in expected.items()) or set(env)-allowed:
        raise control.ScopeError('Bootstrap environment mismatch')
    tmpfs=host.get('Tmpfs') or {}
    if set(tmpfs)!={'/run/osee-private'} or set(tmpfs['/run/osee-private'].split(','))!=set(PRIVATE_TMPFS.split(',')):
        raise control.ScopeError('Bootstrap private filesystem mismatch')
    binds=[]
    for mount in actual['Mounts']:
        if mount['Type']=='tmpfs' and mount['Destination']=='/run/osee-private':
            continue
        source=mount.get('Source','').replace('\\','/')
        for prefix in ['/run/desktop/mnt/host/','/host_mnt/']:
            if source.startswith(prefix) and len(source)>len(prefix)+2:
                source=source[len(prefix)].upper()+':/'+source[len(prefix)+2:]
        if (mount['Type']!='bind' or mount.get('RW') is not False or mount['Destination']!='/run/secrets/staff-master.key'
                or source.casefold()!=(manifest['private_root']+'/staff-master.key').casefold()):
            raise control.ScopeError('Bootstrap unexpected mount refused')
        binds.append(mount)
    if len(binds)!=1:
        raise control.ScopeError('Bootstrap private key mount absent')


def _create_helper(control, manifest, profile, env_file):
    docker=control.DockerClient()
    name=manifest['network']['name']+'-bootstrap'
    control._namespace_absent(docker,name)
    control.verify_owned(manifest,'db')
    key=Path(manifest['private_root'])/'staff-master.key'
    control.verify_private_acl(key)
    identifier=docker.call(['container','create','--pull=never','--name',name,
        '--label',control.SCOPE_LABEL+'='+manifest['scope_id'],'--label',control.ROLE_LABEL+'=bootstrap',
        '--label','osee.testops.profile='+profile,'--network',manifest['network']['name'],
        '--read-only','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--env-file',str(env_file),'--tmpfs','/run/osee-private:'+PRIVATE_TMPFS,
        '--mount','type=bind,source='+key.as_posix()+',target=/run/secrets/staff-master.key,readonly',
        '--entrypoint','/bin/sleep',manifest['images']['candidate'],'60']).stdout.strip()
    manifest['resources']['bootstrap']={'id':identifier,'name':name,'image_id':manifest['images']['candidate'],'profile':profile}
    control._save_metadata(control.MANIFEST,manifest)
    control.verify_owned(manifest,'bootstrap')
    docker.call(['container','start',identifier])
    if not control.verify_owned(manifest,'bootstrap')['State']['Running']:
        raise control.ScopeError('Bounded bootstrap helper unavailable')
    return identifier


def _read_capability(control, manifest):
    identifier=manifest['resources']['bootstrap']['id']
    control.verify_owned(manifest,'bootstrap')
    result=subprocess.run(control.DOCKER+['container','exec',identifier,'/bin/tar','-C','/run/osee-private',
                          '-cf','-','--','setup-capability.txt'],capture_output=True,timeout=15)
    if result.returncode or len(result.stdout)>16384:
        raise control.ScopeError('Private capability copy failed')
    with tarfile.open(fileobj=io.BytesIO(result.stdout),mode='r:') as archive:
        items=archive.getmembers()
        if len(items)!=1 or items[0].name!='setup-capability.txt' or not items[0].isfile() or items[0].size!=43 or items[0].mode!=0o600 or items[0].uid!=65532:
            raise control.ScopeError('Private capability archive invalid')
        stream=archive.extractfile(items[0])
        if stream is None:
            raise control.ScopeError('Private capability missing')
        with stream: content=stream.read(44)
    try:
        decoded=base64.b64decode(content+b'='*((-len(content))%4),altchars=b'-_',validate=True)
    except ValueError as error:
        raise control.ScopeError('Private capability encoding invalid') from error
    if len(content)!=43 or len(decoded)!=32 or base64.urlsafe_b64encode(decoded).rstrip(b'=')!=content:
        raise control.ScopeError('Private capability encoding invalid')
    return content


def _remove_helper(control, manifest):
    control.verify_owned(manifest,'bootstrap')
    identifier=manifest['resources']['bootstrap']['id']
    docker=control.DockerClient()
    docker.call(['container','rm','-f',identifier])
    current=control._load_manifest()
    if current['resources'].get('bootstrap',{}).get('id')!=identifier:
        raise control.ScopeError('Bootstrap cleanup ownership changed')
    del current['resources']['bootstrap']
    control._save_metadata(control.MANIFEST,current)
    if identifier in docker.call(['container','ls','-a','--no-trunc','--format','{{.ID}}']).stdout.splitlines():
        raise control.ScopeError('Bootstrap helper removal unverified')


def bootstrap(control, profile, reset=False):
    if profile not in {'fixture','local'} or type(reset) is not bool:
        raise control.ScopeError('Invalid bootstrap profile/reset')
    manifest=control._load_manifest()
    control._profile_gate(manifest,profile)
    if not control.verify_owned(manifest,'db')['State']['Running']:
        raise control.ScopeError('Stopped database preserved')
    if 'bootstrap' in manifest['resources']:
        raise control.ScopeError('Existing helper preserved; no adoption')
    image=control.DockerClient().inspect('image',manifest['images']['candidate'])
    if image['Config']['Labels'].get('osee.testops.source')!=manifest['build']['source_sha256']:
        raise control.ScopeError('Bootstrap image source mismatch')
    private=Path(manifest['private_root'])
    control.verify_private_acl(private)
    target=private/('fixture-setup-capability.txt' if profile=='fixture' else 'setup-capability.txt')
    if target.exists():
        control.verify_private_acl(target)
        if not reset:
            raise control.ScopeError('Private capability exists; no silent rotation')
    temporary=private/('.bootstrap-'+uuid.uuid4().hex)
    env_file=control._application_environment(manifest,profile)
    identifier=None
    try:
        with temporary.open('x+b') as stream:
            control.verify_private_acl(temporary)
            identifier=_create_helper(control,manifest,profile,env_file)
            control.verify_owned(manifest,'bootstrap')
            args=['container','exec',identifier,'/app/candidatectl','bootstrap',
                  '--reset-empty' if reset else '--empty-only','--capability-file',CAPABILITY_PATH]
            result=control.DockerClient().call(args,timeout=20)
            status=json.loads(result.stdout)
            if set(status)!={'status','expires_at'} or status['status']!='private_capability_written':
                raise control.ScopeError('Bootstrap CLI status invalid')
            content=_read_capability(control,manifest)
            stream.write(content);stream.flush();os.fsync(stream.fileno())
        control.verify_private_acl(temporary)
        if target.exists():
            control.verify_private_acl(target)
            if not reset: raise control.ScopeError('Concurrent private capability refused')
        temporary.replace(target)
        control.verify_private_acl(target)
        result={'scope_id':manifest['scope_id'],'profile':profile,'capability_file':target.as_posix(),
                'private_acl_verified':True,'reset_empty':reset,'expires_at':status['expires_at'],
                'helper_id':identifier,'genuine_owner_enrolled':False,'application_deployed':False}
    finally:
        if identifier is not None or 'bootstrap' in manifest['resources']: _remove_helper(control,manifest)
        if temporary.exists(): temporary.unlink()
    result['exact_helper_removed']=True
    suffix=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    control._save_metadata(control.EVIDENCE/('bootstrap-'+suffix+'.json'),result)
    return result
