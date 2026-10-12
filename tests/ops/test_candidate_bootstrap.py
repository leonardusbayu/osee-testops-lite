import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None: raise RuntimeError('Owned module loader unavailable')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
control=load('bootstrap_test_control',ROOT/'scripts/candidate-control.py')
bootstrap=load('candidate_bootstrap_tests',ROOT/'scripts/candidate_bootstrap.py')

class CandidateBootstrapTests(unittest.TestCase):
    def fixture(self):
        manifest={'scope_id':'a'*32,'images':{'candidate':'sha256:'+'b'*64},'logical_instance_id':'12345678-1234-4234-8234-123456789abc','private_root':'D:/synthetic-private'}
        resource={'profile':'fixture','image_id':manifest['images']['candidate']}
        actual={'Image':resource['image_id'],'Config':{'User':'65532:65532','Entrypoint':['/bin/sleep'],'Cmd':['60'],
                'Labels':{'osee.testops.profile':'fixture'},'Env':['CANDIDATE_PROFILE=fixture','APP_ENV=development','OUTBOUND_MODE=off','DEMO_ENABLED=false','AUTH_ORIGIN=http://127.0.0.1:8091','DATABASE_IDENTITY=osee_testops_test','STAFF_KEY_FILE=/run/secrets/staff-master.key','CANDIDATE_INSTANCE_ID='+manifest['logical_instance_id']]},
                'HostConfig':{'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges:true'],'PortBindings':{},'Tmpfs':{'/run/osee-private':'rw,nosuid,noexec,size=1m,uid=65532,gid=65532,mode=0700'}},
                'Mounts':[{'Type':'bind','Source':manifest['private_root']+'/staff-master.key','Destination':'/run/secrets/staff-master.key','RW':False}]}
        return manifest,actual,resource

    def test_verified_private_bootstrap_boundary_accepted(self):
        manifest,actual,resource=self.fixture()
        try:
            bootstrap.verify_bootstrap(control,manifest,actual,resource)
        except control.ScopeError:
            self.fail('Verified private bootstrap metadata was refused')

    def test_docker_bare_no_new_privileges_boundary_accepted(self):
        manifest,actual,resource=self.fixture()
        actual['HostConfig']['SecurityOpt']=['no-new-privileges']
        try:
            bootstrap.verify_bootstrap(control,manifest,actual,resource)
        except control.ScopeError:
            self.fail('Documented Docker no-new-privileges form refused')

    def test_unsafe_bootstrap_metadata_refused(self):
        for mutation in ['port','privileged','writable','socket','environment','temporary_mode','command','image','profile']:
            manifest,actual,resource=self.fixture()
            if mutation=='port':actual['HostConfig']['PortBindings']={'8080/tcp':[{'HostPort':'8091'}]}
            elif mutation=='privileged':actual['HostConfig']['Privileged']=True
            elif mutation=='writable':actual['HostConfig']['ReadonlyRootfs']=False
            elif mutation=='socket':actual['Mounts'].append({'Type':'bind','Source':'/var/run/docker.sock','Destination':'/socket','RW':False})
            elif mutation=='environment':actual['Config']['Env'].append('LD_PRELOAD=unexpected')
            elif mutation=='temporary_mode':actual['HostConfig']['Tmpfs']['/run/osee-private']='rw,nosuid,noexec,size=1m,mode=0777'
            elif mutation=='command':actual['Config']['Cmd']=['3600']
            elif mutation=='image':actual['Image']='sha256:'+'c'*64
            elif mutation=='profile':resource['profile']='production'
            with self.subTest(mutation=mutation),self.assertRaises(control.ScopeError):bootstrap.verify_bootstrap(control,manifest,actual,resource)

    def test_invalid_bootstrap_profile_refused_before_discovery(self):
        with self.assertRaises(control.ScopeError):bootstrap.bootstrap(control,'production')

if __name__=='__main__':unittest.main()
