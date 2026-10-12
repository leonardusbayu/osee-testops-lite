"""Synthetic tar boundary tests; no Docker process or real capability."""
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('archive_bootstrap', ROOT / 'scripts/candidate_bootstrap.py')
if spec is None or spec.loader is None:
    raise RuntimeError('Owned bootstrap loader unavailable')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class ArchiveScopeError(RuntimeError):
    pass


class PrivateCapabilityArchiveTests(unittest.TestCase):
    def archive(self, *, name='setup-capability.txt', mode=0o600, uid=65532,
                payload=b'A' * 43, extra=False, kind=tarfile.REGTYPE):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            item = tarfile.TarInfo(name)
            item.mode, item.uid, item.gid, item.type = mode, uid, 65532, kind
            item.size = len(payload) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                item.linkname = '/nonsecret-outside'
            archive.addfile(item, io.BytesIO(payload) if kind == tarfile.REGTYPE else None)
            if extra:
                item = tarfile.TarInfo('unexpected.txt')
                item.mode, item.uid, item.gid = 0o600, 65532, 65532
                archive.addfile(item)
        return stream.getvalue()

    def read(self, archive, code=0):
        identifier = 'a' * 64
        docker = ['docker', '--context', 'default']
        control = SimpleNamespace(DOCKER=docker, ScopeError=ArchiveScopeError,
                                  verify_owned=lambda manifest, role: {'State': {'Running': True}})
        expected = docker + ['container', 'exec', identifier, '/bin/tar', '-C', '/run/osee-private',
                             '-cf', '-', '--', 'setup-capability.txt']
        def transport(args, *, capture_output, timeout):
            if args != expected or capture_output is not True or timeout != 15:
                return subprocess.CompletedProcess(args, 1, stdout=b'', stderr=b'fixture transport refused')
            return subprocess.CompletedProcess(args, code, stdout=archive, stderr=b'')
        with patch.object(bootstrap.subprocess, 'run', side_effect=transport):
            return bootstrap._read_capability(control, {'resources': {'bootstrap': {'id': identifier}}})

    def test_owned_private_tar_bytes_roundtrip(self):
        self.assertEqual(self.read(self.archive()), b'A' * 43)

    def test_unsafe_archive_entries_are_refused(self):
        cases = [dict(name='../setup-capability.txt'), dict(name='other.txt'), dict(mode=0o644),
                 dict(uid=0), dict(payload=b'A' * 44), dict(extra=True), dict(kind=tarfile.SYMTYPE),
                 dict(payload=b'A' * 42 + b'!'), dict(payload=b'B' * 43)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ArchiveScopeError):
                self.read(self.archive(**case))

    def test_bounded_archive_refuses_extra_padding(self):
        with self.assertRaises(ArchiveScopeError):
            self.read(self.archive() + b'\0' * 10240)

    def test_failed_transport_does_not_accept_archive(self):
        with self.assertRaises(ArchiveScopeError):
            self.read(self.archive(), code=1)


if __name__ == '__main__':
    unittest.main()
