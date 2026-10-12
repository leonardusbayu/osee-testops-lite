package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"osee-testops-lite/internal/core"
)

type capabilityFile struct {
	directory *os.File
	file      *os.File
	temporary string
	reset     bool
	path      string
}

func noLinkedAncestors(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("private path unavailable")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func ownerOnly(fd int, directory bool) error {
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Uid != uint32(os.Geteuid()) {
		return errors.New("private owner unavailable")
	}
	expected := uint32(unix.S_IFREG)
	permissions := uint32(0600)
	if directory {
		expected = unix.S_IFDIR
		permissions = 0700
	}
	if info.Mode&unix.S_IFMT != expected || info.Mode&0777 != permissions || !directory && info.Nlink != 1 {
		return errors.New("private permissions unavailable")
	}
	return nil
}

func validateExistingCapability(fd int, reset bool) error {
	opened, err := unix.Openat(fd, "setup-capability.txt", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errors.New("private target unavailable")
	}
	defer unix.Close(opened)
	if !reset {
		return errors.New("private target exists")
	}
	return ownerOnly(opened, false)
}

func newCapabilityFile(path string, reset bool) (*capabilityFile, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "setup-capability.txt" || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("private target invalid")
	}
	parent := filepath.Dir(path)
	if err := noLinkedAncestors(parent); err != nil {
		return nil, err
	}
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("private directory unavailable")
	}
	directory := os.NewFile(uintptr(fd), parent)
	if err = ownerOnly(fd, true); err != nil {
		directory.Close()
		return nil, err
	}
	if err = validateExistingCapability(fd, reset); err != nil {
		directory.Close()
		return nil, err
	}
	id, err := core.NewID()
	if err != nil {
		directory.Close()
		return nil, err
	}
	temporary := ".bootstrap-" + string(id)
	created, err := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		directory.Close()
		return nil, errors.New("private creation unavailable")
	}
	private := &capabilityFile{directory: directory, file: os.NewFile(uintptr(created), temporary), temporary: temporary, reset: reset, path: path}
	if err = ownerOnly(created, false); err != nil {
		private.close()
		return nil, err
	}
	return private, nil
}

func (p *capabilityFile) publish(token string) error {
	if len(token) != 43 {
		return errors.New("private capability invalid")
	}
	if err := ownerOnly(int(p.file.Fd()), false); err != nil {
		return err
	}
	if _, err := io.WriteString(p.file, token); err != nil {
		return err
	}
	if err := p.file.Sync(); err != nil {
		return err
	}
	parent, err := os.Stat(filepath.Dir(p.path))
	if err != nil {
		return err
	}
	opened, err := p.directory.Stat()
	if err != nil || !os.SameFile(parent, opened) {
		return errors.New("private directory changed")
	}
	fd := int(p.directory.Fd())
	if err = validateExistingCapability(fd, p.reset); err != nil {
		return err
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if p.reset {
		flags = 0
	}
	if err = unix.Renameat2(fd, p.temporary, fd, "setup-capability.txt", flags); err != nil {
		return errors.New("private publication unavailable")
	}
	p.temporary = ""
	return p.directory.Sync()
}

func (p *capabilityFile) close() {
	p.file.Close()
	if p.temporary != "" {
		unix.Unlinkat(int(p.directory.Fd()), p.temporary, 0)
	}
	p.directory.Close()
}

func readPrivateKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || noLinkedAncestors(filepath.Dir(path)) != nil {
		return nil, errors.New("private key path unavailable")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("private key unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != 32 {
		return nil, errors.New("private key invalid")
	}
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(key) != 32 {
		return nil, errors.New("private key invalid")
	}
	return key, nil
}
