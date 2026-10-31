//go:build darwin || linux

package cli

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func (f *billSyncFS) retainForVerify(name string) (*billVerifyRetained, bool, error) {
	if !safeSyncBasename(name) {
		return nil, false, billSyncOutputConflictError()
	}
	if err := f.verify(); err != nil {
		return nil, false, err
	}
	fd, err := unix.Openat(f.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		if err := f.verify(); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENXIO) {
			return nil, true, billSyncOutputConflictError()
		}
		return nil, true, billSyncOutputFailedError()
	}
	file := os.NewFile(uintptr(fd), name)
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()
	var before, path unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, true, billSyncOutputFailedError()
	}
	if !ownedRegularBillFile(&before) || before.Size < 5 {
		return nil, true, billSyncOutputConflictError()
	}
	if err := unix.Fstatat(f.fd, name, &path, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&before), snapshotFromUnixStat(&path)) {
		return nil, true, billSyncOutputConflictError()
	}
	verified, err := inspectBillPDF(file)
	if err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&before), verified.snapshot) {
		return nil, true, billSyncOutputConflictError()
	}
	retained := &billVerifyRetained{file: file, name: name, verified: verified}
	if err := retained.checkIdentity(f); err != nil {
		return nil, true, err
	}
	keep = true
	return retained, true, nil
}

func (r *billVerifyRetained) checkIdentity(f *billSyncFS) error {
	if err := f.verify(); err != nil {
		return err
	}
	var descriptor, path unix.Stat_t
	if err := unix.Fstat(int(r.file.Fd()), &descriptor); err != nil || !sameUnixSnapshot(r.verified.snapshot, snapshotFromUnixStat(&descriptor)) {
		return billSyncOutputConflictError()
	}
	if err := unix.Fstatat(f.fd, r.name, &path, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(r.verified.snapshot, snapshotFromUnixStat(&path)) {
		return billSyncOutputConflictError()
	}
	return nil
}

func (r *billVerifyRetained) recheck(f *billSyncFS) error {
	if err := r.checkIdentity(f); err != nil {
		return err
	}
	verified, err := inspectBillPDF(r.file)
	if err != nil || verified.Bytes != r.verified.Bytes || verified.SHA256 != r.verified.SHA256 || !sameUnixSnapshot(verified.snapshot, r.verified.snapshot) {
		return billSyncOutputConflictError()
	}
	return r.checkIdentity(f)
}
