//go:build darwin || linux

package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func billSyncPlatformSupported() bool { return true }

func openBillSyncFS(path string) (*billSyncFS, error) {
	if strings.TrimSpace(path) == "" {
		return nil, invalidArgument(nil)
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, invalidArgument(nil)
	}
	inputInfo, err := os.Lstat(abs)
	if err != nil || inputInfo.Mode()&os.ModeSymlink != 0 || !inputInfo.IsDir() {
		return nil, invalidArgument(nil)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, invalidArgument(nil)
	}
	canonical := filepath.Join(parent, filepath.Base(abs))
	canonicalInfo, err := os.Lstat(canonical)
	if err != nil || canonicalInfo.Mode()&os.ModeSymlink != 0 || !canonicalInfo.IsDir() {
		return nil, invalidArgument(nil)
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ENOENT) {
			return nil, invalidArgument(nil)
		}
		return nil, billSyncOutputFailedError()
	}
	root := &billSyncFS{fd: fd, inputPath: abs, canonical: canonical}
	if err := root.verify(); err != nil {
		_ = root.close()
		return nil, err
	}
	return root, nil
}

func (f *billSyncFS) verify() error {
	if f == nil || f.closed {
		return billSyncOutputFailedError()
	}
	var descriptor, canonical, input unix.Stat_t
	if err := unix.Fstat(f.fd, &descriptor); err != nil || descriptor.Mode&unix.S_IFMT != unix.S_IFDIR {
		return billSyncOutputFailedError()
	}
	if err := unix.Lstat(f.canonical, &canonical); err != nil || canonical.Mode&unix.S_IFMT != unix.S_IFDIR || !sameUnixIdentity(&descriptor, &canonical) {
		return billSyncOutputFailedError()
	}
	if err := unix.Lstat(f.inputPath, &input); err != nil || input.Mode&unix.S_IFMT != unix.S_IFDIR || !sameUnixIdentity(&descriptor, &input) {
		return billSyncOutputFailedError()
	}
	return nil
}

func (f *billSyncFS) existing(name string) (billSyncVerifiedFile, bool, error) {
	if !safeSyncBasename(name) {
		return billSyncVerifiedFile{}, false, billSyncOutputConflictError()
	}
	if err := f.verify(); err != nil {
		return billSyncVerifiedFile{}, false, err
	}
	fd, err := unix.Openat(f.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return billSyncVerifiedFile{}, false, nil
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENXIO) {
			return billSyncVerifiedFile{}, true, billSyncOutputConflictError()
		}
		return billSyncVerifiedFile{}, true, billSyncOutputFailedError()
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return billSyncVerifiedFile{}, true, billSyncOutputFailedError()
	}
	if !ownedRegularBillFile(&before) || before.Size < 5 || before.Size > billSyncMaxBytes {
		return billSyncVerifiedFile{}, true, billSyncOutputConflictError()
	}
	var pathBefore unix.Stat_t
	if err := unix.Fstatat(f.fd, name, &pathBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&before), snapshotFromUnixStat(&pathBefore)) {
		return billSyncVerifiedFile{}, true, billSyncOutputConflictError()
	}
	verified, err := inspectBillPDF(file)
	if errors.Is(err, errBillSyncInvalidPDF) {
		return billSyncVerifiedFile{}, true, billSyncOutputConflictError()
	}
	if err != nil {
		return billSyncVerifiedFile{}, true, billSyncOutputFailedError()
	}
	var after, pathAfter unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&before), snapshotFromUnixStat(&after)) {
		return billSyncVerifiedFile{}, true, billSyncOutputConflictError()
	}
	if err := unix.Fstatat(f.fd, name, &pathAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&after), snapshotFromUnixStat(&pathAfter)) {
		return billSyncVerifiedFile{}, true, billSyncOutputConflictError()
	}
	if err := f.verify(); err != nil {
		return billSyncVerifiedFile{}, true, err
	}
	return verified, true, nil
}

func (f *billSyncFS) createTemp() (*os.File, string, error) {
	if err := f.verify(); err != nil {
		return nil, "", err
	}
	for attempt := 0; attempt < 16; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", billSyncOutputFailedError()
		}
		name := ".coned-bill-sync-" + hex.EncodeToString(random[:]) + ".tmp"
		fd, err := unix.Openat(f.fd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", billSyncOutputFailedError()
		}
		file := os.NewFile(uintptr(fd), name)
		if err := file.Chmod(0o600); err != nil {
			_ = f.removeOwned(name, file)
			_ = file.Close()
			return nil, "", billSyncOutputFailedError()
		}
		var opened, entry unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil || !ownedRegularBillFile(&opened) {
			_ = f.removeOwned(name, file)
			_ = file.Close()
			return nil, "", billSyncOutputFailedError()
		}
		if err := unix.Fstatat(f.fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&opened), snapshotFromUnixStat(&entry)) {
			_ = f.removeOwned(name, file)
			_ = file.Close()
			return nil, "", billSyncOutputFailedError()
		}
		if err := f.verify(); err != nil {
			_ = f.removeOwned(name, file)
			_ = file.Close()
			return nil, "", err
		}
		return file, name, nil
	}
	return nil, "", billSyncOutputFailedError()
}

func (f *billSyncFS) publish(temp string, file *os.File, destination string, verified *billSyncVerifiedFile) error {
	if !safeSyncBasename(temp) || !safeSyncBasename(destination) || file == nil {
		return billSyncOutputFailedError()
	}
	if err := file.Sync(); err != nil {
		return billSyncOutputFailedError()
	}
	var openTemp, namedTemp unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &openTemp); err != nil || !ownedRegularBillFile(&openTemp) {
		return billSyncOutputFailedError()
	}
	openSnapshot := snapshotFromUnixStat(&openTemp)
	if verified == nil || !sameUnixSnapshot(openSnapshot, verified.snapshot) {
		return billSyncOutputFailedError()
	}
	if err := unix.Fstatat(f.fd, temp, &namedTemp, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(openSnapshot, snapshotFromUnixStat(&namedTemp)) {
		return billSyncOutputFailedError()
	}
	if err := f.verify(); err != nil {
		return err
	}
	if f.beforeLink != nil {
		f.beforeLink()
	}
	if err := unix.Linkat(f.fd, temp, f.fd, destination, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return billSyncOutputConflictError()
		}
		return billSyncOutputFailedError()
	}
	if f.afterLink != nil {
		f.afterLink()
	}
	rollback := func() error {
		var current unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &current); err != nil {
			return billSyncOutputFailedError()
		}
		return f.removePublished(destination, snapshotFromUnixStat(&current))
	}
	var afterLink, namedAfterLink, published unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &afterLink); err != nil || !sameBillSnapshotExceptCtime(verified.snapshot, snapshotFromUnixStat(&afterLink)) {
		_ = rollback()
		return billSyncOutputFailedError()
	}
	if err := unix.Fstatat(f.fd, temp, &namedAfterLink, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&afterLink), snapshotFromUnixStat(&namedAfterLink)) {
		_ = rollback()
		return billSyncOutputFailedError()
	}
	if err := unix.Fstatat(f.fd, destination, &published, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&afterLink), snapshotFromUnixStat(&published)) {
		_ = rollback()
		return billSyncOutputFailedError()
	}
	if err := f.verify(); err != nil {
		_ = rollback()
		return err
	}
	if err := unix.Fsync(f.fd); err != nil {
		_ = rollback()
		return billSyncOutputFailedError()
	}
	if err := f.removeOwned(temp, file); err != nil {
		_ = rollback()
		return billSyncOutputFailedError()
	}
	var afterTempRemoval, publishedAfterRemoval unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &afterTempRemoval); err != nil || !sameBillSnapshotExceptCtime(verified.snapshot, snapshotFromUnixStat(&afterTempRemoval)) {
		_ = rollback()
		return billSyncOutputFailedError()
	}
	if err := unix.Fstatat(f.fd, destination, &publishedAfterRemoval, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&afterTempRemoval), snapshotFromUnixStat(&publishedAfterRemoval)) {
		_ = rollback()
		return billSyncOutputFailedError()
	}
	if err := unix.Fsync(f.fd); err != nil {
		_ = rollback()
		return billSyncOutputFailedError()
	}
	if err := f.verify(); err != nil {
		_ = rollback()
		return err
	}
	verified.snapshot = snapshotFromUnixStat(&afterTempRemoval)
	return nil
}

func (f *billSyncFS) removeOwned(name string, file *os.File) error {
	if f == nil || f.closed || !safeSyncBasename(name) || file == nil {
		return billSyncOutputFailedError()
	}
	var opened, named unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &opened); err != nil || !ownedRegularSyncTemp(&opened) {
		return billSyncOutputFailedError()
	}
	err := unix.Fstatat(f.fd, name, &named, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !sameUnixSnapshot(snapshotFromUnixStat(&opened), snapshotFromUnixStat(&named)) {
		return billSyncOutputFailedError()
	}
	if err := unix.Unlinkat(f.fd, name, 0); err != nil {
		return billSyncOutputFailedError()
	}
	return nil
}

func (f *billSyncFS) removePublished(name string, expected billSyncSnapshot) error {
	if f == nil || f.closed || !safeSyncBasename(name) {
		return billSyncOutputFailedError()
	}
	var named unix.Stat_t
	if err := unix.Fstatat(f.fd, name, &named, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil || !sameUnixSnapshot(expected, snapshotFromUnixStat(&named)) {
		return billSyncOutputFailedError()
	}
	if err := unix.Unlinkat(f.fd, name, 0); err != nil {
		return billSyncOutputFailedError()
	}
	return nil
}

func inspectBillPDF(file *os.File) (billSyncVerifiedFile, error) {
	var beforeStat, afterStat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &beforeStat); err != nil {
		return billSyncVerifiedFile{}, err
	}
	before := snapshotFromUnixStat(&beforeStat)
	if !ownedRegularBillFile(&beforeStat) || before.size < 5 || before.size > billSyncMaxBytes {
		return billSyncVerifiedFile{}, errBillSyncInvalidPDF
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return billSyncVerifiedFile{}, err
	}
	var signature [5]byte
	if _, err := io.ReadFull(file, signature[:]); err != nil || string(signature[:]) != "%PDF-" {
		return billSyncVerifiedFile{}, errBillSyncInvalidPDF
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return billSyncVerifiedFile{}, err
	}
	hasher := sha256.New()
	bytes, err := io.Copy(hasher, io.LimitReader(file, billSyncMaxBytes+1))
	if err != nil {
		return billSyncVerifiedFile{}, err
	}
	if bytes > billSyncMaxBytes || bytes != before.size {
		return billSyncVerifiedFile{}, errBillSyncInvalidPDF
	}
	if err := unix.Fstat(int(file.Fd()), &afterStat); err != nil {
		return billSyncVerifiedFile{}, err
	}
	if !sameUnixSnapshot(before, snapshotFromUnixStat(&afterStat)) {
		return billSyncVerifiedFile{}, errors.New("file changed while verifying")
	}
	return billSyncVerifiedFile{Bytes: bytes, SHA256: hex.EncodeToString(hasher.Sum(nil)), snapshot: before}, nil
}

func ownedRegularBillFile(stat *unix.Stat_t) bool {
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == uint32(os.Getuid()) && stat.Size >= 0 && stat.Size <= billSyncMaxBytes
}

func ownedRegularSyncTemp(stat *unix.Stat_t) bool {
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == uint32(os.Getuid()) && stat.Size >= 0
}

func sameUnixIdentity(a, b *unix.Stat_t) bool {
	return a != nil && b != nil && uint64(a.Dev) == uint64(b.Dev) && uint64(a.Ino) == uint64(b.Ino)
}

func snapshotFromUnixStat(stat *unix.Stat_t) billSyncSnapshot {
	if stat == nil {
		return billSyncSnapshot{}
	}
	return billSyncSnapshot{
		device: uint64(stat.Dev), inode: uint64(stat.Ino), owner: stat.Uid, group: stat.Gid,
		mode: uint32(stat.Mode), size: stat.Size,
		mtimeSec: stat.Mtim.Sec, mtimeNsec: stat.Mtim.Nsec,
		ctimeSec: stat.Ctim.Sec, ctimeNsec: stat.Ctim.Nsec,
	}
}

func sameUnixSnapshot(a, b billSyncSnapshot) bool { return a == b }

func sameBillSnapshotExceptCtime(a, b billSyncSnapshot) bool {
	a.ctimeSec, a.ctimeNsec = 0, 0
	b.ctimeSec, b.ctimeNsec = 0, 0
	return a == b
}

func safeSyncBasename(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, "/\\\x00")
}
