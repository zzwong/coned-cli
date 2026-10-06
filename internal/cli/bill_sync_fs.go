package cli

import (
	"errors"
	"os"
)

const billSyncMaxBytes = 100 << 20

var (
	errBillSyncInvalidPDF = errors.New("bill PDF failed validation")
)

type billSyncFS struct {
	fd         int
	inputPath  string
	canonical  string
	closed     bool
	beforeLink func()
	afterLink  func()
}

type billSyncVerifiedFile struct {
	Bytes    int64
	SHA256   string
	snapshot billSyncSnapshot
}

type billSyncSnapshot struct {
	device    uint64
	inode     uint64
	owner     uint32
	group     uint32
	mode      uint32
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

func (f *billSyncFS) close() error {
	if f == nil || f.closed {
		return nil
	}
	f.closed = true
	return os.NewFile(uintptr(f.fd), f.canonical).Close()
}
