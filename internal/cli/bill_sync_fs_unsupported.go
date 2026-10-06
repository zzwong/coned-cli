//go:build !darwin && !linux

package cli

import "os"

func billSyncPlatformSupported() bool { return false }

func openBillSyncFS(string) (*billSyncFS, error) {
	return nil, unsupportedPlatformError()
}

func (*billSyncFS) verify() error { return unsupportedPlatformError() }

func (*billSyncFS) existing(string) (billSyncVerifiedFile, bool, error) {
	return billSyncVerifiedFile{}, false, unsupportedPlatformError()
}

func (*billSyncFS) createTemp() (*os.File, string, error) {
	return nil, "", unsupportedPlatformError()
}

func (*billSyncFS) publish(string, *os.File, string, *billSyncVerifiedFile) error {
	return unsupportedPlatformError()
}

func (*billSyncFS) removeOwned(string, *os.File) error { return unsupportedPlatformError() }

func (*billSyncFS) removePublished(string, billSyncSnapshot) error { return unsupportedPlatformError() }

func inspectBillPDF(*os.File) (billSyncVerifiedFile, error) {
	return billSyncVerifiedFile{}, unsupportedPlatformError()
}
