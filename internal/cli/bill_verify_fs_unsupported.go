//go:build !darwin && !linux

package cli

func (*billSyncFS) retainForVerify(string) (*billVerifyRetained, bool, error) {
	return nil, false, unsupportedPlatformError()
}

func (*billVerifyRetained) recheck(*billSyncFS) error { return unsupportedPlatformError() }
