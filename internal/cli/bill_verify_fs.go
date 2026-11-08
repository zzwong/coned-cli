package cli

import "os"

// billVerifyRetained owns one read-only descriptor for the entire comparison.
// It never creates or publishes a file.
type billVerifyRetained struct {
	file     *os.File
	name     string
	verified billSyncVerifiedFile
}
