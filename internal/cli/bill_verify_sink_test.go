package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBillVerifySinkSplitSignatureAndDigest(t *testing.T) {
	const pdf = "%PDF-synthetic\n"
	for chunk := 1; chunk <= len(pdf); chunk++ {
		sink := newBillVerifySink()
		for offset := 0; offset < len(pdf); offset += chunk {
			end := min(offset+chunk, len(pdf))
			n, err := sink.Write([]byte(pdf[offset:end]))
			if err != nil || n != end-offset {
				t.Fatalf("chunk=%d n=%d err=%v", chunk, n, err)
			}
		}
		got, err := sink.complete()
		sum := sha256.Sum256([]byte(pdf))
		if err != nil || got.Bytes != int64(len(pdf)) || got.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("%#v %v", got, err)
		}
	}
}

func TestBillVerifySinkRejectsInvalidAndStickyFailure(t *testing.T) {
	for _, input := range []string{"", "%", "%PDF", "<html>", "%PDX-invalid"} {
		sink := newBillVerifySink()
		_, _ = sink.Write([]byte(input))
		got, err := sink.complete()
		if err == nil || got.SHA256 != "" {
			t.Fatalf("accepted %q", input)
		}
	}
	sink := newBillVerifySink()
	_, _ = sink.Write([]byte("<html>"))
	if n, err := sink.Write([]byte("%PDF-valid")); n != 0 || err == nil {
		t.Fatal("write error was not sticky")
	}
}

func TestBillVerifySinkExactLimitAndOverflow(t *testing.T) {
	sink := newBillVerifySink()
	if _, err := sink.Write([]byte("%PDF-")); err != nil {
		t.Fatal(err)
	}
	chunk := []byte(strings.Repeat("x", 64*1024))
	for sink.bytes < billSyncMaxBytes {
		n := min(int64(len(chunk)), billSyncMaxBytes-sink.bytes)
		if _, err := sink.Write(chunk[:n]); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := sink.complete(); err != nil || got.Bytes != billSyncMaxBytes {
		t.Fatalf("%#v %v", got, err)
	}
	if n, err := sink.Write([]byte("x")); n != 0 || err == nil {
		t.Fatal("overflow accepted")
	}
	if got, err := sink.complete(); err == nil || got.SHA256 != "" {
		t.Fatal("overflow has successful digest")
	}
}
