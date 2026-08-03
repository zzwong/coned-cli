package securestore

import (
	"bytes"
	"testing"
)

func TestDecodeKeyringValueTrimsRawLegacyValue(t *testing.T) {
	got, err := decodeKeyringValue([]byte(" \nlegacy value\t "))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte("legacy value"); !bytes.Equal(got, want) {
		t.Fatalf("decodeKeyringValue() = %q, want %q", got, want)
	}
}

func TestDecodeKeyringValueReadsStandardBase64CompatibilityValue(t *testing.T) {
	got, err := decodeKeyringValue([]byte("go-keyring-base64:AAH/"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 1, 0xff}; !bytes.Equal(got, want) {
		t.Fatalf("decodeKeyringValue() = %x, want %x", got, want)
	}
}

func TestDecodeKeyringValueRejectsMalformedBase64WithoutLeakingStoredValue(t *testing.T) {
	stored := []byte("go-keyring-base64:not-valid-secret")
	_, err := decodeKeyringValue(stored)
	if err == nil {
		t.Fatal("decodeKeyringValue() error = nil, want malformed encoding error")
	}
	if bytes.Contains([]byte(err.Error()), stored) {
		t.Fatalf("decodeKeyringValue() error exposes stored value: %q", err)
	}
}

func TestDecodeKeyringValueReadsLegacyHexCompatibilityValue(t *testing.T) {
	got, err := decodeKeyringValue([]byte("go-keyring-encoded:0001ff"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 1, 0xff}; !bytes.Equal(got, want) {
		t.Fatalf("decodeKeyringValue() = %x, want %x", got, want)
	}
}

func TestDecodeKeyringValueRejectsMalformedHexWithoutLeakingStoredValue(t *testing.T) {
	stored := []byte("go-keyring-encoded:not-valid-secret")
	_, err := decodeKeyringValue(stored)
	if err == nil {
		t.Fatal("decodeKeyringValue() error = nil, want malformed encoding error")
	}
	if bytes.Contains([]byte(err.Error()), stored) {
		t.Fatalf("decodeKeyringValue() error exposes stored value: %q", err)
	}
}

func TestEncodeKeyringValueUsesStandardBase64(t *testing.T) {
	got := encodeKeyringValue([]byte{0, 1, 0xff})
	if want := []byte("go-keyring-base64:AAH/"); !bytes.Equal(got, want) {
		t.Fatalf("encodeKeyringValue() = %q, want %q", got, want)
	}
}

func TestKeyringValueCodecRoundTripsBinaryLargePayload(t *testing.T) {
	value := make([]byte, 16*1024)
	for i := range value {
		value[i] = byte((i*37 + 11) % 256)
	}

	decoded, err := decodeKeyringValue(encodeKeyringValue(value))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, value) {
		t.Fatalf("codec round trip changed binary payload: got %d bytes, want %d", len(decoded), len(value))
	}
}
