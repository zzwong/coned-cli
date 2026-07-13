package coned

import (
	"archive/zip"
	"bytes"
	"net/url"
	"os"
	"testing"
)

func makeExportZIP(t *testing.T, name, body string) string {
	t.Helper()
	f, e := os.CreateTemp(t.TempDir(), "z-*")
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	w, e := z.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write([]byte(body)); e != nil {
		t.Fatal(e)
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	return f.Name()
}
func TestGreenButtonZIPExtractionAndJSON(t *testing.T) {
	p := makeExportZIP(t, "usage.csv", "\ufeff\nName,Synthetic User\n\nTYPE,DATE,USAGE,NOTES\nElectric usage,2026-01-01,3\n")
	if e := validateExportZIP(p); e != nil {
		t.Fatal(e)
	}
	var csv, js bytes.Buffer
	if e := ExtractGreenButton(p, "csv", &csv); e != nil || csv.Len() == 0 {
		t.Fatalf("extract %v %q", e, csv.String())
	}
	if e := GreenButtonCSVJSON(p, &js); e != nil || js.String() != "{\"DATE\":\"2026-01-01\",\"NOTES\":\"\",\"TYPE\":\"Electric usage\",\"USAGE\":\"3\"}\n" {
		t.Fatalf("json %v %q", e, js.String())
	}
}
func TestGreenButtonZIPRejectsUnexpectedType(t *testing.T) {
	p := makeExportZIP(t, "usage.txt", "x")
	var out bytes.Buffer
	if ExtractGreenButton(p, "csv", &out) == nil {
		t.Fatal("accepted unexpected member")
	}
}
func TestValidExportURL(t *testing.T) {
	for _, s := range []string{"https://x.blob.core.windows.net/a?sig=secret", "https://x.opower.com/a", "https://objectstorage.us-ashburn-1.oraclecloud.com/a"} {
		u, _ := url.Parse(s)
		if !validExportURL(u) {
			t.Fatal(s)
		}
	}
	u, _ := url.Parse("http://x.blob.core.windows.net/a")
	if validExportURL(u) {
		t.Fatal("accepted http")
	}
}
