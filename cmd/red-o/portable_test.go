package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordGenerationAndPrivateSettings(t *testing.T) {
	p1, err := randomPassword()
	if err != nil || len(p1) < 25 {
		t.Fatalf("password: %v, %d", err, len(p1))
	}
	p2, err := randomPassword()
	if err != nil || p1 == p2 {
		t.Fatalf("duplicate random passwords: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := writePrivate(path, []byte("WEB_USER=admin\nWEB_PASSWORD=secret\n")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("secret permissions: %v, %v", st, err)
	}
	if err := writePrivate(path, []byte("bad")); !os.IsExist(err) {
		t.Fatal("must not overwrite pre-existing secrets", err)
	}
}
func TestWebRemoteDemoGuard(t *testing.T) {
	cases := []struct {
		addr   string
		denied bool
	}{
		{"127.0.0.1:8088", false}, {"localhost:8088", false}, {"[::1]:8088", false},
		{"0.0.0.0:8088", true}, {":8088", true}, {"192.168.10.15:8088", true}, {"not-a-host", true},
	}
	for _, c := range cases {
		if actual := isRemoteDemoCredentials(c.addr, "admin", "admin"); actual != c.denied {
			t.Fatalf("addr %s denied=%v want %v", c.addr, actual, c.denied)
		}
		if isRemoteDemoCredentials(c.addr, "admin", "a-unique-long-password") {
			t.Fatalf("unique initial secret rejected at %s", c.addr)
		}
	}
}
