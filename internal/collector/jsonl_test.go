package collector

import (
	"context"
	"strings"
	"testing"
)

func TestReadJSONL(t *testing.T) {
	var seen []string
	err := ReadJSONL(context.Background(), strings.NewReader("one\n\ntwo\n"), func(b []byte) error {
		seen = append(seen, string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "one" || seen[1] != "two" {
		t.Fatalf("got %v", seen)
	}
}
