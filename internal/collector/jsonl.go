package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
)

// MaxEventBytes bounds memory usage for unusually large Tetragon JSON lines.
const MaxEventBytes = 16 * 1024 * 1024

// ReadJSONL calls handle once per non-empty physical line. It does not parse
// JSON: preserving the raw payload is the normalizer's caller's responsibility.
// A handler error is returned with the original input line number.
func ReadJSONL(ctx context.Context, r io.Reader, handle func([]byte) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), MaxEventBytes)
	line := 0
	for scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return err
		}
		b := scanner.Bytes()
		if len(b) == 0 {
			continue
		}
		if err := handle(b); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	return ctx.Err()
}
