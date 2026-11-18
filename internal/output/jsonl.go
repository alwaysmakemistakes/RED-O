package output

import (
	"encoding/json"
	"io"
)

func WriteJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func WriteRaw(w io.Writer, line []byte) error {
	if _, err := w.Write(line); err != nil {
		return err
	}
	_, err := w.Write([]byte("\n"))
	return err
}
