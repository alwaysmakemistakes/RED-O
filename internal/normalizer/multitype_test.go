package normalizer

import "testing"

func TestMultiType(t *testing.T) {
	cases := []struct{ raw, typ string }{
		{`{"time":"2026-10-17T14:29:03Z","process_exit":{"process":{"pid":1,"binary":"/bin/sh"},"status":0}}`, "process.exit"},
		{`{"time":"2026-10-17T14:29:03Z","process_kprobe":{"function_name":"security_file_permission","policy_name":"lab-file-access","process":{"pid":2,"binary":"/bin/cat"},"args":[{"file_arg":{"path":"/etc/hostname"}},{"int_arg":4}]}}`, "file.access"},
		{`{"time":"2026-10-17T14:29:03Z","process_kprobe":{"function_name":"tcp_connect","process":{"pid":3,"binary":"/bin/wget"},"args":[{"sock_arg":{"family":"AF_INET","daddr":"1.2.3.4","dport":80}}]}}`, "network.connect"},
		{`{"time":"2026-10-17T14:29:03Z","process_kprobe":{"function_name":"some_unknown_hook","process":{"pid":3},"args":[{"int_arg":1}]}}`, "kernel.hook"},
	}
	for _, tc := range cases {
		v, err := Normalize([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		if v.EventType != tc.typ || v.EventID == "" {
			t.Fatalf("%s: %+v", tc.typ, v)
		}
	}
}
