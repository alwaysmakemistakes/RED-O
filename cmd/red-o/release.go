package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
)

// releaseVersion is the immutable CLI version for the dissertation test baseline.
// VERSION and RELEASE.json are kept in sync by the release contract test.
const releaseVersion = "1.0.2"

// May be injected with -ldflags '-X main.gitCommit=<commit>' during packaging.
// A local go build can also expose vcs.revision through Go build metadata.
var gitCommit = ""

type releaseInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func currentRelease() releaseInfo {
	commit := strings.TrimSpace(gitCommit)
	if commit == "" {
		if b, ok := debug.ReadBuildInfo(); ok {
			for _, s := range b.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					commit = s.Value
					break
				}
			}
		}
	}
	if commit == "" {
		commit = "unknown"
	}
	return releaseInfo{Version: releaseVersion, Commit: commit,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
}

func versionCommand(args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print machine-readable JSON version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "version: unexpected arguments")
		return 2
	}
	v := currentRelease()
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		if err := e.Encode(v); err != nil {
			return 1
		}
	} else {
		fmt.Printf("RED-O v%s (commit %s; %s; %s/%s)\n", v.Version, v.Commit, v.GoVersion, v.OS, v.Arch)
	}
	return 0
}
