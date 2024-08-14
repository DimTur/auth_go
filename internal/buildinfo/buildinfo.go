package buildinfo

import (
	"log"
	"runtime"
)

// BuildInfo represents all available build information.
type BuildInfo struct {
	Version    string `json:"version"`
	CommitHash string `json:"commit_hash"`
	BuildDate  string `json:"build_date"`
	GoVersion  string `json:"go_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Compiler   string `json:"compiler"`
}

// New returns all available build information.
func New() BuildInfo {
	log.Println("BuildInfo: ", version, buildDate)
	return BuildInfo{
		Version:    version,
		CommitHash: commitHash,
		BuildDate:  buildDate,
		GoVersion:  runtime.Version(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Compiler:   runtime.Compiler,
	}
}
