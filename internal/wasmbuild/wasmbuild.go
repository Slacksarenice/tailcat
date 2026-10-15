// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wasmbuild builds the tailcat web WebAssembly binary and
// the distribution directory of static files that servers of the web
// app need. It is shared by cmd/tailcat-web, cmd/tailcat-webdist,
// and the browser integration tests.
package wasmbuild

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/tailscale/tailcat/internal/buildtags"
)

// GoRoot returns the GOROOT of the go command in $PATH.
func GoRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOROOT: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// WasmExecJS returns the path to the Go toolchain's wasm_exec.js,
// the JavaScript support file needed to run Go wasm binaries.
func WasmExecJS() (string, error) {
	goroot, err := GoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(goroot, "lib", "wasm", "wasm_exec.js"), nil
}

// Build compiles the Go package in pkgDir for js/wasm and writes the
// binary to outPath. It builds with the magicsock packet path hook
// (see [PacketPathModfile]) and [PacketPathTag], which the web app's
// WebRTC support needs. The binary records no paths from the build
// machine. With $TAILCAT_WASM_NAMES=1 it keeps the binary's name
// section, so CPU profiles name Go functions rather than
// wasm-function[N].
func Build(pkgDir, outPath string) error {
	modDir, err := os.MkdirTemp("", "tailcat-wasm-modfile")
	if err != nil {
		return err
	}
	defer os.RemoveAll(modDir)
	modfile, err := PacketPathModfile(modDir)
	if err != nil {
		return err
	}
	ldflags := "-ldflags=-s -w"
	if os.Getenv("TAILCAT_WASM_NAMES") == "1" {
		ldflags = "-ldflags=-w" // -s is what drops the name section
	}
	// For A/B measurements: 0 sends and receives through syscall/js only;
	// send uses raw I/O to send only (see web/rawio_js.go).
	switch m := os.Getenv("TAILCAT_WASM_RAWIO"); m {
	case "0":
		ldflags += " -X main.rawIOMode=off"
	case "send":
		ldflags += " -X main.rawIOMode=" + m
	}
	cmd := goCommand([]string{"GOOS=js", "GOARCH=wasm"}, "build",
		"-tags", buildtags.WasmTags()+","+PacketPathTag,
		"-modfile", modfile,
		"-trimpath",
		ldflags, "-o", outPath, pkgDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %v: %v\n%s", pkgDir, err, out)
	}
	return nil
}

// Dist builds the complete set of static files a server needs to
// serve the web app: main.wasm (compiled from the Go package in
// webDir, with precompressed main.wasm.zst and main.wasm.gz
// variants), the toolchain's wasm_exec.js, and index.html, app.js,
// tailcat.js and worker.js copied from webDir. It writes them all to
// outDir, creating it if needed.
func Dist(webDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	pkgArg := webDir
	if !filepath.IsAbs(pkgArg) {
		pkgArg = "./" + filepath.ToSlash(pkgArg)
	}
	wasmPath := filepath.Join(outDir, "main.wasm")
	if err := Build(pkgArg, wasmPath); err != nil {
		return err
	}
	if err := compressWasm(wasmPath); err != nil {
		return err
	}
	wasmExecJS, err := WasmExecJS()
	if err != nil {
		return err
	}
	if err := copyFile(wasmExecJS, filepath.Join(outDir, "wasm_exec.js")); err != nil {
		return err
	}
	for _, name := range []string{"index.html", "app.js", "tailcat.js", "worker.js"} {
		if err := copyFile(filepath.Join(webDir, name), filepath.Join(outDir, name)); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0644)
}

// compressWasm writes path.zst and path.gz next to path.
func compressWasm(path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()

	zf, err := os.Create(path + ".zst")
	if err != nil {
		return err
	}
	defer zf.Close()
	zw, err := zstd.NewWriter(zf)
	if err != nil {
		return err
	}
	if _, err := io.Copy(zw, src); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gf, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	defer gf.Close()
	gw := gzip.NewWriter(gf)
	if _, err := io.Copy(gw, src); err != nil {
		return err
	}
	return gw.Close()
}
