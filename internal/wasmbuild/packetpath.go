// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wasmbuild

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PacketPathTag is the build tag that compiles tailcat's packet path
// API (Server.NewPacketPath and Client.NewPacketPath) and the web
// app's WebRTC support. Builds using it must also use the -modfile
// that [PacketPathModfile] writes, whose tailscale.com has the
// magicsock.PacketPath hook those depend on.
const PacketPathTag = "tailcat_webrtc"

// packetPathSource is the magicsock file the patch adds.
//
//go:embed magicsockpatch/packetpath.go.in
var packetPathSource []byte

// magicsockEdit is one insertion into a tailscale.com magicsock file.
// The anchor must occur exactly once; text is inserted immediately
// before or after it.
type magicsockEdit struct {
	file   string // file name in tailscale.com/wgengine/magicsock
	anchor string
	text   string
	before bool // insert before the anchor instead of after it
}

// packetPathEdits wire packetpath.go into magicsock. They are kept to
// the minimum the hook needs so that a tailscale.com upgrade rarely
// disturbs them; if one does, PacketPathModfile fails, naming it.
var packetPathEdits = []magicsockEdit{
	{
		// The Conn's packet path state.
		file:   "magicsock.go",
		anchor: "\tderpRecvCh chan derpReadResult\n",
		text:   "\n\t// packetPaths are embedder-supplied peer paths; see packetpath.go.\n\tpacketPaths packetPathState\n",
	},
	{
		// connBind.Open: also receive from packet paths.
		file:   "magicsock.go",
		anchor: "\treturn fns, c.LocalPort(), nil\n",
		text:   "\tfns = append(fns, c.receivePacketPath)\n",
		before: true,
	},
	{
		// connBind.Close: wake a receivePacketPath waiting for a datagram.
		file:   "magicsock.go",
		anchor: "\tc.derpRecvCh <- derpReadResult{}\n",
		text:   "\tc.wakePacketPathRecv()\n",
	},
	{
		// endpoint.send: offer datagrams to the peer's packet path
		// first, after the send has been noted for idle tracking.
		file:   "endpoint.go",
		anchor: "\tde.lastSendAny = now\n\tde.mu.Unlock()\n",
		text: "\n\tif n := de.c.sendPacketPath(de.publicKey, buffs, offset); n > 0 {\n" +
			"\t\tbuffs = buffs[n:]\n" +
			"\t\tif len(buffs) == 0 {\n" +
			"\t\t\treturn nil\n" +
			"\t\t}\n" +
			"\t}\n",
	},
}

// goList runs "go list -m -f format mod" in the current directory.
func goList(format, mod string) (string, error) {
	out, err := exec.Command("go", "list", "-m", "-f", format, mod).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("go list -m %s: %v\n%s", mod, err, ee.Stderr)
		}
		return "", fmt.Errorf("go list -m %s: %w", mod, err)
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "", fmt.Errorf("go list -m -f %q %s: empty result", format, mod)
	}
	return s, nil
}

// applyEdits returns src with every edit for file applied.
func applyEdits(file string, src []byte, edits []magicsockEdit) ([]byte, error) {
	s := string(src)
	for _, e := range edits {
		if e.file != file {
			continue
		}
		if n := strings.Count(s, e.anchor); n != 1 {
			return nil, fmt.Errorf("magicsock packet path patch: anchor %q occurs %d times in %s, want 1; did the tailscale.com dependency change? Update internal/wasmbuild/packetpath.go", e.anchor, n, file)
		}
		i := strings.Index(s, e.anchor)
		if !e.before {
			i += len(e.anchor)
		}
		s = s[:i] + e.text + s[i:]
	}
	return []byte(s), nil
}

// patchHash identifies the patch's content, so a changed patch gets a
// fresh patched module copy.
func patchHash() string {
	h := sha256.New()
	for _, e := range packetPathEdits {
		fmt.Fprintf(h, "%q %q %q %v\n", e.file, e.anchor, e.text, e.before)
	}
	h.Write(packetPathSource)
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// patchedTailscale returns a directory holding a copy of the
// tailscale.com module that tailcat requires, with the magicsock
// packet path patch applied. The go command forbids overlaying files
// in the module cache, so the patch is applied to a copy instead. The
// copy lives in the user cache directory, keyed by module version and
// patch content, so builds reuse it (and their build cache stays warm).
func patchedTailscale() (string, error) {
	srcDir, err := goList("{{.Dir}}", "tailscale.com")
	if err != nil {
		return "", err
	}
	version, err := goList("{{.Version}}", "tailscale.com")
	if err != nil {
		return "", err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	parent := filepath.Join(cache, "tailcat-wasmbuild")
	dst := filepath.Join(parent, "tailscale.com@"+version+"-pp"+patchHash())
	if _, err := os.Stat(filepath.Join(dst, "go.mod")); err == nil {
		return dst, nil
	}
	if err := os.MkdirAll(parent, 0755); err != nil {
		return "", err
	}
	// Build in a temporary sibling and rename into place, so a
	// concurrent build never sees a partial copy.
	tmp, err := os.MkdirTemp(parent, "tmp-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	if err := copyModule(srcDir, tmp); err != nil {
		return "", err
	}
	msDir := filepath.Join(tmp, "wgengine", "magicsock")
	for _, name := range []string{"magicsock.go", "endpoint.go"} {
		p := filepath.Join(msDir, name)
		src, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		patched, err := applyEdits(name, src, packetPathEdits)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(p, patched, 0644); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(msDir, "packetpath.go"), packetPathSource, 0644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		if _, statErr := os.Stat(filepath.Join(dst, "go.mod")); statErr == nil {
			return dst, nil // a concurrent build won the race
		}
		return "", err
	}
	return dst, nil
}

// copyModule copies the module source tree in src to dst, which must
// exist, skipping tests and test data, which builds don't need.
func copyModule(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0755)
		}
		if strings.HasSuffix(d.Name(), "_test.go") || !d.Type().IsRegular() {
			return nil
		}
		return copyWritable(path, filepath.Join(dst, rel))
	})
}

// copyWritable copies the file src to dst. Unlike the module cache's
// read-only files, the copy is writable, so it can be patched and
// later removed.
func copyWritable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// PacketPathModfile writes, into dir, a go.mod (and go.sum) for the
// tailcat module in the current directory that replaces tailscale.com
// with a copy carrying the magicsock packet path hook, and returns its
// path. Build with it via -modfile, together with -tags
// [PacketPathTag].
func PacketPathModfile(dir string) (string, error) {
	tsDir, err := patchedTailscale()
	if err != nil {
		return "", err
	}
	gomod, err := goList("{{.GoMod}}", "github.com/tailscale/tailcat")
	if err != nil {
		return "", err
	}
	mod, err := os.ReadFile(gomod)
	if err != nil {
		return "", err
	}
	sum, err := os.ReadFile(strings.TrimSuffix(gomod, ".mod") + ".sum")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	// go.mod paths use forward slashes on every platform.
	mod = fmt.Appendf(mod, "\n// Added by internal/wasmbuild: tailscale.com with the magicsock packet path hook.\nreplace tailscale.com => %s\n", filepath.ToSlash(tsDir))
	modfile := filepath.Join(dir, "tailcat-packetpath.mod")
	if err := os.WriteFile(modfile, mod, 0644); err != nil {
		return "", err
	}
	if err := os.WriteFile(strings.TrimSuffix(modfile, ".mod")+".sum", sum, 0644); err != nil {
		return "", err
	}
	return modfile, nil
}
