// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wasmbuild

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
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

// derpShedSource is the derphttp file the patch adds.
//
//go:embed magicsockpatch/derpshed.go.in
var derpShedSource []byte

// patchFiles are the files the patch adds to tailscale.com, by path in
// the module.
var patchFiles = []struct {
	path string
	src  *[]byte
}{
	{"wgengine/magicsock/packetpath.go", &packetPathSource},
	{"derp/derphttp/derpshed.go", &derpShedSource},
}

// magicsockEdit is one insertion into a tailscale.com file. The anchor
// must occur exactly once; text is inserted immediately before or after
// it.
type magicsockEdit struct {
	file   string // path in the tailscale.com module
	anchor string
	text   string
	before bool // insert before the anchor instead of after it
}

// packetPathEdits wire packetpath.go into magicsock, and derpshed.go
// into derphttp. They are kept to the minimum the hooks need so that a
// tailscale.com upgrade rarely disturbs them; if one does,
// PacketPathModfile fails, naming it.
var packetPathEdits = []magicsockEdit{
	{
		// The Conn's packet path state.
		file:   "wgengine/magicsock/magicsock.go",
		anchor: "\tderpRecvCh chan derpReadResult\n",
		text:   "\n\t// packetPaths are embedder-supplied peer paths; see packetpath.go.\n\tpacketPaths packetPathState\n",
	},
	{
		// connBind.Open: also receive from packet paths.
		file:   "wgengine/magicsock/magicsock.go",
		anchor: "\treturn fns, c.LocalPort(), nil\n",
		text:   "\tfns = append(fns, c.receivePacketPath)\n",
		before: true,
	},
	{
		// connBind.Close: wake a receivePacketPath waiting for a datagram.
		file:   "wgengine/magicsock/magicsock.go",
		anchor: "\tc.derpRecvCh <- derpReadResult{}\n",
		text:   "\tc.wakePacketPathRecv()\n",
	},
	{
		// endpoint.send: offer datagrams to the peer's packet path
		// first, after the send has been noted for idle tracking.
		file:   "wgengine/magicsock/endpoint.go",
		anchor: "\tde.lastSendAny = now\n\tde.mu.Unlock()\n",
		text: "\n\tif n := de.c.sendPacketPath(de.publicKey, buffs, offset); n > 0 {\n" +
			"\t\tbuffs = buffs[n:]\n" +
			"\t\tif len(buffs) == 0 {\n" +
			"\t\t\treturn nil\n" +
			"\t\t}\n" +
			"\t}\n",
	},
	{
		// derphttp.Client.Send: let the connection's queue shed the
		// datagram (see derpshed.go) once connected.
		file:   "derp/derphttp/derphttp_client.go",
		anchor: "\tif err := client.Send(dstKey, b); err != nil {\n",
		text:   "\tif c.shedPacket(len(b)) {\n\t\treturn nil\n\t}\n",
		before: true,
	},
}

// goCommand returns a go command, with any extra environment, that
// resolves modules from the tailcat module alone. A go.work that also
// held, say, a tailscale.com checkout would otherwise take precedence
// over both the module cache copy patched here and the -modfile replace
// that points at it.
func goCommand(env []string, args ...string) *exec.Cmd {
	cmd := exec.Command("go", args...)
	cmd.Env = append(append(os.Environ(), "GOWORK=off"), env...)
	return cmd
}

// downloadModule returns the version of module mod that the main module
// in the current directory requires, and the module cache directory
// holding it, downloading it first if needed. ("go list -m" would
// report an empty directory for a module not yet downloaded, as in a
// fresh clone.)
func downloadModule(mod string) (version, dir string, err error) {
	out, err := goCommand(nil, "mod", "download", "-json", mod).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", "", fmt.Errorf("go mod download %s: %v\n%s%s", mod, err, out, ee.Stderr)
		}
		return "", "", fmt.Errorf("go mod download %s: %w", mod, err)
	}
	var m struct {
		Version, Dir, Error string
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return "", "", fmt.Errorf("go mod download %s: %w", mod, err)
	}
	if m.Error != "" {
		return "", "", fmt.Errorf("go mod download %s: %s", mod, m.Error)
	}
	if m.Version == "" || m.Dir == "" {
		return "", "", fmt.Errorf("go mod download %s: no version or directory in %s", mod, out)
	}
	return m.Version, m.Dir, nil
}

// applyEdits returns src with every edit for file applied.
func applyEdits(file string, src []byte, edits []magicsockEdit) ([]byte, error) {
	s := string(src)
	for _, e := range edits {
		if e.file != file {
			continue
		}
		if n := strings.Count(s, e.anchor); n != 1 {
			return nil, fmt.Errorf("tailscale.com packet path patch: anchor %q occurs %d times in %s, want 1; did the tailscale.com dependency change? Update internal/wasmbuild/packetpath.go", e.anchor, n, file)
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
	for _, f := range patchFiles {
		fmt.Fprintf(h, "%q\n", f.path)
		h.Write(*f.src)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// patchDir is where, under the tailcat module's root, the patched
// tailscale.com copies live. The go command skips directories whose
// names begin with a dot, so ./... never includes them; .gitignore
// lists it.
const patchDir = ".wasmbuild"

// patchedTailscale returns the path, relative to the module root
// modRoot, of a copy of the tailscale.com module that tailcat requires
// with the magicsock packet path patch applied. The go command forbids
// overlaying files in the module cache, so the patch is applied to a
// copy instead. The copy is keyed by module version and patch content,
// so builds reuse it (and their build cache stays warm). It lives
// inside the module so the replace directive can name it relatively:
// the binary's build information records that path, and an absolute
// one would name the build machine's directories even under -trimpath.
func patchedTailscale(modRoot string) (string, error) {
	version, srcDir, err := downloadModule("tailscale.com")
	if err != nil {
		return "", err
	}
	parent := filepath.Join(modRoot, patchDir)
	name := "tailscale.com@" + version + "-pp" + patchHash()
	rel := "./" + patchDir + "/" + name
	dst := filepath.Join(parent, name)
	if _, err := os.Stat(filepath.Join(dst, "go.mod")); err == nil {
		return rel, nil
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
	var edited []string
	for _, e := range packetPathEdits {
		if !slices.Contains(edited, e.file) {
			edited = append(edited, e.file)
		}
	}
	for _, name := range edited {
		p := filepath.Join(tmp, filepath.FromSlash(name))
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
	for _, f := range patchFiles {
		if err := os.WriteFile(filepath.Join(tmp, filepath.FromSlash(f.path)), *f.src, 0644); err != nil {
			return "", err
		}
	}
	// On Windows a rename can fail for a moment while something (an
	// antivirus scanner, an indexer) still holds a file just written.
	for attempt := 1; ; attempt++ {
		err := os.Rename(tmp, dst)
		if err == nil {
			return rel, nil
		}
		if _, statErr := os.Stat(filepath.Join(dst, "go.mod")); statErr == nil {
			return rel, nil // a concurrent build won the race
		}
		if attempt == 5 {
			return "", err
		}
		time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
	}
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
// [PacketPathTag], and with GOWORK=off.
func PacketPathModfile(dir string) (string, error) {
	out, err := goCommand(nil, "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		return "", fmt.Errorf("go env GOMOD: not in a module")
	}
	// Relative replace paths resolve against the main module's root,
	// whichever file -modfile names.
	tsDir, err := patchedTailscale(filepath.Dir(gomod))
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
	mod = fmt.Appendf(mod, "\n// Added by internal/wasmbuild: tailscale.com with the magicsock packet path hook.\nreplace tailscale.com => %s\n", strconv.Quote(tsDir))
	modfile := filepath.Join(dir, "tailcat-packetpath.mod")
	if err := os.WriteFile(modfile, mod, 0644); err != nil {
		return "", err
	}
	if err := os.WriteFile(strings.TrimSuffix(modfile, ".mod")+".sum", sum, 0644); err != nil {
		return "", err
	}
	return modfile, nil
}
