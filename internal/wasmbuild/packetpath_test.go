// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wasmbuild

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyEdits(t *testing.T) {
	edits := []magicsockEdit{
		{file: "a.go", anchor: "B\n", text: "after\n"},
		{file: "a.go", anchor: "D\n", text: "before\n", before: true},
		{file: "b.go", anchor: "X", text: "never"},
	}
	got, err := applyEdits("a.go", []byte("A\nB\nC\nD\n"), edits)
	if err != nil {
		t.Fatal(err)
	}
	if want := "A\nB\nafter\nC\nbefore\nD\n"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, src := range []string{"A\n", "B\nB\nD\n"} {
		if _, err := applyEdits("a.go", []byte(src), edits); err == nil {
			t.Errorf("applyEdits(%q) succeeded; want missing or duplicate anchor error", src)
		}
	}
}

// TestPacketPathModfile checks that the magicsock packet path edits
// still apply to the tailscale.com version in go.mod, and that the
// patched magicsock builds and passes the root package's packet path
// tests (which need the patch and so don't run in plain go test).
func TestPacketPathModfile(t *testing.T) {
	modfile, err := PacketPathModfile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The replace path ends up in the binary's build information, so it
	// must not name the build machine's directories.
	mod, err := os.ReadFile(modfile)
	if err != nil {
		t.Fatal(err)
	}
	if want := `replace tailscale.com => "./` + patchDir + `/`; !strings.Contains(string(mod), want) {
		t.Errorf("modfile has no relative replace %q:\n%s", want, mod)
	}
	if testing.Short() {
		t.Skip("skipping the patched build and packet path tests in -short mode")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		env  []string
		args []string
	}{
		// The browser build is what uses the patch; ./web is js-only.
		{[]string{"GOOS=js", "GOARCH=wasm"}, []string{"vet", "-tags", PacketPathTag, "-modfile", modfile, ".", "./web"}},
		{nil, []string{"test", "-count=1", "-tags", PacketPathTag, "-modfile", modfile, "-run", "PacketPath|NetworkChanged", "."}},
	} {
		args := step.args
		cmd := goCommand(step.env, args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		t.Logf("go %s:\n%s", strings.Join(args, " "), out)
	}
}
