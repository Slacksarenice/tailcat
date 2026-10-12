// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Headless-browser integration tests for the tailcat web app. They
// build the js/wasm binary, serve the page from an httptest server
// alongside a local websocket-capable DERP server, and drive a real
// headless Chrome via chromedp, exchanging files in both directions
// with the Go tailcat library.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/page"
	cdpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/tailscale/tailcat"
	"github.com/tailscale/tailcat/internal/wasmbuild"
	"github.com/tailscale/tailcat/webdemo"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var runHeadlessBrowserTests = flag.Bool("run-headless-browser-tests", false,
	"run tests that require a headless browser (Chromium / Google Chrome)")

var webVerbose = flag.Bool("web-verbose", false,
	"have the WebRTC tests' pages log tailcat's debug output to the console (and so the test log)")

// withVerbose adds the page's verbose parameter to q if --web-verbose is set.
func withVerbose(q url.Values) url.Values {
	if *webVerbose {
		q.Set("verbose", "1")
	}
	return q
}

const transferSize = 2 << 20 // bytes sent in each direction's test

func mkLogf(t testing.TB, name string) logger.Logf {
	return func(format string, args ...any) {
		t.Helper()
		if t.Failed() {
			return
		}
		t.Logf("["+name+"] "+format, args...)
	}
}

// preflight skips the test unless --run-headless-browser-tests is
// set, and returns the path to a Chromium-family binary, failing the
// test if none is found.
func preflight(t *testing.T) (chromiumBin string) {
	t.Helper()
	if !*runHeadlessBrowserTests {
		t.Skip("skipping headless-browser test; set --run-headless-browser-tests to run")
	}
	bin := findChromium()
	if bin == "" {
		t.Fatalf("no chromium / chromium-browser / google-chrome binary in $PATH " +
			"(set $CHROME_BIN to override)")
	}
	return bin
}

func findChromium() string {
	if p := os.Getenv("CHROME_BIN"); p != "" {
		return p
	}
	for _, name := range []string{
		"chromium",
		"chromium-browser",
		"google-chrome",
		"google-chrome-stable",
		"chrome",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	if runtime.GOOS == "darwin" {
		// On macOS, Chrome installs as an .app bundle whose
		// executable is not on $PATH.
		for _, p := range []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// buildDist builds the web app's dist directory once per test
// process and returns its path.
var buildDist = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "tailcat-wasm-test")
	if err != nil {
		return "", err
	}
	if err := wasmbuild.Dist(".", dir); err != nil {
		return "", err
	}
	return dir, nil
})

// renumberRegion returns a copy of dm with its single region 1
// renumbered to newID. Tests pass an arbitrary ID (at most the DERP
// maximum of 999) so that the browser's region auto-selection can't
// get away with assuming small region IDs exist, as it once did.
func renumberRegion(t *testing.T, dm *tailcfg.DERPMap, newID tailcfg.DERPRegionID) *tailcfg.DERPMap {
	t.Helper()
	j, err := json.Marshal(dm)
	if err != nil {
		t.Fatal(err)
	}
	cp := new(tailcfg.DERPMap)
	if err := json.Unmarshal(j, cp); err != nil {
		t.Fatal(err)
	}
	reg, ok := cp.Regions[1]
	if !ok {
		t.Fatalf("no region 1 in test DERP map")
	}
	delete(cp.Regions, 1)
	reg.RegionID = newID
	for _, n := range reg.Nodes {
		n.RegionID = newID
	}
	cp.Regions[newID] = reg
	return cp
}

// newWebServer serves the web app's freshly built dist directory via
// webdemo.Handler (the same handler production servers use), plus a
// same-origin /derpmap.json describing the local test DERP server.
func newWebServer(t *testing.T, dm *tailcfg.DERPMap) *httptest.Server {
	t.Helper()
	distDir, err := buildDist()
	if err != nil {
		t.Fatalf("building dist: %v", err)
	}
	app, err := webdemo.Handler(os.DirFS(distDir))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", app)
	mux.HandleFunc("/derpmap.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dm)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// launchChrome boots a headless Chrome under chromedp and returns a
// context whose cancellation tears down the browser.
func launchChrome(t *testing.T, bin string, extra ...chromedp.ExecAllocatorOption) context.Context {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(bin),
		chromedp.Flag("headless", "new"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		// The test DERP server uses a self-signed TLS cert.
		chromedp.Flag("ignore-certificate-errors", true),
		// For WebRTC between tabs: offer real host addresses
		// rather than mDNS .local names, which headless machines
		// often can't resolve (keeping chromedp's defaults), and
		// loopback on machines with no other interface.
		chromedp.Flag("disable-features", "site-per-process,Translate,BlinkGenPropertyTrees,WebRtcHideLocalIpsWithMdns"),
		chromedp.Flag("allow-loopback-in-peer-connection", true),
	)
	opts = append(opts, extra...)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(t.Context(), opts...)
	t.Cleanup(cancelAlloc)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithLogf(t.Logf))
	t.Cleanup(cancelBrowser)
	logConsole(t, browserCtx, "chrome")
	return browserCtx
}

// newTab opens another tab in the browser of ctx, logging its console
// output under name.
func newTab(t *testing.T, ctx context.Context, name string) context.Context {
	t.Helper()
	tabCtx, cancel := chromedp.NewContext(ctx)
	t.Cleanup(cancel)
	logConsole(t, tabCtx, name)
	allocate(t, tabCtx)
	return tabCtx
}

// allocate starts the browser or opens the tab of ctx, which chromedp
// otherwise does on the first Run, tying it to the context passed
// there: a step's timeout context would close it when the step ends.
func allocate(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := chromedp.Run(ctx); err != nil {
		t.Fatalf("starting browser tab: %v", err)
	}
}

// logConsole pipes the console output and uncaught exceptions of the
// tab of ctx into the test log, prefixed with name.
func logConsole(t *testing.T, ctx context.Context, name string) {
	chromedp.ListenTarget(ctx, func(ev any) {
		switch ev := ev.(type) {
		case *cdpruntime.EventConsoleAPICalled:
			var sb strings.Builder
			for i, arg := range ev.Args {
				if i > 0 {
					sb.WriteByte(' ')
				}
				if len(arg.Value) > 0 {
					sb.Write(arg.Value)
				} else {
					sb.WriteString(arg.Description)
				}
			}
			t.Logf("[%s console.%s] %s", name, ev.Type, sb.String())
		case *cdpruntime.EventExceptionThrown:
			t.Logf("[%s exception] %s", name, ev.ExceptionDetails.Text)
		}
	})
}

func checkPageErrors(t *testing.T, runCtx context.Context) {
	t.Helper()
	var pageErrors []string
	if err := chromedp.Run(runCtx,
		chromedp.Evaluate("window.tcTest.errors", &pageErrors),
	); err != nil {
		t.Fatalf("chromedp evaluate errors: %v", err)
	}
	for _, e := range pageErrors {
		t.Errorf("page error: %s", e)
	}
}

// TestBrowserReceives has the browser listen and a Go tailcat client
// send it random bytes, netcat style, verifying the browser received
// exactly what was sent.
func TestBrowserReceives(t *testing.T) {
	bin := preflight(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, renumberRegion(t, dm, 909))

	browserCtx := launchChrome(t, bin)
	runCtx, cancelRun := context.WithTimeout(browserCtx, 120*time.Second)
	t.Cleanup(cancelRun)

	pageURL := srv.URL + "/?" + url.Values{
		"mode": {"listen"},
		"sink": {"hash"},
	}.Encode()
	t.Logf("navigating to %s", pageURL)

	var (
		gotAddr  bool
		addr     string
		listenOK bool
	)
	if err := chromedp.Run(runCtx,
		chromedp.Navigate(pageURL),
		chromedp.Poll("window.tcTest && window.tcTest.listenAddr !== null", &gotAddr,
			chromedp.WithPollingTimeout(90*time.Second)),
		chromedp.Evaluate("window.tcTest.listenAddr", &addr),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	listenOK = gotAddr && strings.HasPrefix(addr, "tc")
	if !listenOK {
		t.Fatalf("browser listener never produced an address (gotAddr=%v addr=%q)", gotAddr, addr)
	}
	t.Logf("browser listening at %v", addr)

	cl := &tailcat.Client{
		Server:     tailcat.Addr(addr),
		Logf:       mkLogf(t, "client"),
		DERPMapURL: srv.URL + "/derpmap.json",
	}
	t.Cleanup(func() { cl.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	for {
		pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := cl.Ping(pctx)
		pcancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("Ping never succeeded: %v", err)
		}
	}

	conn, err := cl.DialTCPPort(ctx, 1)
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	data := make([]byte, transferSize)
	rand.Read(data)
	wantSum := sha256.Sum256(data)
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	// The browser's close confirms delivery of everything we sent.
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("reading to EOF: %v", err)
	}

	var (
		recvDone  bool
		recvBytes int
		recvSum   string
	)
	if err := chromedp.Run(runCtx,
		chromedp.Poll("window.tcTest.recvDone === true", &recvDone,
			chromedp.WithPollingTimeout(60*time.Second)),
		chromedp.Evaluate("window.tcTest.recvBytes", &recvBytes),
		chromedp.Evaluate("window.tcTest.recvSha256", &recvSum),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if recvBytes != transferSize {
		t.Errorf("browser received %v bytes; want %v", recvBytes, transferSize)
	}
	if want := hex.EncodeToString(wantSum[:]); recvSum != want {
		t.Errorf("browser received sha256 %v; want %v", recvSum, want)
	}
	checkPageErrors(t, runCtx)
}

// TestBrowserSends has a Go tailcat server listen and the browser
// dial it and send random bytes, verifying the server received
// exactly what the browser sent.
func TestBrowserSends(t *testing.T) {
	bin := preflight(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)

	s := &tailcat.Server{Logf: mkLogf(t, "server"), Region: dm.Regions[1]}
	t.Cleanup(func() { s.Close() })

	type recvResult struct {
		n   int64
		sum string
	}
	recvc := make(chan recvResult, 1)
	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		return func(c net.Conn) {
			defer c.Close()
			h := sha256.New()
			n, err := io.Copy(h, c)
			if err != nil {
				t.Errorf("server read: %v", err)
			}
			select {
			case recvc <- recvResult{n, hex.EncodeToString(h.Sum(nil))}:
			default:
			}
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Server.Start: %v", err)
	}
	addr := s.TailcatAddr()
	t.Logf("Go server listening at %v", addr)

	browserCtx := launchChrome(t, bin)
	runCtx, cancelRun := context.WithTimeout(browserCtx, 120*time.Second)
	t.Cleanup(cancelRun)

	pageURL := srv.URL + "/?" + url.Values{
		"mode":  {"send"},
		"addr":  {string(addr)},
		"bytes": {strconv.Itoa(transferSize)},
	}.Encode()
	t.Logf("navigating to %s", pageURL)

	var sendDone bool
	if err := chromedp.Run(runCtx,
		chromedp.Navigate(pageURL),
		chromedp.Poll("window.tcTest.sendDone === true", &sendDone,
			chromedp.WithPollingTimeout(90*time.Second)),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}

	var got recvResult
	select {
	case got = <-recvc:
	case <-time.After(30 * time.Second):
		t.Fatal("Go server never finished receiving")
	}

	var (
		sentBytes int
		sentSum   string
	)
	if err := chromedp.Run(runCtx,
		chromedp.Evaluate("window.tcTest.sentBytes", &sentBytes),
		chromedp.Evaluate("window.tcTest.sentSha256", &sentSum),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if got.n != transferSize || sentBytes != transferSize {
		t.Errorf("server received %v bytes, browser sent %v; want %v", got.n, sentBytes, transferSize)
	}
	if got.sum != sentSum {
		t.Errorf("server received sha256 %v; browser sent %v", got.sum, sentSum)
	}
	checkPageErrors(t, runCtx)
}

// wasmMemScript, run in a page before its own scripts, notes the Go
// program's WebAssembly memory as the page instantiates it, so a test
// can read its size in bytes from window.tcWasmMemBytes() (-1 until
// the program is loaded).
const wasmMemScript = `(() => {
  let mem = null;
  const keep = (r) => {
    const inst = r.instance || r;
    if (inst.exports && inst.exports.mem) mem = inst.exports.mem;
    return r;
  };
  const inst = WebAssembly.instantiate, instS = WebAssembly.instantiateStreaming;
  WebAssembly.instantiate = (...a) => inst.apply(WebAssembly, a).then(keep);
  if (instS) WebAssembly.instantiateStreaming = (...a) => instS.apply(WebAssembly, a).then(keep);
  window.tcWasmMemBytes = () => mem ? mem.buffer.byteLength : -1;
})();`

// TestBrowserSendKeepsNoCopy sends a tab's worth of data to a Go
// server and checks that the tab's Go memory grew by well under what
// it sent. Each write copies its data into Go, so a write that kept
// its copy (as one did while its promise's callback was never
// released) would grow the memory by all of it, until the tab ran out.
func TestBrowserSendKeepsNoCopy(t *testing.T) {
	const size = 64 << 20
	bin := preflight(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)

	s := &tailcat.Server{Logf: mkLogf(t, "server"), Region: dm.Regions[1]}
	t.Cleanup(func() { s.Close() })
	recvc := make(chan int64, 1)
	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		return func(c net.Conn) {
			defer c.Close()
			n, err := io.Copy(io.Discard, c)
			if err != nil {
				t.Errorf("server read: %v", err)
			}
			select {
			case recvc <- n:
			default:
			}
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Server.Start: %v", err)
	}

	browserCtx := launchChrome(t, bin)
	runCtx, cancelRun := context.WithTimeout(browserCtx, 180*time.Second)
	t.Cleanup(cancelRun)

	var before, after, sentBytes int
	var ok bool
	run := func(name string, actions ...chromedp.Action) {
		t.Helper()
		if err := chromedp.Run(runCtx, actions...); err != nil {
			var state string
			ctx, cancel := context.WithTimeout(runCtx, 5*time.Second)
			chromedp.Run(ctx, chromedp.Evaluate(`JSON.stringify({tcTest: window.tcTest, mem: window.tcWasmMemBytes && window.tcWasmMemBytes()})`, &state))
			cancel()
			t.Fatalf("%s: %v (page: %s)", name, err, state)
		}
	}
	// The gate holds the data until the test has noted the memory the
	// page started with.
	run("loading the page",
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(wasmMemScript).Do(ctx)
			return err
		}),
		chromedp.Navigate(srv.URL+"/?"+url.Values{
			"mode":  {"send"},
			"addr":  {string(s.TailcatAddr())},
			"bytes": {strconv.Itoa(size)},
			"gate":  {""},
		}.Encode()),
		chromedp.Poll("window.tcTest && window.tcTest.ready === true", &ok,
			chromedp.WithPollingInterval(100*time.Millisecond), chromedp.WithPollingTimeout(120*time.Second)),
		chromedp.Evaluate("window.tcWasmMemBytes()", &before),
	)
	if before <= 0 {
		t.Fatalf("the page's Go memory reads %d; want its size", before)
	}
	run("sending",
		chromedp.Evaluate("window.tcTest.go = true", nil),
		chromedp.Poll("window.tcTest.sendDone === true", &ok,
			chromedp.WithPollingInterval(100*time.Millisecond), chromedp.WithPollingTimeout(150*time.Second)),
		chromedp.Evaluate("window.tcWasmMemBytes()", &after),
		chromedp.Evaluate("window.tcTest.sentBytes", &sentBytes),
	)

	select {
	case n := <-recvc:
		if n != size || sentBytes != size {
			t.Errorf("server received %d bytes, browser sent %d; want %d", n, sentBytes, size)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Go server never finished receiving")
	}
	t.Logf("the page's Go memory: %d MiB before sending %d MiB, %d MiB after", before>>20, size>>20, after>>20)
	if grew := after - before; grew > size/2 {
		t.Errorf("the page's Go memory grew by %d MiB over sending %d MiB; want under %d MiB", grew>>20, size>>20, size>>21)
	}
	checkPageErrors(t, runCtx)
}

// TestBrowserSendsTextUI drives the send form like a user: it types
// an address and a message into the page, clicks "Send text", and
// verifies a Go tailcat server receives exactly that text.
func TestBrowserSendsTextUI(t *testing.T) {
	bin := preflight(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)

	s := &tailcat.Server{Logf: mkLogf(t, "server"), Region: dm.Regions[1]}
	t.Cleanup(func() { s.Close() })

	recvc := make(chan string, 1)
	s.OnTCP = func(port uint16) (handler func(net.Conn)) {
		return func(c net.Conn) {
			defer c.Close()
			b, err := io.ReadAll(c)
			if err != nil {
				t.Errorf("server read: %v", err)
			}
			select {
			case recvc <- string(b):
			default:
			}
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Server.Start: %v", err)
	}
	addr := s.TailcatAddr()
	t.Logf("Go server listening at %v", addr)

	browserCtx := launchChrome(t, bin)
	runCtx, cancelRun := context.WithTimeout(browserCtx, 120*time.Second)
	t.Cleanup(cancelRun)

	const wantText = "meow 🐱 世界\nsecond line"
	var ready, sendDone bool
	if err := chromedp.Run(runCtx,
		chromedp.Navigate(srv.URL+"/"),
		chromedp.Poll("window.tcTest && window.tcTest.ready === true", &ready,
			chromedp.WithPollingTimeout(60*time.Second)),
		chromedp.SetValue("#send-addr", string(addr)),
		chromedp.SetValue("#send-text", wantText),
		chromedp.Click("#send-text-btn"),
		chromedp.Poll("window.tcTest.sendDone === true", &sendDone,
			chromedp.WithPollingTimeout(90*time.Second)),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}

	select {
	case got := <-recvc:
		if got != wantText {
			t.Errorf("server received %q; browser sent %q", got, wantText)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Go server never finished receiving")
	}
	checkPageErrors(t, runCtx)
}

// TestBrowserReceivesTextUI has the browser listen with the regular
// interface (not the test-mode hash sink), sends it text from a Go
// tailcat client, clicks the incoming connection's "Show as text"
// button, and verifies the page displays the text.
func TestBrowserReceivesTextUI(t *testing.T) {
	bin := preflight(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)

	browserCtx := launchChrome(t, bin)
	runCtx, cancelRun := context.WithTimeout(browserCtx, 120*time.Second)
	t.Cleanup(cancelRun)

	var gotAddr bool
	var addr string
	if err := chromedp.Run(runCtx,
		chromedp.Navigate(srv.URL+"/?mode=listen"),
		chromedp.Poll("window.tcTest && window.tcTest.listenAddr !== null", &gotAddr,
			chromedp.WithPollingTimeout(90*time.Second)),
		chromedp.Evaluate("window.tcTest.listenAddr", &addr),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if !gotAddr || !strings.HasPrefix(addr, "tc") {
		t.Fatalf("browser listener never produced an address (gotAddr=%v addr=%q)", gotAddr, addr)
	}
	t.Logf("browser listening at %v", addr)

	cl := &tailcat.Client{
		Server:     tailcat.Addr(addr),
		Logf:       mkLogf(t, "client"),
		DERPMapURL: srv.URL + "/derpmap.json",
	}
	t.Cleanup(func() { cl.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	for {
		pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := cl.Ping(pctx)
		pcancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("Ping never succeeded: %v", err)
		}
	}

	const wantText = "purr 🐈\nover DERP"
	conn, err := cl.DialTCPPort(ctx, 1)
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	if _, err := conn.Write([]byte(wantText)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	var shown bool
	var gotText string
	if err := chromedp.Run(runCtx,
		chromedp.WaitVisible(`//button[text()="Show as text"]`),
		chromedp.Click(`//button[text()="Show as text"]`),
		chromedp.Poll(`document.querySelector("#incoming .recv-text") !== null`, &shown,
			chromedp.WithPollingTimeout(60*time.Second)),
		chromedp.Evaluate(`document.querySelector("#incoming .recv-text").textContent`, &gotText),
	); err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if gotText != wantText {
		t.Errorf("page shows %q; client sent %q", gotText, wantText)
	}

	// The browser's close after draining confirms delivery.
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("reading to EOF: %v", err)
	}
	checkPageErrors(t, runCtx)
}

// runStoppableDERP runs a local DERP server (WebSocket-capable, with
// no STUN) that, unlike integration.RunDERPAndSTUN's, the test can
// stop midway with the returned func.
func runStoppableDERP(t *testing.T) (dm *tailcfg.DERPMap, stop func()) {
	t.Helper()
	d := derpserver.New(key.NewNode(), mkLogf(t, "derp"))
	httpsrv := httptest.NewUnstartedServer(derpserver.AddWebSocketSupport(d, derpserver.Handler(d)))
	httpsrv.Config.ErrorLog = logger.StdLogger(mkLogf(t, "derp-http"))
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()
	dm = &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{{
					Name:             "t1",
					RegionID:         1,
					HostName:         "127.0.0.1",
					IPv4:             "127.0.0.1",
					IPv6:             "none",
					STUNPort:         -1,
					DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
					InsecureForTests: true,
				}},
			},
		},
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			// Closing the DERP server drops its clients' connections,
			// which the HTTP server stopped tracking at the WebSocket
			// upgrade.
			d.Close()
			httpsrv.Close()
		})
	}
	t.Cleanup(stop)
	return dm, stop
}

// tabPair is the two tabs of a browser-to-browser test.
type tabPair struct {
	t            *testing.T
	listen, send context.Context
}

// newTabPair launches a browser for a browser-to-browser test, whose
// first tab is the listener's.
func newTabPair(t *testing.T) *tabPair {
	bin := preflight(t)
	browserCtx := launchChrome(t, bin)
	allocate(t, browserCtx)
	return &tabPair{t: t, listen: browserCtx}
}

// step runs actions in tab, failing the test with name if they don't
// finish within timeout, and logging both tabs' test state to explain
// why. The deadline is the test's own: a chromedp poll's timeout runs
// on the page's timers, which Chrome may throttle in a background tab.
func (p *tabPair) step(tab context.Context, name string, timeout time.Duration, actions ...chromedp.Action) {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(tab, timeout)
	defer cancel()
	if err := chromedp.Run(ctx, actions...); err != nil {
		p.logState()
		p.t.Fatalf("%s: %v", name, err)
	}
}

// logState logs each open tab's window.tcTest, and its
// window.tailcatTestHooks if it has them.
func (p *tabPair) logState() {
	for _, tab := range []struct {
		name string
		ctx  context.Context
	}{{"listener", p.listen}, {"sender", p.send}} {
		if tab.ctx == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(tab.ctx, 5*time.Second)
		var state string
		err := chromedp.Run(ctx, chromedp.Evaluate(`JSON.stringify(window.tcTest) + " hooks: " + JSON.stringify(window.tailcatTestHooks)`, &state))
		cancel()
		p.t.Logf("%s tab tcTest: %s (err: %v)", tab.name, state, err)
	}
}

// poll waits for the JavaScript expression expr to be true, checking
// every 100ms rather than on each animation frame, which a background
// tab never draws.
func poll(expr string) chromedp.Action {
	var ok bool
	return chromedp.Poll(expr, &ok, chromedp.WithPollingInterval(100*time.Millisecond))
}

// listenTab opens the page in listen mode in the listener's tab, with
// the given extra query parameters, and returns its address.
func (p *tabPair) listenTab(srv *httptest.Server, extra url.Values) string {
	p.t.Helper()
	q := url.Values{"mode": {"listen"}, "sink": {"hash"}}
	for k, v := range extra {
		q[k] = v
	}
	var addr string
	p.step(p.listen, "listener", 90*time.Second,
		chromedp.Navigate(srv.URL+"/?"+withVerbose(q).Encode()),
		poll("window.tcTest && window.tcTest.listenAddr !== null"),
		chromedp.Evaluate("window.tcTest.listenAddr", &addr),
	)
	if !strings.HasPrefix(addr, "tc") {
		p.t.Fatalf("listener produced no address: %q", addr)
	}
	return addr
}

// checkTransfer waits for the listening tab to receive the sending
// tab's transfer of transferSize bytes and checks it arrived intact.
func (p *tabPair) checkTransfer() {
	p.t.Helper()
	p.checkTransferOf(transferSize)
}

// checkTransferOf is checkTransfer for a transfer of size bytes.
func (p *tabPair) checkTransferOf(size int) {
	p.t.Helper()
	var recvBytes int
	var recvSum, sentSum string
	p.step(p.listen, "receiving", 90*time.Second,
		poll("window.tcTest.recvDone === true"),
		chromedp.Evaluate("window.tcTest.recvBytes", &recvBytes),
		chromedp.Evaluate("window.tcTest.recvSha256", &recvSum),
	)
	p.step(p.send, "sending", 30*time.Second,
		poll("window.tcTest.sendDone === true"),
		chromedp.Evaluate("window.tcTest.sentSha256", &sentSum),
	)
	if recvBytes != size {
		p.t.Errorf("listener received %d bytes; want %d", recvBytes, size)
	}
	if recvSum != sentSum {
		p.t.Errorf("listener received sha256 %s; sender sent %s", recvSum, sentSum)
	}
	checkPageErrors(p.t, p.listen)
	checkPageErrors(p.t, p.send)
}

// TestBrowserToBrowserWebRTC has one tab listen and another dial it,
// both with WebRTC enabled, waits for their tunnel to move to a
// direct WebRTC path, then stops the DERP server before sending: the
// transfer can only complete over WebRTC.
func TestBrowserToBrowserWebRTC(t *testing.T) {
	p := newTabPair(t)
	dm, stopDERP := runStoppableDERP(t)
	srv := newWebServer(t, dm)

	addr := p.listenTab(srv, url.Values{"webrtc": {"host"}})
	t.Logf("listener at %v", addr)

	p.send = newTab(t, p.listen, "sender")
	p.step(p.send, "sender reaching a WebRTC path", 90*time.Second,
		chromedp.Navigate(srv.URL+"/?"+withVerbose(url.Values{
			"mode":     {"send"},
			"addr":     {addr},
			"bytes":    {strconv.Itoa(transferSize)},
			"webrtc":   {"host"},
			"waitpath": {"webrtc"},
			"gate":     {""},
		}).Encode()),
		poll(`window.tcTest && window.tcTest.path === "webrtc"`),
	)
	p.step(p.listen, "listener reaching a WebRTC path", 30*time.Second,
		poll(`window.tcTest.path === "webrtc"`),
	)

	t.Logf("both tabs report a WebRTC path; stopping DERP")
	stopDERP()
	p.step(p.send, "starting the send", 10*time.Second,
		chromedp.Evaluate("window.tcTest.go = true", nil),
	)
	p.checkTransfer()
}

// TestBrowserCloseDoesNotBlock closes a listener the moment it is up,
// while its first relay probes are still in flight, and checks that
// the page keeps running. Waiting for those probes inside the call
// would hold the event loop they need to end, freezing the page.
func TestBrowserCloseDoesNotBlock(t *testing.T) {
	bin := preflight(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)

	browserCtx := launchChrome(t, bin)
	runCtx, cancelRun := context.WithTimeout(browserCtx, 90*time.Second)
	t.Cleanup(cancelRun)

	var ready bool
	if err := chromedp.Run(runCtx,
		chromedp.Navigate(srv.URL+"/"),
		chromedp.Poll("window.tcTest && window.tcTest.ready === true", &ready,
			chromedp.WithPollingTimeout(60*time.Second)),
	); err != nil {
		t.Fatalf("loading the page: %v", err)
	}

	var got struct {
		Promises bool `json:"promises"`
		Ticks    int  `json:"ticks"`
	}
	ctx, cancel := context.WithTimeout(runCtx, 30*time.Second)
	defer cancel()
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(async () => {
		const l = await tailcatListen({derpMapURL: location.origin + "/derpmap.json", onConnection() {}});
		let ticks = 0;
		const iv = setInterval(() => ticks++, 10);
		const d = l.disconnect("nodekey:0000000000000000000000000000000000000000000000000000000000000000");
		const c = l.close();
		const promises = typeof d?.then === "function" && typeof c?.then === "function";
		await Promise.all([d, c]);
		await new Promise((resolve) => setTimeout(resolve, 500));
		clearInterval(iv);
		return {promises, ticks};
	})()`, &got, func(p *cdpruntime.EvaluateParams) *cdpruntime.EvaluateParams {
		return p.WithAwaitPromise(true)
	})); err != nil {
		t.Fatalf("closing the listener (a frozen page times out here): %v", err)
	}
	if !got.Promises {
		t.Errorf("disconnect and close returned something other than Promises")
	}
	if got.Ticks == 0 {
		t.Errorf("no timer fired in the 500ms after close")
	}
}

// TestBrowserDialBadAddrDoesNotBlock dials two addresses no client can
// use and checks that the page keeps running. One doesn't parse, and is
// refused at once. The other, a legacy address, parses, but its client
// fails to start on every attempt, without blocking: retrying that with
// no pause would hold the page's thread until the dial timed out.
func TestBrowserDialBadAddrDoesNotBlock(t *testing.T) {
	bin := preflight(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)

	browserCtx := launchChrome(t, bin)
	runCtx, cancelRun := context.WithTimeout(browserCtx, 90*time.Second)
	t.Cleanup(cancelRun)

	var ready bool
	if err := chromedp.Run(runCtx,
		chromedp.Navigate(srv.URL+"/"),
		chromedp.Poll("window.tcTest && window.tcTest.ready === true", &ready,
			chromedp.WithPollingTimeout(60*time.Second)),
	); err != nil {
		t.Fatalf("loading the page: %v", err)
	}

	legacy := (&tailcat.ConnInfo{
		ServerPublic: tailcat.NodePublic{NodePublic: key.NewNode().Public()},
		RegionID:     1,
	}).Addr()
	var got struct {
		Malformed   string  `json:"malformed"`
		MalformedMs float64 `json:"malformedMs"`
		Ticks       int     `json:"ticks"`
	}
	ctx, cancel := context.WithTimeout(runCtx, 30*time.Second)
	defer cancel()
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(async () => {
		const derpMapURL = location.origin + "/derpmap.json";
		const t0 = performance.now();
		let malformed = "resolved";
		try {
			await tailcatDial({addr: "tc" + "A".repeat(40), derpMapURL});
		} catch (e) {
			malformed = String(e);
		}
		const malformedMs = performance.now() - t0;
		let ticks = 0;
		const iv = setInterval(() => ticks++, 10);
		tailcatDial({addr: `+strconv.Quote(string(legacy))+`, derpMapURL}).catch(() => {});
		await new Promise((resolve) => setTimeout(resolve, 2000));
		clearInterval(iv);
		return {malformed, malformedMs, ticks};
	})()`, &got, func(p *cdpruntime.EvaluateParams) *cdpruntime.EvaluateParams {
		return p.WithAwaitPromise(true)
	})); err != nil {
		t.Fatalf("dialing (a frozen page times out here): %v", err)
	}
	if !strings.Contains(got.Malformed, "invalid addr") {
		t.Errorf("dialing a malformed address: %q; want an invalid addr error", got.Malformed)
	}
	if got.MalformedMs > 5000 {
		t.Errorf("dialing a malformed address took %.0fms to fail; want it refused at once", got.MalformedMs)
	}
	// 200 if the 10ms timer ran on time throughout.
	if got.Ticks < 50 {
		t.Errorf("timers fired %d times in the 2s after dialing a legacy address; want the page to keep running", got.Ticks)
	}
}

// TestBrowserWebRTCListenerOff has a WebRTC-enabled tab dial a tab
// listening with WebRTC off: the dialer finds no signaling service and
// the transfer completes over DERP.
func TestBrowserWebRTCListenerOff(t *testing.T) {
	p := newTabPair(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)

	addr := p.listenTab(srv, nil)
	p.send = newTab(t, p.listen, "sender")
	p.step(p.send, "sender", 30*time.Second,
		chromedp.Navigate(srv.URL+"/?"+withVerbose(url.Values{
			"mode":   {"send"},
			"addr":   {addr},
			"bytes":  {strconv.Itoa(transferSize)},
			"webrtc": {"host"},
			"hooks":  {""},
		}).Encode()),
	)
	p.checkTransfer()
	var path string
	p.step(p.send, "reading the path", 10*time.Second,
		chromedp.Evaluate(`String(window.tcTest.path)`, &path),
	)
	if path == "webrtc" {
		t.Errorf("sender reports a WebRTC path to a listener with WebRTC off")
	}
	// The listener refuses the signaling port, which says WebRTC is off
	// there for good: the dialer stops asking rather than retrying as
	// it would a dial that never reached the listener.
	p.step(p.send, "the dialer giving up on WebRTC", 30*time.Second,
		poll(`window.tailcatTestHooks.client === "stopped: refused"`),
	)
}

// webrtcTabs opens a listener and a sender, both with WebRTC (host
// candidates only) and the test hooks, the sender holding a transfer of
// size bytes until the test sets tcTest.go, and waits for both to
// report a WebRTC path.
func (p *tabPair) webrtcTabs(srv *httptest.Server, size int) {
	p.t.Helper()
	addr := p.listenTab(srv, url.Values{"webrtc": {"host"}, "hooks": {""}})
	p.send = newTab(p.t, p.listen, "sender")
	p.step(p.send, "sender reaching a WebRTC path", 90*time.Second,
		chromedp.Navigate(srv.URL+"/?"+withVerbose(url.Values{
			"mode":     {"send"},
			"addr":     {addr},
			"bytes":    {strconv.Itoa(size)},
			"webrtc":   {"host"},
			"waitpath": {"webrtc"},
			"gate":     {""},
			"hooks":    {""},
		}).Encode()),
		poll(`window.tcTest && window.tcTest.path === "webrtc"`),
	)
	p.step(p.listen, "listener reaching a WebRTC path", 30*time.Second,
		poll(`window.tcTest.path === "webrtc"`),
	)
}

// eachTab runs actions in both tabs, the listener's first.
func (p *tabPair) eachTab(name string, timeout time.Duration, actions ...chromedp.Action) {
	p.t.Helper()
	p.step(p.listen, "listener: "+name, timeout, actions...)
	p.step(p.send, "sender: "+name, timeout, actions...)
}

// checkSameSession checks that each tab's traffic is back on the WebRTC
// path it first qualified, the session never having ended: its reports
// alternate between "webrtc" and "derp" (traffic moving off a quiet path
// and back), ending on "webrtc", and the path qualified only once.
func (p *tabPair) checkSameSession() {
	p.t.Helper()
	for _, tab := range []struct {
		name string
		ctx  context.Context
	}{{"listener", p.listen}, {"sender", p.send}} {
		var paths []string
		var qualified int
		p.step(tab.ctx, tab.name+": reading the paths reported", 10*time.Second,
			chromedp.Evaluate(`window.tcTest.paths`, &paths),
			chromedp.Evaluate(`window.tailcatTestHooks.qualified`, &qualified),
		)
		ok := len(paths) > 0 && paths[len(paths)-1] == "webrtc"
		for i, path := range paths {
			want := "webrtc"
			if i%2 == 1 {
				want = "derp"
			}
			ok = ok && path == want
		}
		if !ok || qualified != 1 {
			p.t.Errorf("%s tab reported paths %q and qualified %d times; want webrtc/derp alternating, ending on webrtc, from one qualification",
				tab.name, paths, qualified)
		}
	}
}

// checkDataOnly checks that each tab's last local description offered
// or answered a data channel and no media.
func (p *tabPair) checkDataOnly() {
	p.t.Helper()
	for _, tab := range []struct {
		name string
		ctx  context.Context
	}{{"listener", p.listen}, {"sender", p.send}} {
		var sdp string
		p.step(tab.ctx, tab.name+": reading the local description", 10*time.Second,
			chromedp.Evaluate(`String(window.tailcatTestHooks.localSDP)`, &sdp),
		)
		var media []string
		for _, line := range strings.Split(sdp, "\n") {
			if strings.HasPrefix(line, "m=") {
				media = append(media, strings.Fields(line)[0])
			}
		}
		if len(media) != 1 || media[0] != "m=application" {
			p.t.Errorf("%s tab's local description has media sections %q; want only m=application", tab.name, media)
		}
	}
}

// TestBrowserWebRTCDataOnly checks that the session the tabs negotiate
// carries one data section and no audio or video, that the listener
// learns the dialer takes restart requests, and that the page hears the
// path's stats: a measured round trip and the candidate pair.
func TestBrowserWebRTCDataOnly(t *testing.T) {
	p := newTabPair(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)
	p.webrtcTabs(srv, transferSize)
	p.checkDataOnly()
	p.step(p.listen, "listener: the dialer takes restart requests", 10*time.Second,
		poll(`window.tailcatTestHooks.peerRestarts === true`))
	p.eachTab("ping channel open", 10*time.Second, poll(`window.tailcatTestHooks.ctlOpen === true`))
	p.eachTab("path stats", 10*time.Second,
		poll(`window.tcTest.stats && window.tcTest.stats.path === "webrtc" && window.tcTest.stats.rttMs > 0 && window.tcTest.stats.local === "host"`),
	)
	p.step(p.send, "starting the send", 5*time.Second, chromedp.Evaluate("window.tcTest.go = true", nil))
	p.checkTransfer()
}

// TestBrowserWebRTCOutage cuts the direct WebRTC path between two tabs
// off in both directions, without closing it, as a network outage
// would. Both tabs must move their traffic off it within a few seconds,
// and the dialer must restart ICE; when the path carries traffic again
// both must move back to it, never having reported it down. A second
// outage then checks that a transfer started during one completes, over
// DERP. (Its sender closes the tunnel when done, which ends the path.)
func TestBrowserWebRTCOutage(t *testing.T) {
	const size = 512 << 10
	p := newTabPair(t)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)
	p.webrtcTabs(srv, size)
	p.eachTab("path healthy", 10*time.Second, poll(`window.tailcatTestHooks.state === "healthy"`))

	cut := p.cutPath()
	p.step(p.send, "the dialer restarting ICE", 10*time.Second,
		poll(`window.tailcatTestHooks.iceRestarts >= 1 && window.tailcatTestHooks.answers >= 2`),
	)
	t.Logf("the dialer restarted ICE %v after the cut", time.Since(cut).Round(time.Millisecond))
	p.restorePath(cut)
	p.checkSameSession()

	cut = p.cutPath()
	p.step(p.send, "starting the send", 5*time.Second, chromedp.Evaluate("window.tcTest.go = true", nil))
	p.step(p.listen, "receiving over DERP during the outage", deadAfterForTest-time.Since(cut),
		poll("window.tcTest.recvDone === true"),
	)
	p.checkTransferOf(size)
}

// cutPath makes both tabs drop what their WebRTC path carries, waits
// for both to move their traffic off it, and returns when it cut it.
func (p *tabPair) cutPath() time.Time {
	p.t.Helper()
	cut := time.Now()
	p.eachTab("cutting the path", 5*time.Second, chromedp.Evaluate(`window.tailcatTestHooks.dropRTC = true`, nil))
	p.eachTab("traffic off the path", 12*time.Second, poll(`window.tailcatTestHooks.state === "suspect"`))
	p.t.Logf("both tabs moved their traffic off the path %v after the cut", time.Since(cut).Round(time.Millisecond))
	return cut
}

// restorePath undoes cutPath, checking that the session survived the
// outage, and waits for both tabs to move their traffic back.
func (p *tabPair) restorePath(cut time.Time) {
	p.t.Helper()
	if d := time.Since(cut); d >= deadAfterForTest {
		p.t.Fatalf("the outage lasted %v, long enough to end the session; the test can't check recovery", d)
	}
	p.eachTab("restoring the path", 5*time.Second, chromedp.Evaluate(`window.tailcatTestHooks.dropRTC = false`, nil))
	p.eachTab("traffic back on the path", 10*time.Second, poll(`window.tailcatTestHooks.state === "healthy"`))
}

var stressBytes = flag.Int("web-stress-bytes", 0,
	"run TestBrowserWebRTCStress, sending this many bytes between two browsers")

var stressHide = flag.String("web-stress-hide", "",
	`TestBrowserWebRTCStress: "send" or "listen" runs that side's browser in a window, minimized during the transfer, with Chrome's throttling of hidden pages on`)

// hiddenChrome is how TestBrowserWebRTCStress launches the side it hides:
// in a window it can minimize, and without the switches chromedp passes by
// default that keep a hidden page's timers and renderer at full speed.
var hiddenChrome = []chromedp.ExecAllocatorOption{
	chromedp.Flag("headless", false),
	chromedp.Flag("disable-background-timer-throttling", false),
	chromedp.Flag("disable-backgrounding-occluded-windows", false),
	chromedp.Flag("disable-renderer-backgrounding", false),
}

// minimize minimizes the window of the tab of ctx, which makes its page
// hidden.
func minimize(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		id, _, err := browser.GetWindowForTarget().Do(ctx)
		if err != nil {
			return err
		}
		return browser.SetWindowBounds(id, &browser.Bounds{WindowState: browser.WindowStateMinimized}).Do(ctx)
	})); err != nil {
		t.Fatalf("minimizing the window: %v", err)
	}
}

// TestBrowserWebRTCStress sends a large transfer over a direct WebRTC
// path between two browsers, each in its own process as two people's
// would be, with DERP up as the fallback, and logs how each page's
// transfer, path, round trip and thread fared every second. The path
// must carry the whole transfer intact without leaving it.
func TestBrowserWebRTCStress(t *testing.T) {
	if *stressBytes == 0 {
		t.Skip("set --web-stress-bytes to run")
	}
	size := *stressBytes
	bin := preflight(t)
	opts := map[string][]chromedp.ExecAllocatorOption{}
	switch *stressHide {
	case "":
	case "send", "listen":
		opts[*stressHide] = hiddenChrome
	default:
		t.Fatalf("--web-stress-hide=%q; want send or listen", *stressHide)
	}
	p := &tabPair{t: t, listen: launchChrome(t, bin, opts["listen"]...)}
	allocate(t, p.listen)
	dm := integration.RunDERPAndSTUN(t, mkLogf(t, "derpstun"), "127.0.0.1")
	srv := newWebServer(t, dm)

	addr := p.listenTab(srv, url.Values{"webrtc": {"host"}, "hooks": {""}, "sink": {"count"}, "timeline": {""}})
	p.send = launchChrome(t, bin, opts["send"]...)
	allocate(t, p.send)
	p.step(p.send, "sender reaching a WebRTC path", 90*time.Second,
		chromedp.Navigate(srv.URL+"/?"+withVerbose(url.Values{
			"mode":     {"send"},
			"addr":     {addr},
			"bytes":    {strconv.Itoa(size)},
			"pattern":  {""},
			"webrtc":   {"host"},
			"waitpath": {"webrtc"},
			"gate":     {""},
			"hooks":    {""},
			"timeline": {""},
		}).Encode()),
		poll(`window.tcTest && window.tcTest.path === "webrtc"`),
	)
	p.step(p.listen, "listener reaching a WebRTC path", 30*time.Second, poll(`window.tcTest.path === "webrtc"`))
	switch *stressHide {
	case "send":
		minimize(t, p.send)
	case "listen":
		minimize(t, p.listen)
	}
	start := time.Now()
	p.step(p.send, "starting the send", 5*time.Second, chromedp.Evaluate("window.tcTest.go = true", nil))

	defer func() {
		for _, tab := range []struct {
			name string
			ctx  context.Context
		}{{"listener", p.listen}, {"sender", p.send}} {
			ctx, cancel := context.WithTimeout(tab.ctx, 10*time.Second)
			var timeline, paths, hooks string
			chromedp.Run(ctx,
				chromedp.Evaluate(`(window.tcTest.timeline || []).map(JSON.stringify).join("\n")`, &timeline),
				chromedp.Evaluate(`JSON.stringify(window.tcTest.paths) + " maxLagMs=" + window.tcTest.maxLagMs`, &paths),
				chromedp.Evaluate(`JSON.stringify(window.tailcatTestHooks)`, &hooks),
			)
			cancel()
			t.Logf("%s paths %s\n%s hooks %s\n%s timeline:\n%s", tab.name, paths, tab.name, hooks, tab.name, timeline)
		}
	}()

	timeout := 120*time.Second + time.Duration(size/(256<<10))*time.Second
	var recvBytes, recvBad int
	var done bool
	p.step(p.listen, "receiving", timeout,
		chromedp.Poll("window.tcTest.recvDone === true", &done,
			chromedp.WithPollingInterval(100*time.Millisecond), chromedp.WithPollingTimeout(timeout)),
		chromedp.Evaluate("window.tcTest.recvBytes", &recvBytes),
		chromedp.Evaluate("window.tcTest.recvBad", &recvBad),
	)
	took := time.Since(start)
	t.Logf("received %d bytes in %v (%.1f MB/s)", recvBytes, took.Round(time.Millisecond), float64(recvBytes)/took.Seconds()/1e6)
	if recvBytes != size || recvBad != 0 {
		t.Errorf("listener received %d bytes, %d of its samples wrong; want %d, none wrong", recvBytes, recvBad, size)
	}
	for _, tab := range []struct {
		name string
		ctx  context.Context
	}{{"listener", p.listen}, {"sender", p.send}} {
		// Each page records its paths as its side of the transfer
		// completes, before it closes the connection: the sender once
		// the listener's close confirms delivery. The tunnel's teardown
		// that follows may move the traffic, and isn't counted, but a
		// move to DERP during the transfer is.
		var paths []string
		p.step(tab.ctx, tab.name+": reading the paths", 10*time.Second,
			poll(`window.tcTest.pathsAtDone !== null`),
			chromedp.Evaluate(`window.tcTest.pathsAtDone`, &paths))
		if len(paths) == 0 || slices.ContainsFunc(paths, func(path string) bool { return path != "webrtc" }) {
			t.Errorf("%s tab's traffic moved %q during the transfer; want it on webrtc throughout", tab.name, paths)
		}
	}
	checkPageErrors(t, p.listen)
	checkPageErrors(t, p.send)
}

// deadAfterForTest is how long the WebRTC code lets a path go
// unanswered before ending its session (deadAfter in webrtc_js.go,
// which this native test can't import), less a tick.
const deadAfterForTest = 13 * time.Second

// TestBrowserWebRTCNetworkChange has each tab report a network change,
// as the browser's online event does, while their WebRTC path is up:
// the listener checks the path, and the dialer restarts ICE. The path
// must stay up through both, and then carry a transfer on its own,
// with DERP stopped.
func TestBrowserWebRTCNetworkChange(t *testing.T) {
	p := newTabPair(t)
	dm, stopDERP := runStoppableDERP(t)
	srv := newWebServer(t, dm)
	p.webrtcTabs(srv, transferSize)
	p.eachTab("path healthy", 10*time.Second, poll(`window.tailcatTestHooks.state === "healthy"`))

	p.step(p.send, "dialer: the network changing", 10*time.Second,
		chromedp.Evaluate(`window.dispatchEvent(new Event("online"))`, nil),
		poll(`window.tailcatTestHooks.iceRestarts >= 1 && window.tailcatTestHooks.answers >= 2`),
	)
	p.step(p.listen, "listener: the network changing", 5*time.Second,
		chromedp.Evaluate(`window.dispatchEvent(new Event("online"))`, nil),
		poll(`window.tailcatTestHooks.netChecks >= 1`),
	)
	p.eachTab("path healthy after the change", 10*time.Second, poll(`window.tailcatTestHooks.state === "healthy"`))
	p.checkSameSession()

	t.Logf("both tabs kept their WebRTC path through the change; stopping DERP")
	stopDERP()
	p.step(p.send, "starting the send", 5*time.Second, chromedp.Evaluate("window.tcTest.go = true", nil))
	p.checkTransfer()
}
