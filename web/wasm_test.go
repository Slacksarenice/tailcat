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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
func launchChrome(t *testing.T, bin string) context.Context {
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

// logState logs each open tab's window.tcTest.
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
		err := chromedp.Run(ctx, chromedp.Evaluate(`JSON.stringify(window.tcTest)`, &state))
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
// tab's transfer and checks it arrived intact.
func (p *tabPair) checkTransfer() {
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
	if recvBytes != transferSize {
		p.t.Errorf("listener received %d bytes; want %d", recvBytes, transferSize)
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
}
