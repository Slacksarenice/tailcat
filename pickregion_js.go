// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js

package tailcat

import (
	"context"
	"net/http"
	"sync"
	"time"

	"tailscale.com/tailcfg"
)

// regionProbeTimeout bounds how long PickBestRegion waits for the
// regions to answer, so a slow or unreachable one doesn't hold up the
// start: the regions that answered by then are compared.
const regionProbeTimeout = 3 * time.Second

// regionProbes is how many timed requests each region gets, after the
// one that opens the connection; the fastest counts.
const regionProbes = 2

// PickBestRegion returns the DERP region in dm with the lowest latency,
// measured over HTTPS since a browser can't send netcheck's STUN
// probes: as netcheck does in its HTTP-only mode, a HEAD request to
// each region's /derp/probe opens a connection from the browser's pool,
// and the next ones over it are timed. It returns 0 (and a nil error) if
// no region answered, and [ConnInfo.Expand] then picks one at random.
//
// Without it a browser picked any region in the map, as likely on
// another continent as its own, and the tunnel's traffic over DERP
// crossed the world twice.
func PickBestRegion(ctx context.Context, dm *tailcfg.DERPMap) (regionID tailcfg.DERPRegionID, err error) {
	ctx, cancel := context.WithTimeout(ctx, regionProbeTimeout)
	defer cancel()
	var (
		mu   sync.Mutex
		best = time.Duration(-1)
		wg   sync.WaitGroup
	)
	for rid, r := range dm.Regions {
		if r == nil || r.Avoid || r.NoMeasureNoHome || len(r.Nodes) == 0 {
			continue
		}
		url := derpProbeURL(r.Nodes[0])
		wg.Go(func() {
			d, ok := probeRegion(ctx, url)
			if !ok {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if best < 0 || d < best {
				best, regionID = d, rid
			}
		})
	}
	wg.Wait()
	return regionID, nil
}

// probeRegion reports the fastest of regionProbes requests to url
// after a first that opens the connection, and whether they all
// succeeded.
func probeRegion(ctx context.Context, url string) (time.Duration, bool) {
	probe := func() (time.Duration, bool) {
		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			return 0, false
		}
		t0 := time.Now()
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, false
		}
		res.Body.Close()
		return time.Since(t0), res.StatusCode < 300
	}
	if _, ok := probe(); !ok {
		return 0, false
	}
	best := time.Duration(-1)
	for range regionProbes {
		d, ok := probe()
		if !ok {
			return 0, false
		}
		if best < 0 || d < best {
			best = d
		}
	}
	return best, true
}
