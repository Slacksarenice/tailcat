#!/usr/bin/env bash
# Interleaved ramp-up runs of TestBrowserWebRTCStress over emulated round
# trips (Linux, as root: netem needs it). Every run happens in a network
# namespace of its own, whose loopback carries nothing else and isn't
# rerouted (WSL's mirrored networking sends 127.0.0.1 through the host).
#
#   sudo web/stressbench/ramp.sh -o /tmp/ramp -n 5 -r "20 50 100" -p "webrtc derp switch" \
#     -v "base=" -v "reno=--web-stress-cc=reno"
#
# Each variant is name=extra test flags; a variant's environment can be
# set with name=ENV=value,ENV2=value:flags. Traces land in
# OUT/<variant>-<path>-<rtt>-<run>.json; summarize them with
# go run web/stressbench/rampsum.go OUT.
set -u
out=/tmp/ramp runs=5 rtts="20 50 100" paths="webrtc derp switch" seconds=40 jitter=0
variants=()
while getopts "o:n:r:p:s:j:v:" opt; do
	case $opt in
	o) out=$OPTARG ;;
	n) runs=$OPTARG ;;
	r) rtts=$OPTARG ;;
	p) paths=$OPTARG ;;
	s) seconds=$OPTARG ;;
	j) jitter=$OPTARG ;;
	v) variants+=("$OPTARG") ;;
	*) exit 2 ;;
	esac
done
[ ${#variants[@]} -eq 0 ] && variants=("base=")
repo=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$out"
export GOFLAGS=-buildvcs=false GOPROXY=off CHROME_BIN=${CHROME_BIN:-/usr/bin/chromium}

ns=tcramp
ip netns del $ns 2>/dev/null
ip netns add $ns
ip -n $ns link set lo up
# Chrome gathers no ICE candidates without an interface with a default
# route; traffic between its own addresses still goes over lo.
ip -n $ns link add dummy0 type dummy
ip -n $ns addr add 10.77.0.1/24 dev dummy0
ip -n $ns link set dummy0 up
ip -n $ns route add default dev dummy0
trap 'ip netns del $ns 2>/dev/null' EXIT

for run in $(seq 1 "$runs"); do
	for rtt in $rtts; do
		for path in $paths; do
			for v in "${variants[@]}"; do
				name=${v%%=*} spec=${v#*=} envs="" flags=$spec
				if [[ $spec == *:* ]]; then envs=${spec%%:*} flags=${spec#*:}; fi
				f="$out/$name-$path-$rtt-$run"
				# The namespace's UDP counters, before and after: a receive
				# buffer error is a datagram the kernel dropped.
				ip netns exec $ns grep '^Udp:' /proc/net/snmp >"$f.udp"
				# shellcheck disable=SC2086
				(cd "$repo" && ip netns exec $ns env TAILCAT_WASM_TAGS=tailcat_ramptrace TAILCAT_RAMP_VARIANT="$name" ${envs//,/ } \
					go test ./web -run 'TestBrowserWebRTCStress$' -count=1 -v -timeout 20m \
					--run-headless-browser-tests --web-stress-bytes=100000000000 --web-stress-seconds="$seconds" \
					--web-stress-path="$path" --web-stress-netem="${rtt}ms" --web-stress-jitter="${jitter}ms" \
					--web-stress-trace="$f.json" $flags >"$f.log" 2>&1)
				rc=$?
				ip netns exec $ns grep '^Udp:' /proc/net/snmp | tail -1 >>"$f.udp"
				echo "$(date +%T) $name $path ${rtt}ms #$run rc=$rc $(grep -ho 'ramp: .*' "$f.log" | head -1)"
			done
		done
	done
done
