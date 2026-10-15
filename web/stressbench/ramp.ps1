# Interleaved ramp-up runs of TestBrowserWebRTCStress over the test's own
# delay relays (--web-stress-relay), on Windows' own network stack and
# Chrome (PowerShell 7). ramp.sh does the same on Linux with netem.
#
#   pwsh web/stressbench/ramp.ps1 -Out $env:TEMP\ramp -Runs 5 -Rtts 20,50,100 -Paths webrtc,derp,switch `
#     -Variants @{ base = @{}; reno = @{ flags = "--web-stress-cc=reno" } }
#
# A variant is a hashtable: flags (extra test flags) and env (a hashtable
# of environment variables). Traces land in Out\<variant>-<path>-<rtt>-<run>.json;
# summarize them with go run web/stressbench/rampsum.go Out.
param(
    [string]$Out = (Join-Path ([IO.Path]::GetTempPath()) "tailcat-ramp"),
    [int]$Runs = 5,
    [int[]]$Rtts = @(20, 50, 100),
    [string[]]$Paths = @("webrtc", "derp", "switch"),
    [int]$Seconds = 40,
    [int]$Jitter = 0,
    [hashtable]$Variants = @{ base = @{} },
    [string]$Repo = (Get-Location).Path
)
if (-not $env:CHROME_BIN) { $env:CHROME_BIN = "C:\Program Files\Google\Chrome\Application\chrome.exe" }
New-Item -ItemType Directory -Force $Out | Out-Null
# Windows counts UDP datagrams it dropped as receive errors (IPv4 and IPv6).
function UdpErrors { (((netstat -s -p udp) -match "Receive Errors") -replace "\D", "" | Measure-Object -Sum).Sum }
foreach ($run in 1..$Runs) {
    foreach ($rtt in $Rtts) {
        foreach ($path in $Paths) {
            foreach ($name in ($Variants.Keys | Sort-Object)) {
                $v = $Variants[$name]
                $envs = @{ TAILCAT_WASM_TAGS = "tailcat_ramptrace"; TAILCAT_RAMP_VARIANT = $name } + $(if ($v.env) { $v.env } else { @{} })
                foreach ($k in $envs.Keys) { Set-Item "Env:$k" $envs[$k] }
                $f = Join-Path $Out "$name-$path-$rtt-$run"
                $before = UdpErrors
                $args = @("test", "./web", "-run", "TestBrowserWebRTCStress$", "-count=1", "-v", "-timeout", "20m",
                    "--run-headless-browser-tests", "--web-stress-bytes=100000000000", "--web-stress-seconds=$Seconds",
                    "--web-stress-path=$path", "--web-stress-relay=${rtt}ms", "--web-stress-jitter=${Jitter}ms",
                    "--web-stress-trace=$f.json") + $(if ($v.flags) { -split $v.flags } else { @() })
                Push-Location $Repo
                & go @args *> "$f.log"
                $rc = $LASTEXITCODE
                Pop-Location
                $udp = (UdpErrors) - $before
                foreach ($k in $envs.Keys) { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
                $m = Select-String -Path "$f.log" -Pattern "ramp: .*" | Select-Object -First 1
                "{0:HH:mm:ss} {1} {2} {3}ms #{4} rc={5} udpErrors={6} {7}" -f (Get-Date), $name, $path, $rtt, $run, $rc, $udp, $(if ($m) { $m.Matches[0].Value } else { "" })
            }
        }
    }
}
