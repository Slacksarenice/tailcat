# Interleaved A/B throughput and CPU benchmark over TestBrowserWebRTCStress
# (PowerShell 7, Windows: CPU is summed over the chrome processes each run
# starts). Each variant is a name => hashtable of environment variables set
# for its runs, so alternating runs of two builds cancel the machine's drift.
#
#   pwsh web/stressbench/ab.ps1 -Pairs 5 -Variants @{ a = @{}; b = @{ SOME_KNOB = "1" } }
param(
    [string[]]$Paths = @("webrtc", "derp"),
    [int]$Pairs = 5,
    [int]$Bytes = 268435456,
    [string]$Out = (Join-Path ([IO.Path]::GetTempPath()) "tailcat-stressbench"),
    [hashtable]$Variants = @{ base = @{} },
    [string]$Repo = (Get-Location).Path
)
if (-not $env:CHROME_BIN) { $env:CHROME_BIN = "C:\Program Files\Google\Chrome\Application\chrome.exe" }
New-Item -ItemType Directory -Force $Out | Out-Null
$results = @()
foreach ($path in $Paths) {
    foreach ($i in 1..$Pairs) {
        foreach ($name in ($Variants.Keys | Sort-Object)) {
            $vars = $Variants[$name]
            foreach ($k in $vars.Keys) { Set-Item "Env:$k" $vars[$k] }
            $before = @(Get-Process chrome -ErrorAction SilentlyContinue | ForEach-Object Id)
            $cpu = @{}
            $log = "$Out\$name-$path-$i.log"
            $job = Start-Process -PassThru -NoNewWindow -RedirectStandardOutput $log -RedirectStandardError "$log.err" go -ArgumentList @(
                "test", "./web", "-run", "TestBrowserWebRTCStress$", "-count=1", "-v", "-timeout", "20m",
                "--run-headless-browser-tests", "--web-stress-bytes=$Bytes", "--web-stress-path=$path") -WorkingDirectory $Repo
            while (-not $job.HasExited) {
                foreach ($p in Get-Process chrome -ErrorAction SilentlyContinue) {
                    if ($before -contains $p.Id) { continue }
                    try { $cpu[$p.Id] = $p.TotalProcessorTime.TotalSeconds } catch {}
                }
                Start-Sleep -Milliseconds 200
            }
            foreach ($k in $vars.Keys) { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
            $m = Select-String -Path $log -Pattern "received (\d+) bytes in ([\d.]+)(ms|s) \(([\d.]+) MB/s\)" | Select-Object -First 1
            $pass = [bool](Select-String -Path $log -Pattern "^--- PASS" -Quiet)
            $mbs = if ($m) { [double]$m.Matches[0].Groups[4].Value } else { [double]::NaN }
            $secs = if ($m) { [double]$m.Matches[0].Groups[2].Value / ($(if ($m.Matches[0].Groups[3].Value -eq "ms") { 1000 } else { 1 })) } else { [double]::NaN }
            $cpuSum = ($cpu.Values | Measure-Object -Sum).Sum
            $r = [pscustomobject]@{ path = $path; variant = $name; run = $i; pass = $pass; MBps = $mbs; transferS = $secs; chromeCpuS = [math]::Round($cpuSum, 1) }
            $results += $r
            $r | Format-Table -HideTableHeaders | Out-String | ForEach-Object Trim
        }
    }
}
$results | Export-Csv -NoTypeInformation "$Out\results.csv"
"`nsummary (median MB/s, median Chrome CPU-s per run incl. setup):"
$results | Group-Object path, variant | ForEach-Object {
    $ok = $_.Group | Where-Object pass
    $mb = @($ok.MBps | Sort-Object); $c = @($ok.chromeCpuS | Sort-Object)
    "{0,-22} n={1} median {2:N1} MB/s (min {3:N1}, max {4:N1}); median Chrome CPU {5:N1} s" -f $_.Name, $ok.Count, $mb[[int][math]::Floor($mb.Count / 2)], $mb[0], $mb[-1], $c[[int][math]::Floor($c.Count / 2)]
}
