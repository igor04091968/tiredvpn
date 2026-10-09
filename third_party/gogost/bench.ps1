param(
    [ValidateSet("quick", "stable", "profile", "compare")]
    [string]$Mode = "quick",
    [string]$Bench = ".",
    [string[]]$Packages = @("./..."),
    [string]$BenchTime = "",
    [int]$Count = 10,
    [string]$OutDir = ".bench",
    [string]$Package = "./gost3413/modes",
    [string]$Name = "BenchmarkPreparedModes/Kuznechik/MGM/1KiB/Seal",
    [string]$Old = "",
    [string]$New = ""
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not $env:GOCACHE) {
    New-Item -ItemType Directory -Force -Path ".codex-gocache" | Out-Null
    $env:GOCACHE = (Resolve-Path ".codex-gocache").Path
}
if (-not $env:GOTMPDIR) {
    New-Item -ItemType Directory -Force -Path ".codex-gotmp" | Out-Null
    $env:GOTMPDIR = (Resolve-Path ".codex-gotmp").Path
}

function Read-BenchmarkMedian {
    param([string]$Path)

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $items = @{}
    $pkg = ""
    $text = [System.IO.File]::ReadAllText((Resolve-Path $Path).Path).Replace("`0", "")
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^pkg:\s+(.+)$') {
            $pkg = ($Matches[1] -split '/')[-1]
            continue
        }
        if ($line -match '^(Benchmark\S+)\s+\d+\s+([0-9.]+)\s+ns/op(?:\s+([0-9.]+)\s+MB/s)?\s+([0-9]+)\s+B/op\s+([0-9]+)\s+allocs/op') {
            $key = $Matches[1]
            if ($pkg -ne "") {
                $key = "$pkg/$key"
            }
            if (-not $items.ContainsKey($key)) {
                $items[$key] = [System.Collections.Generic.List[object]]::new()
            }
            $mb = $null
            if ($Matches[3]) {
                $mb = [double]::Parse($Matches[3], $culture)
            }
            $items[$key].Add([pscustomobject]@{
                Ns = [double]::Parse($Matches[2], $culture)
                MB = $mb
                Bytes = [int]$Matches[4]
                Allocs = [int]$Matches[5]
            })
        }
    }

    $result = @{}
    foreach ($key in $items.Keys) {
        $values = $items[$key]
        $ns = @($values | ForEach-Object Ns | Sort-Object)
        $mb = @($values | Where-Object { $null -ne $_.MB } | ForEach-Object MB | Sort-Object)
        $mid = [int]([Math]::Floor($ns.Count / 2))
        $nsMedian = if (($ns.Count % 2) -eq 0) { ($ns[$mid - 1] + $ns[$mid]) / 2 } else { $ns[$mid] }
        $mbMedian = $null
        if ($mb.Count -gt 0) {
            $midMb = [int]([Math]::Floor($mb.Count / 2))
            $mbMedian = if (($mb.Count % 2) -eq 0) { ($mb[$midMb - 1] + $mb[$midMb]) / 2 } else { $mb[$midMb] }
        }
        $first = $values | Select-Object -First 1
        $result[$key] = [pscustomobject]@{
            Ns = $nsMedian
            MB = $mbMedian
            Bytes = $first.Bytes
            Allocs = $first.Allocs
            Count = $values.Count
        }
    }
    $result
}

function Compare-BenchmarkMedian {
    param(
        [string]$OldPath,
        [string]$NewPath
    )

    $oldValues = Read-BenchmarkMedian $OldPath
    $newValues = Read-BenchmarkMedian $NewPath
    foreach ($key in ($oldValues.Keys | Sort-Object)) {
        if (-not $newValues.ContainsKey($key)) {
            continue
        }
        $oldValue = $oldValues[$key]
        $newValue = $newValues[$key]
        $change = (($newValue.Ns / $oldValue.Ns) - 1) * 100
        [pscustomobject]@{
            Name = $key
            Old = ('{0:N2} ns/op' -f $oldValue.Ns)
            New = ('{0:N2} ns/op' -f $newValue.Ns)
            Change = ('{0:+0.0;-0.0;0.0}%' -f $change)
            OldMB = if ($null -ne $oldValue.MB) { ('{0:N2}' -f $oldValue.MB) } else { "" }
            NewMB = if ($null -ne $newValue.MB) { ('{0:N2}' -f $newValue.MB) } else { "" }
            OldAllocs = "$($oldValue.Bytes) B/$($oldValue.Allocs)"
            NewAllocs = "$($newValue.Bytes) B/$($newValue.Allocs)"
        }
    }
}

switch ($Mode) {
    "quick" {
        if ($BenchTime -eq "") { $BenchTime = "200ms" }
        go test -run '^$' -bench $Bench -benchmem "-benchtime=$BenchTime" $Packages
    }
    "stable" {
        if ($BenchTime -eq "") { $BenchTime = "700ms" }
        $stamp = "$(Get-Date -Format "yyyyMMdd-HHmmss-fff")-$PID"
        $out = Join-Path $OutDir "bench-$stamp.txt"
        go test -run '^$' -bench $Bench -benchmem "-benchtime=$BenchTime" "-count=$Count" $Packages | Tee-Object -FilePath $out
        Write-Output $out
    }
    "profile" {
        if ($BenchTime -eq "") { $BenchTime = "2s" }
        $stamp = "$(Get-Date -Format "yyyyMMdd-HHmmss-fff")-$PID"
        $cpu = Join-Path $OutDir "$stamp.cpu.prof"
        $mem = Join-Path $OutDir "$stamp.mem.prof"
        $txt = Join-Path $OutDir "$stamp.profile.txt"
        go test -run '^$' -bench $Name -benchmem "-benchtime=$BenchTime" -cpuprofile $cpu -memprofile $mem $Package | Tee-Object -FilePath $txt
        go tool pprof -top $cpu | Out-File -Encoding utf8 (Join-Path $OutDir "$stamp.cpu.top.txt")
        go tool pprof -top $mem | Out-File -Encoding utf8 (Join-Path $OutDir "$stamp.mem.top.txt")
        Write-Output (Join-Path $OutDir $stamp)
    }
    "compare" {
        if ($Old -eq "" -or $New -eq "") {
            throw "Use -Old old.txt -New new.txt"
        }
        $benchstat = Get-Command benchstat -ErrorAction SilentlyContinue
        if ($null -ne $benchstat) {
            benchstat $Old $New
        } else {
            Compare-BenchmarkMedian $Old $New | Format-Table -AutoSize
        }
    }
}
