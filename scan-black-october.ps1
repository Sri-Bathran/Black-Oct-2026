<#
.SYNOPSIS
  Scans this Windows machine + all WSL distros for the "Black October 2026"
  PHP RCE flaws (CVE-2026-109618 / CVE-2026-109619, "PHP2Shell"), and can
  apply fixes.

.USAGE
  powershell -ExecutionPolicy Bypass -File .\scan-black-october.ps1           # scan only
  powershell -ExecutionPolicy Bypass -File .\scan-black-october.ps1 -Patch    # scan + patch

.NOTES
  Upstream-fixed PHP releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35 (2026-10-21).
  VirtualBox VMs are NOT reachable from here. Copy php2shell-patch.sh (next
  to this script) into each VM and run it there -- see the note this script
  prints at the end.

  Every detection/patch step below is written as a FALLBACK CHAIN: it tries
  its primary command/path first, and only if that fails or returns nothing
  does it try the next-best alternative, logging which one actually worked
  via Write-Fallback. This is deliberate so the same script keeps working
  across machines with different tooling installed (winget vs choco vs
  scoop, registry present or not, IIS present or not, etc.), not just this
  one box.
#>

param(
    [switch]$Patch
)

$FixedVersions = @{
    "8.5" = "8.5.12"
    "8.4" = "8.4.27"
    "8.3" = "8.3.36"
    "8.2" = "8.2.35"
}

function Write-Section($title) { Write-Host ""; Write-Host "== $title ==" -ForegroundColor Cyan }
function Write-Fallback($msg)  { Write-Host "  [fallback] $msg" -ForegroundColor DarkYellow }
function Write-Info($msg)      { Write-Host "  [i] $msg" }

function Test-PhpVersionString($verString) {
    if ($verString -notmatch '^\d+\.\d+\.\d+') { return @{ Vulnerable = $null; Reason = "unparsable version '$verString'" } }
    $parts = $verString -split '\.'
    $branch = "$($parts[0]).$($parts[1])"
    if (-not $FixedVersions.ContainsKey($branch)) {
        return @{ Vulnerable = $true; Reason = "branch $branch is end-of-life upstream, no mainline fix exists" }
    }
    $fixed = $FixedVersions[$branch]
    if ([version]$verString -lt [version]$fixed) {
        return @{ Vulnerable = $true; Reason = "below fixed release $fixed" }
    }
    return @{ Vulnerable = $false; Reason = "meets or exceeds fixed release $fixed" }
}

# ---- version-string extraction fallback chain for one php.exe ----
# tries: `php -r echo PHP_VERSION` -> parse `php -v` -> parse `php --version`
function Get-PhpVersionFromExe($exePath) {
    $ver = & $exePath -r "echo PHP_VERSION;" 2>$null
    if ($ver -match '^\d+\.\d+\.\d+') { return $ver }
    Write-Fallback "'$exePath -r' failed, trying '-v'"
    $vOut = & $exePath -v 2>$null
    if ($vOut -match 'PHP (\d+\.\d+\.\d+)') { return $Matches[1] }
    Write-Fallback "'$exePath -v' failed, trying '--version'"
    $vOut2 = & $exePath --version 2>$null
    if ($vOut2 -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    return $null
}

Write-Host "Black October 2026 (PHP2Shell) scanner" -ForegroundColor Yellow
Write-Host "CVE-2026-109618 / CVE-2026-109619 -- scanning Windows host + WSL"

$findings = @()

# ---------- 1. PHP on Windows PATH ----------
# fallback chain: Get-Command -> where.exe -> $env:PATH manual split-scan
Write-Section "Windows PATH"
$phpExePath = $null
$gc = Get-Command php.exe -ErrorAction SilentlyContinue
if ($gc) {
    $phpExePath = $gc.Source
} else {
    Write-Fallback "Get-Command found nothing, trying where.exe"
    $whereOut = & where.exe php.exe 2>$null
    if ($LASTEXITCODE -eq 0 -and $whereOut) {
        $phpExePath = ($whereOut -split "`n")[0].Trim()
    } else {
        Write-Fallback "where.exe found nothing, manually scanning PATH entries"
        foreach ($dir in ($env:PATH -split ';')) {
            if ($dir -and (Test-Path (Join-Path $dir "php.exe"))) {
                $phpExePath = Join-Path $dir "php.exe"
                break
            }
        }
    }
}
if ($phpExePath) {
    $verOut = Get-PhpVersionFromExe $phpExePath
    if ($verOut) {
        $res = Test-PhpVersionString $verOut
        $findings += [pscustomobject]@{ Location = $phpExePath; Version = $verOut; Vulnerable = $res.Vulnerable; Reason = $res.Reason }
        Write-Host "  Found: $phpExePath -> PHP $verOut"
    } else {
        Write-Host "  Found $phpExePath but could not determine its version."
    }
} else {
    Write-Host "  No php.exe on PATH."
}

# ---------- 2. Common bundled-stack install locations ----------
# fallback chain: fixed known paths -> registry Uninstall keys -> broad Program Files / drive-root search
Write-Section "Common PHP bundles (XAMPP / WAMP / Laragon / MAMP) + registry + filesystem fallback"
$candidatePaths = @(
    "C:\xampp\php\php.exe",
    "C:\wamp64\bin\php\*\php.exe",
    "C:\laragon\bin\php\*\php.exe",
    "C:\Program Files\PHP\*\php.exe",
    "C:\php\php.exe"
)
$bundleHits = @()
foreach ($pattern in $candidatePaths) {
    Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object { $bundleHits += $_.FullName }
}

if (-not $bundleHits) {
    Write-Fallback "No hits in common bundle paths, checking registry Uninstall keys for PHP entries"
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($rp in $regPaths) {
            Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*PHP*" } |
                ForEach-Object {
                    Write-Info "Registry entry: $($_.DisplayName) ($($_.InstallLocation))"
                    if ($_.InstallLocation) {
                        $maybeExe = Join-Path $_.InstallLocation "php.exe"
                        if (Test-Path $maybeExe) { $bundleHits += $maybeExe }
                    }
                }
        }
    } catch {
        Write-Fallback "Registry query failed ($($_.Exception.Message)); skipping registry check"
    }
}

if (-not $bundleHits) {
    Write-Fallback "Registry check found nothing usable, doing a bounded filesystem search under Program Files / drive roots"
    try {
        $searchRoots = @("C:\Program Files", "C:\Program Files (x86)", "C:\")
        foreach ($root in $searchRoots) {
            if (Test-Path $root) {
                Get-ChildItem -Path $root -Filter "php.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                    ForEach-Object { $bundleHits += $_.FullName }
            }
        }
    } catch {
        Write-Fallback "Filesystem search failed ($($_.Exception.Message)); giving up on this host-side check"
    }
}

$bundleHits = $bundleHits | Select-Object -Unique
foreach ($hit in $bundleHits) {
    $verOut = Get-PhpVersionFromExe $hit
    if ($verOut) {
        $res = Test-PhpVersionString $verOut
        $findings += [pscustomobject]@{ Location = $hit; Version = $verOut; Vulnerable = $res.Vulnerable; Reason = $res.Reason }
        Write-Host "  Found: $hit -> PHP $verOut"
    }
}
if (-not $bundleHits) { Write-Host "  None found via fixed paths, registry, or filesystem search." }

# ---------- 3. Package-manager-tracked PHP installs ----------
# fallback chain: winget -> choco -> scoop
Write-Section "Package-manager-tracked PHP (winget / choco / scoop)"
$pmFound = $false
$winget = Get-Command winget -ErrorAction SilentlyContinue
if ($winget) {
    $wingetList = winget list --source winget 2>$null | Select-String -Pattern '^PHP'
    if ($wingetList) {
        $pmFound = $true
        $wingetList | ForEach-Object { Write-Host "  [winget] $_" }
    }
}
if (-not $pmFound) {
    Write-Fallback "winget not present or found no PHP package, trying choco"
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco) {
        $chocoList = choco list --local-only 2>$null | Select-String -Pattern '^php'
        if ($chocoList) {
            $pmFound = $true
            $chocoList | ForEach-Object { Write-Host "  [choco] $_" }
        }
    }
}
if (-not $pmFound) {
    Write-Fallback "choco not present or found no PHP package, trying scoop"
    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if ($scoop) {
        $scoopList = scoop list 2>$null | Select-String -Pattern '^php'
        if ($scoopList) {
            $pmFound = $true
            $scoopList | ForEach-Object { Write-Host "  [scoop] $_" }
        }
    }
}
if (-not $pmFound) { Write-Host "  No PHP package tracked by winget, choco, or scoop." }

# ---------- 4. IIS FastCGI config pointing at php-cgi ----------
Write-Section "IIS FastCGI (applicationHost.config)"
$iisCfg = "$env:windir\System32\inetsrv\config\applicationHost.config"
if (Test-Path $iisCfg) {
    $phpCgiRefs = Select-String -Path $iisCfg -Pattern 'php-cgi\.exe' -ErrorAction SilentlyContinue
    if ($phpCgiRefs) {
        $phpCgiRefs | ForEach-Object { Write-Host "  $($_.Line.Trim())" }
    } else {
        Write-Host "  No php-cgi.exe FastCGI handlers configured."
    }
} else {
    Write-Host "  IIS not installed on this host (no applicationHost.config)."
}

# ---------- 5. WSL distros ----------
# fallback chain: wsl -l -q -> wsl -l -v parse -> skip with explanation
Write-Section "WSL distros"
$wslAvailable = Get-Command wsl.exe -ErrorAction SilentlyContinue
$wslResults = @()
if ($wslAvailable) {
    $distros = @()
    $distrosRaw = wsl.exe -l -q 2>$null
    if ($LASTEXITCODE -eq 0 -and $distrosRaw) {
        $distros = $distrosRaw | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() -replace "`0", "" }
    } else {
        Write-Fallback "'wsl -l -q' failed, parsing 'wsl -l -v' instead"
        $verboseRaw = wsl.exe -l -v 2>$null
        $distros = $verboseRaw | Select-Object -Skip 1 | ForEach-Object {
            ($_ -replace "`0", "").Trim() -replace '^\*\s*', '' -split '\s+' | Select-Object -First 1
        } | Where-Object { $_ -ne "" }
    }
    $distros = $distros | Where-Object { $_ -notmatch '^docker-desktop' }

    if (-not $distros) {
        Write-Host "  No WSL distros installed (after both detection methods)."
    }
    foreach ($distro in $distros) {
        Write-Host "  -- $distro --"
        $scriptPath = Join-Path $PSScriptRoot "php2shell-patch.sh"
        if (-not (Test-Path $scriptPath)) {
            Write-Host "     php2shell-patch.sh not found next to this script; skipping." -ForegroundColor Red
            continue
        }

        # fallback chain: distro's own wslpath -> manual /mnt/<drive> construction
        $wslPath = $null
        try {
            $wslPath = (wsl.exe -d $distro -- bash -c "wslpath -u '$($scriptPath -replace '\\','/')'" 2>$null)
        } catch { $wslPath = $null }
        if (-not $wslPath) {
            Write-Fallback "wslpath unavailable/failed in $distro, constructing /mnt/<drive> path manually"
            $drive = $scriptPath.Substring(0,1).ToLower()
            $rest = $scriptPath.Substring(2) -replace '\\','/'
            $wslPath = "/mnt/$drive$rest"
        }

        # fallback chain for a shell to run it with: bash -> sh
        $flag = if ($Patch) { "--patch" } else { "" }
        $ranOk = $false
        try {
            wsl.exe -d $distro -- bash -c "chmod +x '$wslPath' 2>/dev/null; '$wslPath' $flag"
            if ($LASTEXITCODE -eq 0) { $ranOk = $true }
        } catch { $ranOk = $false }
        if (-not $ranOk) {
            Write-Fallback "bash unavailable/failed in $distro, trying sh"
            wsl.exe -d $distro -- sh -c "chmod +x '$wslPath' 2>/dev/null; '$wslPath' $flag" 2>$null
        }
        $wslResults += $distro
    }
} else {
    Write-Host "  wsl.exe not found on this system."
}

# ---------- 6. Patch Windows-side findings ----------
if ($Patch) {
    Write-Section "Patching Windows host"
    $vulnerableFound = $findings | Where-Object { $_.Vulnerable -eq $true }
    if ($vulnerableFound) {
        $patched = $false
        if ($winget) {
            Write-Host "Attempting winget upgrade for installed PHP.PHP.* packages..."
            $installedPhpIds = (winget list --source winget 2>$null | Select-String -Pattern '^PHP\.PHP') | ForEach-Object {
                ($_ -split '\s+')[1]
            }
            foreach ($id in $installedPhpIds) {
                Write-Host "  winget upgrade --id $id"
                winget upgrade --id $id --silent --accept-package-agreements --accept-source-agreements
                if ($LASTEXITCODE -eq 0) { $patched = $true }
            }
        }
        if (-not $patched) {
            Write-Fallback "winget upgrade unavailable or found nothing to upgrade, checking choco"
            $choco = Get-Command choco -ErrorAction SilentlyContinue
            if ($choco) {
                choco upgrade php -y 2>$null
                if ($LASTEXITCODE -eq 0) { $patched = $true }
            }
        }
        if (-not $patched) {
            Write-Fallback "choco upgrade unavailable or failed, checking scoop"
            $scoop = Get-Command scoop -ErrorAction SilentlyContinue
            if ($scoop) {
                scoop update php 2>$null
                if ($LASTEXITCODE -eq 0) { $patched = $true }
            }
        }
        Write-Host ""
        Write-Host "For PHP installed via XAMPP/WAMP/Laragon/manual zip (not package-manager-managed):" -ForegroundColor Yellow
        Write-Host "  These stacks bundle their own PHP build; no package manager can patch them."
        Write-Host "  Download the matching fixed build (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)"
        Write-Host "  from https://windows.php.net/download/ and swap it into the bundle's"
        Write-Host "  php\ folder (back up the old folder first), or update the bundle itself"
        Write-Host "  (e.g. XAMPP's own updater) if it ships a newer PHP build."
    } else {
        Write-Host "No vulnerable Windows-side PHP found; nothing to patch on the host."
    }
}

# ---------- Summary ----------
Write-Section "Summary"
if ($findings.Count -gt 0) {
    $findings | Format-Table Location, Version, Vulnerable, Reason -AutoSize
} else {
    Write-Host "No PHP found directly on the Windows host (outside WSL)."
}
if ($wslResults.Count -gt 0) {
    Write-Host "WSL distros scanned: $($wslResults -join ', ') -- see output above for per-distro results."
}

Write-Host ""
Write-Host "VirtualBox VMs are NOT scanned by this script -- no VirtualBox access from here." -ForegroundColor Yellow
Write-Host "Copy php2shell-patch.sh into each Linux VM and run it there:" -ForegroundColor Yellow
Write-Host "    chmod +x php2shell-patch.sh && ./php2shell-patch.sh          # scan"
Write-Host "    ./php2shell-patch.sh --patch                                 # patch"
Write-Host "For a Windows VirtualBox guest, copy this whole folder in and run this .ps1 directly on the guest."
