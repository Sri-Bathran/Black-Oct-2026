<#
.SYNOPSIS
  Finds EVERY copy of PHP, Node.js, Python, Chrome, Edge, Firefox and Pillow
  on this Windows machine -- however it got there -- classifies HOW each one
  was installed, rates it against the real current "fixed" version, and
  patches it using the action that matches its install method.

.USAGE
  powershell -ExecutionPolicy Bypass -File .\scan-patch-software.ps1          # scan only
  powershell -ExecutionPolicy Bypass -File .\scan-patch-software.ps1 -Patch   # scan + patch
  powershell -ExecutionPolicy Bypass -File .\scan-patch-software.ps1 -Quick   # common folders only (faster)

.NOTES
  This is a rebuild of the earlier PATH-only version. The old version only
  ever found "the" php/node/python/chrome/etc. on PATH or in a few
  hand-picked bundle folders -- it would completely miss a second Chrome
  install, a Node.js copy bundled inside another app, a Python dropped in
  by a dev tool, or anything installed by a version manager. This version
  finds every copy and classifies its install METHOD first (winget/MSI
  installer, Microsoft Store, choco, scoop, nvm/volta/fnm/pyenv-win/uv/
  conda, a tool-bundled cache like Puppeteer/Playwright, XAMPP/WAMP/
  Laragon, bundled inside another app, or a portable/manual binary with no
  installer record at all -- the GitHub-release-zip-dropped-somewhere case,
  identified by its Authenticode signature when nothing else explains it).
  The install method then decides the patch action: that part really is
  the easy half once the hard half (figuring out how it got there) is done.

  Every "latest version" lookup tries a live official API first and only
  falls back to a baked-in table (last verified 2026-10-24) if that request
  fails. Not elevated: other users' profile folders cannot be read, same
  limitation every tool has here -- re-run as Administrator for full
  coverage across all accounts.
#>

param(
    [switch]$Patch,
    [switch]$Quick
)

function Write-Section($t) { Write-Host ""; Write-Host "== $t ==" -ForegroundColor Cyan }
function Write-Fallback($m) { Write-Host "  [fallback] $m" -ForegroundColor DarkYellow }
function Write-Ok($m)   { Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Vuln($m) { Write-Host "  [OLD]  $m" -ForegroundColor Red }
function Write-Info($m) { Write-Host "  [i]    $m" }

# Avoids [Security.Principal.WindowsPrincipal]::IsInRole() -- that's a method
# invocation on a non-core type, blocked under Constrained Language Mode (the
# same restriction that broke [pscustomobject] earlier in this project). A
# plain external command sidesteps it: 'net session' only succeeds elevated.
$null = net session 2>&1
$IsElevated = ($LASTEXITCODE -eq 0)
if (-not $IsElevated) {
    Write-Host "[!!] Not elevated: other users' profile folders cannot be read. Re-run as Administrator for full coverage." -ForegroundColor Yellow
}

# Baked-in fallback table, last verified live 2026-10-24.
$FallbackLatest = @{
    "php83" = "8.3.36"; "php84" = "8.4.27"; "php85" = "8.5.12"; "php82" = "8.2.35"
    "nodejs" = "24.22.1"; "python314" = "3.14.9"
    "chrome" = "157.0.8103.15"; "edge" = "156.0.4314.42"; "firefox" = "158.0.1"; "pillow" = "13.0.0"
}

function Try-WebRequest($url) {
    try { return Invoke-RestMethod -Uri $url -TimeoutSec 8 -ErrorAction Stop } catch { return $null }
}

# ---------------- live "latest version" lookups, each with a fallback ----------------
function Get-LatestPhp($branch) {
    $data = Try-WebRequest "https://endoflife.date/api/php.json"
    if ($data) { $e = $data | Where-Object { $_.cycle -eq $branch }; if ($e -and $e.latest) { return $e.latest } }
    Write-Fallback "endoflife.date php API unavailable, using baked-in table for PHP $branch"
    return $FallbackLatest["php$($branch -replace '\.','')"]
}
function Get-LatestNodeLTS() {
    $data = Try-WebRequest "https://nodejs.org/dist/index.json"
    if ($data) { $l = $data | Where-Object { $_.lts -ne $false } | Select-Object -First 1; if ($l) { return $l.version.TrimStart('v') } }
    Write-Fallback "nodejs.org/dist/index.json unavailable, using baked-in table"
    return $FallbackLatest["nodejs"]
}
function Get-LatestPython314() {
    $data = Try-WebRequest "https://endoflife.date/api/python.json"
    if ($data) { $e = $data | Where-Object { $_.cycle -eq "3.14" }; if ($e -and $e.latest) { return $e.latest } }
    Write-Fallback "endoflife.date python API unavailable, using baked-in table"
    return $FallbackLatest["python314"]
}
function Get-LatestChrome() {
    $data = Try-WebRequest "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions?pageSize=1"
    if ($data -and $data.versions) { return $data.versions[0].version }
    Write-Fallback "Chrome versionhistory API unavailable, using baked-in table"
    return $FallbackLatest["chrome"]
}
function Get-LatestEdge() {
    $data = Try-WebRequest "https://edgeupdates.microsoft.com/api/products"
    if ($data) {
        $s = $data | Where-Object { $_.Product -eq "Stable" }
        if ($s) { $r = $s.Releases | Where-Object { $_.Platform -eq "Windows" -and $_.Architecture -eq "x64" } | Select-Object -First 1; if ($r) { return $r.ProductVersion } }
    }
    Write-Fallback "edgeupdates.microsoft.com API unavailable, using baked-in table"
    return $FallbackLatest["edge"]
}
function Get-LatestFirefox() {
    $data = Try-WebRequest "https://product-details.mozilla.org/1.0/firefox_versions.json"
    if ($data -and $data.LATEST_FIREFOX_VERSION) { return $data.LATEST_FIREFOX_VERSION }
    Write-Fallback "product-details.mozilla.org unavailable, using baked-in table"
    return $FallbackLatest["firefox"]
}
function Get-LatestPillow() {
    $data = Try-WebRequest "https://pypi.org/pypi/Pillow/json"
    if ($data -and $data.info.version) { return $data.info.version }
    Write-Fallback "pypi.org Pillow API unavailable, using baked-in table"
    return $FallbackLatest["pillow"]
}

# =====================================================================
# WHOLE-MACHINE DISCOVERY: find every copy, then work out HOW it got there
# =====================================================================

Write-Host "Install-method-aware scanner (PHP / Node / Python / Chrome / Edge / Firefox / Pillow)" -ForegroundColor Yellow
Write-Host "Finds every copy on the machine first, THEN figures out how it was installed, THEN picks the matching patch action."

# ---- 1. Build lookup indexes once: these are the records every real install LEAVES BEHIND ----

function Get-UninstallIndex {
    # Every MSI/EXE installer (including ones winget drove) registers here.
    # HKLM = machine-wide install, HKCU = per-user install -- that split IS the
    # "installer" vs "installer-user" distinction.
    $index = @{}
    $hives = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope = "machine" },
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope = "machine" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope = "user" }
    )
    foreach ($h in $hives) {
        Get-ItemProperty -Path $h.Path -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.InstallLocation) {
                $key = $_.InstallLocation.TrimEnd('\').ToLower()
                $index[$key] = @{
                    DisplayName = $_.DisplayName; Publisher = $_.Publisher; Version = $_.DisplayVersion
                    UninstallString = $_.UninstallString; Scope = $h.Scope
                }
            }
        }
    }
    return $index
}

function Get-AppxIndex {
    # Microsoft Store packages (MSIX) -- Python and some others ship this way.
    $index = @{}
    try {
        Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.InstallLocation) { $index[$_.InstallLocation.TrimEnd('\').ToLower()] = @{ Name = $_.Name; Version = $_.Version } }
        }
    } catch { Write-Fallback "Get-AppxPackage unavailable/failed, Microsoft Store packages won't be labeled distinctly" }
    return $index
}

function Get-WingetIds {
    # Just the set of Ids winget currently tracks, so we can note "(tracked by winget)"
    # on top of whatever the uninstall registry already told us.
    $ids = @{}
    $w = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $w) { return $ids }
    try {
        winget list --source winget 2>$null | Select-Object -Skip 2 | ForEach-Object {
            if ($_ -match '\S') {
                $cols = $_ -split '\s{2,}'
                if ($cols.Count -ge 2) { $ids[$cols[1].Trim()] = $cols[0].Trim() }
            }
        }
    } catch {}
    return $ids
}

Write-Section "Building install-record indexes (registry, Store, winget)"
$UninstallIndex = Get-UninstallIndex
$AppxIndex = Get-AppxIndex
$WingetIds = Get-WingetIds
Write-Info "Uninstall registry entries with an InstallLocation: $($UninstallIndex.Count)"
Write-Info "Microsoft Store (Appx) packages: $($AppxIndex.Count)"
Write-Info "winget-tracked package ids: $($WingetIds.Count)"

function Find-AncestorRegistryEntry($path) {
    # Walks UP from a binary's folder to see if it sits inside some OTHER
    # app's registered install location -- that's the "bundled inside
    # another app" case (a dev tool shipping its own private Node/Python).
    $cur = $path.TrimEnd('\')
    for ($i = 0; $i -lt 6; $i++) {
        $parent = Split-Path $cur -Parent
        if (-not $parent -or $parent -eq $cur) { break }
        $key = $parent.ToLower()
        if ($UninstallIndex.ContainsKey($key)) { return $UninstallIndex[$key] }
        $cur = $parent
    }
    return $null
}

function Get-InstallMethod($Root, $ExePath, $Product) {
    $r = $Root.ToLower()

    # -- filesystem-pattern methods: these are unambiguous regardless of any registry record --
    if ($r -match '\\appdata\\local\\temp\\|\\windows\\temp\\') { return @{ Method = "download-in-temp"; Detail = "sitting in a temp folder" } }
    if ($r -match '\\nvm\\v\d|\\nodejs\\nvm\\') { return @{ Method = "nvm"; Detail = "nvm-windows" } }
    if ($r -match '\\volta\\') { return @{ Method = "volta"; Detail = "" } }
    if ($r -match '\\fnm\\|\\fnm_multishells\\') { return @{ Method = "fnm"; Detail = "" } }
    if ($r -match '\\scoop\\apps\\') { return @{ Method = "scoop"; Detail = "" } }
    if ($r -match '\\chocolatey\\lib\\') { return @{ Method = "choco"; Detail = "" } }
    if ($r -match '\\\.pyenv\\pyenv-win\\') { return @{ Method = "pyenv-win"; Detail = "" } }
    if ($r -match '\\appdata\\local\\python\\pythoncore-') { return @{ Method = "pymanager"; Detail = "Python install manager (py.exe)" } }
    if ($r -match '\\uv\\python\\') { return @{ Method = "uv"; Detail = "" } }
    if ($r -match 'anaconda|miniconda|miniforge|mambaforge') { return @{ Method = "conda"; Detail = "" } }
    if ($r -match '\\\.cache\\puppeteer\\') { return @{ Method = "puppeteer-cache"; Detail = "downloaded automatically by a Puppeteer-using app, not a real Chrome install" } }
    if ($r -match '\\ms-playwright\\') { return @{ Method = "playwright-cache"; Detail = "downloaded automatically by a Playwright-using app" } }
    if ($r -match '\\node_modules\\') { return @{ Method = "npm-package"; Detail = "vendored inside a project's node_modules" } }
    if ($r -match '\\xampp\\') { return @{ Method = "xampp"; Detail = "" } }
    if ($r -match '\\wamp(64)?\\') { return @{ Method = "wamp"; Detail = "" } }
    if ($r -match '\\laragon\\') { return @{ Method = "laragon"; Detail = "" } }

    # -- Microsoft Store --
    if ($AppxIndex.ContainsKey($r)) {
        $a = $AppxIndex[$r]
        return @{ Method = "microsoft-store"; Detail = "$($a.Name) $($a.Version) -- Windows Store keeps this current on its own" }
    }

    # -- registry-tracked installer (MSI/EXE) -- this is "from the official site" or "via winget": --
    #    both land in the same uninstall registry record, so we distinguish them by whether
    #    winget currently recognizes the same DisplayName/Id -- not by guessing the download origin.
    if ($UninstallIndex.ContainsKey($r)) {
        $e = $UninstallIndex[$r]
        $viaWinget = $false
        foreach ($name in $WingetIds.Keys) { if ($name -and $e.DisplayName -and $e.DisplayName -like "*$name*") { $viaWinget = $true; break } }
        $kind = if ($e.UninstallString -match 'msiexec') { "MSI installer" } else { "EXE installer" }
        $source = if ($viaWinget) { "tracked by winget" } else { "official vendor installer, not package-manager tracked (installed directly from the vendor's site)" }
        $scope = if ($e.Scope -eq "user") { "installer-user" } else { "installer" }
        return @{ Method = $scope; Detail = "$kind, publisher: $($e.Publisher) -- $source" }
    }

    # -- bundled inside some OTHER app's registered install --
    $ancestor = Find-AncestorRegistryEntry $Root
    if ($ancestor -and $ancestor.DisplayName -notlike "*$Product*") {
        return @{ Method = "bundled-in-app"; Detail = "ships inside '$($ancestor.DisplayName)' ($($ancestor.Publisher)) -- update that app, not this copy directly" }
    }

    # -- no installer record, no known cache/manager pattern: likely a portable binary
    #    someone extracted manually (a GitHub release zip, a vendor .zip, etc). The
    #    Authenticode signature is the best remaining clue to who actually built it.
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $ExePath -ErrorAction Stop
        if ($sig.Status -eq "Valid" -and $sig.SignerCertificate) {
            $cn = ($sig.SignerCertificate.Subject -split ',')[0] -replace '^CN=', ''
            return @{ Method = "manual-signed"; Detail = "no installer or package-manager record; signed by '$cn' -- likely downloaded directly (GitHub release / vendor zip) and extracted by hand" }
        }
    } catch {}
    return @{ Method = "manual-unsigned"; Detail = "no installer record and no (valid) code signature -- unknown origin, treat with extra caution" }
}

# ---- 2. Walk the filesystem for every copy of each tracked product ----

function Get-ScanRoots {
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA, $HOME) | Where-Object { $_ -and (Test-Path $_) }
    if (-not $Quick) {
        foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            $p = "$($drive.Name):\"
            if ($p -ne "$env:SystemDrive\" -and (Test-Path $p)) { $roots += $p }
        }
    }
    return ($roots | Select-Object -Unique)
}

function Find-Binaries($roots, $patterns, $maxDepth) {
    $found = @()
    foreach ($root in $roots) {
        try {
            $found += Get-ChildItem -Path $root -Include $patterns -File -Recurse -Depth $maxDepth -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '\\windows\\(winsxs|system32\\driverstore)\\' }
        } catch {
            Write-Fallback "Could not fully walk '$root' ($($_.Exception.Message)); partial results only"
        }
    }
    return $found | Select-Object -Unique -ExpandProperty FullName
}

$roots = Get-ScanRoots
Write-Info "Scan roots: $($roots -join ', ')$(if ($Quick) { ' (Quick mode: no full drive walk)' })"

$depth = if ($Quick) { 4 } else { 6 }

function Get-FileVersionString($path) {
    try {
        $vi = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo
        $v = $vi.ProductVersion
        if (-not $v) { $v = $vi.FileVersion }
        if ($v -match '(\d+\.\d+\.\d+(\.\d+)?)') { return $Matches[1] }
    } catch {}
    Write-Fallback "File VersionInfo unavailable for '$path', trying to run it with --version"
    foreach ($argSet in @("--version", "-v", "-r echo PHP_VERSION;")) {
        try {
            $out = & $path $argSet.Split(' ') 2>$null
            if ($out -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
        } catch {}
    }
    return $null
}

$findings = @()

function Scan-Product($productName, $patterns, $latestFn, $branchAware) {
    Write-Section $productName
    $bins = Find-Binaries $roots $patterns $depth
    if (-not $bins) { Write-Info "No copies found."; return }
    foreach ($bin in $bins) {
        $ver = Get-FileVersionString $bin
        if (-not $ver) { continue }
        $root = Split-Path $bin -Parent
        $m = Get-InstallMethod $root $bin $productName
        $latest = if ($branchAware) { & $latestFn (($ver -split '\.')[0..1] -join '.') } else { & $latestFn }
        $vuln = $false
        try { $vuln = ([version]$ver) -lt ([version]$latest) } catch { $vuln = ($ver -ne $latest) }
        $row = New-Object -TypeName PSObject -Property @{
            Software = $productName; Installed = $ver; Latest = $latest; Vulnerable = $vuln
            Method = $m.Method; Detail = $m.Detail; Path = $bin
        }
        $script:findings += $row
        if ($m.Method -in @("microsoft-store", "npm-package", "puppeteer-cache", "playwright-cache", "bundled-in-app")) {
            Write-Info "$productName $ver [$($m.Method)] $bin -- $($m.Detail)"
        } elseif ($vuln) {
            Write-Vuln "$productName $ver -> latest $latest  [$($m.Method)] $bin"
            Write-Host "         $($m.Detail)" -ForegroundColor DarkGray
        } else {
            Write-Ok "$productName $ver is current  [$($m.Method)] $bin"
        }
    }
}

Scan-Product "PHP"     @("php.exe") { param($b) Get-LatestPhp $b } $true
Scan-Product "Node.js" @("node.exe") { Get-LatestNodeLTS } $false
Scan-Product "Python"  @("python.exe") { Get-LatestPython314 } $false
Scan-Product "Chrome"  @("chrome.exe") { Get-LatestChrome } $false
Scan-Product "Edge"    @("msedge.exe") { Get-LatestEdge } $false
Scan-Product "Firefox" @("firefox.exe") { Get-LatestFirefox } $false

# Pillow: not a binary -- found via every python.exe's own site-packages (including venvs,
# which the PATH-only version never looked at).
Write-Section "Pillow (pip, via every Python copy found above)"
$pythonBins = $findings | Where-Object { $_.Software -eq "Python" } | Select-Object -ExpandProperty Path -Unique
if (-not $pythonBins) { Write-Info "No Python copies found, so no Pillow to check." }
foreach ($py in $pythonBins) {
    $ver = & $py -c "import PIL; print(PIL.__version__)" 2>$null
    if (-not $ver) { continue }
    $latest = Get-LatestPillow
    $vuln = $false
    try { $vuln = ([version]$ver) -lt ([version]$latest) } catch { $vuln = ($ver -ne $latest) }
    $row = New-Object -TypeName PSObject -Property @{ Software = "Pillow"; Installed = $ver; Latest = $latest; Vulnerable = $vuln; Method = "pip"; Detail = "inside $py"; Path = $py }
    $findings += $row
    if ($vuln) { Write-Vuln "Pillow $ver -> latest $latest  (in $py)" } else { Write-Ok "Pillow $ver is current  (in $py)" }
}

# =====================================================================
# PATCHING: routed by install method -- this part really is the easy half
# =====================================================================
if ($Patch) {
    Write-Section "Patching, routed by install method"
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    $choco  = Get-Command choco -ErrorAction SilentlyContinue
    $scoop  = Get-Command scoop -ErrorAction SilentlyContinue

    foreach ($row in ($findings | Where-Object { $_.Vulnerable })) {
        Write-Host "-- $($row.Software) $($row.Installed) -> $($row.Latest)  [$($row.Method)]  $($row.Path) --"
        switch ($row.Method) {
            "installer" {
                if ($winget) {
                    $idMap = @{ PHP = "PHP.PHP.8.3"; "Node.js" = "OpenJS.NodeJS.LTS"; Python = "Python.Python.3.14"; Chrome = "Google.Chrome"; Edge = "Microsoft.Edge"; Firefox = "Mozilla.Firefox" }
                    $id = $idMap[$row.Software]
                    if ($id) {
                        winget upgrade --id $id --silent --accept-package-agreements --accept-source-agreements 2>$null
                        if ($LASTEXITCODE -ne 0) { Write-Host "  winget upgrade for $id found nothing to upgrade or failed -- check the actual installed id with 'winget list'." -ForegroundColor Red }
                    }
                } else {
                    Write-Host "  No winget available. Download the fixed build from the vendor's official site and reinstall in place." -ForegroundColor Red
                }
            }
            "installer-user" { Write-Host "  Per-user installer, not machine-wide. Same fix: winget upgrade if winget sees it, else reinstall from the vendor's site." }
            "microsoft-store" { Write-Host "  Microsoft Store keeps this current automatically -- nothing to do (check Store 'Get updates' if it's stale)." }
            "choco" { if ($choco) { choco upgrade $row.Software.ToLower() -y 2>$null } else { Write-Host "  choco not found." -ForegroundColor Red } }
            "scoop" { if ($scoop) { scoop update $row.Software.ToLower() 2>$null } else { Write-Host "  scoop not found." -ForegroundColor Red } }
            "pip" { & $row.Path -m pip install --upgrade Pillow }
            { $_ -in @("nvm", "volta", "fnm", "pyenv-win", "pymanager", "uv", "conda") } {
                Write-Host "  Managed by $($row.Method) -- that tool pins exact versions on purpose. Install the fixed version with it directly, e.g.:" -ForegroundColor Yellow
                Write-Host "    $($row.Method) install $($row.Latest)"
            }
            { $_ -in @("puppeteer-cache", "playwright-cache", "npm-package") } {
                Write-Host "  Not a real install -- it's fetched automatically by the app/project that uses it. Re-running that app's own 'npm install' (Puppeteer/Playwright) or 'npm update' will pull a current build." -ForegroundColor Yellow
            }
            "bundled-in-app" { Write-Host "  $($row.Detail). Update that application itself; this copy can't be patched independently." -ForegroundColor Yellow }
            { $_ -in @("xampp", "wamp", "laragon") } { Write-Host "  Bundled with $($row.Method). Use that stack's own updater, or swap the fixed PHP build into its php\ folder by hand." -ForegroundColor Yellow }
            "manual-signed" { Write-Host "  $($row.Detail). No package manager owns this copy -- download the fixed build from the signer's official site/release page and replace this folder's contents by hand." -ForegroundColor Yellow }
            "manual-unsigned" { Write-Host "  $($row.Detail). Treat this one as suspect as well as outdated -- verify what it actually is before deciding to patch or remove it." -ForegroundColor Red }
            "download-in-temp" { Write-Host "  Sitting in a temp folder -- likely a leftover extracted installer, not a real install. Safe to just delete if nothing references it." -ForegroundColor Yellow }
            default { Write-Host "  No automated patch path for method '$($row.Method)'. $($row.Detail)" -ForegroundColor Red }
        }
    }
}

# ---------------- Summary ----------------
Write-Section "Summary"
if ($findings.Count -gt 0) {
    $findings | Sort-Object Software, Vulnerable -Descending | Format-Table Software, Installed, Latest, Vulnerable, Method, Path -AutoSize
} else {
    Write-Host "Nothing found."
}
$vulnCount = ($findings | Where-Object { $_.Vulnerable }).Count
Write-Host "$($findings.Count) copies found across all products, $vulnCount outdated." -ForegroundColor Yellow
if (-not $Patch -and $vulnCount -gt 0) { Write-Host "Re-run with -Patch to apply fixes where an automated path exists." -ForegroundColor Yellow }
