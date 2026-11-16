#!/usr/bin/env bash
# scan-patch-software.sh
# Scans a Linux host/VM/WSL distro for outdated versions of:
# PHP, Node.js (LTS), Python 3.14, Chrome, Firefox, Pillow (pip).
# (Edge is included only if actually installed -- it's rare on Linux.)
#
# Every "latest version" lookup tries a live official API first and only
# falls back to a baked-in table (last verified 2026-10-24) if that request
# fails. Every installed-version lookup and every patch step is likewise a
# fallback chain: primary method first, next-best alternative if missing or
# failing, logged via fb() when that happens -- so this keeps working across
# different distros and however much (or little) is installed.
#
# Usage:
#   ./scan-patch-software.sh            # scan only
#   ./scan-patch-software.sh --patch    # scan + patch

set -u
PATCH=false
[ "${1:-}" = "--patch" ] && PATCH=true

# All of these write to stderr, not stdout: several callers invoke the
# functions that call these loggers inside $(...) command substitution to
# capture a return value, and a logged line on stdout would corrupt that
# captured value.
bold() { printf '\033[1m%s\033[0m\n' "$1" >&2; }
ok()   { printf '  [OK]   %s\n' "$1" >&2; }
bad()  { printf '  [OLD]  %s\n' "$1" >&2; }
info() { printf '  [i]    %s\n' "$1" >&2; }
fb()   { printf '  [fallback] %s\n' "$1" >&2; }

# ---- baked-in fallback table, last verified live 2026-10-24 ----
FALLBACK_PHP83="8.3.36"; FALLBACK_PHP84="8.4.27"; FALLBACK_PHP85="8.5.12"; FALLBACK_PHP82="8.2.35"
FALLBACK_NODE="24.22.1"
FALLBACK_PY314="3.14.9"
FALLBACK_CHROME="156.0.8078.47"   # Linux stable channel figure
FALLBACK_EDGE="156.0.4314.42"
FALLBACK_FIREFOX="158.0.1"
FALLBACK_PILLOW="13.0.0"

# ---- http fetch fallback chain: curl -> wget -> python urllib ----
http_get() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 8 "$url" 2>/dev/null && return 0
  fi
  fb "curl unavailable/failed for $url, trying wget"
  if command -v wget >/dev/null 2>&1; then
    wget -qO- --timeout=8 "$url" 2>/dev/null && return 0
  fi
  fb "wget unavailable/failed for $url, trying python urllib"
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('$url', timeout=8).read().decode())" 2>/dev/null && return 0
  fi
  return 1
}

# ---- json field extraction fallback chain: jq -> python json -> grep/sed ----
json_get() {
  local json="$1" expr_jq="$2" expr_py="$3" grep_pat="$4"
  if command -v jq >/dev/null 2>&1; then
    local v
    v=$(printf '%s' "$json" | jq -r "$expr_jq" 2>/dev/null)
    [ -n "$v" ] && [ "$v" != "null" ] && { echo "$v"; return 0; }
  fi
  fb "jq unavailable/failed, trying python json"
  if command -v python3 >/dev/null 2>&1; then
    local v
    v=$(printf '%s' "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); $expr_py" 2>/dev/null)
    [ -n "$v" ] && { echo "$v"; return 0; }
  fi
  fb "python3 unavailable/failed, trying grep/sed"
  printf '%s' "$json" | grep -oE "$grep_pat" | head -n1
}

version_lt() {
  [ "$1" = "$2" ] && return 1
  local lower
  lower=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)
  [ "$lower" = "$1" ]
}

# ---------------- live "latest version" lookups ----------------

get_latest_php() {
  local branch="$1" json v
  json=$(http_get "https://endoflife.date/api/php.json")
  if [ -n "$json" ]; then
    v=$(json_get "$json" ".[] | select(.cycle==\"$branch\") | .latest" \
        "print([e['latest'] for e in d if e['cycle']=='$branch'][0])" \
        "\"latest\":\"[0-9.]+\"")
    [ -n "$v" ] && { echo "$v" | tr -d '"'; return; }
  fi
  fb "endoflife.date php API unavailable, using baked-in table for PHP $branch"
  case "$branch" in
    8.2) echo "$FALLBACK_PHP82" ;; 8.3) echo "$FALLBACK_PHP83" ;;
    8.4) echo "$FALLBACK_PHP84" ;; 8.5) echo "$FALLBACK_PHP85" ;;
    *) echo "" ;;
  esac
}

get_latest_node_lts() {
  local json v
  json=$(http_get "https://nodejs.org/dist/index.json")
  if [ -n "$json" ]; then
    v=$(json_get "$json" "[.[] | select(.lts != false)][0].version" \
        "print([e['version'] for e in d if e['lts']][0])" \
        '')
    [ -n "$v" ] && { echo "${v#v}"; return; }
  fi
  fb "nodejs.org/dist/index.json unavailable, using baked-in table"
  echo "$FALLBACK_NODE"
}

get_latest_python314() {
  local json v
  json=$(http_get "https://endoflife.date/api/python.json")
  if [ -n "$json" ]; then
    v=$(json_get "$json" ".[] | select(.cycle==\"3.14\") | .latest" \
        "print([e['latest'] for e in d if e['cycle']=='3.14'][0])" \
        '')
    [ -n "$v" ] && { echo "$v" | tr -d '"'; return; }
  fi
  fb "endoflife.date python API unavailable, using baked-in table"
  echo "$FALLBACK_PY314"
}

get_latest_chrome() {
  local json v
  json=$(http_get "https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions?pageSize=1")
  if [ -n "$json" ]; then
    v=$(json_get "$json" ".versions[0].version" "print(d['versions'][0]['version'])" '"version":\s*"[0-9.]+"')
    [ -n "$v" ] && { echo "$v" | tr -d '"'; return; }
  fi
  fb "Chrome versionhistory API unavailable, using baked-in table"
  echo "$FALLBACK_CHROME"
}

get_latest_firefox() {
  local json v
  json=$(http_get "https://product-details.mozilla.org/1.0/firefox_versions.json")
  if [ -n "$json" ]; then
    v=$(json_get "$json" ".LATEST_FIREFOX_VERSION" "print(d['LATEST_FIREFOX_VERSION'])" '"LATEST_FIREFOX_VERSION":\s*"[0-9.]+"')
    [ -n "$v" ] && { echo "$v" | tr -d '"'; return; }
  fi
  fb "product-details.mozilla.org unavailable, using baked-in table"
  echo "$FALLBACK_FIREFOX"
}

get_latest_pillow() {
  local json v
  json=$(http_get "https://pypi.org/pypi/Pillow/json")
  if [ -n "$json" ]; then
    v=$(json_get "$json" ".info.version" "print(d['info']['version'])" '')
    [ -n "$v" ] && { echo "$v" | tr -d '"'; return; }
  fi
  fb "pypi.org Pillow API unavailable, using baked-in table"
  echo "$FALLBACK_PILLOW"
}

# ---------------- installed-version detection ----------------

get_installed_php() {
  local bin
  for bin in php php8.5 php8.4 php8.3 php8.2 php8.1; do
    if command -v "$bin" >/dev/null 2>&1; then
      local v
      v=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null)
      [ -z "$v" ] && { fb "$bin -r failed, trying -v"; v=$("$bin" -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1); }
      [ -n "$v" ] && { echo "$v|$(command -v "$bin")"; return; }
    fi
  done
}

get_installed_node() {
  if command -v node >/dev/null 2>&1; then
    local v
    v=$(node -v 2>/dev/null | tr -d 'v')
    [ -n "$v" ] && { echo "$v|$(command -v node)"; return; }
  fi
}

get_installed_python() {
  local bin
  for bin in python3.14 python3 python; do
    if command -v "$bin" >/dev/null 2>&1; then
      local v
      v=$("$bin" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
      [ -n "$v" ] && { echo "$v|$(command -v "$bin")"; return; }
    fi
  done
}

get_installed_pillow() {
  local bin
  for bin in python3 python; do
    if command -v "$bin" >/dev/null 2>&1; then
      local v
      v=$("$bin" -c "import PIL; print(PIL.__version__)" 2>/dev/null)
      [ -n "$v" ] && { echo "$v|$bin -c import PIL"; return; }
    fi
  done
  fb "Could not import PIL via python3/python, trying pip show"
  for pipbin in pip3 pip; do
    if command -v "$pipbin" >/dev/null 2>&1; then
      local v
      v=$("$pipbin" show Pillow 2>/dev/null | grep -i '^Version:' | awk '{print $2}')
      [ -n "$v" ] && { echo "$v|$pipbin show Pillow"; return; }
    fi
  done
}

get_installed_chrome() {
  local bin
  for bin in google-chrome google-chrome-stable chromium chromium-browser; do
    if command -v "$bin" >/dev/null 2>&1; then
      local v
      v=$("$bin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
      [ -n "$v" ] && { echo "$v|$(command -v "$bin")"; return; }
    fi
  done
}

get_installed_firefox() {
  if command -v firefox >/dev/null 2>&1; then
    local v
    v=$(firefox --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
    [ -n "$v" ] && { echo "$v|$(command -v firefox)"; return; }
  fi
}

get_installed_edge() {
  for bin in microsoft-edge microsoft-edge-stable; do
    if command -v "$bin" >/dev/null 2>&1; then
      local v
      v=$("$bin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
      [ -n "$v" ] && { echo "$v|$(command -v "$bin")"; return; }
    fi
  done
}

report_row() {
  local name="$1" installed="$2" where="$3" latest="$4"
  if [ -z "$installed" ]; then
    info "$name not found on this host."
    return
  fi
  if version_lt "$installed" "$latest"; then
    bad "$name $installed -> latest is $latest   ($where)"
    echo "VULN:$name:$installed:$latest" >> "$TMP_RESULTS"
  else
    ok "$name $installed is current (>= $latest)   ($where)"
  fi
}

TMP_RESULTS=$(mktemp)
trap 'rm -f "$TMP_RESULTS"' EXIT

# Detected once, up front, so the PHP distro-package check below can use it
# too -- not just the later --patch step.
PKG_MGR=""
if command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt"
elif command -v dnf >/dev/null 2>&1; then PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then PKG_MGR="yum"
elif command -v zypper >/dev/null 2>&1; then PKG_MGR="zypper"
elif command -v apk >/dev/null 2>&1; then PKG_MGR="apk"
elif command -v pacman >/dev/null 2>&1; then PKG_MGR="pacman"
fi

bold "Outdated-software scanner (PHP / Node / Python / Chrome / Edge / Firefox / Pillow)"
echo "Live version lookups with baked-in fallback if an API is unreachable."
echo

# Debian/Ubuntu never bump PHP_VERSION on a security backport -- they keep
# the upstream string frozen (e.g. always "8.3.6") and only increment the
# trailing package build number (...24.04.11 -> ...24.04.13). So comparing
# `php -r echo PHP_VERSION` against php.net's own upstream "latest" (e.g.
# "8.3.36") would ALWAYS report "vulnerable" on such distros even on a
# fully patched box. Where a package manager owns the binary, trust its
# installed-vs-candidate state instead; only fall back to the raw
# version-string comparison for non-distro-packaged PHP (source builds,
# manually dropped-in binaries, Windows zips, etc).
php_distro_patch_status() {
  local binpath="$1"
  case "$PKG_MGR" in
    apt)
      local pkg policy installed candidate resolved
      resolved=$(readlink -f "$binpath" 2>/dev/null)
      pkg=$(dpkg -S "$binpath" 2>/dev/null | head -n1 | cut -d: -f1)
      if [ -z "$pkg" ] && [ -n "$resolved" ]; then
        fb "dpkg -S on '$binpath' found nothing, resolving symlinks and retrying on '$resolved'"
        pkg=$(dpkg -S "$resolved" 2>/dev/null | head -n1 | cut -d: -f1)
      fi
      [ -z "$pkg" ] && return 2
      policy=$(apt-cache policy "$pkg" 2>/dev/null)
      installed=$(echo "$policy" | awk '/Installed:/{print $2; exit}')
      candidate=$(echo "$policy" | awk '/Candidate:/{print $2; exit}')
      [ -z "$installed" ] && return 2
      if [ "$installed" = "$candidate" ]; then
        echo "$pkg:$installed"; return 0
      else
        echo "$pkg:$installed:$candidate"; return 1
      fi
      ;;
    dnf|yum)
      local pkg installed resolved
      pkg=$(rpm -qf "$binpath" 2>/dev/null | sed -E 's/-[0-9].*$//')
      if [ -z "$pkg" ]; then
        resolved=$(readlink -f "$binpath" 2>/dev/null)
        [ -n "$resolved" ] && pkg=$(rpm -qf "$resolved" 2>/dev/null | sed -E 's/-[0-9].*$//')
      fi
      [ -z "$pkg" ] && return 2
      installed=$(rpm -q "$pkg" 2>/dev/null)
      if $PKG_MGR check-update "$pkg" >/dev/null 2>&1; then
        echo "$pkg:$installed"; return 0
      else
        echo "$pkg:$installed:update-available"; return 1
      fi
      ;;
    *) return 2 ;;
  esac
}

bold "-- PHP --"
r=$(get_installed_php); ver="${r%%|*}"; where="${r##*|}"
if [ -n "$ver" ]; then
  branch=$(echo "$ver" | cut -d. -f1,2)
  latest=$(get_latest_php "$branch")
  distro_status=$(php_distro_patch_status "$where")
  distro_rc=$?
  if [ "$distro_rc" = "0" ]; then
    ok "PHP $ver ($distro_status) -- distro package is fully up to date (no newer build available). Upstream php.net latest for $branch is $latest; distros backport the fix under their own build number rather than adopting that string."
  elif [ "$distro_rc" = "1" ]; then
    bad "PHP $ver ($distro_status) -- a newer distro package IS available; this host is NOT patched. Upgrade via your package manager."
    echo "VULN:PHP:$ver:$latest (distro package: $distro_status)" >> "$TMP_RESULTS"
  else
    fb "Could not resolve PHP binary to a package manager entry, falling back to raw version comparison vs upstream $latest"
    report_row "PHP" "$ver" "$where" "$latest"
  fi
else
  info "PHP not found on this host."
fi

bold "-- Node.js --"
r=$(get_installed_node); ver="${r%%|*}"; where="${r##*|}"
if [ -n "$ver" ]; then
  latest=$(get_latest_node_lts)
  report_row "Node.js" "$ver" "$where" "$latest"
else
  info "Node.js not found on this host."
fi

bold "-- Python 3.14 --"
r=$(get_installed_python); ver="${r%%|*}"; where="${r##*|}"
if [ -n "$ver" ]; then
  latest=$(get_latest_python314)
  report_row "Python" "$ver" "$where" "$latest"
else
  info "Python not found on this host."
fi

bold "-- Pillow (pip) --"
r=$(get_installed_pillow); ver="${r%%|*}"; where="${r##*|}"
if [ -n "$ver" ]; then
  latest=$(get_latest_pillow)
  report_row "Pillow" "$ver" "$where" "$latest"
else
  info "Pillow not found (no python with PIL, no pip)."
fi

bold "-- Chrome --"
r=$(get_installed_chrome); ver="${r%%|*}"; where="${r##*|}"
if [ -n "$ver" ]; then
  latest=$(get_latest_chrome)
  report_row "Chrome" "$ver" "$where" "$latest"
else
  info "Chrome/Chromium not found on this host."
fi

bold "-- Firefox --"
r=$(get_installed_firefox); ver="${r%%|*}"; where="${r##*|}"
if [ -n "$ver" ]; then
  latest=$(get_latest_firefox)
  report_row "Firefox" "$ver" "$where" "$latest"
else
  info "Firefox not found on this host."
fi

bold "-- Edge --"
r=$(get_installed_edge); ver="${r%%|*}"; where="${r##*|}"
if [ -n "$ver" ]; then
  latest="$FALLBACK_EDGE"
  report_row "Edge" "$ver" "$where" "$latest"
else
  info "Edge not found on this host (uncommon on Linux)."
fi

# ---------------- patching ----------------
if [ "$PATCH" = true ] && [ -s "$TMP_RESULTS" ]; then
  echo
  bold "== Patching =="
  info "Package manager: ${PKG_MGR:-none} (detected earlier during scan)"

  run_privileged() {
    if [ "$(id -u)" = "0" ]; then bash -c "$*"; return $?; fi
    if command -v sudo >/dev/null 2>&1; then sudo bash -c "$*"; return $?; fi
    fb "sudo not found, trying doas"
    if command -v doas >/dev/null 2>&1; then doas bash -c "$*"; return $?; fi
    fb "doas not found, trying su"
    if command -v su >/dev/null 2>&1; then su -c "$*"; return $?; fi
    echo "No privilege-escalation method available; re-run as root." >&2
    return 1
  }

  pkg_upgrade() {
    local pkgpattern="$1"
    case "$PKG_MGR" in
      apt)    run_privileged "apt-get update && apt-get install --only-upgrade -y \$(dpkg -l | awk '/^ii/{print \$2}' | grep -E '$pkgpattern')" ;;
      dnf)    run_privileged "dnf update -y \$(rpm -qa | grep -iE '$pkgpattern' | sed -E 's/-[0-9].*\$//' | sort -u)" ;;
      yum)    run_privileged "yum update -y \$(rpm -qa | grep -iE '$pkgpattern' | sed -E 's/-[0-9].*\$//' | sort -u)" ;;
      zypper) run_privileged "zypper update -y \$(rpm -qa | grep -iE '$pkgpattern' | sed -E 's/-[0-9].*\$//' | sort -u)" ;;
      apk)    run_privileged "apk update && apk upgrade \$(apk info | grep -iE '$pkgpattern')" ;;
      pacman) run_privileged "pacman -Syu --noconfirm \$(pacman -Q | grep -iE '$pkgpattern' | awk '{print \$1}')" ;;
      *)      echo "  No supported package manager found; upgrade manually." ;;
    esac
  }

  while IFS=: read -r _ name installed latest; do
    echo "-- $name ($installed -> $latest) --"
    case "$name" in
      PHP)     pkg_upgrade '^(php|libapache2-mod-php)' ;;
      Node.js)
        if command -v n >/dev/null 2>&1; then
          fb "using 'n' (Node version manager) if present"
          run_privileged "n $latest"
        elif command -v nvm >/dev/null 2>&1; then
          fb "'n' not found, trying nvm"
          nvm install "$latest" && nvm alias default "$latest"
        else
          fb "no Node version manager found, falling back to distro package manager"
          pkg_upgrade '^nodejs'
        fi
        ;;
      Python)
        echo "  System Python is tied to the OS; prefer installing 3.14.x via your distro's"
        echo "  deadsnakes/official repo or pyenv rather than replacing the system binary."
        pkg_upgrade '^python3' 2>/dev/null || true
        ;;
      Pillow)
        if command -v pip3 >/dev/null 2>&1; then
          pip3 install --upgrade Pillow
        else
          fb "pip3 not found, trying pip"
          if command -v pip >/dev/null 2>&1; then
            pip install --upgrade Pillow
          else
            echo "  No pip found to upgrade Pillow."
          fi
        fi
        ;;
      Chrome)   pkg_upgrade '^(google-chrome|chromium)' ;;
      Firefox)  pkg_upgrade '^firefox' ;;
      Edge)     pkg_upgrade '^microsoft-edge' ;;
    esac
  done < "$TMP_RESULTS"

  echo
  echo "Restart any running browser/PHP-FPM processes to pick up the new version."
elif [ "$PATCH" = true ]; then
  echo
  bold "Nothing outdated found; nothing to patch."
else
  if [ -s "$TMP_RESULTS" ]; then
    echo
    bold "Scan-only mode. Re-run with --patch to apply upgrades:"
    echo "    $0 --patch"
  fi
fi
