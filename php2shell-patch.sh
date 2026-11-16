#!/usr/bin/env bash
# php2shell-patch.sh
# Scan (and optionally patch) a Linux host/VM for the "Black October 2026" PHP
# remote-code-execution flaws: CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell").
#
# Upstream-fixed PHP releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35 (2026-10-21).
# Distros backport the fix under their own package version suffix, so this
# script upgrades via the distro's package manager rather than trying to
# hard-code every vendor's patched build number.
#
# This script is written as a FALLBACK CHAIN: every detection or patch step
# tries its primary command first, and if that command is missing or fails,
# moves on to the next-best alternative for that step, logging which one
# actually worked. That's deliberate -- the goal is one script that behaves
# correctly across different distros, minimal containers, and partially
# locked-down hosts, not just the box it was first tested on.
#
# Usage:
#   ./php2shell-patch.sh            # scan only, no changes made
#   ./php2shell-patch.sh --patch    # scan, then apply the upgrade
#
# Works standalone on any Linux box, including:
#   - a WSL distro (run directly inside it)
#   - a VirtualBox guest (copy this file into the VM and run it there,
#     since this host has no VirtualBox access to reach the VM directly)

set -u
PATCH=false
[ "${1:-}" = "--patch" ] && PATCH=true

# All of these write to stderr: some callers invoke functions that use
# these loggers inside $(...) command substitution to capture a return
# value, and a logged line on stdout would corrupt that captured value.
bold() { printf '\033[1m%s\033[0m\n' "$1" >&2; }
ok()   { printf '  [OK]    %s\n' "$1" >&2; }
bad()  { printf '  [VULN]  %s\n' "$1" >&2; }
info() { printf '  [i]     %s\n' "$1" >&2; }
fb()   { printf '  [fallback] %s\n' "$1" >&2; }

bold "== php2shell scan (CVE-2026-109618 / CVE-2026-109619) =="
echo "Host: $(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown) ($(uname -a 2>/dev/null))"
echo

FIXED_UPSTREAM="8.5.12 8.4.27 8.3.36 8.2.35"
FOUND_VULNERABLE=false
FOUND_PHP=false

version_lt() {
  [ "$1" = "$2" ] && return 1
  lower=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)
  [ "$lower" = "$1" ]
}

# ---- version detection fallback chain for one binary ----
# tries: `bin -r echo PHP_VERSION` -> `bin --version` parse -> `bin -v` parse
get_php_version() {
  local bin="$1" ver=""
  ver=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null)
  if [ -n "$ver" ]; then echo "$ver"; return; fi
  fb "$bin -r failed, trying '$bin --version'"
  ver=$("$bin" --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  if [ -n "$ver" ]; then echo "$ver"; return; fi
  fb "$bin --version failed, trying '$bin -v'"
  ver=$("$bin" -v 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  echo "$ver"
}

check_binary_version() {
  local bin="$1"
  local ver major_minor fixed
  ver=$(get_php_version "$bin")
  [ -z "$ver" ] && return
  FOUND_PHP=true
  major_minor=$(echo "$ver" | cut -d. -f1,2)
  fixed=""
  for f in $FIXED_UPSTREAM; do
    case "$f" in
      "$major_minor".*) fixed="$f" ;;
    esac
  done
  if [ -z "$fixed" ]; then
    info "$bin -> PHP $ver (branch $major_minor is end-of-life upstream; no mainline fixed release exists for it)"
    FOUND_VULNERABLE=true
    return
  fi
  if version_lt "$ver" "$fixed"; then
    bad "$bin -> PHP $ver  (vulnerable; upstream fix is $fixed or your distro's equivalent backport)"
    FOUND_VULNERABLE=true
  else
    ok "$bin -> PHP $ver  (>= $fixed, not vulnerable to the upstream CVE)"
  fi
}

# ---- binary discovery fallback chain ----
# tries: `command -v` for common names -> `which` -> `type -P` -> filesystem search
discover_php_binaries() {
  local found="" name
  for name in php php-cgi php-fpm php8.1 php8.2 php8.3 php8.4 php8.5 php7.4 php7.3; do
    if command -v "$name" >/dev/null 2>&1; then
      found="$found $(command -v "$name")"
    fi
  done
  if [ -z "$found" ] && command -v which >/dev/null 2>&1; then
    fb "'command -v' found nothing, trying 'which'"
    for name in php php-cgi php-fpm; do
      w=$(which "$name" 2>/dev/null)
      [ -n "$w" ] && found="$found $w"
    done
  fi
  if [ -z "$found" ]; then
    fb "which found nothing, falling back to filesystem search"
    found=$(find /usr/bin /usr/local/bin /opt -maxdepth 3 -iname 'php*' -type f -executable 2>/dev/null | tr '\n' ' ')
  fi
  echo "$found" | tr ' ' '\n' | sort -u | grep -v '^$'
}

for bin in $(discover_php_binaries); do
  [ -x "$bin" ] && check_binary_version "$bin"
done

echo
bold "-- installed packages --"

# ---- package manager detection fallback chain ----
PKG_MGR=""
detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then echo apt; return; fi
  fb "apt/dpkg not found, trying dnf"
  if command -v dnf >/dev/null 2>&1; then echo dnf; return; fi
  fb "dnf not found, trying yum"
  if command -v yum >/dev/null 2>&1; then echo yum; return; fi
  fb "yum not found, trying zypper"
  if command -v zypper >/dev/null 2>&1; then echo zypper; return; fi
  fb "zypper not found, trying apk"
  if command -v apk >/dev/null 2>&1; then echo apk; return; fi
  fb "apk not found, trying pacman"
  if command -v pacman >/dev/null 2>&1; then echo pacman; return; fi
  fb "no known package manager found"
  echo ""
}
PKG_MGR=$(detect_pkg_mgr)
info "Package manager detected: ${PKG_MGR:-none}"

list_php_packages() {
  case "$PKG_MGR" in
    apt)
      # primary: dpkg -l ; fallback: apt list --installed (older/minimal images sometimes lack dpkg -l formatting)
      out=$(dpkg -l 2>/dev/null | awk '/^ii/{print $2, $3}' | grep -E '^(php|libapache2-mod-php)')
      if [ -z "$out" ]; then
        fb "dpkg -l gave nothing, trying 'apt list --installed'"
        out=$(apt list --installed 2>/dev/null | grep -E '^php' )
      fi
      echo "$out"
      ;;
    dnf|yum|zypper)
      # primary: rpm -qa ; fallback: dnf/yum list installed
      out=$(rpm -qa 2>/dev/null | grep -i '^php')
      if [ -z "$out" ]; then
        fb "rpm -qa gave nothing, trying '$PKG_MGR list installed'"
        out=$($PKG_MGR list installed 2>/dev/null | grep -i '^php')
      fi
      echo "$out"
      ;;
    apk)
      out=$(apk info 2>/dev/null | grep -i '^php')
      echo "$out"
      ;;
    pacman)
      out=$(pacman -Q 2>/dev/null | grep -i '^php')
      echo "$out"
      ;;
  esac
}

PKG_LIST=$(list_php_packages)
if [ -n "$PKG_LIST" ]; then
  echo "$PKG_LIST" | sed 's/^/    /'
  FOUND_PHP=true
fi

if [ "$FOUND_PHP" = false ] && [ -z "$PKG_MGR" ]; then
  info "No PHP binaries on PATH, no filesystem matches, and no supported package manager found."
fi

echo
if [ "$FOUND_PHP" = false ]; then
  bold "No PHP installation detected on this host. Nothing to patch."
  exit 0
fi

if [ "$FOUND_VULNERABLE" = false ]; then
  bold "No vulnerable PHP version detected by binary-version check."
  info "Package versions above may still need a vendor security update even if"
  info "the -r check looked fine (some distros keep the upstream version string"
  info "in the package name and only bump a trailing build suffix on patch)."
fi

echo
if [ "$PATCH" = false ]; then
  bold "Scan-only mode. Re-run with --patch to apply the update:"
  echo "    $0 --patch"
  exit 0
fi

bold "== Applying patch via ${PKG_MGR:-<none>} =="

# ---- privilege-escalation fallback chain ----
# tries: already root -> sudo -> su -c (interactive) -> doas
run_privileged() {
  if [ "$(id -u)" = "0" ]; then
    eval "$@"
    return $?
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo bash -c "$*"
    return $?
  fi
  fb "sudo not found, trying doas"
  if command -v doas >/dev/null 2>&1; then
    doas bash -c "$*"
    return $?
  fi
  fb "doas not found, trying su"
  if command -v su >/dev/null 2>&1; then
    su -c "$*"
    return $?
  fi
  echo "No privilege-escalation method available (no root, sudo, doas, or su). Re-run as root." >&2
  return 1
}

case "$PKG_MGR" in
  apt)
    pkgs=$(dpkg -l 2>/dev/null | awk '/^ii/{print $2}' | grep -E '^(php|libapache2-mod-php)')
    run_privileged "apt-get update && apt-get install --only-upgrade -y $pkgs"
    ;;
  dnf)
    pkgs=$(rpm -qa | grep -i '^php' | sed -E 's/-[0-9].*$//' | sort -u)
    run_privileged "dnf update -y $pkgs"
    ;;
  yum)
    pkgs=$(rpm -qa | grep -i '^php' | sed -E 's/-[0-9].*$//' | sort -u)
    run_privileged "yum update -y $pkgs"
    ;;
  zypper)
    pkgs=$(rpm -qa | grep -i '^php' | sed -E 's/-[0-9].*$//' | sort -u)
    run_privileged "zypper update -y $pkgs"
    ;;
  apk)
    pkgs=$(apk info | grep -i '^php')
    run_privileged "apk update && apk upgrade $pkgs"
    ;;
  pacman)
    pkgs=$(pacman -Q | grep -i '^php' | awk '{print $1}')
    run_privileged "pacman -Syu --noconfirm $pkgs"
    ;;
  *)
    echo "No supported package manager -- PHP must be from source or a vendor tarball."
    echo "Manual remediation:"
    echo "  - If your branch is 8.2/8.3/8.4/8.5: rebuild/download the fixed release"
    echo "    (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) from https://www.php.net/downloads"
    echo "  - If your branch is EOL (<=8.1, 7.x, 5.x): apply the PHP security team's"
    echo "    minimal source backport for php2shell, or upgrade to a supported branch."
    exit 1
    ;;
esac

echo
bold "== Post-patch re-check =="
for bin in $(discover_php_binaries); do
  [ -x "$bin" ] && check_binary_version "$bin"
done

echo "Restart any running PHP-FPM/Apache/Nginx services so the new PHP is loaded, e.g.:"
if command -v systemctl >/dev/null 2>&1; then
  echo "    sudo systemctl restart php*-fpm apache2 nginx 2>/dev/null"
elif command -v service >/dev/null 2>&1; then
  fb "systemctl not available, use 'service' instead"
  echo "    sudo service apache2 restart ; sudo service nginx restart"
else
  fb "no systemctl/service found (common in containers) -- restart the PHP process manually"
  echo "    (no init system detected; restart your PHP process/container manually)"
fi
