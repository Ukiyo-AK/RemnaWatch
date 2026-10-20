#!/bin/sh
# Python-free entry point; safe on minimal Debian/Ubuntu installations.
set -eu
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset PYTHONPATH PYTHONHOME
export PYTHONNOUSERSITE=1

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repo_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
apply=no
install_deps=no
skip_deps=no
for arg do
    case "$arg" in
        --apply) apply=yes ;;
        --install-deps) install_deps=yes ;;
        --no-install-deps) skip_deps=yes ;;
    esac
done
if [ "$install_deps" = yes ] && [ "$skip_deps" = yes ]; then
    printf '%s\n' 'Choose --install-deps or --no-install-deps, not both.' >&2
    exit 2
fi

die() { printf '%s\n' "$1" >&2; exit 1; }
apt_failure() {
    if grep -Eiq 'could not get lock|unable to acquire|is another process using it' "$apt_log"; then
        die 'dependencies_apt_locked: wait for the package manager to finish; never delete its lock files.'
    elif grep -Eiq 'temporary failure resolving|could not resolve' "$apt_log"; then
        die 'dependencies_dns_failed: restore DNS resolution for configured repositories and retry.'
    elif grep -Eiq '404[[:space:]]+Not Found|does not have a Release file|no installation candidate|unable to locate package' "$apt_log"; then
        die 'dependencies_repository_unavailable: configure an available signed repository for this release (ESM/ELTS if needed). Mirrors and trust were not changed.'
    elif grep -Eiq 'no space left|not enough free space' "$apt_log"; then
        die 'dependencies_disk_full: free disk space and retry.'
    elif grep -Eiq 'certificate verification failed|certificate verify failed|NO_PUBKEY|is not signed|signatures could' "$apt_log"; then
        die 'dependencies_repository_trust_failed: check CA/keyring and clock; do not disable TLS or signatures.'
    fi
    die 'dependencies_apt_failed: check apt/dpkg and repository health locally; raw output suppressed, locks and repositories unchanged.'
}

# Read fields as data. Do not source /etc/os-release as executable shell code.
[ -r /etc/os-release ] || die 'unsupported_os: /etc/os-release is missing.'
distro=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
case "$distro:$version" in
    debian:11|debian:12|debian:13|ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
    *) die 'unsupported_os: Debian 11/12/13 or Ubuntu LTS 20.04/22.04/24.04/26.04 required. OS will not be upgraded.' ;;
esac
case "$(uname -m)" in
    x86_64|aarch64|amd64|arm64) ;;
    *) die 'unsupported_architecture: amd64 or arm64 required.' ;;
esac
if [ ! -d /run/systemd/system ] || [ "$(cat /proc/1/comm)" != systemd ]; then
    die 'systemd_unavailable: use a systemd host; no packages or units were changed.'
fi

if [ "$apply" = yes ] || [ "$install_deps" = yes ]; then
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || die 'root_required: run this script as root; sudo is unavailable.'
        exec sudo -H -- /bin/sh "$script_dir/install.sh" "$@"
    fi
fi

python_ready=no
if [ -x /usr/bin/python3 ] && /usr/bin/python3 -I -c 'import sys,ssl,sqlite3; sys.exit(0 if sys.version_info >= (3,8) else 1)' >/dev/null 2>&1; then
    python_ready=yes
fi
if [ "$python_ready" = no ]; then
    if [ "$skip_deps" = yes ] || { [ "$apply" = no ] && [ "$install_deps" = no ]; }; then
        die 'python_missing_or_old: Python 3.8+ required. Rerun with --install-deps or --apply to install distro packages.'
    fi
    if ! command -v apt-get >/dev/null 2>&1 || ! command -v dpkg-query >/dev/null 2>&1; then
        die 'package_manager_unavailable: apt-get and dpkg-query required.'
    fi
    free_kb=$(df -Pk / | awk 'NR==2 {print $4}')
    if [ -z "$free_kb" ] || [ "$free_kb" -lt 262144 ]; then
        die 'dependencies_disk_full: free at least 256 MiB.'
    fi
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 UCF_FORCE_CONFFOLD=1 LC_ALL=C
    # A private temporary file prevents repository/proxy credentials reaching logs.
    umask 077
    apt_log=$(mktemp /tmp/remnawatch-dependencies.XXXXXX)
    trap 'rm -f -- "$apt_log"' EXIT HUP INT TERM
    printf '%s\n' 'Bootstrapping distro Python and required RemnaWatch dependencies...'
    missing=''
    for package in python3 python3-venv ca-certificates iproute2 systemd; do
        status=$(dpkg-query -W '-f=${db:Status-Status}' "$package" 2>/dev/null || true)
        if [ "$status" != installed ]; then missing="$missing $package"; fi
    done
    # Repair the distro interpreter if its files/modules were removed manually.
    for package in python3 python3-venv; do
        case " $missing " in *" $package "*) ;; *) missing="$missing $package" ;; esac
    done
    apt-get -o DPkg::Lock::Timeout=60 -o Acquire::Retries=2 update >"$apt_log" 2>&1 ||
        apt_failure
    if grep -Eq '^Err:|^W: Failed to fetch|^W: Some index files failed' "$apt_log"; then apt_failure; fi
    # Fixed allowlist only. No upgrade/remove, no repository rewrite, no PPA/pip.
    # shellcheck disable=SC2086 # Fixed allowlisted package words; globbing disabled.
    apt-get -o DPkg::Lock::Timeout=60 --no-upgrade --no-remove --no-install-recommends --reinstall --simulate install $missing >"$apt_log" 2>&1 ||
        die 'dependencies_conflict: package plan failed; inspect apt state locally.'
    awk '/^Remv / {bad=1} /^Inst / && $3 ~ /^\[/ {old=$3; new=$4; gsub(/^\[|\]$/, "", old); sub(/^\(/, "", new); if(old != new) bad=1} END {exit bad}' "$apt_log" ||
        die 'dependencies_conflict: existing packages would be removed/upgraded; review separately.'
    # shellcheck disable=SC2086 # Fixed allowlisted package words; globbing disabled.
    apt-get -o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confold --no-upgrade --no-remove --no-install-recommends --reinstall -y install $missing >"$apt_log" 2>&1 ||
        apt_failure
    /usr/bin/python3 -I -c 'import sys,ssl,sqlite3,venv; sys.exit(0 if sys.version_info >= (3,8) else 1)' >/dev/null 2>&1 ||
        die 'dependencies_verification_failed: distro Python is still unavailable or incomplete.'
    rm -f -- "$apt_log"
    trap - EXIT HUP INT TERM
fi
cd -- "$repo_dir"
exec /usr/bin/python3 -m remnawatch.install "$@"
