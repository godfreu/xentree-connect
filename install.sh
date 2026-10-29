#!/bin/sh
# Xentree Connect installer (Linux and macOS).
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://get.xentree.ai/connect | sh
#   curl --proto '=https' --tlsv1.2 -fsSL https://get.xentree.ai/connect | sh -s -- --init
#
# Downloads the release binary for this machine and SHA256SUMS, verifies the
# checksum, and only then installs it. Windows users: see install.ps1.
#
# Everything runs inside main(), invoked on the last line, so a download that
# is cut short never executes a partial script.

set -eu

usage() {
    cat <<'EOF'
Install Xentree Connect.

Usage: install.sh [OPTIONS]

Options:
  --init              Run `xentree-connect init` after installing
  --version VERSION   Install a specific release, e.g. v1.2.3 (default: latest)
  --bin-dir DIR       Install into DIR (default: /usr/local/bin as root,
                      otherwise ~/.local/bin)
  -h, --help          Show this help

Environment:
  XENTREE_CONNECT_VERSION   same as --version
  XENTREE_CONNECT_BIN_DIR   same as --bin-dir
  XENTREE_CONNECT_REPO      GitHub "owner/name" to download from
  XENTREE_CONNECT_BASE_URL  releases URL (must be https), for mirrors
EOF
}

say() {
    printf '%s\n' "$*"
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

# Print the Rust target triple of the release build for this machine.
#
# Linux builds are static musl binaries: they run on glibc and musl distros
# alike, so there is no libc to detect.
detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        *) die "unsupported CPU architecture: $arch (supported: x86_64, aarch64)" ;;
    esac
    case "$os" in
        Linux)
            printf '%s-unknown-linux-musl\n' "$arch"
            ;;
        Darwin)
            # A shell running under Rosetta reports x86_64 on Apple Silicon;
            # prefer the native build.
            if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
                arch=aarch64
            fi
            printf '%s-apple-darwin\n' "$arch"
            ;;
        MINGW* | MSYS* | CYGWIN*)
            die "this looks like Windows; use install.ps1 instead"
            ;;
        *) die "unsupported operating system: $os (supported: Linux, macOS)" ;;
    esac
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        die "no SHA-256 tool found (need sha256sum, shasum or openssl)"
    fi
}

# https only, TLS 1.2+, on redirects too.
fetch() {
    curl --proto '=https' --tlsv1.2 --proto-redir '=https' \
        --fail --silent --show-error --location \
        --retry 3 --connect-timeout 15 --max-time 300 \
        --output "$2" "$1"
}

main() {
    repo=${XENTREE_CONNECT_REPO:-godfreu/xentree-connect}
    base_url=${XENTREE_CONNECT_BASE_URL:-https://github.com/$repo/releases}
    version=${XENTREE_CONNECT_VERSION:-latest}
    bin_dir=${XENTREE_CONNECT_BIN_DIR:-}
    run_init=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --init) run_init=1 ;;
            --version)
                [ $# -ge 2 ] || die "--version needs a value"
                version=$2
                shift
                ;;
            --version=*) version=${1#*=} ;;
            --bin-dir)
                [ $# -ge 2 ] || die "--bin-dir needs a value"
                bin_dir=$2
                shift
                ;;
            --bin-dir=*) bin_dir=${1#*=} ;;
            -h | --help)
                usage
                exit 0
                ;;
            *) die "unknown option: $1 (try --help)" ;;
        esac
        shift
    done

    command -v curl >/dev/null 2>&1 || die "curl is required"

    case "$base_url" in
        https://*) ;;
        *) die "release URL must start with https:// (got: $base_url)" ;;
    esac
    base_url=${base_url%/}

    # The version ends up in a URL path: accept only release-tag shapes.
    if [ "$version" != latest ]; then
        case "$version" in v*) ;; *) version=v$version ;; esac
        printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-+.][0-9A-Za-z.-]+)?$' ||
            die "invalid version: $version (expected something like v1.2.3)"
        release_url=$base_url/download/$version
    else
        release_url=$base_url/latest/download
    fi

    if [ -z "$bin_dir" ]; then
        if [ "$(id -u)" = 0 ]; then
            bin_dir=/usr/local/bin
        else
            [ -n "${HOME:-}" ] || die "HOME is not set; pass --bin-dir"
            bin_dir=$HOME/.local/bin
        fi
    fi

    target=$(detect_target)
    asset=xentree-connect-$target
    say "Installing Xentree Connect ($version, $target)"

    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t xentree-connect)
    trap 'rm -rf "$tmp"' EXIT HUP INT TERM

    say "Downloading $asset"
    fetch "$release_url/$asset" "$tmp/$asset" ||
        die "could not download $release_url/$asset (is there a release for $target?)"
    fetch "$release_url/SHA256SUMS" "$tmp/SHA256SUMS" ||
        die "could not download $release_url/SHA256SUMS"

    # The checksum must come from SHA256SUMS and name this exact asset once.
    matches=$(awk -v f="$asset" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$tmp/SHA256SUMS")
    [ -n "$matches" ] || die "SHA256SUMS has no entry for $asset"
    [ "$(printf '%s\n' "$matches" | wc -l | tr -d ' ')" = 1 ] || die "SHA256SUMS lists $asset more than once"
    printf '%s' "$matches" | grep -Eq '^[0-9a-fA-F]{64}$' || die "SHA256SUMS entry for $asset is malformed"
    expected=$(printf '%s' "$matches" | tr 'A-F' 'a-f')
    actual=$(sha256_of "$tmp/$asset" | tr 'A-F' 'a-f')
    if [ "$expected" != "$actual" ]; then
        die "checksum mismatch for $asset
  expected: $expected
  actual:   $actual
Nothing was installed."
    fi
    say "Checksum verified (sha256 $actual)"

    # Only now does the file become executable and move into place. The move
    # is a rename within the target directory, so a running copy is never
    # half-overwritten.
    mkdir -p "$bin_dir" || die "cannot create $bin_dir (try --bin-dir, or run as root)"
    dest=$bin_dir/xentree-connect
    staged=$bin_dir/.xentree-connect.$$
    cp "$tmp/$asset" "$staged" || die "cannot write to $bin_dir (try --bin-dir, or run as root)"
    chmod 755 "$staged"
    mv -f "$staged" "$dest"

    if installed=$("$dest" --version 2>&1); then
        say "Installed $installed to $dest"
    else
        warn "installed to $dest, but it does not run on this system: $installed"
    fi

    case ":${PATH:-}:" in
        *":$bin_dir:"*) ;;
        *)
            say ""
            say "$bin_dir is not on your PATH. Add it with:"
            say "  export PATH=\"$bin_dir:\$PATH\""
            ;;
    esac

    if [ "$run_init" = 1 ]; then
        say ""
        # Under `curl | sh`, stdin is the script, so the wizard needs the terminal.
        rm -rf "$tmp"
        trap - EXIT HUP INT TERM
        if [ -t 0 ]; then
            exec "$dest" init
        elif (: </dev/tty) 2>/dev/null; then
            exec "$dest" init </dev/tty
        else
            warn "no terminal available for the interactive setup; run: $dest init"
        fi
    else
        say ""
        say "Next: xentree-connect init"
    fi
}

main "$@"
