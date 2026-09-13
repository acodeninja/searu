#!/bin/sh
# Install searu: fetch a prebuilt binary for this platform, or build from source where none is
# published. Usage: curl -fsSL .../install.sh | sh   (set SEARU_VERSION=vX.Y.Z to pin a release,
# SEARU_BIN_DIR to change where the binary lands.)
set -eu

repo="acodeninja/searu"
git_url="https://github.com/${repo}.git"
bin_dir="${SEARU_BIN_DIR:-$HOME/.local/bin}"
version="${SEARU_VERSION:-}"

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

build_from_source() {
    reason="$1"
    say "No prebuilt binary for ${reason}; building from source."
    have cargo || die "cargo not found. Install Rust from https://rustup.rs and re-run."
    if [ -n "$version" ]; then
        cargo install --git "$git_url" searu --tag "$version" --locked
    else
        cargo install --git "$git_url" searu --locked
    fi
    say "Installed searu with cargo (typically ~/.cargo/bin)."
    finish "cargo"
}

finish() {
    where="$1"
    have docker || warn "Docker was not found on PATH. searu needs Docker to run its tools."
    case ":$PATH:" in
        *":$where:"*) : ;;
        *) [ "$where" = "cargo" ] || warn "$where is not on your PATH; add it, e.g. export PATH=\"$where:\$PATH\"" ;;
    esac
    if [ -z "${SEARU_NO_SKILL:-}" ]; then
        if have searu; then exe=searu
        elif [ -n "${bin:-}" ] && [ -x "$bin_dir/$bin" ]; then exe="$bin_dir/$bin"
        else exe=""; fi
        [ -n "$exe" ] && { "$exe" install-skill || warn "could not install the /searu skill"; }
    fi
    say "Done. Try: searu tool list"
    exit 0
}

os=$(uname -s)
arch=$(uname -m)

case "$os" in
    Linux)
        case "$arch" in
            x86_64|amd64) target="x86_64-unknown-linux-musl"; ext="tar.gz"; bin="searu" ;;
            *) build_from_source "linux/$arch" ;;
        esac
        ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        case "$arch" in
            x86_64|amd64) target="x86_64-pc-windows-gnu"; ext="zip"; bin="searu.exe" ;;
            *) build_from_source "windows/$arch" ;;
        esac
        ;;
    *)
        build_from_source "$os/$arch"
        ;;
esac

if have curl; then dl() { curl -fsSL "$1" -o "$2"; }
elif have wget; then dl() { wget -qO "$2" "$1"; }
else die "need curl or wget to download the binary"; fi

asset="searu-${target}.${ext}"
if [ -n "$version" ]; then
    base="https://github.com/${repo}/releases/download/${version}"
else
    base="https://github.com/${repo}/releases/latest/download"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "Downloading ${asset} ..."
dl "${base}/${asset}" "${tmp}/${asset}" || die "download failed: ${base}/${asset}"

if dl "${base}/${asset}.sha256" "${tmp}/${asset}.sha256" 2>/dev/null; then
    expected=$(awk '{print $1}' "${tmp}/${asset}.sha256")
    if have sha256sum; then actual=$(sha256sum "${tmp}/${asset}" | awk '{print $1}')
    elif have shasum; then actual=$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')
    else actual=""; fi
    if [ -n "$actual" ] && [ "$expected" != "$actual" ]; then
        die "checksum mismatch for ${asset}"
    fi
fi

say "Extracting ..."
case "$ext" in
    tar.gz) tar -xzf "${tmp}/${asset}" -C "$tmp" ;;
    zip) have unzip || die "need unzip to extract ${asset}"; unzip -q "${tmp}/${asset}" -d "$tmp" ;;
esac
[ -f "${tmp}/${bin}" ] || die "${bin} not found in ${asset}"

mkdir -p "$bin_dir"
if have install; then install -m 0755 "${tmp}/${bin}" "${bin_dir}/${bin}"
else cp "${tmp}/${bin}" "${bin_dir}/${bin}"; chmod 0755 "${bin_dir}/${bin}"; fi
say "Installed ${bin_dir}/${bin}"

finish "$bin_dir"
