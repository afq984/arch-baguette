#!/usr/bin/env bash
# Build every PKGBUILD under packages/ with makepkg (rootless) and assemble
# the local pacman repository consumed by image/build.sh:
#
#   out/packages/            all built *.pkg.tar.zst
#   out/repo/baguette.db...  repo-add database + hardlinked packages
#
# Usage: scripts/build-repo.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_packages="${repo_root}/out/packages"
out_repo="${repo_root}/out/repo"
out_sources="${repo_root}/out/sources"
db_name=baguette

mkdir -p "${out_packages}" "${out_repo}" "${out_sources}"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# --- makepkg config: force !debug ---------------------------------------------

# The package set must not depend on the host's makepkg.conf: archlinux:latest
# (CI) ships `debug` in OPTIONS, so `makepkg --packagelist` advertises a
# $pkgbase-debug split package — but none is ever produced for these
# config-only packages (nothing to strip), which broke the repo assembly
# below. Derive a config that replays the system config (+ drop-ins, exactly
# as makepkg would) and appends !debug — the last OPTIONS entry wins. Setting
# MAKEPKG_CONF also skips per-user configs, keeping builds hermetic.
makepkg_conf="${tmp}/makepkg.conf"
cat >"${makepkg_conf}" <<'EOF'
source /etc/makepkg.conf
for _conf in /etc/makepkg.conf.d/*.conf; do
    [[ -r ${_conf} ]] && source "${_conf}"
done
unset _conf
OPTIONS+=('!debug')
EOF
export MAKEPKG_CONF="${makepkg_conf}"

# --- build all packages -----------------------------------------------------

built_pkgs=()
for pkgbuild in "${repo_root}"/packages/*/PKGBUILD; do
    pkgdir="$(dirname "${pkgbuild}")"
    echo "==> Building $(basename "${pkgdir}")"
    # --cleanbuild: fresh src/ every run; --force: rebuild existing pkgver;
    # --noconfirm: never prompt. PKGDEST drops artifacts into out/packages;
    # SRCDEST keeps downloaded sources (git clones) out of the package dirs.
    (cd "${pkgdir}" && PKGDEST="${out_packages}" SRCDEST="${out_sources}" \
        makepkg --force --cleanbuild --noconfirm)
    while IFS= read -r pkg; do
        built_pkgs+=("${pkg}")
    done < <(cd "${pkgdir}" && PKGDEST="${out_packages}" \
        SRCDEST="${out_sources}" makepkg --packagelist)
done

if [[ ${#built_pkgs[@]} -eq 0 ]]; then
    echo "error: no packages built" >&2
    exit 1
fi

# --- assemble the pacman repo ------------------------------------------------

# Rebuild the repo from scratch each run so stale packages/db entries from
# earlier versions can never leak into the image build.
rm -f "${out_repo}/${db_name}".db* "${out_repo}/${db_name}".files* \
    "${out_repo}"/*.pkg.tar.*

repo_pkgs=()
for pkg in "${built_pkgs[@]}"; do
    # Hardlink (fall back to copy across filesystems) into the repo dir:
    # a file:// pacman repo serves packages from the directory with the db.
    ln -f "${pkg}" "${out_repo}/" 2>/dev/null || cp -f "${pkg}" "${out_repo}/"
    repo_pkgs+=("${out_repo}/$(basename "${pkg}")")
done

repo-add --new "${out_repo}/${db_name}.db.tar.zst" "${repo_pkgs[@]}"

# --- sanity check: the repo resolves with pacman ------------------------------

# Refresh the db into a throwaway dbpath (fakeroot satisfies pacman's root
# check for -Sy; nothing system-wide is touched) and resolve every package
# URL out of it. Proves db integrity + package visibility end to end.
cat >"${tmp}/pacman.conf" <<EOF
[options]
Architecture = auto

[${db_name}]
SigLevel = Optional TrustAll
Server = file://${out_repo}
EOF
mkdir -p "${tmp}/db"
fakeroot -- pacman -Sy --config "${tmp}/pacman.conf" --dbpath "${tmp}/db" \
    --logfile "${tmp}/pacman.log" >/dev/null

pkg_names=()
for pkg in "${built_pkgs[@]}"; do
    name="$(basename "${pkg}")"
    # strip -pkgver-pkgrel-arch.pkg.tar.* -> package name
    pkg_names+=("$(printf '%s' "${name}" | sed -E 's/-[^-]+-[^-]+-[^-]+\.pkg\.tar\..*$//')")
done
pacman -S --print --nodeps --nodeps --config "${tmp}/pacman.conf" \
    --dbpath "${tmp}/db" "${pkg_names[@]}"

echo "==> OK: $(basename "${out_repo}")/${db_name}.db.tar.zst with ${#repo_pkgs[@]} packages"
