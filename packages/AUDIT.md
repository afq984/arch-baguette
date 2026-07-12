# Package content audit

Comparison of the union of files installed by the six built packages against
(a) the official Debian Baguette image data
(`platform2/vm_tools/baguette_image/src/data/` + `setup_in_guest.sh`) and
(b) the ad-hoc script `arch-baguette/build-arch-baguette.sh` steps 6–8.

- Upstream guest-tools pin: `072b588ae6b9ea8d05fde6b4795d0c2a32a060e4`
  (cros-container-guest-tools main HEAD at implementation time,
  pkgver `20260508.r496.g072b588`).
- Audited artifacts: `tar -tvf` of all `out/packages/*.pkg.tar.zst`
  (baguette-base 0.1.0-1, cros-{sommelier,garcon,wayland,port-listener,notificationd}
  20260508.r496.g072b588-1).
- "byte-identical" below was verified with `diff`/`cmp` against the parity
  source file.

## A. Official Debian data files → our packages

| Official file (Debian image) | Shipped by | Our path | Parity |
|---|---|---|---|
| `usr/local/lib/systemd/system/maitred.service` | baguette-base | `/usr/lib/systemd/system/maitred.service` | byte-identical (PATH env incl. `/opt/google/cros-containers/bin` kept exactly; `/usr/sbin`,`/sbin`,`/bin` resolve via Arch usr-merge) |
| `usr/local/lib/systemd/system/vshd.service` | baguette-base | `/usr/lib/systemd/system/vshd.service` | byte-identical |
| `usr/local/lib/systemd/system/opt-google-cros\x2dcontainers.mount` | baguette-base | `/usr/lib/systemd/system/opt-google-cros\x2dcontainers.mount` | byte-identical (What=LABEL=cros-vm-tools, Options=ro, TimeoutSec=10; literal `\x2d` in filename verified in tar) |
| `usr/local/lib/systemd/system/first-boot-cros.service` | baguette-base | `/usr/lib/systemd/system/first-boot-cros.service` | adapted: ExecStart → `/usr/lib/baguette/first-boot-cros`; rest identical |
| `usr/local/bin/first-boot-cros` | baguette-base | `/usr/lib/baguette/first-boot-cros` | adapted: `set -euo pipefail` (fail loud, no `\|\| true`); `dpkg-reconfigure openssh-server` → `ssh-keygen -A` guarded by `command -v`; `rm -fv` so a keyless image doesn't fail; btrfs resize + syncs kept |
| `usr/local/lib/systemd/journald.conf.d/50-console.conf` | baguette-base | `/usr/lib/systemd/journald.conf.d/50-console.conf` | byte-identical (`ForwardToConsole=yes`) |
| `etc/maitred/50-mount-fonts.textproto` | baguette-base | `/etc/maitred/50-mount-fonts.textproto` | byte-identical, shipped as a plain 0644 file. (Upstream `setup_in_guest.sh` uses `install -t /etc/maitred/50-mount-fonts.textproto`, which actually creates a *directory* of that name — looks like an upstream bug; the old Arch script and we ship a file, and fonts mounting is verified working.) |
| `etc/profile.d/10-baguette-envs.sh` | baguette-base | `/etc/profile.d/10-baguette-envs.sh` | byte-identical (DBUS/XDG/USER env + sommelier wait loop) |
| `etc/sudoers.d/10-no-password` | baguette-base | `/etc/sudoers.d/10-baguette` | semantic-identical rule `%sudo ALL=(ALL:ALL) NOPASSWD: ALL` only; renamed per DESIGN; mode 0440; `visudo -c -f` parses OK |
| `usr/local/bin/update-cros-list` | — | — | dropped: rewrites the apt `cros.list` milestone; no pacman equivalent (repo updates arrive via `pacman -Syu`, DESIGN "milestone matching") |
| `usr/local/lib/systemd/system/update-cros-list.service` | — | — | dropped: see above |
| `setup_in_guest.sh`: mkdir `/mnt/chromeos/fonts`, `/mnt/shared`; `ln -s /mnt/shared /mnt/chromeos(/shared)`; mountpoint `/opt/google/cros-containers` | baguette-base | same paths | shipped in the package tar as empty dirs + symlink `/mnt/chromeos/shared → /mnt/shared` (verified present in `tar -tvf`) |
| `setup_in_guest.sh`: groups via Debian defaults (host requests audio cdrom dialout disk floppy kvm netdev plugdev sudo tss video) | baguette-base | `/usr/lib/sysusers.d/baguette.conf` | `g floppy/netdev/plugdev/sudo/tss` (Arch already ships the rest); applied with `systemd-sysusers --root` in test: all 5 created |
| `setup_in_guest.sh`: `systemctl enable maitred update-cros-list vshd opt-google-cros\x2dcontainers.mount first-boot-cros` | baguette-base | `/usr/lib/systemd/system-preset/50-baguette.preset` | preset lists mount, maitred, vshd, first-boot-cros, cros-port-listener, dbus, systemd-timesyncd (update-cros-list dropped, see above). `systemctl --root preset-all` verified: all four shipped units enabled, incl. the `\x2d` mount unit |

Debian `CROS_PACKAGES` not ported: `baguette-motd` (cosmetic MOTD),
`cros-ui-config` (GTK/fontconfig theming tuned for Debian),
`cros-sommelier-config` (see B: its enablement symlinks are folded into
cros-sommelier; its SOMMELIER_SCALE/low-density override drop-ins are not
shipped — defaults from the unit files apply).

## B. `build-arch-baguette.sh` steps 6–8 → our packages

| Old script install | Shipped by | Our path | Parity |
|---|---|---|---|
| `/usr/bin/garcon-url-handler` (755) | cros-garcon | same | byte-identical to upstream @pin |
| `/usr/bin/garcon-terminal-handler` (755) | cros-garcon | same | byte-identical |
| `/usr/share/applications/garcon_host_browser.desktop` | cros-garcon | same | byte-identical |
| `/usr/lib/systemd/user/cros-garcon.service` | cros-garcon | same | byte-identical |
| `/usr/lib/systemd/user/sommelier@.service` | cros-sommelier | same | byte-identical |
| `/usr/lib/systemd/user/sommelier-x@.service` | cros-sommelier | same | byte-identical |
| `/etc/profile.d/sommelier.sh` | cros-sommelier | same | byte-identical |
| `/etc/sommelierrc` | cros-sommelier | same | byte-identical |
| `/usr/lib/systemd/user/cros-notificationd.service` | cros-notificationd | same | byte-identical |
| `/usr/share/dbus-1/services/org.freedesktop.Notifications.service` | cros-notificationd | same | byte-identical |
| `/usr/lib/udev/rules.d/10-cros-virtwl.rules` | cros-wayland | same | byte-identical |
| `/usr/lib/udev/rules.d/10-cros-port-listener.rules` | cros-port-listener | same | byte-identical |
| `/usr/lib/systemd/system/cros-port-listener.service` | cros-port-listener | same | byte-identical |
| `/usr/bin/sommelier` → `/opt/google/cros-containers/bin/sommelier` | cros-sommelier | same | same symlink (upstream Debian does this via update-alternatives in cros-sommelier-config postinst) |
| `/usr/bin/sommelier.elf` → `…/sommelier.elf` | cros-sommelier | same | same symlink |
| `/etc/systemd/system/opt-google-cros\x2dcontainers.mount` | baguette-base | `/usr/lib/systemd/system/…` | moved to vendor dir per DESIGN conventions; content byte-identical to official |
| `/etc/systemd/system/maitred.service` | baguette-base | `/usr/lib/systemd/system/…` | vendor dir; official PATH restored (old script had inserted `/usr/local/*` entries) |
| `/etc/systemd/system/vshd.service` | baguette-base | `/usr/lib/systemd/system/…` | vendor dir; byte-identical to official |
| `/usr/local/bin/first-boot-cros` (with `\|\| true` on every line) | baguette-base | `/usr/lib/baguette/first-boot-cros` | fail-loud rewrite per DESIGN (see table A) |
| `/etc/systemd/system/first-boot-cros.service` | baguette-base | `/usr/lib/systemd/system/…` | vendor dir; ExecStart path updated |
| `/etc/maitred/50-mount-fonts.textproto` | baguette-base | same | byte-identical to official |
| `/etc/profile.d/10-baguette-envs.sh` (script's `:-`-guarded variant) | baguette-base | same | replaced by the official byte-identical version |
| `/etc/sudoers.d/10-cros-nopasswd` (`%sudo` **and** `%wheel`) | baguette-base | `/etc/sudoers.d/10-baguette` | `%sudo` only — DESIGN explicitly drops the `%wheel` grant |
| `/etc/fstab` (`LABEL=arch-baguette / btrfs`) | — | — | dropped per DESIGN: default btrfs subvolume does the job, no LABEL coupling (image-build scope) |
| dirs `/opt/google/cros-containers`, `/mnt/chromeos/fonts`, `/mnt/shared` | baguette-base | same | shipped; **plus** `/mnt/chromeos/shared → /mnt/shared` symlink the old script was missing vs the official image |
| step 8 `systemctl --root enable` (mount, maitred, vshd, first-boot-cros, cros-port-listener, dbus, systemd-timesyncd) | baguette-base | `50-baguette.preset` | identical unit list; applied at image build via `preset-all` instead of hand enabling |
| step 8 user wants symlinks `sommelier@0/1`, `sommelier-x@0/1` (in `/etc/systemd/user/default.target.wants`) | cros-sommelier | `/usr/lib/systemd/user/default.target.wants/` | shipped inside the package (vendor dir per DESIGN); relative symlinks, resolve-verified |
| step 8 `cros-garcon.service` wants symlink | cros-garcon | `/usr/lib/systemd/user/default.target.wants/cros-garcon.service` | shipped inside the package (upstream Debian ships the identical symlink) |

Old-script items outside steps 6–8 that touch the same ground (for
completeness): `groupadd` loop → sysusers.d (table A); `/usr/sbin/usermod`
symlink → unnecessary on Arch (usr-merge `/usr/sbin → bin` provides it,
DESIGN "verified facts"); `/usr/lib/openssh/sftp-server` symlink → dropped
(only Debian's cros-sftp references that path; cros-sftp is not part of the
Baguette package set); user creation/chpasswd/linger → runtime job of maitred
`SetUpUser` (or `image/build.sh --dev-user`); hostname/hosts/locale/
machine-id/pacman-key/resolv.conf → image build scope.

## C. Upstream guest-tools files deliberately not shipped

| Upstream file | Reason |
|---|---|
| `cros-sommelier/skel.sommelierrc`, `cros-wayland/skel.weston.ini`, `cros-garcon/skel.cros-garcon.conf` | Debian `/etc/skel` dotfiles; Arch skel stays pristine, per-user config is optional |
| `cros-garcon/cros-garcon-override.conf` | apt/PackageKit `Environment=` overrides for garcon package-manager integration; no apt on Arch |
| `cros-garcon/{50-garcon-packagekit.rules,50-garcon-synaptic.rules,garcon-packagekit.pkla,garcon-synaptic.pkla}` | polkit grants for PackageKit/synaptic (Debian package management), not applicable |
| `cros-sommelier-config/*-override.conf` | SOMMELIER_SCALE / low-density drop-ins; unit-file defaults apply. Candidate for a future cros-sommelier-config port if scaling tuning is wanted |
| all `BUILD`, `deb-description`, `conffiles`, `postinst`/`prerm`/`postrm`/`preinst` | Debian/Bazel packaging plumbing; pacman equivalents are declarative (wants symlinks, preset, sysusers — no scriptlets, per DESIGN) |
| other upstream dirs (baguette-motd, cros-adapta, cros-apt-config, cros-debs, cros-guest-tools meta, cros-host-fonts, cros-logging, cros-motd, cros-pipe-config, cros-pulse-config, cros-sftp, cros-sudo-config, cros-systemd-overrides, cros-tast-tests, cros-ui-config, cros-vmstat-metrics, cros-xdg-desktop-portal, lxd, mesa, termina, scripts, kokoro) | not part of the DESIGN package set for Baguette phase 1 (mostly Crostini-container- or Debian-specific) |

## D. Verification evidence

- Both PKGBUILDs build rootless with `makepkg --force --cleanbuild --noconfirm`
  (no `-d` needed anywhere; split-pkg depends mirrored into makedepends).
- `namcap` 3.6.0 on both PKGBUILDs and all 6 packages: findings limited to the
  waivers documented at the top of each PKGBUILD (dangling `/opt/google/...`
  symlinks by design, deliberate empty mountpoint dirs and `/mnt` layout,
  sudoers 0440, runtime-only deps, `$startdir` for the `files/` layout).
- sudoers: `visudo -c -f` → "parsed OK"; mode in tar `-r--r-----`.
- sysusers: `systemd-sysusers --root=<extracted pkg>` created
  floppy/netdev/plugdev/sudo/tss.
- preset: `systemctl --root=<extracted pkg> preset-all` enabled
  `opt-google-cros\x2dcontainers.mount` (backslash name matches — verified),
  maitred, vshd, first-boot-cros.
- All byte-identical claims: `cmp` against
  `platform2/vm_tools/baguette_image/src/data/` and the upstream checkout at
  the pinned commit (13/13 upstream files identical).
- `scripts/build-repo.sh` end-to-end: `out/repo/baguette.db.tar.zst` +
  `baguette.files.tar.zst` + 6 packages; `pacman -Sy` into a throwaway
  `--dbpath` (fakeroot) then `pacman -Sl baguette`, `pacman -Si`, and
  `pacman -S --print` all resolve; db `tar -tf` lists all 6 desc entries.
