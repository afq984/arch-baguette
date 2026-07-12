# arch-baguette-v2 — Design

Production-quality Arch Linux image + pacman packages for ChromeOS **Baguette**
(Crostini Containerless). This document is the authoritative spec; implementation
must match it or propose an amendment.

## Goals

1. **Userless production image** — the login user is provisioned at runtime by
   maitred (`SetUpUser` gRPC), exactly like the official Debian image.
2. **Guest integration as real pacman packages** in a repo — updatable via
   `pacman -Syu`, pinned to a reviewed upstream commit, not files rsynced from
   an unpinned git HEAD.
3. **Small, content-sized artifact** — btrfs sized to content (`--shrink`),
   `zstd -19` for releases; first boot grows it (`btrfs filesystem resize max /`).
4. **Single rootless build path** used both for local dev and CI. No docker,
   no sudo, no loop mounts anywhere.

Non-goals (phase 1): aarch64, per-milestone package repos (see "Milestone
matching" below), GUI installer integration.

## Verified facts this design builds on

These were established experimentally on this machine (see
`/home/r/baguette/DEV-WORKFLOW.md` and `/home/r/baguette/cros-vm/RUNBOOK.md`):

- `pacstrap -N` (arch-install-scripts ≥ 31) builds a correct Arch rootfs fully
  rootless (subid ranges + `newuidmap`/`newgidmap` with file caps present).
  Signature verification stays ON; `pacman-key` needs a userns wrapper with a
  user-owned GPG dir.
- `mkfs.btrfs --rootdir=<dir> --subvol default:rootfs_subvol --shrink`
  (btrfs-progs ≥ 6.8; 7.0 on this host) produces the exact image format
  concierge expects — **must run inside the user namespace** or all files get
  the calling uid. Verified: ownership 0:0, setuid bits, v2 cap xattrs,
  hardlinks, ACLs all correct; boots in the real rig.
- **pacstrap ignores `CacheDir` from `-C` configs** → naive builds ship
  ~300 MB of `.pkg` files inside the image. The build must seed/evacuate the
  cache (hardlink trick) or otherwise guarantee `/var/cache/pacman/pkg` is
  empty in the final rootfs.
- `vmc create --vm-type baguette --size .. --source <img> <name>` +
  `vmc start` works end-to-end in the nested ChromeOS rig. Stock images with
  no user hit a garcon-wait timeout on first `vmc start` (Chrome's UI
  installer normally does user setup); a dev-user-baked image starts RC=0
  first try. This is expected behavior, not a bug in our image.
- maitred `SetUpUser` **hard-rejects** the request if any host-requested group
  is missing (`getgrnam` check). The host requests the Debian group set:
  `audio cdrom dialout disk floppy kvm netdev plugdev sudo tss video`.
  Arch's systemd sysusers provides `audio cdrom dialout disk kvm video`;
  the image must additionally provide `floppy netdev plugdev sudo tss`
  (tss normally arrives via tpm2-tss; do not rely on it silently — assert it).
- maitred invokes `/usr/sbin/useradd` by absolute path; Arch's usr-merge
  symlink (`/usr/sbin` → `bin`) satisfies it. Assert in tests.
- Official image `/mnt` layout (replicate exactly): real dirs
  `/mnt/chromeos/fonts` and `/mnt/shared`, plus symlink
  `/mnt/chromeos/shared` → `/mnt/shared`. Fonts are virtiofs-mounted by
  maitred at `/mnt/chromeos/fonts` per `50-mount-fonts.textproto`.
- On Baguette the heavy binaries (sommelier, garcon, maitred, vshd) come from
  the **host-mounted** `cros-vm-tools` filesystem at
  `/opt/google/cros-containers` — guest packages are thin wrappers/config, so
  they track the host milestone automatically. ("Milestone matching": Google's
  per-milestone deb repo scheme is unnecessary here; our equivalent is repo
  updates via `pacman -Syu` + a pinned upstream commit bumped by an uprev
  workflow.)
- `makepkg` + `namcap` work rootless on this machine; `guestfs-tools` is
  installed (qemu appliance, no root) and may be used for *inspection* of
  built images (default-subvol check, ownership spot-checks) — not as the
  primary builder.

## Repository layout

```
arch-baguette-v2/
├── DESIGN.md
├── README.md
├── LICENSE                      # BSD-3-Clause
├── packages/
│   ├── baguette-base/           # PKGBUILD + files/ (all sources local)
│   └── cros-guest-tools/        # PKGBUILD (split), pinned upstream commit
├── image/
│   ├── build.sh                 # rootfs + image, rootless-first (see below)
│   ├── pacman.conf.in           # core/extra + local [baguette] repo
│   └── tests/
│       ├── verify-rootfs.sh     # contract asserts against rootfs dir
│       └── verify-image.sh      # image-level asserts (guestfish/btrfs inspect)
├── scripts/
│   ├── build-repo.sh            # makepkg all packages → out/repo (repo-add)
│   └── deploy-test.sh           # push image into the nested ChromeOS rig
├── .github/workflows/           # packages.yaml, image.yaml, uprev.yaml (phase D)
└── out/                         # build products (gitignored)
    ├── packages/                # *.pkg.tar.zst
    ├── repo/                    # baguette.db + packages (local pacman repo)
    └── image/                   # baguette_arch_rootfs.img.zst + .sha256 + manifest.txt
```

VCS: jj (colocated). Implementation agents do NOT run jj/git; the orchestrator
commits at milestones.

## Packages

### Conventions (both packages)

- `pkgver` scheme: upstream-pinned packages use `<date>.r<count>.g<shortsha>`;
  local-source packages use plain semver starting `0.1.0`.
- Unit/config files install under `/usr/lib` (vendor), never `/etc`
  (admin). User-session units are enabled by shipping
  `/usr/lib/systemd/user/default.target.wants/*` symlinks in the package.
  System units are enabled via a preset file
  `/usr/lib/systemd/system-preset/50-baguette.preset` shipped in
  baguette-base; the image build applies `systemctl --root preset-all` (or
  equivalent) — packages must not rely on install scriptlets for enablement.
- `namcap` clean (or documented waivers).

### `baguette-base` (all sources local in `files/`)

Content parity source of truth:
`/home/r/baguette/platform2/vm_tools/baguette_image/src/data/` (official
Debian data files) and the units written inline by
`/home/r/baguette/arch-baguette/build-arch-baguette.sh`. Ships:

- `maitred.service`, `vshd.service`, `opt-google-cros\x2dcontainers.mount`
  (What=LABEL=cros-vm-tools, ro), `first-boot-cros.service` +
  `/usr/lib/baguette/first-boot-cros` script (btrfs resize max /, regenerate
  ssh host keys **without** `|| true` blanket — fail loud, but ssh-keygen only
  if openssh present), all byte-equivalent to official semantics adapted to
  Arch paths.
- `/etc/maitred/50-mount-fonts.textproto` (maitred config is read from /etc —
  exception to the vendor-dir rule, matches official).
- `sysusers.d/baguette.conf`: `g floppy`, `g netdev`, `g plugdev`, `g sudo`,
  `g tss` (idempotent if tpm2-tss also creates it).
- `sudoers.d/10-baguette`: `%sudo ALL=(ALL:ALL) NOPASSWD: ALL` **only**
  (no %wheel grant), mode 0440, in `/etc/sudoers.d/`.
- journald drop-in `ForwardToConsole=yes`
  (`/usr/lib/systemd/journald.conf.d/50-console.conf`).
- `/etc/profile.d/10-baguette-envs.sh` (official content: DBUS/XDG/USER env +
  sommelier wait loop).
- Directories/symlinks: `/mnt/chromeos/fonts`, `/mnt/shared`,
  `/mnt/chromeos/shared` → `/mnt/shared`, `/opt/google/cros-containers`
  (empty mountpoint). Prefer shipping in the package; use tmpfiles.d if
  pacman can't own an entry cleanly.
- Preset file enabling: the mount unit, maitred, vshd, first-boot-cros,
  cros-port-listener, dbus, systemd-timesyncd.
- Depends: btrfs-progs (resize), systemd, sudo, bash.

### `cros-guest-tools` (split PKGBUILD)

Source: `git+https://chromium.googlesource.com/chromiumos/containers/cros-container-guest-tools#commit=<PINNED_FULL_SHA>`
(pin at implementation time to current main HEAD; record SHA in PKGBUILD).
License BSD-3-Clause. Split packages, mirroring the Debian set:

| split pkg | contents (upstream paths) |
|---|---|
| `cros-sommelier` | `cros-sommelier/sommelier@.service`, `sommelier-x@.service`, `sommelier.sh` → `/etc/profile.d/`, `sommelierrc` → `/etc/sommelierrc`; symlinks `/usr/bin/sommelier{,.elf}` → `/opt/google/cros-containers/bin/…`; user wants-symlinks enabling `sommelier@0 sommelier-x@0 sommelier@1 sommelier-x@1` |
| `cros-garcon` | `garcon-url-handler`, `garcon-terminal-handler` → `/usr/bin/`; `garcon_host_browser.desktop`; `cros-garcon.service` (user) + wants-symlink |
| `cros-wayland` | `10-cros-virtwl.rules` → `/usr/lib/udev/rules.d/` |
| `cros-port-listener` | `10-cros-port-listener.rules`, `cros-port-listener.service` (system) |
| `cros-notificationd` | `cros-notificationd.service` (user), `org.freedesktop.Notifications.service` dbus activation |

Verify against what `build-arch-baguette.sh` installs (steps 6/8) — same file
set, same destinations (modulo /usr/lib vs /etc placement per conventions).

## Image build (`image/build.sh`)

Base: port of the **verified** `/home/r/baguette/dev-workflow/build-arch-baguette-rootless.sh`
(read it; keep its userns/pacman-key/cache-seeding techniques) restructured for
this repo. Requirements:

- Rootless-first (`pacstrap -N`, in-userns mkfs); if EUID==0 (CI container
  fallback) use the rootful equivalents of the same steps. One script, two
  modes, identical output.
- Consumes the local repo: `[baguette] Server = file:///.../out/repo` with
  `SigLevel = Optional TrustAll` locally (CI signing comes in phase D;
  core/extra stay `SigLevel = Required DatabaseOptional`).
- Package set: `base archlinux-keyring systemd-sysvcompat sudo btrfs-progs
  dbus openssh acl bash-completion curl wget vim nano xz gnupg tpm2-tools
  usbutils pciutils alsa-utils pipewire pipewire-pulse wireplumber xdg-utils
  xdg-desktop-portal-gtk gsettings-desktop-schemas wayland xorg-xwayland
  xorg-xauth xorg-xrdb xorg-xset xkeyboard-config wl-clipboard` +
  `baguette-base cros-sommelier cros-garcon cros-wayland cros-port-listener
  cros-notificationd`. (Trim later if audit shows dead weight; keep parity now.)
- Config steps (parity with official setup_in_guest.sh, adapted):
  hostname `penguin`; `/etc/hosts` with `127.0.0.1 localhost`,
  `127.0.1.1 penguin`, `100.115.92.2 arc`; `en_US.UTF-8` locale-gen +
  locale.conf; `/etc/resolv.conf` → `/run/resolv.conf` symlink;
  `: > /etc/machine-id`; delete `/etc/ssh/ssh_host_*`; in-target
  `pacman-key --init && --populate archlinux`; `systemctl --root preset-all`
  (or explicit enable list matching the preset); empty pacman cache in the
  final rootfs; `pacman -Q` manifest emitted next to the image.
- **No user creation by default.** `--dev-user NAME[:PASSWORD]` flag creates a
  dev user (uid 1000, the full contract group list, linger enabled, default
  password `test0000`) for local testing — mirrors official `-c`/`-u`.
- No `/etc/fstab` entry (default subvolume does the job); no hardcoded LABEL
  coupling. Image label: `arch-baguette` (cosmetic only).
- Output: `out/image/baguette_arch_rootfs.img.zst` (+ `.sha256`,
  `manifest.txt`). `--fast` flag: zstd -3 for the dev loop; default -19.

## Tests

- `image/tests/verify-rootfs.sh <rootfs-dir>`: userns-chroot asserts —
  all 11 contract groups resolve; `/usr/sbin/useradd` resolves; enabled units
  (system + user wants-symlinks) present; `/etc/machine-id` empty; no
  `ssh_host_*`; no passwd entries uid ≥ 1000 (unless --dev-user build);
  sudoers file mode 0440 & visudo-parses; `/mnt` layout; empty pacman cache;
  profile.d files present; sommelier symlinks dangling-but-correct.
- `image/tests/verify-image.sh <img>`: btrfs check; default subvol is
  `rootfs_subvol`; spot-check ownership/setuid via `btrfs inspect-internal`
  or guestfish.
- `scripts/deploy-test.sh`: parameterized port of
  `/home/r/baguette/dev-workflow/deploy-test.sh` — pushes an image into the
  running nested ChromeOS VM (ssh 127.0.0.1:9222, testing_rsa), creates/starts
  a VM named `v2test` by default (NEVER touch `baguette` (stock) or the
  rig-owned `archtest`), captures os-release / is-system-running / df / id
  evidence.

## CI (phase D — GitHub Actions)

- Hosting: GitHub **Releases** (artifacts expire and need auth). Pacman repo
  on a rolling `repo-x86_64` release tag (`repo-add --sign`, key in secrets;
  `SigLevel = Required` for consumers). Images on dated releases + rolling
  `latest`; weekly cron (rolling distro → fresh images keep first `-Syu`
  small). `uprev.yaml`: daily check of guest-tools HEAD → PR bumping the
  PKGBUILD pin. PR builds → plain artifacts, unsigned, `--fast`.
- Runners: ubuntu-24.04. Same rootless path (userns is available); pacman +
  arch-install-scripts from apt or bootstrapped — implementation detail for
  phase D, but the build script itself must not assume an Arch host beyond
  pacman/pacstrap availability.

## Security posture

- Production image: no users, no passwords, no baked credentials; NOPASSWD
  only for `%sudo`; upstream pinned by full commit SHA; repo signing in CI.
- Never weaken core/extra SigLevel. Local [baguette] repo may be unsigned.
