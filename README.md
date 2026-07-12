# arch-baguette-v2

Arch Linux for ChromeOS **Baguette** (Crostini Containerless): a
production-quality, userless btrfs image plus the ChromeOS guest integration
packaged as real, signed pacman packages — updatable with `pacman -Syu` and
pinned to a reviewed upstream commit.

[DESIGN.md](DESIGN.md) is the authoritative design document.

- **Userless production image** — like the official Debian image, your user
  is provisioned at first start (maitred `SetUpUser`), not baked in. No
  users, no passwords, no credentials in the artifact.
- **Real packages** — `baguette-base` (maitred/vshd units, contract groups,
  sudoers, `/mnt` layout) and `cros-{sommelier,garcon,wayland,port-listener,
  notificationd}` (split from a pinned
  [cros-container-guest-tools](https://chromium.googlesource.com/chromiumos/containers/cros-container-guest-tools)
  commit), served from a signed pacman repo on GitHub Releases.
- **Small artifact** — btrfs sized to content, `zstd -19`; the filesystem
  grows to your chosen disk size on first boot.
- **Single rootless build path** — the same script builds locally without
  root/docker/loop-mounts and in CI.

> Throughout, replace `OWNER/REPO` with the GitHub repository this project
> is hosted at (CI fills in `${{ github.repository }}` automatically).

## Install on a Chromebook

Baguette is the containerless Crostini stack (default for new environments
since ChromeOS 143; on 147+ the `#crostini-containerless` flag is on by
default).

1. Download `baguette_arch_rootfs.img.zst` from the
   [latest release](https://github.com/OWNER/REPO/releases/latest) into the
   ChromeOS **Downloads** folder. (Optional: check it against the published
   `.sha256`; `manifest.txt` lists every package in the image.)
2. Open crosh (Ctrl+Alt+T) and create + start the VM:

   ```
   vmc create --vm-type BAGUETTE --size 10G \
     --source /home/chronos/user/MyFiles/Downloads/baguette_arch_rootfs.img.zst \
     arch
   vmc start --vm-type BAGUETTE arch
   ```

   `--size` is the disk the image grows into on first boot — pick what you
   want to give the VM (concierge preallocates it, so that much free space
   must exist). Any name works; `arch` is used below.

3. **First start, CLI users:** this image ships no user, and `vmc start`
   waits for a signal that only fires once a user session runs garcon — so
   the **first** start of a fresh VM ends in a garcon-wait timeout
   ("timeout while waiting for a signal"). The VM itself is up. This is
   expected (the Chrome UI installer flow normally creates the user for
   you). Create your user once, replicating maitred's `SetUpUser` (from
   crosh; pick your username):

   ```
   vsh --vm_name=arch --user=root -- sh -c \
     'useradd --uid 1000 --create-home --shell /bin/bash \
        --groups audio,cdrom,dialout,disk,floppy,kvm,netdev,plugdev,sudo,tss,video USERNAME \
      && loginctl enable-linger USERNAME'
   vmc stop arch
   vmc start --vm-type BAGUETTE arch    # completes cleanly now
   ```

4. Enter the VM:

   ```
   vsh arch
   ```

Tip: creating the VM with the name `termina` lets the ChromeOS Terminal app
launch it directly (see
[NixOS Baguette images in ChromeOS](https://aldur.blog/articles/2025/10/29/nixos-baguette-images-in-chromeos)).
If your device still runs the legacy LXD Crostini, remove and reinstall the
Linux development environment to migrate.

## Updates

Images built by CI bake the signed `[baguette]` repo, so a plain

```sh
sudo pacman -Syu
```

updates Arch **and** the ChromeOS integration packages. The heavy binaries
(sommelier, garcon, maitred, vshd) live on the host-mounted
`/opt/google/cros-containers` filesystem and track your ChromeOS milestone
automatically — the packages are thin wrappers/config, so there is no
per-milestone repo to switch.

## Adding the [baguette] repo to an existing Arch install

```sh
curl -LO https://github.com/OWNER/REPO/releases/download/repo-x86_64/baguette.pub
sudo pacman-key --add baguette.pub
gpg --show-keys baguette.pub          # note the fingerprint, then:
sudo pacman-key --lsign-key <FINGERPRINT>

sudo tee -a /etc/pacman.conf <<'EOF'

[baguette]
SigLevel = Required
Server = https://github.com/OWNER/REPO/releases/download/repo-x86_64
EOF

sudo pacman -Syu baguette-base cros-sommelier cros-garcon cros-wayland \
  cros-port-listener cros-notificationd
```

## Local development (rootless build loop)

No sudo, no docker, no loop mounts. Requirements: `pacstrap`/`arch-chroot`
(arch-install-scripts ≥ 31), btrfs-progs ≥ 6.8, `zstd`, subuid/subgid
ranges with `newuidmap`/`newgidmap`, `makepkg` + `namcap` for packages.

```sh
scripts/build-repo.sh                    # PKGBUILDs -> out/repo (local, unsigned)
image/build.sh --fast --dev-user test    # image -> out/image (+ test:test0000 user)

image/tests/verify-rootfs.sh --dev-user test build/image/rootfs
image/tests/verify-image.sh build/image/baguette_arch_rootfs.img

scripts/deploy-test.sh                   # boot it in the nested ChromeOS rig
```

Local images deliberately ship **no** `[baguette]` repo entry (the local
repo is unsigned; see `keys/README.md` for the posture). Production-flavor
release builds are what CI does: no `--dev-user`, default `zstd -19`, plus
`--guest-repo-url` pointing at the published signed repo.

## CI

| workflow | what it does |
|---|---|
| `packages.yaml` | PRs: build + namcap, unsigned artifact. Main: sign packages + db and publish the flat repo to the rolling `repo-x86_64` release. |
| `image.yaml` | PRs touching `image/**`: `--fast` build + verify, artifact only. Weekly cron / dispatch / after each packages publish: hermetic rebuild (fresh packages → image), verify, release to dated `vYYYY.MM.DD` + rolling `latest`. |
| `uprev.yaml` | Daily: if cros-container-guest-tools main moved past the PKGBUILD pin, opens a PR bumping `_commit`/`pkgver` (pkgrel reset to 1). |

First-time signing/bootstrap setup: see [keys/README.md](keys/README.md).

## Layout

- `packages/` — PKGBUILDs (`baguette-base`, split `cros-guest-tools`) and
  the content audit (`packages/AUDIT.md`)
- `image/` — `build.sh` (rootless-first image build), `pacman.conf.in`,
  contract tests under `image/tests/`
- `scripts/` — `build-repo.sh` (local repo), `deploy-test.sh` (nested
  ChromeOS rig deploy/boot-test)
- `keys/` — repo signing public key + key management docs
- `out/`, `build/` — build products (gitignored)

## License

[BSD-3-Clause](LICENSE).
