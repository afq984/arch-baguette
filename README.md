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


## Install on a Chromebook

Baguette is the containerless Crostini stack (default for new environments
since ChromeOS 143; on 147+ the `#crostini-containerless` flag is on by
default).

First, download `baguette_arch_rootfs.img.zst` from the
[latest release](https://github.com/afq984/arch-baguette/releases/latest) into the
ChromeOS **Downloads** folder. (Optional: check it against the published
`.sha256`; `manifest.txt` lists every package in the image.)

`--size` in the command below is the disk size the image grows into on first
boot — pick what you want to give the VM (`vm_concierge` preallocates it, so
that much free space must exist).

### Setup: Default `termina` VM + ChromeOS Settings UI

Pre-creating the `termina` disk from `crosh` lets ChromeOS's built-in Linux
installer reuse your Arch image (skipping the Debian download) and
automatically configure your user, Files app integration, and the ChromeOS
Terminal app (see
[NixOS Baguette images in ChromeOS](https://aldur.blog/articles/2025/10/29/nixos-baguette-images-in-chromeos)):

1. Open **crosh** (`Ctrl+Alt+T`) and create the `termina` VM disk (do not start
   it yet — the Settings installer starts it for you):

   ```sh
   vmc create --vm-type BAGUETTE --size 10G \
     --source /home/chronos/user/MyFiles/Downloads/baguette_arch_rootfs.img.zst \
     termina
   ```

2. Open **ChromeOS Settings** › **About ChromeOS** › **Developers** › **Linux
   development environment** and click **Set up**, then click **Next**, enter
   your desired username, and click **Install**.
3. ChromeOS detects the existing `termina` disk, boots the VM, provisions your
   UID `1000` user (`SetUpUser`), starts `cros-garcon.service`, and opens the
   Terminal app in Arch Linux. *(On slower hardware, `cros-garcon.service` can
   still be starting when the installer finishes: the first Terminal window may
   show `Error starting crostini for terminal`, and `vsh termina penguin` may
   report `requested container does not exist: penguin`. Wait a moment, then
   open `penguin` from the Terminal app or retry `vsh termina penguin`.)*
4. Alongside the ChromeOS Terminal app, you can also open additional shells
   into `termina` from **crosh**:

   ```sh
   vsh termina penguin
   ```

   *(In Baguette mode, `vsh <vm_name> penguin` attaches a login shell for UID
   `1000` inside the VM regardless of the Linux username you chose.)*

*(If your device already has a Linux environment installed, remove the existing
Linux development environment in Settings first — this also covers migrating
from legacy LXD Crostini — then run Step 1. Custom VM names and CLI-only setup
without the ChromeOS Settings installer are not supported by the userless image
yet.)*

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
curl -LO https://github.com/afq984/arch-baguette/releases/download/repo-x86_64/baguette.pub
sudo pacman-key --add baguette.pub
gpg --show-keys baguette.pub          # note the fingerprint, then:
sudo pacman-key --lsign-key <FINGERPRINT>

sudo tee -a /etc/pacman.conf <<'EOF'

[baguette]
SigLevel = Required
Server = https://github.com/afq984/arch-baguette/releases/download/repo-x86_64
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

# End-to-end ChromeOS UI + crosh user-flow verification:
uv sync --locked
uv run --locked scripts/test_user_flows.py --self-test
uv run --locked scripts/test_user_flows.py --baguette-image out/image/baguette_arch_rootfs.img.zst
```

Local images deliberately ship **no** `[baguette]` repo entry (the local
repo is unsigned; see `keys/README.md` for the posture). Production-flavor
release builds are what CI does: no `--dev-user`, default `zstd -19`, plus
`--guest-repo-url` pointing at the published signed repo.

## CI

| workflow | what it does |
|---|---|
| `packages.yaml` | PRs: build + namcap, unsigned artifact. Main: sign packages + db and publish the flat repo to the rolling `repo-x86_64` release. |
| `image.yaml` | PRs touching `image/**`, `scripts/test_user_flows.py`, `scripts/protos/**`, `pyproject.toml`, `uv.lock`, `.github/workflows/test-user-flows.yaml`, or `README.md`: `--fast` build + verify, then runs `test-user-flows.yaml` against the built artifact. Weekly cron / dispatch / after each `packages` publish on `main`: hermetic rebuild (fresh packages → image), verify, hard-gated on `test-user-flows.yaml` (bypassable on manual `workflow_dispatch` via `skip_e2e: true`), and release to dated `vYYYY.MM.DD` + rolling `latest`. |
| `test-user-flows.yaml` | Reusable workflow (`workflow_call`) + manual `workflow_dispatch`: runs the offline README/proto self-test (`--self-test`), boots a nested-KVM ChromiumOS VM (board and release pinned in `scripts/protos/metadata.json`), and drives the `termina` + ChromeOS Settings UI setup flow, the ChromeOS Terminal app (`chrome-untrusted://terminal`), and `crosh` shell entry (`vsh termina penguin`) gated on `VmCicerone.ContainerStarted`. |
| `uprev.yaml` | Daily: if cros-container-guest-tools main moved past the PKGBUILD pin, opens a PR bumping `_commit`/`pkgver` (pkgrel reset to 1). |

First-time signing/bootstrap setup: see [keys/README.md](keys/README.md).

## Layout

- `packages/` — PKGBUILDs (`baguette-base`, split `cros-guest-tools`) and
  the content audit (`packages/AUDIT.md`)
- `image/` — `build.sh` (rootless-first image build), `pacman.conf.in`,
  contract tests under `image/tests/`
- `scripts/` — `build-repo.sh` (local repo), `deploy-test.sh` (nested
  ChromeOS rig deploy/boot-test), `test_user_flows.py` + `scripts/protos/`
  (automated ChromeOS UI/crosh E2E user-flow test and vendored ChromiumOS D-Bus
  `.proto` schemas pinned to the test image release)
- `pyproject.toml`, `uv.lock` — hash-locked Python test dependencies (`uv`)
- `keys/` — repo signing public key + key management docs
- `out/`, `build/` — build products (gitignored)

## License

[BSD-3-Clause](LICENSE).
