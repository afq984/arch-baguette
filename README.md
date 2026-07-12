# arch-baguette-v2

Production-quality Arch Linux image and pacman packages for ChromeOS
**Baguette** (Crostini Containerless).

Status: under construction. See [DESIGN.md](DESIGN.md) for the authoritative
design and [/home/r/baguette/DEV-WORKFLOW.md] for the verified rootless
build/test techniques this is built on.

## Layout

- `packages/` — PKGBUILDs: `baguette-base` (guest glue) and
  `cros-guest-tools` (split packages pinned to an upstream commit)
- `image/` — rootless image build + verification tests
- `scripts/` — local repo builder and nested-VM deploy/test loop

## Quick start (local, rootless)

```sh
scripts/build-repo.sh          # build packages -> out/repo
image/build.sh --fast --dev-user test   # build image -> out/image
scripts/deploy-test.sh         # boot it in the nested ChromeOS rig
```
