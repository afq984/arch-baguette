# Vendored ChromiumOS D-Bus Protocol Buffer Schemas

These `.proto` files are vendored from the exact `chromiumos/platform2` revision
recorded in the release manifest of the pinned ChromiumOS test image (defined in
[`metadata.json`](./metadata.json)):

- `vm_concierge/concierge_service.proto` (`system_api/dbus/vm_concierge/concierge_service.proto`)
- `vm_cicerone/cicerone_service.proto` (`system_api/dbus/vm_cicerone/cicerone_service.proto`)
- `vm_applications/apps.proto` (`system_api/dbus/vm_applications/apps.proto`, imported by `cicerone_service.proto`)
- `arc/arc.proto` (`system_api/dbus/arc/arc.proto`, imported by `concierge_service.proto`)

All files are governed by the ChromiumOS BSD-style license in [`LICENSE`](./LICENSE).

## Single Source of Truth & Updating

[`metadata.json`](./metadata.json) is the single source of truth for the pinned
ChromeOS test image (`board` and `cros_release`), `manifest_url`,
`platform2_revision`, and per-file SHA-256 digests:

- `scripts/test_user_flows.py --self-test` (and every E2E run at startup)
  verifies `metadata.json` and the SHA-256 digests of all vendored files.
- At runtime, `scripts/test_user_flows.py` downloads the ChromeOS test image for
  `board`/`cros_release` from `metadata.json`, inspects `/etc/lsb-release`
  inside the booted ChromeOS VM (`CHROMEOS_RELEASE_BUILDER_PATH`,
  `CHROMEOS_RELEASE_CHROME_MILESTONE`, and `CHROMEOS_RELEASE_VERSION`), and
  aborts immediately if the booted image does not match `metadata.json`.

To bump the pinned ChromeOS test image release and re-fetch matching `.proto`
schemas (`--release` is required; `--board` defaults to the existing `board` in
`metadata.json`):

```sh
uv run scripts/protos/update.py --release <RELEASE>
```
