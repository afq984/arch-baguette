# Repo signing key

The CI-published pacman repository (rolling release tag `repo-x86_64`, built
by `.github/workflows/packages.yaml`) is signed: every package gets a
detached `.sig` and the `baguette.db` database is signed too. Images built on
main bake the repo with `SigLevel = Required`, so consumers always verify.

This directory holds the **public** key only:

- `keys/baguette.pub` — ASCII-armored public key, committed to the repo.
  `image/build.sh --guest-repo-url` installs and locally signs it in the
  image's pacman keyring; `packages.yaml` cross-checks that the secret key
  in CI matches it and publishes it as a release asset.

**NEVER commit private key material.** Only `baguette.pub` and this README
belong here (`.gitignore` additionally blocks common private-key
extensions). The private key lives exclusively in GitHub Actions secrets.

## Generating the key (one-time)

Ed25519, sign-only, **no expiry** (rotation is manual, see below). Use a
throwaway GNUPGHOME so your personal keyring stays out of it:

```sh
export GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"
PASS='choose-a-strong-passphrase'

gpg --batch --pinentry-mode loopback --passphrase "$PASS" \
    --quick-generate-key 'arch-baguette repo signing key' ed25519 sign never

FPR="$(gpg --batch --with-colons --list-secret-keys \
       | awk -F: '/^fpr:/ {print $10; exit}')"
echo "fingerprint: $FPR"
```

## Secrets to set (GitHub repository secrets)

| secret | content |
|---|---|
| `BAGUETTE_GPG_PRIVATE_KEY` | ASCII-armored private key (`gpg --armor --export-secret-keys`) |
| `BAGUETTE_GPG_PASSPHRASE`  | the passphrase protecting it |

```sh
gpg --batch --pinentry-mode loopback --passphrase "$PASS" \
    --armor --export-secret-keys "$FPR" \
  | gh secret set BAGUETTE_GPG_PRIVATE_KEY
printf '%s' "$PASS" | gh secret set BAGUETTE_GPG_PASSPHRASE
```

## Publishing the public key

```sh
gpg --armor --export "$FPR" > keys/baguette.pub
gpg --show-keys keys/baguette.pub    # sanity: one key, [S] usage, no expiry
```

Commit `keys/baguette.pub` (record the fingerprint in the commit message).
The packages workflow refuses to publish if the secret key's fingerprint
does not match the committed `baguette.pub`, and also uploads `baguette.pub`
to the `repo-x86_64` release so consumers can fetch it next to the repo.

Afterwards, shred the throwaway GNUPGHOME (the secrets are now the only
copy — that is intentional; rotation, not recovery, is the failure plan):

```sh
rm -rf "$GNUPGHOME"; unset GNUPGHOME PASS
```

## Bootstrap order (first-time setup)

The image bakes the repo **URL**; the repo release must exist before a baked
image first runs `pacman -Sy`:

1. Generate the key, set both secrets, commit `keys/baguette.pub` to main
   (image builds on main **fail loudly** if it is missing).
2. Run the `packages` workflow on main (push touching `packages/**`, or
   `workflow_dispatch`). This creates the rolling `repo-x86_64` release and
   uploads the signed repo.
3. Image builds on main follow automatically (`workflow_run` chains the
   `image` workflow after every successful packages publish; also weekly
   cron / manual dispatch). They pass
   `--guest-repo-url https://github.com/OWNER/REPO/releases/download/repo-x86_64`
   so the resulting guests can `pacman -Syu` the baguette packages.

## Rotation (manual, documented — no expiry to force it)

1. Generate a fresh key (steps above); update both secrets and
   `keys/baguette.pub` in the same commit.
2. Re-run the packages workflow: the repo is re-signed with the new key and
   the release's `baguette.pub` is replaced.
3. Newly published images trust the new key automatically (they bake the
   committed `baguette.pub` at build time). **Existing installs must import
   it manually** before their next `-Syu`:

   ```sh
   curl -LO https://github.com/OWNER/REPO/releases/download/repo-x86_64/baguette.pub
   sudo pacman-key --add baguette.pub
   sudo pacman-key --lsign-key <new fingerprint>
   ```

Treat a compromised key the same way, plus revoke trust where it was
imported (`pacman-key --delete <old fingerprint>` on installs).

## Local development posture (per DESIGN.md)

Local builds never touch this key:

- `scripts/build-repo.sh` produces an **unsigned** repo in `out/repo`; the
  image build consumes it as `file://` with `SigLevel = Optional TrustAll`
  (core/extra keep `SigLevel = Required DatabaseOptional` — never weakened).
- Local `image/build.sh` runs omit `--guest-repo-url`, so locally built
  images ship **no** `[baguette]` entry at all (verify-rootfs.sh asserts
  this). Only CI main builds bake the signed repo URL.
