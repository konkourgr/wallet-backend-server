
# 1 Development
## Install

```
yarn install
```

## Change configuration

Edit `config/config.dev.ts` file to change the configuration of the app.
## Run in dev mode

```
yarn dev
```

Set `REGISTRATION_DISABLED=true` to omit the public user-registration endpoints from the server. By default, registration remains enabled. This disables `/user/register`, `/user/register-webauthn-begin`, and `/user/register-webauthn-finish`; authenticated passkey-management endpoints remain available.

## Pre-commit

We use [pre-commit](https://pre-commit.com/) to enforce our `.editorconfig` before code is committed.

### One-time setup

```
# install pre-commit if you don’t already have it
pip install pre-commit       # or brew install pre-commit / pipx install pre-commit

# enable the git hook in this repo
pre-commit install

# optional: clean up the repo on demand
pre-commit run --all-files

git add -A
```
### What happens on commit
- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, the editorconfig-checker runs inside Docker to validate all staged files.
- If violations remain, fix them manually until the commit passes.

# 2 Production

## 2.1. Preparation (The following steps should run on a clone of the production VM)

### 2.1.1. Configuration

1. Copy `config/config.template.ts` to `config/config.dev.ts`  and change it accordingly

2. Place the ssl keys on the ssl_keys/ directory

This directory must contain the following files

- `<server_name>-chain-only.pem`

- `<server_name>-server-only.pem`

- `<server_name>-server-with-chain.pem`

3. Change the server_name variable on the `entrypoint.sh` file

### 2.1.2. Install and Build for production

This step must run on a VM identical to the production system (same distribution, version and architecture)

```
yarn build:prod
```

Test the application

```
yarn start
```

### 2.1.3. Install 'paketo' globally and produce a snapshot

```
npm i -g @gsiou/paketo
yarn snapshot
```


### 2.1.4. Transfer the snapshot to the production server with rsync

```
rsync --rsh='ssh -p 65432' <snapshot_name>.tar.gz root@ip:/tmp
```

## 2.2. Deploy on the production server

```
cd /tmp
rm -rf wallet-backend
mkdir wallet-backend
tar -xf <snapshot_name>.tar.gz -C wallet-backend
cd wallet-backend
chmod +x entrypoint.sh
./entrypoint.sh
```

Add `Listen 9002` below the `Listen 443` line on `/etc/apache2/ports.conf`
and restart apache


## 💡Contributing
Want to contribute? Check out our [Contribution Guidelines](https://github.com/wwWallet/.github/blob/main/CONTRIBUTING.md) for more details!

## Experimental previewSign with one shared passkey

Use `previewSign-single-key` together with the matching frontend. Hardware signing defaults to enabled in both applications (`PREVIEW_SIGN_ENABLED=false` explicitly opts out). New wallet and added-passkey registrations request PRF and previewSign v4 in one creation ceremony and validate both capabilities. The normal WebAuthn record retains the seed attestation provisionally. The frontend automatically completes proof of possession through that same credential ID during signup and added-passkey registration, saves the public seed in the encrypted wallet, and selects hardware signing before reporting success. No Settings enable action or second WebAuthn registration is required. An online login retries incomplete setup if that passkey has no saved seed or no active seed was selected.

Use a fresh database (`wallet_single_key` in this worktree's `.env`). This branch intentionally changes the fresh-install `AddSigningCredential1793577600000` migration rather than migrating old signing registrations. It adds `pendingSigningAttestation` to `webauthn_credential` and creates a normalized `signing_credential` with a unique FK to that credential, seed metadata, and deletion cascading. Do not apply this variant to a database already migrated by the separate-key `previewSign` branch. Original database contents are not modified by this worktree's setup.

Run migrations with `yarn typeorm migration:run`, or follow the parent project's `yarn init-db` instructions to seed default issuer/verifier/certificate records too. The frontend guide at `../wallet-frontend/docs/preview-sign.md` describes the user flow.

`/user/session/preview-sign/register-begin` now accepts the ID of an existing PRF credential. It looks up the stored registration and seed attestation, checks ownership and PRF capability, then returns a server-derived test signing key and one-time challenge. `register-complete` verifies its purpose-bound token, the shared credential assertion and the test signature before saving seed metadata. Retrying an already completed enrollment returns its verified public metadata so an interrupted encrypted-wallet upload can recover. The previous separate-credential `register-finish` endpoint is removed.

Login, enrollment proof and `sign-finish` all lock and update the authoritative `webauthn_credential.signatureCount` in a transaction. No counter or WebAuthn public key is duplicated in `signing_credential`. Signing only returns extension signature bytes covered by the verified assertion. The frontend verifies the derived-key signature. Packed and none seed attestations retain the proof-of-possession requirement; manufacturer trust is not established.

Validation:

```sh
yarn test:preview-sign
yarn build
```

Real HTTP/MariaDB integration tests require an **empty disposable database** and refuse any other database name or an already populated schema:

```sh
docker run -d --name single-key-integration --tmpfs /var/lib/mysql \
  -e MARIADB_ROOT_PASSWORD=single-key-test \
  -e MARIADB_DATABASE=preview_sign_single_key_test \
  -p 127.0.0.1:33307:3306 mariadb:12
# Wait until the container is ready, then:
DB_HOST=127.0.0.1 DB_PORT=33307 DB_USER=root DB_PASSWORD=single-key-test \
  DB_NAME=preview_sign_single_key_test yarn test:single-key:integration
docker rm -f single-key-integration
```

Tests cover combined signup and added passkeys, a single credential ID, proof/replay/ownership checks, login-sign-login counters, concurrent updates, recovery, deletion cascade, and migration down/up. They use simulated authenticators; real PRF + previewSign device/client support still needs a physical test.
