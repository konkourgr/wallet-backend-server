# wwWallet Backend Server
wwWallet Backend Server is the backend of [wwWallet/wallet-frontend](https://github.com/wwWallet/wallet-frontend). It manages user accounts and WebAuthn passkeys, stores each user's encrypted wallet data, and provides helper services for the wallet like an HTTP proxy and an OHTTP relay.

> [!NOTE]
> To quickly setup the **wwWallet** ecosystem see https://github.com/wwWallet/wwwallet

## How to run

Install dependencies
```
yarn install
```

Create the configuration (see [Configuration](#configuration))
```
cp .env.template .env
```

Run database migrations (needs a running MariaDB/MySQL, see `DB_*` below)
```
yarn typeorm migration:run
```

Run in dev mode
```
yarn dev
```

## Configuration
Configuration is loaded from `.env` (see `.env.template`). Values are read via `dotenv` and validated in `config/index.ts`.

The server refuses to start if a required variable is missing or invalid. Empty values count as unset.

| Variable | Purpose | Default / Notes |
| --- | --- | --- |
| `PORT` | Port the server listens on. | **Required.** |
| `APP_URL` | Public URL of the server. | Only used in the startup log. Default: `http://localhost:$PORT`. |
| `APP_SECRET` | Secret used to sign session tokens. | **Required.** The `.env.template` value is for local development only and is refused when `NODE_ENV=production`; `yarn setup` in the parent repo generates a random one. Use a long random value in production. |
| `DB_HOST` | Database host (MariaDB/MySQL). | **Required.** |
| `DB_PORT` | Database port. | **Required.** |
| `DB_USER` | Database user. | **Required.** |
| `DB_PASSWORD` | Database password. | **Required.** |
| `DB_NAME` | Database name. | **Required.** |
| `WEBAUTHN_ORIGIN` | Origin(s) of the wallet frontend accepted in WebAuthn ceremonies. | **Required.** Comma-separated, e.g. `https://wallet.example.com`. |
| `WEBAUTHN_RP_ID` | WebAuthn Relying Party ID, usually the frontend's domain. | **Required.** e.g. `wallet.example.com`. |
| `WEBAUTHN_RP_NAME` | Relying Party name shown by authenticators. | Default: `wwWallet demo`. |
| `KEYS_DIR` | Directory with the wallet-provider keys: `wallet-provider.key`, `wallet-provider.pem` and `ca.pem`. | Default: `/app/keys` (Docker image layout). |
| `OHTTP_GATEWAY_URL` | Oblivious HTTP gateway that `/relay` forwards to. | Default: `http://localhost:4567`. |
| `METADATA_FIDO_URL` | FIDO Metadata Service used to identify authenticators. | Default: `https://c-mds.fidoalliance.org`. |
| `METADATA_COMMUNITY_AAGUID_URL` | Community list of passkey provider AAGUIDs. | Default: the [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) list. |
| `METADATA_REFRESH_INTERVAL_MS` | How often authenticator metadata is refreshed (ms). | Default: `604800000` (7 days). |
| `REGISTRATION_DISABLED` | Set to `true` to disable new user registration (`/user/register`, `/user/register-webauthn-begin`, `/user/register-webauthn-finish`). | Default: `false`. Passkey management for existing users keeps working. |
| `LOG_LEVEL` | Minimum log level: `trace`, `debug`, `info`, `warn`, `error`, `fatal` or `silent`. | Default: `info`. Logs are JSON on stdout when `NODE_ENV=production`, pretty-printed otherwise. |
| `LOG_HTTP` | Set to `true` to log every HTTP request (method, path, status, response time). | Default: `false`. The `Authorization` and `Cookie` headers and all query values are redacted. |
| `DEBUG_ACCEPT_UNAUTHORIZED_HTTPS` | Set to `true` to accept invalid TLS certificates in `/proxy` and `/helper/get-cert`. | **Development only.** With `NODE_ENV=production`, the server refuses to start if any `DEBUG_*` variable is set. |

## Production

Build the Docker image from `Dockerfile` (version tags publish it as `ghcr.io/wwwallet/wallet-backend-server:<tag>`). To run it:

- Set the variables above as environment variables (at least the required ones).
- Mount the wallet-provider keys at `/app/keys` (or set `KEYS_DIR`).
- Run the migrations before starting a new version: `yarn migration:run:prod` inside the container.

## Formatting and checks

```sh
# Check ESLint rules
yarn lint

# Format files with Prettier
yarn format

# Check Prettier formatting without changing files
yarn format:check

# Check TypeScript types without generating output
yarn typecheck
```

## Pre-commit

We use [pre-commit](https://pre-commit.com/) to enforce our `.editorconfig` before code is committed.

#### One-time setup

```
# install pre-commit if you don’t already have it
pip install pre-commit       # or brew install pre-commit / pipx install pre-commit

# enable the git hook in this repo
pre-commit install

# optional: clean up the repo on demand
pre-commit run --all-files

git add -A
```

#### Local checks without committing

Run only the EditorConfig check, without running auto-fixers:

```sh
pre-commit run editorconfig-checker --all-files
```

Omit `--all-files` to check only staged files. The first run installs the pinned native checker in pre-commit's cache. This check reports violations without changing or staging files.

#### What happens on commit

- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, editorconfig-checker validates staged files.
- If violations remain, fix them manually until the commit passes.

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
