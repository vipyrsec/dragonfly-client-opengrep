# dragonfly-client-opengrep

Dragonfly's isolated OpenGrep worker. It leases OpenGrep jobs from Mainframe,
downloads and safely extracts Python package distributions, executes the reviewed
OpenGrep ruleset, and submits bounded findings.

Scanner behavior, dependencies, images, releases, and performance policy are
maintained independently in this repository.

## Build and test

The Rust version is pinned in `rust-toolchain.toml`.

```bash
cargo build --locked --release
cargo test --locked --all-targets --no-fail-fast
```

OpenGrep-dependent integration tests run when `OPENGREP_BIN` points to a reviewed
OpenGrep executable. Other tests do not require the executable.

## Container

The release image downloads the reviewed OpenGrep executable and verifies its
SHA-256 digest before installing it.

```bash
docker build --tag ghcr.io/vipyrsec/dragonfly-client-opengrep:local .
```

## Configuration

Configuration is loaded from defaults, `Config.toml`, `Config-dev.toml`, and
`DRAGONFLY_` environment variables, in that order.

| Variable | Default | Description |
| --- | --- | --- |
| `DRAGONFLY_BASE_URL` | `https://dragonfly.vipyrsec.com` | Mainframe API base URL |
| `DRAGONFLY_CF_ACCESS_CLIENT_ID` | | Cloudflare Access service-token client ID |
| `DRAGONFLY_CF_ACCESS_CLIENT_SECRET` | | Cloudflare Access service-token secret |
| `DRAGONFLY_THREADS` | Available parallelism | Concurrent package workers |
| `DRAGONFLY_LOAD_DURATION` | `60` | Delay between empty or failed job requests, in seconds |
| `DRAGONFLY_BULK_SIZE` | `20` | Maximum jobs leased per request |
| `DRAGONFLY_MAX_ARCHIVE_ENTRIES` | `4096` | Maximum entries in one distribution archive |
| `DRAGONFLY_MAX_DISTRIBUTIONS` | `32` | Maximum distributions in one package |
| `DRAGONFLY_MAX_DOWNLOAD_SIZE` | `33554432` | Maximum compressed distribution size in bytes |
| `DRAGONFLY_MAX_EXPANDED_SIZE` | `67108864` | Maximum expanded distribution size in bytes |
| `DRAGONFLY_MAX_SCAN_SIZE` | `16777216` | Maximum individual scan target size in bytes |

`OPENGREP_BIN` defaults to `/usr/local/bin/opengrep`.
