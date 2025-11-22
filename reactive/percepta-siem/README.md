# Percepta SIEM — Dev quickstart

This repo contains a Rust gRPC server (SIEM core) and a cross-platform agent for event collection.

What’s here
- `server/`: gRPC services, CA/enrollment, storage, rules engine
- `agent/`: event collection client (with optional Windows integration)
- `shared/proto/siem_core.proto`: protobuf definitions (compiled at build time)

## Build with low disk usage

If your local disk is tight, direct build artifacts to another path using `--target-dir`.

- Build only the agent (Linux/macOS):
```bash
cd agent
cargo build --features simulate --target-dir /tmp/cargo-target
```

- Build only the server:
```bash
cd server
cargo build --target-dir /tmp/cargo-target
```

- Build the whole workspace (optional):
```bash
cargo build --workspace --target-dir /tmp/cargo-target
```

Tip: Replace `/tmp/cargo-target` with any path on a disk that has space (external drive, another mount).

## Run locally

- Run the server (default port 50051 unless overridden by CLI flags):
```bash
cd server
cargo run -- --listen 0.0.0.0:50051
```

- Run the agent (simulation mode):
```bash
cd agent
cargo run --features simulate -- --help
cargo run --features simulate -- --log-level debug
```

## Protobuf / gRPC codegen

The `build.rs` in both crates uses `tonic-build` to generate Rust code from `shared/proto/siem_core.proto` at build time.

- CI installs `protoc` automatically.
- Locally, install it if missing:
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y protobuf-compiler
protoc --version
```

## Tests

- Unit tests:
```bash
cargo test --workspace --lib
```

- Integration tests (agent): expect the workspace to be built first, or run:
```bash
cargo build --workspace --target-dir /tmp/cargo-target
cargo test --test integration -- --nocapture
```

If tests reference built binaries, pre-building the workspace makes them deterministic.

## Windows-specific feature

The agent has optional Windows APIs gated by the `windows` feature. On non-Windows hosts, keep defaults.

- Enable on Windows if needed:
```bash
cd agent
cargo build --features windows
```

## Disk-space tips

- Clean build artifacts in this repo:
```bash
cargo clean
```
- Use `--target-dir` to relocate artifacts off the repo disk.
- Prefer CI builds when possible (see below).

## Continuous Integration (CI)

This repo includes a GitHub Actions workflow that:
- Checks out the code
- Installs Rust toolchain and `protoc`
- Builds the workspace and runs tests
- Stores artifacts in the runner's temporary storage (not your local disk)

Run it by pushing to a branch or opening a pull request.

## Troubleshooting

- Missing `protoc`: install `protobuf-compiler` (see above) or rely on CI.
- TLS/certs: the server generates/loads certs; if CA files are missing, startup may error. We’re replacing `unwrap/expect` in those paths; report any crashes with logs.
- Feature flags: if a build fails on non-Windows systems, ensure `windows` feature is not enabled.
