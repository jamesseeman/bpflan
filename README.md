# bpflan

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' --bin bpflan -- --iface eno1
```
