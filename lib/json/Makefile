.PHONY: all
all: clippy test debug release

.PHONY: clippy
clippy:
	cargo clippy

.PHONY: test
test:
	cargo test

.PHONY: debug
debug:
	cargo build

.PHONY: release
release:
	#cargo install cargo-auditable cargo-audit
	cargo auditable build --release

.PHONY: bench
bench:
	cargo bench --features benchmark
