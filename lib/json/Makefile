.PHONY: all
all: test debug release

.PHONY: test
test:
	cargo test --features benchmark

.PHONY: bench
bench:
	cargo bench --features benchmark

.PHONY: debug
debug:
	cargo build

.PHONY: release
release:
	#cargo install cargo-auditable cargo-audit
	cargo auditable build --release
