.PHONY: all
all: test debug release

.PHONY: test
test:
	cargo test

.PHONY: bench
bench:
	cargo bench

.PHONY: debug
debug:
	cargo build

.PHONY: release
release:
	#cargo install cargo-auditable cargo-audit
	cargo auditable build --release
