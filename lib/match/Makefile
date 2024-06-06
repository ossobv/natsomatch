.PHONY: all
all: clippy test debug release

.PHONY: clippy
clippy:
	cargo clippy

.PHONY: test
test:
	grep 'format!("bulk[.]' src/log_matcher.rs | \
	  sed -e 's/^[^"]*"//;s/{.*//' | sort | while read -r l; do \
	    grep -q "assert.*\"$$l" src/log_matcher.rs || \
	      echo "WARNING: no test for: $$l"; done
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
