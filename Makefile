.PHONY: all
all: lib test debug release

.PHONY: test
test:
	make -C lib test
	cargo test

.PHONY: bench
bench:
	make -C lib bench
	cargo bench

.PHONY: debug
debug:
	cargo build

.PHONY: release
release:
	#cargo install cargo-auditable cargo-audit
	#cargo auditable build --release
	./build-docker.sh
