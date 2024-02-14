.PHONY: release
release:
	#cargo install cargo-auditable cargo-audit
	cargo auditable build --release
