ALL = $(filter-out Makefile,$(wildcard *))

.PHONY: all
all:
	for lib in $(ALL); do make -C $$lib; done

.PHONY: bench
bench:
	for lib in $(ALL); do make -C $$lib bench; done

.PHONY: test
test:
	for lib in $(ALL); do make -C $$lib test; done
