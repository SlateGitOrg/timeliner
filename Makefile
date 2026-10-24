# timeliner — one-command gates. `make check` is what CI runs.
CARGO ?= cargo
COV_MIN ?= 80

.PHONY: check fmt fmt-check lint doc test cov build release demo bench fixtures loc clean

check: fmt-check lint doc cov
	@echo "make check: all gates passed"

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --locked --all-targets -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --locked --no-deps

test:
	$(CARGO) test --locked

# Runs the whole test suite under coverage instrumentation and enforces the threshold.
cov:
	$(CARGO) llvm-cov --locked --summary-only --fail-under-lines $(COV_MIN)

build:
	$(CARGO) build --locked

release:
	$(CARGO) build --locked --release

demo: release
	./scripts/demo.sh

bench: release
	./scripts/bench.sh

# Regenerates the committed synthetic evidence (byte-identical unless the generator changed).
fixtures:
	rm -rf fixtures/incident
	$(CARGO) run --locked --quiet -- fixtures --out fixtures/incident

loc:
	./scripts/loc.sh

clean:
	$(CARGO) clean
	rm -rf out
