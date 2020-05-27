#!/usr/bin/env gmake

# Check if we're running in an interactive terminal.
ISATTY := $(shell [ -t 0 ] && echo 1)

ifdef ISATTY
# Running in interactive terminal, OK to use colors!
MAGENTA = \e[35;1m
CYAN = \e[36;1m
OFF = \e[0m

# Built-in echo doesn't support '-e'.
ECHO = /bin/echo -e
else
# Don't use colors if not running interactively.
MAGENTA = ""
CYAN = ""
OFF = ""

# OK to use built-in echo.
ECHO = echo
endif

.PHONY: all debug test release bench fmt clean

all: debug test release bench
	@$(ECHO) "$(CYAN)*** Everything built successfully!$(OFF)"

debug:
	@$(ECHO) "$(CYAN)*** Building debug target...$(OFF)"
	@cargo build

release:
	@$(ECHO) "$(CYAN)*** Building release target...$(OFF)"
	@cargo build --release

test:
	@$(ECHO) "$(CYAN)*** Running tests...$(OFF)"
	@cargo test -- tests::test_

bench:
	@$(ECHO) "$(CYAN)*** Running benchmarks...$(OFF)"
	@cargo bench -- tests::bench_

fmt:
	@$(ECHO) "$(CYAN)*** Formatting code...$(OFF)"
	@cargo fmt

clean:
	@$(ECHO) "$(CYAN)*** Cleaning up...$(OFF)"
	@cargo clean
	@-rm -f Cargo.lock
