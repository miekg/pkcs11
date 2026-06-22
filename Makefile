# Makefile for miekg/pkcs11 — PKCS #11 v3.2 support
#
# The three official OASIS PKCS #11 v3.2 headers are downloaded verbatim from
# the OASIS pkcs11 GitHub repository (tag pkcs11-3.20, commit 858bfc8b93ded02a40886e2321240b5978e1aa42).
# They must never be hand-edited.
# After any header refresh, re-run `make generate` to regenerate zconst.go.

OASIS_COMMIT := 858bfc8b93ded02a40886e2321240b5978e1aa42
OASIS := https://raw.githubusercontent.com/oasis-tcs/pkcs11/$(OASIS_COMMIT)/published/3-02

.PHONY: all headers generate build test integration integration-v32 clean-headers

all: headers generate build test

# ── Download official OASIS headers ──────────────────────────────────────────
headers: pkcs11t.h pkcs11f.h pkcs11.h

pkcs11t.h:
	curl -sSfL "$(OASIS)/pkcs11t.h" -o $@

pkcs11f.h:
	curl -sSfL "$(OASIS)/pkcs11f.h" -o $@

pkcs11.h:
	curl -sSfL "$(OASIS)/pkcs11.h" -o $@

# Force re-download even when files already exist
.PHONY: refresh-headers
refresh-headers:
	curl -sSfL "$(OASIS)/pkcs11t.h" -o pkcs11t.h
	curl -sSfL "$(OASIS)/pkcs11f.h" -o pkcs11f.h
	curl -sSfL "$(OASIS)/pkcs11.h"  -o pkcs11.h
	@echo "Refreshed all three official OASIS v3.2 headers."

# ── Code generation ──────────────────────────────────────────────────────────
# zconst.go is generated from pkcs11t.h by the //go:generate directive.
# Must be re-run after `make headers` or `make refresh-headers`.
generate:
	go generate ./...

# ── Build ────────────────────────────────────────────────────────────────────
build:
	go build ./...

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	go test ./...

# Integration tests use a single PKCS11_MODULE for both PKCS #11 v2.4 and v3.2.
#
# SoftHSMv3 (https://github.com/pqctoday/pqctoday-hsm) is recommended because it
# implements v3.2 while remaining fully backward-compatible with v2.4.
# System-installed libsofthsm2.so also works; v3.2/PQC tests will self-skip.
#
# No external tools required — token initialisation is done entirely via the
# PKCS#11 API (C_InitToken / C_InitPIN).
#
# Build SoftHSMv3 from source:
#   git clone https://github.com/pqctoday/pqctoday-hsm
#   cd pqctoday-hsm
#   mkdir build && cd build
#   cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
#   make
#   make check
#   
# Run all integration tests (v2.4 compat + v3.2):
#   make integration PKCS11_MODULE=$PWD/pqctoday-hsm/build/src/lib/libsofthsmv3.so
#
# Run only v3.2/PQC tests:
#   make integration-v32 PKCS11_MODULE=$PWD/pqctoday-hsm/build/src/lib/libsofthsmv3.so

PKCS11_MODULE ?=
PKCS11_PIN    ?= 1234

.PHONY: integration integration-v32

integration:
	@if [ -z "$(PKCS11_MODULE)" ]; then \
	    echo ""; \
	    echo "Error: PKCS11_MODULE is not set."; \
	    echo ""; \
	    echo "Example:"; \
	    echo "  make integration PKCS11_MODULE=/path/to/libsofthsmv3.so"; \
	    echo ""; \
	    exit 1; \
	fi
	PKCS11_MODULE="$(PKCS11_MODULE)" PKCS11_PIN="$(PKCS11_PIN)" \
	    go test -v ./...

# Run only v3.2 and PQC tests (faster when iterating on new algorithms).
integration-v32:
	@if [ -z "$(PKCS11_MODULE)" ]; then \
	    echo "Error: PKCS11_MODULE is not set."; \
	    exit 1; \
	fi
	PKCS11_MODULE="$(PKCS11_MODULE)" PKCS11_PIN="$(PKCS11_PIN)" \
	    go test -v -run 'TestPQC|TestV32' ./...

# ── clean-headers ────────────────────────────────────────────────────────────
# Removes the downloaded OASIS headers (run `make headers` to restore them).
clean-headers:
	rm -f pkcs11t.h pkcs11f.h pkcs11.h
