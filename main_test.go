// Copyright 2026 Miek Gieben and the Golang pkcs11 Contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SPDX-License-Identifier: BSD-3-Clause

package pkcs11

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain bootstraps an ephemeral SoftHSM token when PKCS11_MODULE is set,
// runs all tests against it, then cleans up.
//
// A single PKCS11_MODULE covers both test suites:
//   - v2.4 compatibility tests (RSA, AES, digest, …) — always run
//   - v3.2 / PQC tests (ML-KEM, ML-DSA, …)          — skip when the token
//     does not advertise the required mechanism
//
// Recommended module: softhsmv3 from https://github.com/pqctoday/pqctoday-hsm
// (supports both v2.4 and v3.2).
// System-installed libsofthsm2.so works too; v3.2 tests will self-skip.
//
// No external tools are required: token initialisation is done entirely
// through the PKCS#11 API (C_InitToken / C_InitPIN).
func TestMain(m *testing.M) {
	if mod := os.Getenv("PKCS11_MODULE"); mod != "" {
		teardown := initSoftHSMToken(mod)
		verifySoftHSMToken(mod)
		code := m.Run()
		teardown()
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// initSoftHSMToken creates a temp directory, writes a fresh softhsm2.conf
// (same INI format for SoftHSMv2 and SoftHSMv3), then initialises the token
// directly via the PKCS#11 API — no softhsm2-util required.
//
// The PKCS#11 flow is:
//  1. C_Initialize / C_GetSlotList (tokenPresent=false) to find a free slot
//  2. C_InitToken to initialise the slot with an SO-PIN and label
//  3. C_GetSlotList (tokenPresent=true) to find the newly-created slot
//  4. C_OpenSession / C_Login(SO) / C_InitPIN to set the user PIN
func initSoftHSMToken(modulePath string) func() {
	dir, err := os.MkdirTemp("", "softhsm-test-*")
	if err != nil {
		panic(err)
	}

	// tokens/ subdirectory keeps token objects separate from the conf file.
	tokensDir := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokensDir, 0700); err != nil {
		panic(err)
	}

	// softhsm2.conf format is identical for SoftHSMv2 and SoftHSMv3.
	// SOFTHSM2_CONF is honoured by both.
	conf := filepath.Join(dir, "softhsm2.conf")
	content := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n", tokensDir,
	)
	if err := os.WriteFile(conf, []byte(content), 0600); err != nil {
		panic(err)
	}
	// Must be set before the module is loaded so SoftHSM reads the right config.
	os.Setenv("SOFTHSM2_CONF", conf)

	if os.Getenv("PKCS11_PIN") == "" {
		os.Setenv("PKCS11_PIN", "1234")
	}

	const soPin = "0000"
	const tokenLabel = "test-token"
	userPin := os.Getenv("PKCS11_PIN")

	// ── Load the module ───────────────────────────────────────────────────────
	ctx := New(modulePath)
	if ctx == nil {
		panic("failed to load PKCS11_MODULE: " + modulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		panic("C_Initialize: " + err.Error())
	}

	// ── Find an uninitialised slot (tokenPresent=false) ───────────────────────
	slots, err := ctx.GetSlotList(false)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		panic(fmt.Sprintf("C_GetSlotList(false): %v (count=%d)", err, len(slots)))
	}

	// ── Initialise the token ──────────────────────────────────────────────────
	if err := ctx.InitToken(slots[0], soPin, tokenLabel); err != nil {
		ctx.Finalize()
		ctx.Destroy()
		panic("C_InitToken: " + err.Error())
	}

	// After C_InitToken the slot gets a new ID; re-fetch with tokenPresent=true.
	slots, err = ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		panic(fmt.Sprintf("C_GetSlotList(true) after InitToken: %v (count=%d)", err, len(slots)))
	}

	// ── Set the user PIN via C_InitPIN ────────────────────────────────────────
	sh, err := ctx.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		panic("OpenSession: " + err.Error())
	}
	if err := ctx.Login(sh, CKU_SO, soPin); err != nil {
		ctx.CloseSession(sh)
		ctx.Finalize()
		ctx.Destroy()
		panic("Login(SO): " + err.Error())
	}
	if err := ctx.InitPIN(sh, userPin); err != nil {
		ctx.Logout(sh)
		ctx.CloseSession(sh)
		ctx.Finalize()
		ctx.Destroy()
		panic("C_InitPIN: " + err.Error())
	}
	ctx.Logout(sh)
	ctx.CloseSession(sh)
	ctx.Finalize()
	ctx.Destroy()

	return func() { os.RemoveAll(dir) }
}

// verifySoftHSMToken reopens the module and asserts that:
//   - exactly one initialised token is visible
//   - its label matches "test-token"
//   - CKF_TOKEN_INITIALIZED is set
//   - CKF_USER_PIN_INITIALIZED is set
//
// It panics with a descriptive message on any failure so a misconfigured
// token causes an immediate, obvious failure rather than cryptic test errors.
func verifySoftHSMToken(modulePath string) {
	const tokenLabel = "test-token"

	ctx := New(modulePath)
	if ctx == nil {
		panic("verifySoftHSMToken: failed to load module " + modulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		panic("verifySoftHSMToken: C_Initialize: " + err.Error())
	}
	defer func() {
		ctx.Finalize()
		ctx.Destroy()
	}()

	slots, err := ctx.GetSlotList(true) // tokenPresent=true
	if err != nil {
		panic("verifySoftHSMToken: C_GetSlotList: " + err.Error())
	}
	if len(slots) == 0 {
		panic("verifySoftHSMToken: no initialised token found — expected one with label " + tokenLabel)
	}

	// Find our token by label and validate its flags.
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			panic(fmt.Sprintf("verifySoftHSMToken: C_GetTokenInfo(slot %d): %v", slot, err))
		}

		label := strings.TrimRight(info.Label, " ")
		if label != tokenLabel {
			continue
		}

		if info.Flags&CKF_TOKEN_INITIALIZED == 0 {
			panic(fmt.Sprintf("verifySoftHSMToken: token %q found but CKF_TOKEN_INITIALIZED is not set (flags=0x%x)", tokenLabel, info.Flags))
		}
		if info.Flags&CKF_USER_PIN_INITIALIZED == 0 {
			panic(fmt.Sprintf("verifySoftHSMToken: token %q found but CKF_USER_PIN_INITIALIZED is not set (flags=0x%x)", tokenLabel, info.Flags))
		}

		// Smoke-test: open a user session and log in with PKCS11_PIN.
		sh, err := ctx.OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION)
		if err != nil {
			panic(fmt.Sprintf("verifySoftHSMToken: OpenSession on token %q: %v", tokenLabel, err))
		}
		if err := ctx.Login(sh, CKU_USER, os.Getenv("PKCS11_PIN")); err != nil {
			ctx.CloseSession(sh)
			panic(fmt.Sprintf("verifySoftHSMToken: Login(USER) on token %q: %v", tokenLabel, err))
		}
		ctx.Logout(sh)
		ctx.CloseSession(sh)

		fmt.Printf("verifySoftHSMToken: token %q on slot %d OK (flags=0x%x, lib=%s)\n",
			tokenLabel, slot, info.Flags, modulePath)
		return
	}

	panic(fmt.Sprintf("verifySoftHSMToken: no token with label %q found among %d initialised slot(s)", tokenLabel, len(slots)))
}
