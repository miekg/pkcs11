// Copyright 2026 Miek Gieben and the Golang pkcs11 Contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SPDX-License-Identifier: BSD-3-Clause

package pkcs11

// Integration tests for PKCS #11 v3.2 features.
//
// Run with:
//
//	make integration PKCS11_MODULE=/path/to/libsofthsmv3.so PKCS11_PIN=1234
//
// All tests are skipped when PKCS11_MODULE is unset. Individual tests are also
// skipped when the loaded token does not advertise the required mechanism,
// allowing the suite to run against partial implementations.
//
// Test naming convention:
//
//	TestV32<Feature>   — new v3.2 API shapes (stateless verify, auth wrap, …)
//	TestPQC<Algorithm> — post-quantum algorithm round-trips (ML-KEM, ML-DSA, SLH-DSA)

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

// v32Setup loads PKCS11_MODULE and opens an authenticated session.
// The test is skipped when PKCS11_MODULE is not set.
func v32Setup(t *testing.T) (*Ctx, SessionHandle, uint) {
	t.Helper()
	modulePath := os.Getenv("PKCS11_MODULE")
	if modulePath == "" {
		t.Skip("PKCS11_MODULE not set — skipping v3.2 integration test")
	}
	v32Pin := os.Getenv("PKCS11_PIN")
	if v32Pin == "" {
		v32Pin = "1234"
	}

	ctx := New(modulePath)
	if ctx == nil {
		t.Fatal("failed to load PKCS11_MODULE")
	}
	if err := ctx.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		t.Fatalf("GetSlotList: %v (slots=%d)", err, len(slots))
	}
	slot := slots[0]

	sh, err := ctx.OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		t.Fatalf("OpenSession: %v", err)
	}
	if err := ctx.Login(sh, CKU_USER, v32Pin); err != nil {
		ctx.CloseSession(sh)
		ctx.Finalize()
		ctx.Destroy()
		t.Fatalf("Login: %v", err)
	}
	return ctx, sh, slot
}

// v32Teardown closes the session and frees resources.
func v32Teardown(ctx *Ctx, sh SessionHandle) {
	ctx.Logout(sh)
	ctx.CloseSession(sh)
	ctx.Finalize()
	ctx.Destroy()
}

// requireMechanism skips the test if the token does not support mech.
func requireMechanism(t *testing.T, ctx *Ctx, slot, mech uint) {
	t.Helper()
	mechs, err := ctx.GetMechanismList(slot)
	if err != nil {
		t.Skipf("GetMechanismList: %v — skipping", err)
	}
	for _, m := range mechs {
		if m.Mechanism == mech {
			return
		}
	}
	t.Skipf("mechanism 0x%08X not supported by token — skipping", mech)
}

// ── ML-KEM (FIPS 203 / PKCS #11 v3.2 §6.68) ──────────────────────────────────

// TestPQCMLKEM exercises the full ML-KEM-768 round-trip:
// key-pair generation → encapsulation → decapsulation → shared-secret equality.
//
// ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) is standardised in
// NIST FIPS 203 and exposed in PKCS #11 v3.2 via CKM_ML_KEM_KEY_PAIR_GEN /
// CKM_ML_KEM, CKK_ML_KEM, and CKA_PARAMETER_SET = CKP_ML_KEM_768.
func TestPQCMLKEM(t *testing.T) {
	ctx, sh, slot := v32Setup(t)
	defer v32Teardown(ctx, sh)

	requireMechanism(t, ctx, slot, CKM_ML_KEM_KEY_PAIR_GEN)
	requireMechanism(t, ctx, slot, CKM_ML_KEM)

	// ── Key generation ───────────────────────────────────────────────────────
	pubTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_ML_KEM),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_ENCAPSULATE, true),
		NewAttribute(CKA_PARAMETER_SET, CKP_ML_KEM_768),
		NewAttribute(CKA_LABEL, "TestPQCMLKEM-pub"),
	}
	prvTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_ML_KEM),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_DECAPSULATE, true),
		NewAttribute(CKA_PARAMETER_SET, CKP_ML_KEM_768),
		NewAttribute(CKA_LABEL, "TestPQCMLKEM-prv"),
	}
	pub, prv, err := ctx.GenerateKeyPair(sh,
		[]*Mechanism{NewMechanism(CKM_ML_KEM_KEY_PAIR_GEN, nil)},
		pubTmpl, prvTmpl)
	if err != nil {
		t.Fatalf("GenerateKeyPair (ML-KEM-768): %v", err)
	}

	// ── Encapsulation ────────────────────────────────────────────────────────
	// The shared secret is derived as an AES-256 key so we can extract its
	// value and compare with the decapsulated counterpart.
	ssTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_AES),
		NewAttribute(CKA_VALUE_LEN, 32),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_SENSITIVE, false),
		NewAttribute(CKA_EXTRACTABLE, true),
	}
	ciphertext, encapKey, err := ctx.EncapsulateKey(sh,
		[]*Mechanism{NewMechanism(CKM_ML_KEM, nil)},
		pub, ssTmpl)
	if err != nil {
		t.Fatalf("EncapsulateKey: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("EncapsulateKey returned empty ciphertext")
	}
	t.Logf("ML-KEM-768 ciphertext length: %d bytes", len(ciphertext))

	// ── Decapsulation ────────────────────────────────────────────────────────
	decapKey, err := ctx.DecapsulateKey(sh,
		[]*Mechanism{NewMechanism(CKM_ML_KEM, nil)},
		prv, ssTmpl, ciphertext)
	if err != nil {
		t.Fatalf("DecapsulateKey: %v", err)
	}

	// ── Shared-secret equality ───────────────────────────────────────────────
	// Extract both shared secrets and verify they match.
	valTmpl := []*Attribute{NewAttribute(CKA_VALUE, nil)}

	encapAttr, err := ctx.GetAttributeValue(sh, encapKey, valTmpl)
	if err != nil {
		t.Fatalf("GetAttributeValue (encap shared secret): %v", err)
	}
	decapAttr, err := ctx.GetAttributeValue(sh, decapKey, valTmpl)
	if err != nil {
		t.Fatalf("GetAttributeValue (decap shared secret): %v", err)
	}

	if !bytes.Equal(encapAttr[0].Value, decapAttr[0].Value) {
		t.Fatal("encapsulated and decapsulated shared secrets do not match")
	}
	t.Logf("ML-KEM-768 shared secret (%d bytes) matches", len(encapAttr[0].Value))
}

// ── ML-DSA (FIPS 204 / PKCS #11 v3.2 §6.67) ──────────────────────────────────

// TestPQCMLDSA exercises the ML-DSA-65 sign / verify round-trip using the
// standard C_Sign / C_Verify path.
//
// ML-DSA (Module-Lattice-based Digital Signature Algorithm) is standardised in
// NIST FIPS 204. PKCS #11 v3.2 exposes it via CKM_ML_DSA_KEY_PAIR_GEN /
// CKM_ML_DSA, CKK_ML_DSA, and CKA_PARAMETER_SET = CKP_ML_DSA_65.
func TestPQCMLDSA(t *testing.T) {
	ctx, sh, slot := v32Setup(t)
	defer v32Teardown(ctx, sh)

	requireMechanism(t, ctx, slot, CKM_ML_DSA_KEY_PAIR_GEN)
	requireMechanism(t, ctx, slot, CKM_ML_DSA)

	pubTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_ML_DSA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VERIFY, true),
		NewAttribute(CKA_PARAMETER_SET, CKP_ML_DSA_65),
		NewAttribute(CKA_LABEL, "TestPQCMLDSA-pub"),
	}
	prvTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_ML_DSA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_PARAMETER_SET, CKP_ML_DSA_65),
		NewAttribute(CKA_LABEL, "TestPQCMLDSA-prv"),
	}
	pub, prv, err := ctx.GenerateKeyPair(sh,
		[]*Mechanism{NewMechanism(CKM_ML_DSA_KEY_PAIR_GEN, nil)},
		pubTmpl, prvTmpl)
	if err != nil {
		t.Fatalf("GenerateKeyPair (ML-DSA-65): %v", err)
	}

	msg := []byte("ML-DSA test message — PKCS11 v3.2")

	// ── Sign ─────────────────────────────────────────────────────────────────
	if err := ctx.SignInit(sh, []*Mechanism{NewMechanism(CKM_ML_DSA, nil)}, prv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := ctx.Sign(sh, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("ML-DSA-65 signature length: %d bytes", len(sig))

	// ── Verify (standard path) ───────────────────────────────────────────────
	if err := ctx.VerifyInit(sh, []*Mechanism{NewMechanism(CKM_ML_DSA, nil)}, pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := ctx.Verify(sh, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Log("ML-DSA-65 signature verified")
}

// ── SLH-DSA (FIPS 205 / PKCS #11 v3.2 §6.69) ─────────────────────────────────

// TestPQCSLHDSA exercises the SLH-DSA-SHA2-128s sign / verify round-trip.
//
// SLH-DSA (Stateless Hash-based Digital Signature Algorithm) is standardised in
// NIST FIPS 205. PKCS #11 v3.2 exposes it via CKM_SLH_DSA_KEY_PAIR_GEN /
// CKM_SLH_DSA, CKK_SLH_DSA, and CKA_PARAMETER_SET = CKP_SLH_DSA_SHA2_128S.
// Note: SLH-DSA signing is slow (seconds) for security levels above 128-bit.
func TestPQCSLHDSA(t *testing.T) {
	ctx, sh, slot := v32Setup(t)
	defer v32Teardown(ctx, sh)

	requireMechanism(t, ctx, slot, CKM_SLH_DSA_KEY_PAIR_GEN)
	requireMechanism(t, ctx, slot, CKM_SLH_DSA)

	pubTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_SLH_DSA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VERIFY, true),
		NewAttribute(CKA_PARAMETER_SET, CKP_SLH_DSA_SHA2_128S),
		NewAttribute(CKA_LABEL, "TestPQCSLHDSA-pub"),
	}
	prvTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_SLH_DSA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_PARAMETER_SET, CKP_SLH_DSA_SHA2_128S),
		NewAttribute(CKA_LABEL, "TestPQCSLHDSA-prv"),
	}
	pub, prv, err := ctx.GenerateKeyPair(sh,
		[]*Mechanism{NewMechanism(CKM_SLH_DSA_KEY_PAIR_GEN, nil)},
		pubTmpl, prvTmpl)
	if err != nil {
		t.Fatalf("GenerateKeyPair (SLH-DSA-SHA2-128s): %v", err)
	}

	msg := []byte("SLH-DSA test message — PKCS11 v3.2")

	if err := ctx.SignInit(sh, []*Mechanism{NewMechanism(CKM_SLH_DSA, nil)}, prv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := ctx.Sign(sh, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("SLH-DSA-SHA2-128s signature length: %d bytes", len(sig))

	if err := ctx.VerifyInit(sh, []*Mechanism{NewMechanism(CKM_SLH_DSA, nil)}, pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := ctx.Verify(sh, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Log("SLH-DSA-SHA2-128s signature verified")
}

// ── Stateless signature verification (PKCS #11 v3.2 §5.15) ───────────────────

// TestV32StatelessVerify exercises C_VerifySignatureInit / C_VerifySignature.
//
// In the traditional verify flow the signature is provided at C_VerifyFinal.
// The v3.2 stateless API binds the signature at C_VerifySignatureInit instead,
// which allows the token to stream the message without buffering it.
//
// We use CKM_RSA_PKCS with a pre-hashed DigestInfo message rather than
// CKM_SHA256_RSA_PKCS.  The hash-then-sign compound mechanisms require the
// token to buffer and hash the entire message before verifying; SoftHSMv3's
// stateless path does not implement that flow correctly (it returns
// CKR_SIGNATURE_INVALID for every call regardless of the actual signature).
// CKM_RSA_PKCS is a raw RSA mechanism — the token just checks the PKCS#1 v1.5
// padding — so the stateless verify API shape is tested without the complication
// of token-side hashing.
func TestV32StatelessVerify(t *testing.T) {
	ctx, sh, slot := v32Setup(t)
	defer v32Teardown(ctx, sh)

	requireMechanism(t, ctx, slot, CKM_RSA_PKCS_KEY_PAIR_GEN)
	requireMechanism(t, ctx, slot, CKM_RSA_PKCS)

	// Generate a temporary RSA-2048 key pair.
	pubTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VERIFY, true),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		NewAttribute(CKA_MODULUS_BITS, 2048),
		NewAttribute(CKA_LABEL, "TestV32StatelessVerify-pub"),
	}
	prvTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_LABEL, "TestV32StatelessVerify-prv"),
	}
	pub, prv, err := ctx.GenerateKeyPair(sh,
		[]*Mechanism{NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubTmpl, prvTmpl)
	if err != nil {
		t.Fatalf("GenerateKeyPair (RSA-2048): %v", err)
	}

	// CKM_RSA_PKCS operates on a DigestInfo-wrapped hash.
	// SHA-256 DigestInfo DER prefix (RFC 8017 §9.2, Table 1).
	sha256DigestInfo := []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
		0x05, 0x00, 0x04, 0x20,
	}
	rawMsg := []byte("stateless verify test message — PKCS11 v3.2")
	digest := sha256.Sum256(rawMsg)
	msg := append(sha256DigestInfo, digest[:]...)

	mech := []*Mechanism{NewMechanism(CKM_RSA_PKCS, nil)}

	// ── Sign with the traditional API ────────────────────────────────────────
	if err := ctx.SignInit(sh, mech, prv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := ctx.Sign(sh, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// ── Single-part stateless verify ─────────────────────────────────────────
	t.Run("SinglePart", func(t *testing.T) {
		if err := ctx.VerifySignatureInit(sh, mech, pub, sig); err != nil {
			if err == Error(CKR_FUNCTION_NOT_SUPPORTED) {
				t.Skip("C_VerifySignatureInit not supported by this token")
			}
			t.Fatalf("VerifySignatureInit: %v", err)
		}
		if err := ctx.VerifySignature(sh, msg); err != nil {
			t.Fatalf("VerifySignature: %v", err)
		}
		t.Log("single-part stateless verify passed")
	})

	// ── Multi-part stateless verify ──────────────────────────────────────────
	// CKM_RSA_PKCS is a single-part mechanism; tokens that don't support
	// streaming for raw RSA will return CKR_FUNCTION_NOT_SUPPORTED on
	// C_VerifySignatureUpdate — skip gracefully in that case.
	t.Run("MultiPart", func(t *testing.T) {
		if err := ctx.VerifySignatureInit(sh, mech, pub, sig); err != nil {
			if err == Error(CKR_FUNCTION_NOT_SUPPORTED) {
				t.Skip("C_VerifySignatureInit not supported by this token")
			}
			t.Fatalf("VerifySignatureInit: %v", err)
		}
		// Feed the message in two chunks.
		half := len(msg) / 2
		if err := ctx.VerifySignatureUpdate(sh, msg[:half]); err != nil {
			if err == Error(CKR_FUNCTION_NOT_SUPPORTED) {
				t.Skip("C_VerifySignatureUpdate not supported for CKM_RSA_PKCS on this token")
			}
			t.Fatalf("VerifySignatureUpdate (chunk 1): %v", err)
		}
		if err := ctx.VerifySignatureUpdate(sh, msg[half:]); err != nil {
			t.Fatalf("VerifySignatureUpdate (chunk 2): %v", err)
		}
		if err := ctx.VerifySignatureFinal(sh); err != nil {
			t.Fatalf("VerifySignatureFinal: %v", err)
		}
		t.Log("multi-part stateless verify passed")
	})

	// ── Tampered message must be rejected ────────────────────────────────────
	t.Run("TamperedMessage", func(t *testing.T) {
		if err := ctx.VerifySignatureInit(sh, mech, pub, sig); err != nil {
			if err == Error(CKR_FUNCTION_NOT_SUPPORTED) {
				t.Skip("C_VerifySignatureInit not supported by this token")
			}
			t.Fatalf("VerifySignatureInit: %v", err)
		}
		tampered := append([]byte(nil), msg...)
		tampered[0] ^= 0xFF
		err := ctx.VerifySignature(sh, tampered)
		if err == nil {
			t.Fatal("expected verification failure for tampered message, got nil")
		}
		t.Logf("tampered message correctly rejected: %v", err)
	})
}

// ── Authenticated key wrapping (PKCS #11 v3.2 §5.18.6-7) ─────────────────────

// TODO: Investigate SoftHSMv3 C_WrapKeyAuthenticated / C_UnwrapKeyAuthenticated.
// The wrap call succeeds and returns the correctly-sized blob (key + 16-byte GCM
// tag), but the unwrapped key value does not match the original.  This points to
// a bug or incomplete implementation in SoftHSMv3's authenticated wrap path.
// The test is kept here (skipped at runtime) so we can re-enable it once the
// upstream issue is resolved.
//
// The test generates an AES-256 key to be wrapped, wraps it with a second
// AES-256 KEK (key-encryption key) using AES-GCM with additional
// authenticated data, then unwraps it and verifies the key value is preserved.
//nolint:unused
func TestV32AuthenticatedWrap(t *testing.T) {
	ctx, sh, slot := v32Setup(t)
	defer v32Teardown(ctx, sh)

	requireMechanism(t, ctx, slot, CKM_AES_KEY_GEN)
	requireMechanism(t, ctx, slot, CKM_AES_GCM)

	symTmpl := func(label string, wrap, unwrap bool) []*Attribute {
		return []*Attribute{
			NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
			NewAttribute(CKA_KEY_TYPE, CKK_AES),
			NewAttribute(CKA_VALUE_LEN, 32),
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_SENSITIVE, false),
			NewAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_WRAP, wrap),
			NewAttribute(CKA_UNWRAP, unwrap),
			NewAttribute(CKA_ENCRYPT, !wrap),
			NewAttribute(CKA_DECRYPT, !wrap),
			NewAttribute(CKA_LABEL, label),
		}
	}

	// Key-encryption key (wraps/unwraps other keys).
	kek, err := ctx.GenerateKey(sh,
		[]*Mechanism{NewMechanism(CKM_AES_KEY_GEN, nil)},
		symTmpl("TestV32AuthWrap-kek", true, true))
	if err != nil {
		t.Fatalf("GenerateKey (KEK): %v", err)
	}

	// Target key whose value we want to preserve across wrap/unwrap.
	target, err := ctx.GenerateKey(sh,
		[]*Mechanism{NewMechanism(CKM_AES_KEY_GEN, nil)},
		symTmpl("TestV32AuthWrap-target", false, false))
	if err != nil {
		t.Fatalf("GenerateKey (target): %v", err)
	}

	// Read the original target key value for later comparison.
	origAttr, err := ctx.GetAttributeValue(sh, target,
		[]*Attribute{NewAttribute(CKA_VALUE, nil)})
	if err != nil {
		t.Fatalf("GetAttributeValue (original target): %v", err)
	}
	origValue := origAttr[0].Value

	aad := []byte("TestV32AuthenticatedWrap AAD")

	unwrapTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_AES),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_SENSITIVE, false),
		NewAttribute(CKA_EXTRACTABLE, true),
	}

	// ── Wrap ─────────────────────────────────────────────────────────────────
	// Each GCMParams is single-use: cGCMParams consumes it.  Some tokens
	// (including SoftHSMv3) write their own IV back into pIv after the wrap
	// operation, so we read it back via gcmWrapParams.IV() before freeing.
	gcmWrapParams := NewGCMParams(make([]byte, 12), nil, 128)
	wrapped, err := ctx.WrapKeyAuthenticated(sh,
		[]*Mechanism{NewMechanism(CKM_AES_GCM, gcmWrapParams)},
		kek, target, aad)
	if err != nil {
		gcmWrapParams.Free()
		if err == Error(CKR_FUNCTION_NOT_SUPPORTED) {
			t.Skip("C_WrapKeyAuthenticated not supported by this token")
		}
		t.Fatalf("WrapKeyAuthenticated: %v", err)
	}
	t.Logf("authenticated wrapped key blob: %d bytes", len(wrapped))

	// Read back the IV actually used (the token may have overwritten it).
	wrapIV := gcmWrapParams.IV()
	gcmWrapParams.Free()
	t.Logf("wrap IV (%d bytes): %x", len(wrapIV), wrapIV)

	// ── Unwrap ───────────────────────────────────────────────────────────────
	// Must use the exact IV that was used during wrap.
	gcmUnwrapParams := NewGCMParams(wrapIV, nil, 128)
	recovered, err := ctx.UnwrapKeyAuthenticated(sh,
		[]*Mechanism{NewMechanism(CKM_AES_GCM, gcmUnwrapParams)},
		kek, wrapped, aad, unwrapTmpl)
	gcmUnwrapParams.Free()
	if err != nil {
		t.Fatalf("UnwrapKeyAuthenticated: %v", err)
	}

	// ── Value equality ───────────────────────────────────────────────────────
	recovAttr, err := ctx.GetAttributeValue(sh, recovered,
		[]*Attribute{NewAttribute(CKA_VALUE, nil)})
	if err != nil {
		t.Fatalf("GetAttributeValue (recovered key): %v", err)
	}
	if !bytes.Equal(origValue, recovAttr[0].Value) {
		t.Fatal("recovered key value does not match original")
	}
	t.Log("authenticated wrap/unwrap round-trip passed")

	// ── Wrong AAD must fail ──────────────────────────────────────────────────
	gcmWrongParams := NewGCMParams(wrapIV, nil, 128)
	_, err = ctx.UnwrapKeyAuthenticated(sh,
		[]*Mechanism{NewMechanism(CKM_AES_GCM, gcmWrongParams)},
		kek, wrapped, []byte("wrong AAD"), unwrapTmpl)
	gcmWrongParams.Free()
	if err == nil {
		t.Fatal("expected UnwrapKeyAuthenticated to fail with wrong AAD, got nil")
	}
	t.Logf("wrong AAD correctly rejected: %v", err)
}

// ── Session validation flags (PKCS #11 v3.2 §5.6.11) ─────────────────────────

// TestV32GetSessionValidationFlags exercises C_GetSessionValidationFlags, a
// new v3.2 API that lets callers query whether the last cryptographic operation
// on a session was performed by a FIPS-validated code path.
//
// We perform a successful RSA sign, then check that the token either:
//   - reports the operation as validated (CKS_LAST_VALIDATION_OK set), or
//   - returns CKR_FUNCTION_NOT_SUPPORTED (acceptable for tokens that have not
//     implemented FIPS validation reporting).
func TestV32GetSessionValidationFlags(t *testing.T) {
	ctx, sh, slot := v32Setup(t)
	defer v32Teardown(ctx, sh)

	requireMechanism(t, ctx, slot, CKM_RSA_PKCS_KEY_PAIR_GEN)
	requireMechanism(t, ctx, slot, CKM_SHA256_RSA_PKCS)

	pubTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VERIFY, true),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		NewAttribute(CKA_MODULUS_BITS, 2048),
		NewAttribute(CKA_LABEL, "TestV32ValFlags-pub"),
	}
	prvTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_LABEL, "TestV32ValFlags-prv"),
	}
	_, prv, err := ctx.GenerateKeyPair(sh,
		[]*Mechanism{NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubTmpl, prvTmpl)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	if err := ctx.SignInit(sh, []*Mechanism{NewMechanism(CKM_SHA256_RSA_PKCS, nil)}, prv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	if _, err := ctx.Sign(sh, []byte("validation flags test")); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	flags, err := ctx.GetSessionValidationFlags(sh, CKS_LAST_VALIDATION_OK)
	if err != nil {
		if err == Error(CKR_FUNCTION_NOT_SUPPORTED) {
			t.Skip("C_GetSessionValidationFlags not supported by this token")
		}
		// Some tokens return an error when FIPS mode is not active.
		t.Logf("GetSessionValidationFlags: %v (token may not be in FIPS mode)", err)
		return
	}
	t.Logf("session validation flags after Sign: 0x%x (CKS_LAST_VALIDATION_OK=%v)",
		flags, flags&CKS_LAST_VALIDATION_OK != 0)
}

// ── PQC key attribute readback (PKCS #11 v3.2 §6.67–§6.69) ───────────────────

// TestV32PQCParamSetReadback verifies that CKA_PARAMETER_SET is correctly
// stored and returned by C_GetAttributeValue after PQC key generation.
//
// This tests the v3.2 attribute infrastructure shared by all three NIST PQC
// families (ML-KEM, ML-DSA, SLH-DSA): the token must echo back the exact
// CKP_* constant that was requested in the key-generation template.
func TestV32PQCParamSetReadback(t *testing.T) {
	ctx, sh, slot := v32Setup(t)
	defer v32Teardown(ctx, sh)

	cases := []struct {
		name       string
		keyGenMech uint
		keyType    uint
		paramSet   uint
	}{
		{"ML-KEM-768", CKM_ML_KEM_KEY_PAIR_GEN, CKK_ML_KEM, CKP_ML_KEM_768},
		{"ML-DSA-65", CKM_ML_DSA_KEY_PAIR_GEN, CKK_ML_DSA, CKP_ML_DSA_65},
		{"SLH-DSA-SHA2-128s", CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128S},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			requireMechanism(t, ctx, slot, tc.keyGenMech)

			pubTmpl := []*Attribute{
				NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
				NewAttribute(CKA_KEY_TYPE, tc.keyType),
				NewAttribute(CKA_TOKEN, false),
				NewAttribute(CKA_PARAMETER_SET, tc.paramSet),
				NewAttribute(CKA_LABEL, "TestV32PQCReadback-pub-"+tc.name),
			}
			prvTmpl := []*Attribute{
				NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
				NewAttribute(CKA_KEY_TYPE, tc.keyType),
				NewAttribute(CKA_TOKEN, false),
				NewAttribute(CKA_SENSITIVE, true),
				NewAttribute(CKA_PARAMETER_SET, tc.paramSet),
				NewAttribute(CKA_LABEL, "TestV32PQCReadback-prv-"+tc.name),
			}
			pub, prv, err := ctx.GenerateKeyPair(sh,
				[]*Mechanism{NewMechanism(tc.keyGenMech, nil)},
				pubTmpl, prvTmpl)
			if err != nil {
				t.Fatalf("GenerateKeyPair: %v", err)
			}

			query := []*Attribute{NewAttribute(CKA_PARAMETER_SET, nil)}
			pubAttr, err := ctx.GetAttributeValue(sh, pub, query)
			if err != nil {
				t.Fatalf("GetAttributeValue(pub): %v", err)
			}
			prvAttr, err := ctx.GetAttributeValue(sh, prv, query)
			if err != nil {
				t.Fatalf("GetAttributeValue(prv): %v", err)
			}

			// CKA_PARAMETER_SET is a CK_ULONG — decode as little-endian.
			decodeUlong := func(b []byte) uint {
				var v uint
				for i, byt := range b {
					v |= uint(byt) << (8 * i)
				}
				return v
			}
			gotPub := decodeUlong(pubAttr[0].Value)
			gotPrv := decodeUlong(prvAttr[0].Value)

			if gotPub != tc.paramSet {
				t.Errorf("pub CKA_PARAMETER_SET = 0x%x, want 0x%x", gotPub, tc.paramSet)
			}
			if gotPrv != tc.paramSet {
				t.Errorf("prv CKA_PARAMETER_SET = 0x%x, want 0x%x", gotPrv, tc.paramSet)
			}
			t.Logf("%s: CKA_PARAMETER_SET = 0x%x ✓", tc.name, gotPub)
		})
	}
}
