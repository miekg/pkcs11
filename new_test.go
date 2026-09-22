// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

// These tests build throwaway modules with the host C compiler, so that New
// can be checked against modules that misbehave. They do not need SoftHSM.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildModule compiles source into a shared library and returns its path.
func buildModule(t *testing.T, source string) string {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("the module is built as an ELF shared library")
	}

	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Skipf("no C compiler available: %s", err)
	}

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "module.c")
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	module := filepath.Join(dir, "module.so")
	if out, err := exec.Command(cc, "-shared", "-fPIC", "-o", module, sourcePath).CombinedOutput(); err != nil {
		t.Fatalf("failed to build module: %s: %s", err, out)
	}
	return module
}

// checkNewFails asserts that neither New nor NewWithError accepts the module,
// and that the error names the module and contains want.
func checkNewFails(t *testing.T, module, want string) {
	t.Helper()

	if p := New(module); p != nil {
		p.Destroy()
		t.Error("New succeeded for a module it cannot use")
	}

	p, err := NewWithError(module)
	if err == nil {
		p.Destroy()
		t.Fatal("NewWithError succeeded for a module it cannot use")
	}
	if p != nil {
		p.Destroy()
		t.Error("NewWithError returned a context along with an error")
	}
	if !strings.Contains(err.Error(), module) {
		t.Errorf("error is %q, want it to name the module %q", err, module)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error is %q, want it to contain %q", err, want)
	}
}

// TestNewGetFunctionListFails checks a module whose C_GetFunctionList fails
// without writing to ppFunctionList. Such a module used to yield a context
// with a NULL function list, which crashed the process on the first call into
// the module.
func TestNewGetFunctionListFails(t *testing.T) {
	module := buildModule(t, `
		unsigned long C_GetFunctionList(void **ppFunctionList)
		{
			return 0x5UL; // CKR_GENERAL_ERROR
		}
	`)

	checkNewFails(t, module, "C_GetFunctionList failed: 0x5")
}

// TestNewGetFunctionListReturnsNil checks a module that reports success but
// hands out no function list, which is just as unusable.
func TestNewGetFunctionListReturnsNil(t *testing.T) {
	module := buildModule(t, `
		unsigned long C_GetFunctionList(void **ppFunctionList)
		{
			*ppFunctionList = 0;
			return 0UL; // CKR_OK
		}
	`)

	checkNewFails(t, module, "C_GetFunctionList returned no function list")
}

func TestNewWithoutGetFunctionList(t *testing.T) {
	module := buildModule(t, `
		int not_a_pkcs11_module(void)
		{
			return 0;
		}
	`)

	checkNewFails(t, module, "C_GetFunctionList")
}

// TestNewModuleNotFound leaves the wording of the loader's message to the
// platform, and only asks that the error names the module it could not find.
func TestNewModuleNotFound(t *testing.T) {
	module := filepath.Join(t.TempDir(), "does-not-exist.so")

	checkNewFails(t, module, "does-not-exist.so")
}

// TestNewGetFunctionListSucceeds guards against the checks above rejecting a
// module that is fine. The function list is never called into.
func TestNewGetFunctionListSucceeds(t *testing.T) {
	module := buildModule(t, `
		static void *function_list[512];

		unsigned long C_GetFunctionList(void **ppFunctionList)
		{
			*ppFunctionList = function_list;
			return 0UL; // CKR_OK
		}
	`)

	p := New(module)
	if p == nil {
		t.Fatal("New failed for a module that returned a function list")
	}
	p.Destroy()

	p, err := NewWithError(module)
	if err != nil {
		t.Fatalf("NewWithError failed for a module that returned a function list: %s", err)
	}
	p.Destroy()
}
