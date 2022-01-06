package pkcs11

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"testing"
)

func TestConstCouunt(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "zconst.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	// Range through declarations:
	for _, dd := range f.Decls {
		if gd, ok := dd.(*ast.GenDecl); ok {
			if gd.Tok == token.CONST {
				for range gd.Specs {
					count++
				}
			}
		}
	}

	// Now to validate, run a shell pipeline to get the number in a different way from pkcs11t.h .
	grep := exec.Command("grep", "^#define CK", "pkcs11t.h")
	out, err := grep.Output()
	if err != nil {
		t.Fatal(err)
	}
	newline := []byte{'\n'}
	defines := bytes.Count(out, newline)

	if count != defines {
		t.Fatalf("Got %d constants from zconst.go, but %d #defines from pkcs11t.h", count, defines)
	}
}
