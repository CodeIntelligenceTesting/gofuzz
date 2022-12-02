package hook

import (
	"encoding/binary"
	"go/ast"
	"go/printer"
	"go/token"
	"hash/fnv"
	"io"
	"strconv"
)

func NodeId(n ast.Node, file string, fSet *token.FileSet) *ast.BasicLit {
	// In order to get deterministic IDs, we include the absolute filename,
	// line number, column number in the calculation of the ID for the IR node.
	hash := fnv.New32()
	// We ignore the errors here because the `io.Writer` in the `hash.Hash` interface
	// never returns an error.

	_, _ = io.WriteString(hash, file)
	if n.Pos().IsValid() {
		_ = binary.Write(hash, binary.LittleEndian, int64(n.Pos()))
	}
	_ = printer.Fprint(hash, fSet, n)
	return &ast.BasicLit{
		Kind:  token.INT,
		Value: strconv.Itoa(int(hash.Sum32())),
	}
}
