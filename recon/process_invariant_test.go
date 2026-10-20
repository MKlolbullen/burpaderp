package recon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Resolve import paths and inspect function references as well as calls (including aliased imports).
func processViolations(name string, source []byte) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return nil, err
	}
	processAliases := map[string]map[string]bool{}
	for _, imp := range file.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		names := map[string]bool{}
		switch path {
		case "os/exec":
			names = map[string]bool{"Command": true, "CommandContext": true, "Cmd": true}
		case "os":
			names = map[string]bool{"StartProcess": true}
		case "syscall":
			names = map[string]bool{"Exec": true, "ForkExec": true, "StartProcess": true}
		}
		if len(names) != 0 {
			alias := filepath.Base(path)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			processAliases[alias] = names
		}

	}
	var failures []string
	ast.Inspect(file, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && processAliases[id.Name][sel.Sel.Name] && name != "runner.go" {
				failures = append(failures, name+": ungoverned process start")
			}
		}
		if id, ok := node.(*ast.Ident); ok && id.Name == "runExternal" && name != "runner.go" && name != "execute.go" {
			failures = append(failures, name+": bypass of profile execution")
		}
		if id, ok := node.(*ast.Ident); ok && processAliases["."][id.Name] && name != "runner.go" {
			failures = append(failures, name+": dot-imported process start")
		}
		return true
	})
	return failures, nil
}

func TestOnlyRunnerCanStartExternalProcesses(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		failures, err := processViolations(filepath.ToSlash(path), source)
		if err != nil {
			return err
		}
		if len(failures) != 0 {
			t.Error(failures)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProcessGuardDetectsAliasesReferencesAndDotImports(t *testing.T) {
	for _, source := range []string{
		`package bypass; import e "os/exec"; var start = e.CommandContext`,
		`package bypass; import "os/exec"; var command = exec.Command("nuclei")`,
		`package bypass; import . "os/exec"; var start = Command`,
		`package recon; var bypass = runExternal`,
		`package bypass; import e "os/exec"; var command = e.Cmd{}`,
		`package bypass; import o "os"; var start = o.StartProcess`,
		`package bypass; import s "syscall"; var start = s.ForkExec`,
	} {
		failures, err := processViolations("bypass.go", []byte(source))
		if err != nil || len(failures) == 0 {
			t.Fatalf("guard missed %s: %v %v", source, failures, err)
		}
	}
}
