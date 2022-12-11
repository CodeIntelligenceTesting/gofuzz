package sanitize

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/tools/go/packages"

	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/fileutil"
	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/log"
	"github.com/CodeIntelligenceTesting/gofuzz/pkg/hook"
)

func Sanitize(pkgPattern string, opts *Options) (*packages.OverlayJSON, error) {
	pkgs, err := packages.Load(&packages.Config{
		Mode:       NeededLoadMode(),
		Env:        os.Environ(),
		BuildFlags: opts.BuildTags,
	}, "pattern="+pkgPattern)

	if err != nil {
		return nil, errors.Errorf("Failed to load package with pattern %q: %v", pkgPattern, err)
	}

	if err = checkPackageErrors(pkgs); err != nil {
		return nil, err
	}

	overlayJson := &packages.OverlayJSON{Replace: map[string]string{}}
	workDir, err := os.MkdirTemp("", "gofuzz-sanitize-")
	if err != nil {
		return nil, errors.Errorf("Failed to create working directory: %v", err)
	}
	log.Debugf("Working directory: %q\n", workDir)

	for _, pkg := range pkgs {
		if !opts.shouldSanitize(pkg.PkgPath) {
			continue
		}
		for i, sourceFile := range pkg.Syntax {
			transformer := hook.NewTransformer(sourceFile, pkg.Fset, pkg.CompiledGoFiles[i], pkg.TypesInfo)
			if transformer.TransformFile() {
				originalSourceFile := pkg.CompiledGoFiles[i]
				rel, err := fileutil.RelativePathInModule(pkg.Module.Dir, originalSourceFile)
				if err != nil {
					log.Warnf("Skipped instrumenting %q: %s", originalSourceFile, err.Error())
					continue
				}

				instrumentedFilePath := filepath.Join(workDir, rel)
				err = fileutil.SaveASTFile(sourceFile, pkg.Fset, instrumentedFilePath)
				if err != nil {
					log.Warnf("Skipped instrumenting %q: %v", originalSourceFile, err.Error())
					continue
				}
				log.Debugf("Instrumented source file: %q", originalSourceFile)
				overlayJson.Replace[originalSourceFile] = instrumentedFilePath
			}
		}
	}

	return overlayJson, nil
}

func NeededLoadMode() packages.LoadMode {
	return packages.NeedName |
		packages.NeedDeps |
		packages.NeedImports |
		packages.NeedCompiledGoFiles |
		packages.NeedModule |
		packages.NeedSyntax |
		packages.NeedTypes |
		packages.NeedTypesInfo
}

func checkPackageErrors(pkgs []*packages.Package) error {
	var errMsgs []string
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			errMsgs = append(errMsgs, fmt.Sprintf("%v", err))
		}
	})
	if len(errMsgs) > 0 {
		return errors.New(strings.Join(errMsgs, "\n"))
	}
	return nil
}
