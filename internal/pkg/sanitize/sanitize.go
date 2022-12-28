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
		BuildFlags: opts.BuildFlags,
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

	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if !opts.shouldSanitize(pkg.PkgPath) {
			return
		}
		log.Debugf("Instrumenting package %q", pkg.PkgPath)
		for i, sourceFile := range pkg.Syntax {
			originalSourceFile := pkg.CompiledGoFiles[i]
			transformer := hook.NewTransformer(sourceFile, pkg.Fset, originalSourceFile, pkg.TypesInfo, hook.NodeId)
			if numHooks := transformer.TransformFile(); numHooks > 0 {
				instrumentedFilePath := originalSourceFile
				if !opts.OverwriteSources {
					baseFile := filepath.Base(originalSourceFile)
					baseFileNoExtension := baseFile[:len(baseFile)-len(filepath.Ext(baseFile))]
					instrumentedFile, err := os.CreateTemp(workDir, fmt.Sprintf("%s-instrumented.*.go", baseFileNoExtension))
					if err != nil {
						log.Warnf("Failed to create a temporary file to store the instrumented code for %q: %v\n"+
							"\tThe source file will be not be instrumented with bug detection capabilities.\n"+
							"\tAs a result, some bugs in this file might be missed when fuzzing.",
							originalSourceFile, err)
						continue
					}
					instrumentedFilePath = instrumentedFile.Name()
				}
				err = fileutil.SaveASTFile(sourceFile, pkg.Fset, instrumentedFilePath)
				if err != nil {
					log.Warnf("Failed to save the instrumented code for %q: %v\n"+
						"\tThe source file will be not be instrumented with bug detection capabilities.\n"+
						"\tAs a result, some bugs in this file might be missed when fuzzing.",
						originalSourceFile, err.Error())
					continue
				}
				if instrumentedFilePath != originalSourceFile {
					overlayJson.Replace[originalSourceFile] = instrumentedFilePath
				}
				log.Infof("Added %d hook(s) to source file %q", numHooks, originalSourceFile)
			} else {
				log.Debugf("No hooks were added to source file %q", originalSourceFile)
			}
		}
	})

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
