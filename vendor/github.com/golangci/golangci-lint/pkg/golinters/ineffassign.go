package golinters

import (
	"fmt"
	"sync"

	"github.com/golangci/ineffassign"
	"golang.org/x/tools/go/analysis"

	"github.com/golangci/golangci-lint/pkg/golinters/goanalysis"
	"github.com/golangci/golangci-lint/pkg/lint/linter"
	"github.com/golangci/golangci-lint/pkg/result"
)

const ineffassignName = "ineffassign"

func NewIneffassign() *goanalysis.Linter {
	var mu sync.Mutex
	var resIssues []goanalysis.Issue

	analyzer := &analysis.Analyzer{
		Name: ineffassignName,
		Doc:  goanalysis.TheOnlyanalyzerDoc,
	}
	return goanalysis.NewLinter(
		ineffassignName,
		"Detects when assignments to existing variables are not used",
		[]*analysis.Analyzer{analyzer},
		nil,
	).WithContextSetter(func(lintCtx *linter.Context) {
		analyzer.Run = func(pass *analysis.Pass) (interface{}, error) {
			var fileNames []string
			for _, f := range pass.Files {
				pos := pass.Fset.Position(f.Pos())
				fileNames = append(fileNames, pos.Filename)
			}

			issues := ineffassign.Run(fileNames)
			if len(issues) == 0 {
				return nil, nil
			}

			res := make([]goanalysis.Issue, 0, len(issues))
			for _, i := range issues {
				res = append(res, goanalysis.NewIssue(&result.Issue{ //nolint:scopelint
					Pos:        i.Pos,
					Text:       fmt.Sprintf("ineffectual assignment to %s", formatCode(i.IdentName, lintCtx.Cfg)),
					FromLinter: ineffassignName,
				}, pass))
			}

			mu.Lock()
			resIssues = append(resIssues, res...)
			mu.Unlock()

			return nil, nil
		}
	}).WithIssuesReporter(func(*linter.Context) []goanalysis.Issue {
		return resIssues
	}).WithLoadMode(goanalysis.LoadModeSyntax)
}
