package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/mandiant/GoReSym/debug/gosym"
)

func calculateGimphash(funcs []gosym.Func) string {
	var functionNames []string

	for _, function := range funcs {
		functionName := function.Name

		// Exclude compiler/runtime generated symbols.
		if strings.HasPrefix(functionName, "go.") ||
			strings.HasPrefix(functionName, "go:") ||
			strings.HasPrefix(functionName, "type.") ||
			strings.HasPrefix(functionName, "type:") {
			continue
		}

		// Normalize vendored package paths.
		if i := strings.LastIndex(functionName, "vendor/"); i != -1 {
			functionName = functionName[i+len("vendor/"):]
		}

		// Exclude internal packages.
		if strings.Contains(functionName, "internal/") {
			continue
		}

		// Exclude standard-library packages.
		lastSlash := strings.LastIndex(functionName, "/")
		if lastSlash < 0 {
			lastSlash = 0
		}

		if i := strings.Index(functionName[lastSlash:], "."); i != -1 {
			packageName := functionName[:lastSlash+i]
			if isStdPackage(packageName) {
				continue
			}
		}

		functionNames = append(functionNames, functionName)
	}

	sort.Strings(functionNames)

	hash := sha256.New()
	for _, functionName := range functionNames {
		hash.Write([]byte(functionName))
	}

	return hex.EncodeToString(hash.Sum(nil))
}
