package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"testing"

	"github.com/mandiant/GoReSym/debug/gosym"
)

func TestCalculateGimphash(t *testing.T) {
	tests := []struct {
		name  string
		funcs []gosym.Func
		want  string
	}{
		{
			name: "user function",
			funcs: []gosym.Func{
				{Sym: &gosym.Sym{Name: "example.com/app.Run"}},
			},
			want: hashFunctionNames("example.com/app.Run"),
		},
		{
			name: "internal functions are ignored",
			funcs: []gosym.Func{
				{Sym: &gosym.Sym{Name: "example.com/app/internal/helper.Run"}},
				{Sym: &gosym.Sym{Name: "example.com/app.Run"}},
			},
			want: hashFunctionNames("example.com/app.Run"),
		},
		{
			name: "unexported function is included",
			funcs: []gosym.Func{
				{Sym: &gosym.Sym{Name: "example.com/app.run"}},
				{Sym: &gosym.Sym{Name: "example.com/app.Run"}},
			},
			want: hashFunctionNames(
				"example.com/app.Run",
				"example.com/app.run",
			),
		},
		{
			name: "unexported receiver is included",
			funcs: []gosym.Func{
				{Sym: &gosym.Sym{Name: "example.com/app.(*server).Run"}},
				{Sym: &gosym.Sym{Name: "example.com/app.(*Server).Run"}},
			},
			want: hashFunctionNames(
				"example.com/app.(*Server).Run",
				"example.com/app.(*server).Run",
			),
		},
		{
			name: "standard library functions are ignored",
			funcs: []gosym.Func{
				{Sym: &gosym.Sym{Name: "fmt.Println"}},
				{Sym: &gosym.Sym{Name: "example.com/app.Run"}},
			},
			want: hashFunctionNames("example.com/app.Run"),
		},
		{
			name: "compiler generated functions are ignored",
			funcs: []gosym.Func{
				{Sym: &gosym.Sym{Name: "go.buildid"}},
				{Sym: &gosym.Sym{Name: "type:.eq.internal/foo.Bar"}},
				{Sym: &gosym.Sym{Name: "example.com/app.Run"}},
			},
			want: hashFunctionNames("example.com/app.Run"),
		},
		{
			name: "vendor prefix is removed",
			funcs: []gosym.Func{
				{Sym: &gosym.Sym{Name: "example.com/project/vendor/example.com/lib.Run"}},
			},
			want: hashFunctionNames("example.com/lib.Run"),
		},
		{
			name: "function order does not affect hash",
			funcs: []gosym.Func{
				{Sym: &gosym.Sym{Name: "example.com/app.Second"}},
				{Sym: &gosym.Sym{Name: "example.com/app.First"}},
			},
			want: hashFunctionNames(
				"example.com/app.First",
				"example.com/app.Second",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateGimphash(tt.funcs)
			if got != tt.want {
				t.Errorf("calculateGimphash() = %q, want %q", got, tt.want)
			}
		})
	}
}

func hashFunctionNames(names ...string) string {
	names = append([]string(nil), names...)
	sort.Strings(names)

	hash := sha256.New()

	for _, name := range names {
		hash.Write([]byte(name))
	}

	return hex.EncodeToString(hash.Sum(nil))
}
