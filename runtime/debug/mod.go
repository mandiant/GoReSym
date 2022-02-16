// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"bytes"
	"fmt"
	"strings"
)

// ReadBuildInfo returns the build information embedded
// in the running binary. The information is available only
// in binaries built with module support.
func ReadBuildInfo() (info *BuildInfo, ok bool) {
	bi := &BuildInfo{}
	return bi, false
}

// BuildInfo represents the build information read from a Go binary.
type BuildInfo struct {
	GoVersion string         // Version of Go that produced this binary.
	Path      string         // The main package path
	Main      Module         // The module containing the main package
	Deps      []*Module      // Module dependencies
	Settings  []BuildSetting // Other information about the build.
}

// Module represents a module.
type Module struct {
	Path    string  // module path
	Version string  // module version
	Sum     string  // checksum
	Replace *Module // replaced by this module
}

// BuildSetting describes a setting that may be used to understand how the
// binary was built. For example, VCS commit and dirty status is stored here.
type BuildSetting struct {
	// Key and Value describe the build setting.
	// Key must not contain an equals sign, space, tab, or newline.
	// Value must not contain newlines ('\n').
	Key, Value string
}

func (bi *BuildInfo) MarshalText() ([]byte, error) {
	buf := &bytes.Buffer{}
	if bi.GoVersion != "" {
		fmt.Fprintf(buf, "go\t%s\n", bi.GoVersion)
	}
	if bi.Path != "" {
		fmt.Fprintf(buf, "path\t%s\n", bi.Path)
	}
	var formatMod func(string, Module)
	formatMod = func(word string, m Module) {
		buf.WriteString(word)
		buf.WriteByte('\t')
		buf.WriteString(m.Path)
		mv := m.Version
		if mv == "" {
			mv = "(devel)"
		}
		buf.WriteByte('\t')
		buf.WriteString(mv)
		if m.Replace == nil {
			buf.WriteByte('\t')
			buf.WriteString(m.Sum)
		} else {
			buf.WriteByte('\n')
			formatMod("=>", *m.Replace)
		}
		buf.WriteByte('\n')
	}
	if bi.Main.Path != "" {
		formatMod("mod", bi.Main)
	}
	for _, dep := range bi.Deps {
		formatMod("dep", *dep)
	}
	for _, s := range bi.Settings {
		if strings.ContainsAny(s.Key, "= \t\n") {
			return nil, fmt.Errorf("invalid build setting key %q", s.Key)
		}
		if strings.Contains(s.Value, "\n") {
			return nil, fmt.Errorf("invalid build setting value for key %q: contains newline", s.Value)
		}
		fmt.Fprintf(buf, "build\t%s=%s\n", s.Key, s.Value)
	}

	return buf.Bytes(), nil
}

func Cut(s, sep []byte) (before, after []byte, found bool) {
	if i := bytes.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, nil, false
}

func (bi *BuildInfo) UnmarshalText(data []byte) (err error) {
	*bi = BuildInfo{}
	lineNum := 1
	defer func() {
		if err != nil {
			err = fmt.Errorf("could not parse Go build info: line %d: %w", lineNum, err)
		}
	}()

	var (
		pathLine  = []byte("path\t")
		modLine   = []byte("mod\t")
		depLine   = []byte("dep\t")
		repLine   = []byte("=>\t")
		buildLine = []byte("build\t")
		newline   = []byte("\n")
		tab       = []byte("\t")
	)

	readModuleLine := func(elem [][]byte) (Module, error) {
		if len(elem) != 2 && len(elem) != 3 {
			return Module{}, fmt.Errorf("expected 2 or 3 columns; got %d", len(elem))
		}
		sum := ""
		if len(elem) == 3 {
			sum = string(elem[2])
		}
		return Module{
			Path:    string(elem[0]),
			Version: string(elem[1]),
			Sum:     sum,
		}, nil
	}

	var (
		last *Module
		line []byte
		ok   bool
	)
	// Reverse of BuildInfo.String(), except for go version.
	for len(data) > 0 {
		line, data, ok = Cut(data, newline)
		if !ok {
			break
		}
		switch {
		case bytes.HasPrefix(line, pathLine):
			elem := line[len(pathLine):]
			bi.Path = string(elem)
		case bytes.HasPrefix(line, modLine):
			elem := bytes.Split(line[len(modLine):], tab)
			last = &bi.Main
			*last, err = readModuleLine(elem)
			if err != nil {
				return err
			}
		case bytes.HasPrefix(line, depLine):
			elem := bytes.Split(line[len(depLine):], tab)
			last = new(Module)
			bi.Deps = append(bi.Deps, last)
			*last, err = readModuleLine(elem)
			if err != nil {
				return err
			}
		case bytes.HasPrefix(line, repLine):
			elem := bytes.Split(line[len(repLine):], tab)
			if len(elem) != 3 {
				return fmt.Errorf("expected 3 columns for replacement; got %d", len(elem))
			}
			if last == nil {
				return fmt.Errorf("replacement with no module on previous line")
			}
			last.Replace = &Module{
				Path:    string(elem[0]),
				Version: string(elem[1]),
				Sum:     string(elem[2]),
			}
			last = nil
		case bytes.HasPrefix(line, buildLine):
			key, val, ok := Cut(line[len(buildLine):], []byte("="))
			if !ok {
				return fmt.Errorf("invalid build line")
			}
			if string(key) == "" {
				return fmt.Errorf("empty key")
			}
			bi.Settings = append(bi.Settings, BuildSetting{Key: string(key), Value: string(val)})
		}
		lineNum++
	}
	return nil
}
